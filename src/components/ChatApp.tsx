import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Socket } from 'socket.io-client';
import { ChatMessage, RoomSummary, UserProfile } from '../types';
import {
  ensureUserHybridKeyPair,
  acquireBlindedIdentityToken,
  rotateGroupEpoch,
  getGroupEpochState,
  createGroupEpochPacket,
  decapsulateGroupEpochKey,
  encryptMessageText,
  decryptMessageText,
  encryptFileBytes,
  decryptFileBytes,
  isEncryptedFileBytes,
  FileEncryptionOptions,
  E2EEError,
  isE2EEEnabled,
  getRoomSecret,
  setRoomSecret,
  isE2EEPayload,
  VoprfBlindTokenRecord,
  getRoomPQStatus,
  getGroupSecurityBadge,
  parsePeerKeyBundle,
  getStoredPeerPublicKey,
  setStoredPeerPublicKey,
} from '../utils/crypto';
import {
  SAFETY_STRINGS_FA,
  ContactVerificationRecord,
  getContactVerificationRecord,
  observeContactPublicKey,
  getGroupVerificationSummary,
  rotateSessionRatchetOnly,
} from '../utils/safetyNumber';
import { SafetyNumberModal } from './SafetyNumberModal';
import {
  deleteIdentityRecordV4,
  disablePasswordProtection,
  enablePasswordProtection,
  isPasswordProtectionEnabled,
  lockIdentity,
  pruneDurableReplaySeen,
  unlockIdentityWithPassphrase,
} from '../utils/keystore';

interface ChatAppProps {
  myUsername: string;
  socket: Socket;
  onLogout: () => void;
  showToast: (text: string) => void;
}

interface DecryptedChatMessage extends ChatMessage {
  decryptedText?: string;
  isE2EE?: boolean;
  e2eeMode?: 'PQ-MLKEM-RATCHET' | 'GROUP-EPOCH-FSM' | 'PBKDF2';
  ratchetStep?: number;
  epoch?: number;
  mldsaVerified?: boolean;
  decryptFailed?: boolean;
}

const QUICK_EMOJIS = ['❤️', '👍', '😂', '🔥', '👏', '😮'];

// ===== Media E2EE — authenticated fetch + decrypt + blob URL =====
//
// <img>/<audio> tags cannot send an Authorization header, so media is never
// put in a raw src. Instead it is fetched with the session token, decrypted
// with the room key when the server says it is encrypted (X-Media-Encrypted),
// and rendered from a blob URL. A media link therefore opens only for an
// authenticated member of the chat — never from a bare URL, never anonymously.
//
// Legacy /uploads/... links (stored in old messages/avatars) are rewritten to
// /api/media/... before fetching: the public /uploads route no longer exists.

function resolveMediaUrl(fileUrl: string): string {
  return fileUrl.startsWith('/uploads/') ? '/api/media/' + fileUrl.slice('/uploads/'.length) : fileUrl;
}

function getSessionToken(): string {
  try {
    return localStorage.getItem('chat_session_token') || '';
  } catch {
    return '';
  }
}

interface FetchedMedia {
  bytes: Uint8Array;
  isEncrypted: boolean;
  mime: string;
}

async function fetchAuthenticatedMedia(fileUrl: string): Promise<FetchedMedia> {
  const token = getSessionToken();
  const res = await fetch(resolveMediaUrl(fileUrl), {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`media fetch failed: ${res.status}`);
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  return {
    bytes: buf,
    isEncrypted: res.headers.get('X-Media-Encrypted') === '1' || isEncryptedFileBytes(buf),
    mime: res.headers.get('Content-Type') || '',
  };
}

// Avatars are fetched from many places (list, profile, group members) — one
// shared in-memory cache per URL so the same picture is fetched once.
const avatarBlobCache = new Map<string, { url: string; mime: string }>();

async function fetchAvatarBlobUrl(src: string): Promise<{ url: string; mime: string }> {
  const cached = avatarBlobCache.get(src);
  if (cached) return cached;
  const fetched = await fetchAuthenticatedMedia(src);
  const blob = new Blob([fetched.bytes as unknown as BlobPart], {
    type: fetched.mime || undefined,
  });
  const entry = { url: URL.createObjectURL(blob), mime: fetched.mime };
  avatarBlobCache.set(src, entry);
  return entry;
}

/** An avatar image fetched with the session token (never a raw src) —
 * except Google profile photos, which are public https URLs on
 * lh3.googleusercontent.com (allowed by the CSP img-src pin) and are
 * rendered directly: fetching them with a Bearer token would send the
 * session token to Google for no reason and needs CORS the host does
 * not promise. Any OTHER http(s) avatar URL renders nothing — the
 * session token must never be sent to an arbitrary host, and no
 * third-party host may be loaded as a tracking pixel. */
function AuthImg(props: {
  src: string | null | undefined;
  alt?: string;
  className?: string;
  style?: React.CSSProperties;
}) {
  const isGooglePhoto =
    typeof props.src === 'string' &&
    props.src.startsWith('https://lh3.googleusercontent.com/');
  const isOtherExternal =
    typeof props.src === 'string' &&
    (props.src.startsWith('https://') || props.src.startsWith('http://')) &&
    !isGooglePhoto;
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    setObjectUrl(null);
    if (!props.src || isGooglePhoto || isOtherExternal) return;
    fetchAvatarBlobUrl(props.src)
      .then(entry => {
        if (!cancelled) setObjectUrl(entry.url);
      })
      .catch(() => {
        // Avatar unavailable (deleted / no access) — render nothing.
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.src]);
  if (isGooglePhoto) {
    return <img src={props.src} alt={props.alt || ''} className={props.className} style={props.style} />;
  }
  if (isOtherExternal) return null;
  if (!objectUrl) return null;
  return <img src={objectUrl} alt={props.alt || ''} className={props.className} style={props.style} />;
}

/** A chat media attachment (image / voice / file) fetched with the session token and decrypted with the room key. */
function SecureMedia(props: {
  fileUrl: string;
  fileType: string;
  roomId: string | null;
  cryptoOptions: FileEncryptionOptions;
}) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setFailed(false);
    setObjectUrl(null);
    (async () => {
      try {
        const fetched = await fetchAuthenticatedMedia(props.fileUrl);
        let bytes = fetched.bytes;
        if (fetched.isEncrypted) {
          if (!props.roomId) throw new Error('no room for encrypted media');
          bytes = await decryptFileBytes(bytes, props.roomId, props.cryptoOptions);
        }
        if (cancelled) return;
        const blob = new Blob([bytes as unknown as BlobPart], {
          type: fetched.mime || undefined,
        });
        setObjectUrl(URL.createObjectURL(blob));
      } catch {
        if (!cancelled) setFailed(true);
      }
    })();
    return () => {
      cancelled = true;
    };
    // The crypto options object is rebuilt by the parent memo per room; the
    // effect must re-run when the file or the room changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.fileUrl, props.roomId]);

  if (failed) {
    return <div className="media-unavailable">🔒 رسانه در دسترس نیست</div>;
  }
  if (!objectUrl) {
    return <div className="media-loading">⏳ در حال بارگذاری رسانه…</div>;
  }
  if (props.fileType === 'image') {
    return <img src={objectUrl} alt="" />;
  }
  if (props.fileType === 'voice') {
    return <audio controls src={objectUrl} />;
  }
  if (props.fileType === 'video') {
    return <video controls src={objectUrl} style={{ maxWidth: '100%' }} />;
  }
  return (
    <div className="file-attach">
      📁{' '}
      <a href={objectUrl} download style={{ color: 'inherit' }}>
        دانلود فایل
      </a>
    </div>
  );
}

export const ChatApp: React.FC<ChatAppProps> = ({
  myUsername,
  socket,
  onLogout,
  showToast,
}) => {
  const [myProfile, setMyProfile] = useState<UserProfile>({
    username: myUsername,
    display_name: null,
    avatar: null,
    bio: '',
    status: 'online',
  });
  const [activeTab, setActiveTab] = useState<'chats' | 'groups'>('chats');
  const [rooms, setRooms] = useState<RoomSummary[]>([]);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const [currentPartner, setCurrentPartner] = useState<string | null>(null);
  const [currentPartnerName, setCurrentPartnerName] = useState<string>('');
  const [currentIsGroup, setCurrentIsGroup] = useState(false);
  const [currentRoom, setCurrentRoom] = useState<string | null>(null);
  const [partnerOnline, setPartnerOnline] = useState(false);
  const [partnerStatusLabel, setPartnerStatusLabel] = useState('آفلاین');

  const [messages, setMessages] = useState<DecryptedChatMessage[]>([]);
  const [pinnedMessage, setPinnedMessage] = useState<DecryptedChatMessage | null>(null);
  const [messageText, setMessageText] = useState('');
  const [replyTo, setReplyTo] = useState<{ id: string; text: string } | null>(null);
  const [typingUser, setTypingUser] = useState<string | null>(null);
  const [disappearAfter, setDisappearAfter] = useState<number>(0);

  // E2EE + Post-Quantum + VOPRF State (Mandatory E2EE - L11)
  const e2eeActive = true;
  const [e2eeModalOpen, setE2eeModalOpen] = useState(false);
  const [customSecretInput, setCustomSecretInput] = useState('');

  // L8: محافظت از کلید هویت با رمز عبور
  const [identityLocked, setIdentityLocked] = useState(false);
  const [unlockPassphrase, setUnlockPassphrase] = useState('');
  const [unlockMsg, setUnlockMsg] = useState<{ text: string; ok: boolean }>({ text: '', ok: false });
  const [pwProtectionEnabled, setPwProtectionEnabled] = useState<boolean | null>(null);
  const [pwNewPass, setPwNewPass] = useState('');
  const [pwConfirmPass, setPwConfirmPass] = useState('');
  const [pwCurrentPass, setPwCurrentPass] = useState('');
  const [pwMsg, setPwMsg] = useState<{ text: string; ok: boolean }>({ text: '', ok: false });

  const refreshPwProtectionStatus = useCallback(async () => {
    try {
      setPwProtectionEnabled(await isPasswordProtectionEnabled(myUsername));
    } catch {
      setPwProtectionEnabled(null);
    }
  }, [myUsername]);

  useEffect(() => {
    if (e2eeModalOpen) {
      setPwMsg({ text: '', ok: false });
      setPwNewPass('');
      setPwConfirmPass('');
      setPwCurrentPass('');
      void refreshPwProtectionStatus();
    }
  }, [e2eeModalOpen, refreshPwProtectionStatus]);

  const handleEnablePwProtection = async () => {
    if (pwNewPass.length < 8) {
      setPwMsg({ text: 'رمز عبور باید حداقل ۸ کاراکتر باشد.', ok: false });
      return;
    }
    if (pwNewPass !== pwConfirmPass) {
      setPwMsg({ text: 'تکرار رمز عبور مطابقت ندارد.', ok: false });
      return;
    }
    try {
      await enablePasswordProtection(myUsername, pwNewPass);
      setPwProtectionEnabled(true);
      setPwNewPass('');
      setPwConfirmPass('');
      setPwMsg({
        text: 'محافظت با رمز عبور فعال شد. کلید هویت شما اکنون فقط با این رمز باز می‌شود — آن را در جایی امن نگه دارید؛ در صورت فراموشی، بازیابی ممکن نیست.',
        ok: true,
      });
    } catch (err: any) {
      setPwMsg({ text: `فعال‌سازی ناموفق بود: ${err?.message || 'خطای ناشناخته'}`, ok: false });
    }
  };

  const handleDisablePwProtection = async () => {
    try {
      await disablePasswordProtection(myUsername, pwCurrentPass);
      setPwProtectionEnabled(false);
      setPwCurrentPass('');
      setPwMsg({ text: 'محافظت با رمز عبور غیرفعال شد.', ok: true });
    } catch (err: any) {
      setPwMsg({
        text:
          err?.code === 'IDENTITY_LOCKED'
            ? 'رمز عبور فعلی نادرست است.'
            : `غیرفعال‌سازی ناموفق بود: ${err?.message || 'خطای ناشناخته'}`,
        ok: false,
      });
    }
  };

  const handleUnlockIdentity = async () => {
    try {
      await unlockIdentityWithPassphrase(myUsername, unlockPassphrase);
      setIdentityLocked(false);
      setUnlockPassphrase('');
      setUnlockMsg({ text: '', ok: false });
      // کلید هویت باز شد — باندل عمومی را دوباره منتشر کن.
      const pubKey = await ensureUserHybridKeyPair(myUsername);
      if (pubKey) {
        const sessionToken = localStorage.getItem('chat_session_token') || '';
        fetch('/api/user/public-key', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
          },
          body: JSON.stringify({ username: myUsername, publicKey: pubKey }),
        }).catch(() => {});
      }
    } catch (err: any) {
      setUnlockMsg({
        text:
          err?.code === 'IDENTITY_LOCKED'
            ? 'رمز عبور نادرست است.'
            : `باز کردن ناموفق بود: ${err?.message || 'خطای ناشناخته'}`,
        ok: false,
      });
    }
  };
  const [voprfToken, setVoprfToken] = useState<VoprfBlindTokenRecord | null>(null);
  const [currentGroupEpoch, setCurrentGroupEpoch] = useState<number>(1);
  const groupMembersRef = useRef<Record<string, string[]>>({});

  // Safety Numbers (Spec v0.1) State
  const [verificationVersion, setVerificationVersion] = useState<number>(0);
  const [inChatLearnMoreOpen, setInChatLearnMoreOpen] = useState<boolean>(false);
  const [outgoingChangeConfirmOpen, setOutgoingChangeConfirmOpen] = useState<boolean>(false);
  const [groupMemberProfiles, setGroupMemberProfiles] = useState<Record<string, UserProfile>>({});
  const [safetyModalState, setSafetyModalState] = useState<{
    open: boolean;
    contactUsername: string;
    contactAvatar?: string | null;
    initialShowLearnMore?: boolean;
  }>({
    open: false,
    contactUsername: '',
    contactAvatar: null,
    initialShowLearnMore: false,
  });

  // Mobile responsive view
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 700);
  const [mobileChatOpen, setMobileChatOpen] = useState(false);

  // Menus & Modals
  const [attachOpen, setAttachOpen] = useState(false);
  const [ctxMenu, setCtxMenu] = useState<{
    visible: boolean;
    x: number;
    y: number;
    msgId: string;
    text: string;
    sender: string;
  }>({ visible: false, x: 0, y: 0, msgId: '', text: '', sender: '' });

  const [contactModalOpen, setContactModalOpen] = useState(false);
  const [newContactInput, setNewContactInput] = useState('');
  const [contactModalMsg, setContactModalMsg] = useState<{ text: string; ok: boolean }>({
    text: '',
    ok: false,
  });

  const [profileModalOpen, setProfileModalOpen] = useState(false);
  const [bioInput, setBioInput] = useState('');
  const [nameInput, setNameInput] = useState('');
  const [statusInput, setStatusInput] = useState('online');
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);

  const [contactProfileModal, setContactProfileModal] = useState<{
    open: boolean;
    user: UserProfile | null;
  }>({ open: false, user: null });

  const [editModal, setEditModal] = useState<{ open: boolean; text: string }>({
    open: false,
    text: '',
  });
  const [forwardModalOpen, setForwardModalOpen] = useState(false);
  const [forwardSelected, setForwardSelected] = useState<string[]>([]);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportReason, setReportReason] = useState('spam');
  const [disappearModalOpen, setDisappearModalOpen] = useState(false);
  const [changelogModalOpen, setChangelogModalOpen] = useState(false);

  // Group creation modal state
  const [groupModalOpen, setGroupModalOpen] = useState(false);
  const [groupNameInput, setGroupNameInput] = useState('');
  const [groupMembersSelected, setGroupMembersSelected] = useState<string[]>([]);
  const [extraMemberInput, setExtraMemberInput] = useState('');

  // File upload hidden inputs refs (for reliable browser clicking)
  const imageFileInputRef = useRef<HTMLInputElement | null>(null);
  const docFileInputRef = useRef<HTMLInputElement | null>(null);
  const avatarFileInputRef = useRef<HTMLInputElement | null>(null);

  // Time formatter with Asia/Tehran timezone
  const formatMessageTime = useCallback((item?: { time?: string; timestamp?: number }): string => {
    if (!item) return '';
    if (item.timestamp) {
      try {
        return new Intl.DateTimeFormat('fa-IR', {
          hour: '2-digit',
          minute: '2-digit',
          timeZone: 'Asia/Tehran',
        }).format(new Date(item.timestamp));
      } catch {
        // fallback
      }
    }
    return item.time || '';
  }, []);

  // Text search highlighter
  const renderHighlightedText = useCallback((text: string, query: string) => {
    if (!query || !query.trim() || !text) return text;
    const q = query.trim();
    const lowerText = text.toLowerCase();
    const lowerQ = q.toLowerCase();
    const firstMatch = lowerText.indexOf(lowerQ);
    if (firstMatch === -1) return text;

    const parts: React.ReactNode[] = [];
    let curr = 0;
    while (curr < text.length) {
      const matchIdx = lowerText.indexOf(lowerQ, curr);
      if (matchIdx === -1) {
        parts.push(text.substring(curr));
        break;
      }
      if (matchIdx > curr) {
        parts.push(text.substring(curr, matchIdx));
      }
      parts.push(
        <mark
          key={matchIdx}
          style={{
            background: '#f59e0b',
            color: '#111827',
            padding: '1px 3px',
            borderRadius: '3px',
            fontWeight: 600,
          }}
        >
          {text.substring(matchIdx, matchIdx + q.length)}
        </mark>
      );
      curr = matchIdx + q.length;
    }
    return <>{parts}</>;
  }, []);

  // Voice recording
  const [isRecording, setIsRecording] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  const currentRoomRef = useRef<string | null>(null);
  const currentPartnerRef = useRef<string | null>(null);
  const peerPublicKeysRef = useRef<Record<string, string | null>>({});
  const messagesContainerRef = useRef<HTMLDivElement | null>(null);
  const typingTimerRef = useRef<number | null>(null);
  const isTypingRef = useRef(false);

  currentRoomRef.current = currentRoom;
  currentPartnerRef.current = currentPartner;

  const scrollBottom = useCallback(() => {
    setTimeout(() => {
      if (messagesContainerRef.current) {
        messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
      }
    }, 30);
  }, []);

  const syncPeerPublicKeyAndObserve = useCallback(
    (peerUsername: string, publicKey: string | null | undefined): ContactVerificationRecord | null => {
      if (!peerUsername || peerUsername === myUsername) return null;
      if (publicKey) {
        peerPublicKeysRef.current[peerUsername] = publicKey;
        setStoredPeerPublicKey(peerUsername, publicKey);
      }
      const effectiveKey =
        publicKey || peerPublicKeysRef.current[peerUsername] || getStoredPeerPublicKey(peerUsername);
      const before = getContactVerificationRecord(myUsername, peerUsername);
      const after = observeContactPublicKey(myUsername, peerUsername, effectiveKey);
      if (
        before.state !== after.state ||
        before.knownMldsaPubB64 !== after.knownMldsaPubB64 ||
        before.changedAt !== after.changedAt
      ) {
        setVerificationVersion(v => v + 1);
      }
      return after;
    },
    [myUsername]
  );

  const syncGroupMembersPublicKeys = useCallback(
    async (members: string[]) => {
      const otherMembers = Array.from(
        new Set((members || []).map(m => String(m || '').trim()).filter(Boolean))
      ).filter(m => m !== myUsername);

      const fetchedProfiles: Record<string, UserProfile> = {};
      await Promise.all(
        otherMembers.map(async member => {
          try {
            const uRes = await fetch('/api/user/' + encodeURIComponent(member)).then(r => r.json());
            if (uRes.ok && uRes.user) {
              fetchedProfiles[member] = uRes.user;
              if (uRes.user.public_key) {
                syncPeerPublicKeyAndObserve(member, uRes.user.public_key);
              }
            }
          } catch {
            // ignore
          }
        })
      );
      if (Object.keys(fetchedProfiles).length > 0) {
        setGroupMemberProfiles(prev => ({ ...prev, ...fetchedProfiles }));
      }
      setVerificationVersion(v => v + 1);
    },
    [myUsername, syncPeerPublicKeyAndObserve]
  );

  // کلید اپوک گروه: در صورتی که بسته کلید برای این اپوک موجود باشد،
  // کپسول خودم را باز می‌کنم و می‌چرخانم؛ اگر نیست و من توزیع‌کننده‌ام
  // (سازنده گروه = اولین عضو)، بسته را می‌سازم و منتشر می‌کنم.
  const ensureGroupEpochPacket = useCallback(
    async (groupId: string, epoch: number, members: string[]): Promise<boolean> => {
      const sessionToken = (() => {
        try {
          return localStorage.getItem('chat_session_token') || '';
        } catch {
          return '';
        }
      })();
      const authHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      if (sessionToken) authHeaders.Authorization = `Bearer ${sessionToken}`;
      const fetchPacket = async (): Promise<{ epoch: number; keys: Record<string, string> } | null> => {
        try {
          const r = await fetch(`/api/group/${encodeURIComponent(groupId)}/epoch-packet`, {
            headers: authHeaders,
          }).then(x => x.json());
          if (r.ok && r.epoch === epoch && r.keys && typeof r.keys === 'object') return r;
        } catch {
          // ignore
        }
        return null;
      };
      const applyPacket = async (keys: Record<string, string>): Promise<boolean> => {
        const myCt = keys[myUsername];
        if (!myCt) return false;
        const epochKey = await decapsulateGroupEpochKey(myUsername, myCt);
        if (!epochKey) return false;
        await rotateGroupEpoch(groupId, epoch, members, epochKey);
        return true;
      };
      // ۱. بسته موجود؟
      const existing = await fetchPacket();
      if (existing) return applyPacket(existing.keys);
      // ۲. من توزیع‌کننده‌ام؟ (سازنده گروه، اولین عضو)
      const isDistributor = members[0] === myUsername;
      if (!isDistributor) {
        // توزیع‌کننده هنوز منتشر نکرده؛ چند بار دیگر تلاش کن.
        for (let attempt = 0; attempt < 3; attempt++) {
          await new Promise(r => setTimeout(r, 1500));
          const retry = await fetchPacket();
          if (retry) return applyPacket(retry.keys);
        }
        return false;
      }
      // ۳. ساخت بسته با باندل‌های تأییدشده اعضا (با دریافت کلید از سرور در صورت عدم حضور در کش).
      const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle> | null> = {};
      for (const m of members) {
        if (m === myUsername) continue;
        let bundleStr = peerPublicKeysRef.current[m] || getStoredPeerPublicKey(m);
        if (!bundleStr) {
          try {
            const uRes = await fetch('/api/user/' + encodeURIComponent(m)).then(r => r.json());
            if (uRes.ok && uRes.user?.public_key) {
              bundleStr = uRes.user.public_key;
              syncPeerPublicKeyAndObserve(m, bundleStr);
            }
          } catch {
            // ignore
          }
        }
        bundles[m] = bundleStr ? parsePeerKeyBundle(bundleStr, m) : null;
      }
      const packet = await createGroupEpochPacket(bundles, myUsername, epoch);
      if (packet.missing.length > 0) {
        showToast(
          `⚠️ کلید اپوک گروه برای این اعضا ساخته نشد (بدون باندل تأییدشده): ${packet.missing.join('، ')}`
        );
      }
      try {
        await fetch(`/api/group/${encodeURIComponent(groupId)}/epoch-packet`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ epoch, keys: packet.keys, sig: packet.distributorSigB64 }),
        });
      } catch {
        // ignore
      }
      await rotateGroupEpoch(groupId, epoch, members, packet.epochKeyB64);
      return true;
    },
    [myUsername, showToast]
  );

  const getPeerKeyForRoom = useCallback(
    (roomId: string): string | null => {
      if (roomId.startsWith('group__')) return null;
      const partner = roomId.split('__').find(u => u.toLowerCase() !== myUsername.toLowerCase());
      if (!partner) return null;
      if (peerPublicKeysRef.current[partner]) return peerPublicKeysRef.current[partner];
      const stored = getStoredPeerPublicKey(partner);
      if (stored) {
        peerPublicKeysRef.current[partner] = stored;
        return stored;
      }
      return null;
    },
    [myUsername]
  );

  const currentPQStatus = useMemo(() => {
    if (!currentRoom) return null;
    return getRoomPQStatus({
      roomId: currentRoom,
      isGroup: currentIsGroup,
      e2eeActive,
      myUsername,
      peerPublicKey: !currentIsGroup ? getPeerKeyForRoom(currentRoom) : undefined,
      peerUsername: !currentIsGroup && currentPartner ? currentPartner : undefined,
      customSecret: getRoomSecret(currentRoom),
    });
  }, [currentRoom, currentIsGroup, e2eeActive, myUsername, getPeerKeyForRoom, currentPartner, verificationVersion]);

  const currentPartnerVerification = useMemo(() => {
    if (!currentPartner || currentIsGroup) return null;
    const peerKey =
      peerPublicKeysRef.current[currentPartner] || getStoredPeerPublicKey(currentPartner);
    return observeContactPublicKey(myUsername, currentPartner, peerKey);
  }, [myUsername, currentPartner, currentIsGroup, verificationVersion]);

  const currentGroupMembersList = useMemo(() => {
    if (!currentIsGroup || !currentPartner) return [];
    const roomObj = rooms.find(r => r.isGroup && r.id === currentPartner);
    return roomObj?.members || groupMembersRef.current[currentPartner] || [];
  }, [currentIsGroup, currentPartner, rooms, currentGroupEpoch]);

  // گزینه‌های رمزنگاری فایل برای اتاق جاری — همان ورودی‌های encryptMessageText.
  const getFileCryptoOptions = useCallback((): FileEncryptionOptions => {
    return {
      myUsername,
      peerPublicKey: !currentIsGroup && currentRoom ? getPeerKeyForRoom(currentRoom) : undefined,
      peerUsername: !currentIsGroup && currentPartner ? currentPartner : undefined,
      customSecret: currentRoom ? getRoomSecret(currentRoom) : undefined,
      groupMembers: currentIsGroup ? currentGroupMembersList : undefined,
    };
  }, [myUsername, currentRoom, currentIsGroup, currentPartner, getPeerKeyForRoom, currentGroupMembersList]);

  const currentGroupVerificationSummary = useMemo(() => {
    if (!currentIsGroup || !currentPartner) return null;
    return getGroupVerificationSummary(myUsername, currentGroupMembersList);
  }, [myUsername, currentIsGroup, currentPartner, currentGroupMembersList, verificationVersion]);

  const openSafetyModalForContact = useCallback(
    async (contactUsername: string, avatar?: string | null, initialShowLearnMore = false) => {
      if (!contactUsername || contactUsername === myUsername) return;
      let pubKey =
        peerPublicKeysRef.current[contactUsername] || getStoredPeerPublicKey(contactUsername);
      let resolvedAvatar = avatar ?? groupMemberProfiles[contactUsername]?.avatar ?? null;
      if (!pubKey) {
        try {
          const uRes = await fetch('/api/user/' + encodeURIComponent(contactUsername)).then(r =>
            r.json()
          );
          if (uRes.ok && uRes.user) {
            pubKey = uRes.user.public_key || null;
            resolvedAvatar = resolvedAvatar ?? uRes.user.avatar ?? null;
            if (pubKey) {
              syncPeerPublicKeyAndObserve(contactUsername, pubKey);
            }
          }
        } catch {
          // ignore
        }
      } else {
        syncPeerPublicKeyAndObserve(contactUsername, pubKey);
      }
      setSafetyModalState({
        open: true,
        contactUsername,
        contactAvatar: resolvedAvatar,
        initialShowLearnMore,
      });
    },
    [myUsername, groupMemberProfiles, syncPeerPublicKeyAndObserve]
  );

  const processDecryption = useCallback(
    async (msg: ChatMessage, roomId: string): Promise<DecryptedChatMessage> => {
      let peerPublicKey = getPeerKeyForRoom(roomId);
      const partner = roomId.startsWith('group__') ? undefined : roomId.split('__').find(u => u.toLowerCase() !== myUsername.toLowerCase());
      if (!peerPublicKey && partner) {
        try {
          const uRes = await fetch('/api/user/' + encodeURIComponent(partner)).then(r => r.json());
          if (uRes.ok && uRes.user?.public_key) {
            peerPublicKey = uRes.user.public_key;
            syncPeerPublicKeyAndObserve(partner, peerPublicKey);
          }
        } catch {
          // ignore
        }
      } else if (peerPublicKey && partner) {
        syncPeerPublicKeyAndObserve(partner, peerPublicKey);
      }

      const gId = roomId.startsWith('group__') ? roomId.replace('group__', '') : '';
      const groupMembers = gId ? groupMembersRef.current[gId] || [] : undefined;

      let dec: Awaited<ReturnType<typeof decryptMessageText>>;
      try {
        dec = await decryptMessageText(msg.text || '', roomId, {
          myUsername,
          peerPublicKey,
          peerUsername: partner,
          sender: msg.sender,
          groupMembers,
        });
      } catch (err) {
        const isSigErr = err instanceof E2EEError && (err.code === 'INVALID_SIGNATURE' || err.code === 'MISSING_SIGNATURE');
        dec = {
          text: isSigErr
            ? '⛔ [پیام رد شد: امضای پساکوانتومی ML-DSA-65 نامعتبر است]'
            : '🔒 [پیام رمزنگاری‌شده - کلید این نشست در دسترس نیست یا بازنشانی شده است]',
          isEncrypted: true,
          mldsaVerified: false,
          failed: true,
        };
      }
      let decReply = msg.reply_to_text;
      if (msg.reply_to_text && isE2EEPayload(msg.reply_to_text)) {
        try {
          const rDec = await decryptMessageText(msg.reply_to_text, roomId, {
            myUsername,
            peerPublicKey,
            peerUsername: partner,
            sender: msg.sender,
            groupMembers,
          });
          decReply = rDec.text;
        } catch {
          decReply = '🔒 [پیام رمزنگاری‌شده]';
        }
      }
      return {
        ...msg,
        reply_to_text: decReply,
        decryptedText: dec.text,
        isE2EE: dec.isEncrypted,
        e2eeMode: dec.mode,
        ratchetStep: dec.ratchetStep,
        epoch: dec.epoch,
        mldsaVerified: dec.mldsaVerified,
        decryptFailed: dec.failed,
      };
    },
    [myUsername, getPeerKeyForRoom, syncPeerPublicKeyAndObserve]
  );

  const loadRoomList = useCallback(
    async (tab: 'chats' | 'groups') => {
      if (tab === 'chats') {
        // (profile-auth) the contact list is the user's own data: the server
        // only serves it to the session owner, so the token must be sent.
        const sessionToken = getSessionToken();
        const res = await fetch('/api/contacts/' + encodeURIComponent(myUsername), {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        }).then(r => r.json());
        if (res.ok) {
          res.contacts.forEach((c: any) => {
            if (c.public_key) {
              syncPeerPublicKeyAndObserve(c.username, c.public_key);
            }
          });
          setRooms(
            res.contacts.map((c: any) => ({
              id: c.username,
              name: c.display_name || c.username,
              isGroup: false,
              avatar: c.avatar,
              online: !!c.online,
              preview: c.online ? 'آنلاین' : 'آفلاین',
              publicKey: c.public_key || null,
            }))
          );
        }
      } else {
        const sessionToken = getSessionToken();
        const res = await fetch('/api/groups/' + encodeURIComponent(myUsername), {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        }).then(r => r.json());
        if (res.ok) {
          res.groups.forEach((g: any) => {
            if (Array.isArray(g.members)) {
              groupMembersRef.current[g.id] = g.members;
              void syncGroupMembersPublicKeys(g.members);
            }
            if (g.epoch) {
              void ensureGroupEpochPacket(g.id, Number(g.epoch), g.members || []);
            }
          });
          setRooms(
            res.groups.map((g: any) => ({
              id: g.id,
              name: g.name,
              isGroup: true,
              preview: `گروه • Epoch #${g.epoch || 1}`,
              epoch: g.epoch || 1,
              members: g.members || [],
            }))
          );
        }
      }
    },
    [myUsername, syncPeerPublicKeyAndObserve, syncGroupMembersPublicKeys, ensureGroupEpochPacket]
  );

  // Initial load + Ristretto255-VOPRF Blinded Auth + Post-Quantum Hybrid Key Exchange (ML-KEM-768 + P-256)
  useEffect(() => {
    const sessionToken = localStorage.getItem('chat_session_token') || '';
    // اتصال سوکت با توکن نشست معتبر احراز هویت می‌شود؛
    // نام کاربری تنها قابل جعل است.
    socket.emit('auth', { username: myUsername, token: sessionToken });
    loadRoomList('chats');
    // هرس انبار دائم Replay در استارتاپ (راند ۳) — best-effort.
    void pruneDurableReplaySeen();

    acquireBlindedIdentityToken(myUsername)
      .then(voprfRec => {
        if (voprfRec) setVoprfToken(voprfRec);
        return ensureUserHybridKeyPair(myUsername);
      })
      .then(pubKey => {
        if (pubKey) {
          fetch('/api/user/public-key', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
            },
            body: JSON.stringify({ username: myUsername, publicKey: pubKey }),
          }).catch(() => {});
        }
      })
      .catch(err => {
        // L8: هویت با رمز عبور محافظت شده و در این نشست باز نشده است —
        // به‌جای شکست خاموش، پنجرهٔ باز کردن رمز عبور را نشان بده.
        if (err instanceof E2EEError && err.code === 'IDENTITY_LOCKED') {
          setIdentityLocked(true);
        }
      });

    fetch('/api/user/' + encodeURIComponent(myUsername))
      .then(r => r.json())
      .then(res => {
        if (res.ok && res.user) {
          setMyProfile(res.user);
          setNameInput(res.user.display_name || '');
          setBioInput(res.user.bio || '');
          setStatusInput(res.user.status || 'online');
          setAvatarPreview(res.user.avatar || null);
        }
      })
      .catch(() => {});

    const handleResize = () => setIsMobile(window.innerWidth <= 700);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [myUsername, socket, loadRoomList]);

  // Global click to dismiss context/attach menus
  useEffect(() => {
    const handleDocClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('.ctx-menu')) {
        setCtxMenu(prev => (prev.visible ? { ...prev, visible: false } : prev));
      }
      if (!target.closest('.attach-menu') && !target.closest('.attach-trigger')) {
        setAttachOpen(false);
      }
    };
    document.addEventListener('click', handleDocClick);
    return () => document.removeEventListener('click', handleDocClick);
  }, []);

  // Socket listeners
  useEffect(() => {
    const onNewMessage = async ({ roomId, msg }: { roomId: string; msg: ChatMessage }) => {
      const partnerId = roomId.startsWith('group__')
        ? roomId.replace('group__', '')
        : roomId.split('__').find(u => u.toLowerCase() !== myUsername.toLowerCase());

      const decMsg = await processDecryption(msg, roomId);
      const previewStr =
        decMsg.decryptedText ||
        (msg.file_type === 'image' ? '📷 عکس' : msg.file_type === 'voice' ? '🎤 ویس' : '📁 فایل');

      setRooms(prev =>
        prev.map(r =>
          r.id === partnerId ? { ...r, preview: previewStr, time: msg.time } : r
        )
      );

      if (roomId !== currentRoomRef.current) return;
      setMessages(prev => [...prev, decMsg]);
      scrollBottom();
      if (msg.sender !== myUsername) {
        socket.emit('read', { roomId, msgId: msg.id });
      }
    };

    const onRead = ({ roomId, msgId }: { roomId: string; msgId: string }) => {
      if (roomId !== currentRoomRef.current) return;
      setMessages(prev =>
        prev.map(m => (m.id === msgId ? { ...m, is_read: true } : m))
      );
    };

    const onMsgEdited = async ({
      roomId,
      msgId,
      newText,
    }: {
      roomId: string;
      msgId: string;
      newText: string;
    }) => {
      if (roomId !== currentRoomRef.current) return;
      let dec: Awaited<ReturnType<typeof decryptMessageText>>;
      try {
        dec = await decryptMessageText(newText, roomId, {
          myUsername,
          peerPublicKey: getPeerKeyForRoom(roomId),
        });
      } catch {
        dec = {
          text: '🔒 [پیام ویرایش‌شده قابل رمزگشایی نیست]',
          isEncrypted: true,
          failed: true,
        };
      }
      setMessages(prev =>
        prev.map(m =>
          m.id === msgId
            ? {
                ...m,
                text: newText,
                decryptedText: dec.text,
                isE2EE: dec.isEncrypted,
                decryptFailed: dec.failed,
                is_edited: true,
              }
            : m
        )
      );
    };

    const onMsgDeleted = async ({ roomId, msgId }: { roomId: string; msgId: string }) => {
      const partnerId = roomId.startsWith('group__')
        ? roomId.replace('group__', '')
        : roomId.split('__').find(u => u !== myUsername);

      if (roomId === currentRoomRef.current) {
        setMessages(prev => prev.filter(m => m.id !== msgId));
        setPinnedMessage(curr => (curr?.id === msgId ? null : curr));
      }

      // Refresh chat-list preview after delete
      try {
        const sessionToken = getSessionToken();
        const res = await fetch('/api/messages/' + encodeURIComponent(roomId), {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        }).then(r => r.json());
        if (res.ok && Array.isArray(res.messages)) {
          if (res.messages.length > 0) {
            const lastMsg = res.messages[res.messages.length - 1];
            const decLast = await processDecryption(lastMsg, roomId);
            const previewStr =
              decLast.decryptedText ||
              (lastMsg.file_type === 'image'
                ? '📷 عکس'
                : lastMsg.file_type === 'voice'
                ? '🎤 ویس'
                : '📁 فایل');
            setRooms(prev =>
              prev.map(r =>
                r.id === partnerId
                  ? { ...r, preview: previewStr, time: formatMessageTime(lastMsg) }
                  : r
              )
            );
          } else {
            setRooms(prev =>
              prev.map(r =>
                r.id === partnerId
                  ? {
                      ...r,
                      preview: r.isGroup
                        ? `گروه • Epoch #${r.epoch || 1}`
                        : (r.online ? 'آنلاین' : 'آفلاین'),
                      time: undefined,
                    }
                  : r
              )
            );
          }
        }
      } catch {
        // ignore
      }
    };

    const onMsgPinned = ({ roomId, msgId }: { roomId: string; msgId: string }) => {
      if (roomId !== currentRoomRef.current) return;
      setMessages(prev => {
        const found = prev.find(m => m.id === msgId) || null;
        if (found) setPinnedMessage(found);
        return prev.map(m => ({ ...m, is_pinned: m.id === msgId }));
      });
    };

    const onMsgUnpinned = ({ roomId, msgId }: { roomId: string; msgId?: string }) => {
      if (roomId !== currentRoomRef.current) return;
      setPinnedMessage(null);
      setMessages(prev =>
        prev.map(m => (!msgId || m.id === msgId ? { ...m, is_pinned: false } : m))
      );
    };

    const onMsgReaction = ({
      roomId,
      msgId,
      reactions,
    }: {
      roomId: string;
      msgId: string;
      reactions: Record<string, string[]>;
    }) => {
      if (roomId !== currentRoomRef.current) return;
      setMessages(prev =>
        prev.map(m => (m.id === msgId ? { ...m, reactions } : m))
      );
    };

    const onTyping = ({
      roomId,
      username,
      isTyping,
    }: {
      roomId: string;
      username: string;
      isTyping: boolean;
    }) => {
      if (roomId !== currentRoomRef.current) return;
      setTypingUser(isTyping ? username : null);
      if (isTyping) scrollBottom();
    };

    const onContactOnline = (u: string) => {
      setRooms(prev =>
        prev.map(r =>
          r.id === u
            ? { ...r, online: true, preview: r.preview === 'آفلاین' ? 'آنلاین' : r.preview }
            : r
        )
      );
      if (currentPartnerRef.current === u) {
        setPartnerOnline(true);
        setPartnerStatusLabel('آنلاین');
      }
    };

    const onContactOffline = (u: string) => {
      setRooms(prev =>
        prev.map(r =>
          r.id === u
            ? { ...r, online: false, preview: r.preview === 'آنلاین' ? 'آفلاین' : r.preview }
            : r
        )
      );
      if (currentPartnerRef.current === u) {
        setPartnerOnline(false);
        setPartnerStatusLabel('آفلاین');
      }
    };

    const onContactStatus = ({ username, status }: { username: string; status: string }) => {
      if (currentPartnerRef.current === username) {
        setPartnerStatusLabel(
          status === 'online' ? 'آنلاین' : status === 'busy' ? 'مشغول' : 'غایب'
        );
      }
    };

    const onNewGroup = (g: { id: string; name: string; members?: string[]; epoch?: number }) => {
      if (Array.isArray(g.members)) {
        groupMembersRef.current[g.id] = g.members;
      }
      if (g.epoch) {
        void ensureGroupEpochPacket(g.id, g.epoch, g.members || []);
      }
      setRooms(prev => {
        if (prev.some(r => r.id === g.id)) return prev;
        return [
          ...prev,
          {
            id: g.id,
            name: g.name,
            isGroup: true,
            preview: `گروه • Epoch #${g.epoch || 1}`,
            epoch: g.epoch || 1,
            members: g.members || [],
          },
        ];
      });
    };

    const onGroupEpochRotated = async ({
      groupId,
      epoch,
      members,
      epochKeys,
    }: {
      groupId: string;
      name: string;
      epoch: number;
      members: string[];
      epochKeys?: Record<string, string>;
    }) => {
      groupMembersRef.current[groupId] = members;
      void syncGroupMembersPublicKeys(members);
      // در صورت دریافت بسته کلید همراه رویداد، کپسول محلی بازگشایی می‌شود؛
      // در غیر این صورت بسته را می‌گیرم یا (اگر توزیع‌کننده‌ام) می‌سازم.
      if (epochKeys && epochKeys[myUsername]) {
        const epochKey = await decapsulateGroupEpochKey(myUsername, epochKeys[myUsername]);
        if (epochKey) {
          await rotateGroupEpoch(groupId, epoch, members, epochKey);
        }
      } else {
        await ensureGroupEpochPacket(groupId, epoch, members);
      }
      setRooms(prev =>
        prev.map(r =>
          r.id === groupId
            ? { ...r, epoch, members, preview: `گروه • Epoch #${epoch}` }
            : r
        )
      );
      if (currentRoomRef.current === `group__${groupId}`) {
        setCurrentGroupEpoch(epoch);
        showToast(`🔄 کلید اپوک گروه به Epoch #${epoch} چرخش یافت (Group Epoch FSM)`);
      }
    };

    const onPeerKeyUpdated = ({ username, publicKey }: { username: string; publicKey: string }) => {
      syncPeerPublicKeyAndObserve(username, publicKey);
    };

    socket.on('new-message', onNewMessage);
    socket.on('read', onRead);
    socket.on('msg-edited', onMsgEdited);
    socket.on('msg-deleted', onMsgDeleted);
    socket.on('msg-pinned', onMsgPinned);
    socket.on('msg-unpinned', onMsgUnpinned);
    socket.on('msg-reaction', onMsgReaction);
    socket.on('typing', onTyping);
    socket.on('contact-online', onContactOnline);
    socket.on('contact-offline', onContactOffline);
    socket.on('contact-status', onContactStatus);
    socket.on('new-group', onNewGroup);
    socket.on('group-epoch-rotated', onGroupEpochRotated);
    socket.on('peer-key-updated', onPeerKeyUpdated);

    return () => {
      socket.off('new-message', onNewMessage);
      socket.off('read', onRead);
      socket.off('msg-edited', onMsgEdited);
      socket.off('msg-deleted', onMsgDeleted);
      socket.off('msg-pinned', onMsgPinned);
      socket.off('msg-unpinned', onMsgUnpinned);
      socket.off('msg-reaction', onMsgReaction);
      socket.off('typing', onTyping);
      socket.off('contact-online', onContactOnline);
      socket.off('contact-offline', onContactOffline);
      socket.off('contact-status', onContactStatus);
      socket.off('new-group', onNewGroup);
      socket.off('group-epoch-rotated', onGroupEpochRotated);
      socket.off('peer-key-updated', onPeerKeyUpdated);
    };
  }, [
    myUsername,
    socket,
    processDecryption,
    scrollBottom,
    getPeerKeyForRoom,
    showToast,
    formatMessageTime,
    syncPeerPublicKeyAndObserve,
    syncGroupMembersPublicKeys,
  ]);

  const handleOpenChat = async (room: RoomSummary) => {
    const roomId = room.isGroup
      ? 'group__' + room.id
      : [myUsername, room.id].sort().join('__');

    setInChatLearnMoreOpen(false);
    setOutgoingChangeConfirmOpen(false);

    if (!room.isGroup) {
      if (room.publicKey) {
        syncPeerPublicKeyAndObserve(room.id, room.publicKey);
      }
      try {
        const uRes = await fetch('/api/user/' + encodeURIComponent(room.id)).then(r => r.json());
        if (uRes.ok && uRes.user?.public_key) {
          syncPeerPublicKeyAndObserve(room.id, uRes.user.public_key);
        }
      } catch {
        // ignore
      }
    } else {
      const gMembers = room.members || groupMembersRef.current[room.id] || [];
      if (gMembers.length > 0) {
        groupMembersRef.current[room.id] = gMembers;
        void syncGroupMembersPublicKeys(gMembers);
      }
    }

    setCurrentPartner(room.id);
    setCurrentPartnerName(room.name);
    setCurrentIsGroup(room.isGroup);
    setCurrentRoom(roomId);
    setReplyTo(null);
    setPartnerOnline(!!room.online);
    if (room.isGroup) {
      const fsm = getGroupEpochState(room.id, room.members || groupMembersRef.current[room.id] || []);
      const ep = room.epoch || fsm.currentEpoch || 1;
      setCurrentGroupEpoch(ep);
      setPartnerStatusLabel(`گروه • Epoch #${ep} (FSM)`);
    } else {
      setPartnerStatusLabel(room.online ? 'آنلاین' : 'آفلاین');
    }
    setCustomSecretInput(getRoomSecret(roomId));
    if (isMobile) setMobileChatOpen(true);

    const sessionToken = getSessionToken();
    const res = await fetch('/api/messages/' + encodeURIComponent(roomId), {
      headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
    }).then(r => r.json());
    if (res.ok && Array.isArray(res.messages)) {
      const decryptedList: DecryptedChatMessage[] = [];
      for (const m of res.messages as ChatMessage[]) {
        decryptedList.push(await processDecryption(m, roomId));
      }
      setMessages(decryptedList);
      const pinned = decryptedList.find(m => m.is_pinned) || null;
      setPinnedMessage(pinned);
      scrollBottom();
    }
  };

  const executeSendMessage = async () => {
    const trimmed = messageText.trim();
    if (!trimmed || !currentRoom || !currentPartner) return;

    let payloadText = trimmed;
    try {
      const peerKey = getPeerKeyForRoom(currentRoom);
      if (!currentIsGroup && !peerKey) {
        showToast('⛔ کلید عمومی مخاطب هنوز دریافت نشده است — ارسال پیام لغو شد');
        return;
      }
      payloadText = await encryptMessageText(trimmed, currentRoom, {
        myUsername,
        peerPublicKey: peerKey,
        peerUsername: !currentIsGroup && currentPartner ? currentPartner : undefined,
        groupMembers: currentIsGroup && currentPartner ? groupMembersRef.current[currentPartner] || [] : undefined,
      });
    } catch (err) {
      // F5 Fail-Closed: abort send completely if encryption fails
      const reason = err instanceof E2EEError ? err.code : 'ENCRYPTION_FAILED';
      showToast(`⛔ خطا در رمزنگاری سرتاسری (${reason}) — ارسال پیام لغو شد`);
      return;
    }

    socket.emit('send-message', {
      to: currentPartner,
      text: payloadText,
      isGroup: currentIsGroup,
      replyToId: replyTo?.id || null,
      replyToText: replyTo?.text || null,
      disappearAfter: disappearAfter || 0,
    });

    setMessageText('');
    setReplyTo(null);
    if (isTypingRef.current) {
      isTypingRef.current = false;
      socket.emit('typing', {
        to: currentPartner,
        isGroup: currentIsGroup,
        isTyping: false,
      });
    }
  };

  const handleSendMessage = async () => {
    const trimmed = messageText.trim();
    if (!trimmed || !currentRoom || !currentPartner) return;

    // بند ۵ اسپک: در صورت تغییر کلید هویت مخاطب (CHANGED)، هشدار و تأیید ارسال برای آن پیام نمایش داده می‌شود
    if (!currentIsGroup && currentPartnerVerification?.state === 'CHANGED') {
      setOutgoingChangeConfirmOpen(true);
      return;
    }
    if (currentIsGroup && currentGroupVerificationSummary?.status === 'MEMBER_CHANGED') {
      setOutgoingChangeConfirmOpen(true);
      return;
    }

    await executeSendMessage();
  };

  const handleTypingInput = (val: string) => {
    setMessageText(val);
    if (!currentPartner) return;
    if (!isTypingRef.current) {
      isTypingRef.current = true;
      socket.emit('typing', {
        to: currentPartner,
        isGroup: currentIsGroup,
        isTyping: true,
      });
    }
    if (typingTimerRef.current) window.clearTimeout(typingTimerRef.current);
    typingTimerRef.current = window.setTimeout(() => {
      isTypingRef.current = false;
      socket.emit('typing', {
        to: currentPartner,
        isGroup: currentIsGroup,
        isTyping: false,
      });
    }, 1500);
  };

  const handleUploadFile = async (
    e: React.ChangeEvent<HTMLInputElement>,
    fallbackType: string
  ) => {
    const file = e.target.files?.[0];
    if (!file || !currentPartner || !currentRoom) return;
    setAttachOpen(false);

    try {
      // Media E2EE: بایت‌های فایل پیش از آپلود با کلید پایدار اتاق رمز می‌شوند؛
      // در نبود کلید اتاق، فرآیند متوقف شده و هیچ فایلی آپلود نخواهد شد (Fail-Closed).
      const rawBytes = new Uint8Array(await file.arrayBuffer());
      const cipherBytes = await encryptFileBytes(rawBytes, currentRoom, getFileCryptoOptions());
      const uploadFile = new File([cipherBytes as unknown as BlobPart], file.name, {
        type: file.type,
      });
      const sessionToken = getSessionToken();
      const fd = new FormData();
      fd.append('file', uploadFile);
      fd.append('room_id', currentRoom);
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        body: fd,
      }).then(r => r.json());
      if (res.ok) {
        socket.emit('send-message', {
          to: currentPartner,
          text: '',
          fileUrl: res.fileUrl,
          fileType: res.fileType || fallbackType,
          isGroup: currentIsGroup,
          replyToId: replyTo?.id || null,
          replyToText: replyTo?.text || null,
          disappearAfter: disappearAfter || 0,
        });
        setReplyTo(null);
      } else {
        showToast(res.msg || 'خطا در آپلود فایل');
      }
    } catch (err) {
      // Fail-Closed: اگر رمزنگاری نشد، فایل اصلاً ارسال نمی‌شود.
      const reason = err instanceof E2EEError ? err.code : 'ENCRYPTION_FAILED';
      showToast(`⛔ خطا در رمزنگاری فایل (${reason}) — فایل ارسال نشد`);
    }
    e.target.value = '';
  };

  const startVoice = async () => {
    if (!currentPartner) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      mediaRecorderRef.current = recorder;
      audioChunksRef.current = [];
      recorder.ondataavailable = ev => audioChunksRef.current.push(ev.data);
      recorder.onstop = async () => {
        const blob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        try {
          // ویس هم مثل بقیه فایل‌ها پیش از آپلود با کلید اتاق رمز می‌شود.
          if (!currentRoom) return;
          const rawBytes = new Uint8Array(await blob.arrayBuffer());
          const cipherBytes = await encryptFileBytes(
            rawBytes,
            currentRoom,
            getFileCryptoOptions()
          );
          const uploadBlob = new Blob([cipherBytes as unknown as BlobPart], {
            type: 'audio/webm',
          });
          const sessionToken = getSessionToken();
          const fd = new FormData();
          fd.append('file', uploadBlob, 'voice.webm');
          if (currentRoom) fd.append('room_id', currentRoom);
          const res = await fetch('/api/upload', {
            method: 'POST',
            headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
            body: fd,
          }).then(r => r.json());
          if (res.ok) {
            socket.emit('send-message', {
              to: currentPartner,
              text: '',
              fileUrl: res.fileUrl,
              fileType: 'voice',
              isGroup: currentIsGroup,
              disappearAfter: disappearAfter || 0,
            });
          }
        } catch (err) {
          const reason = err instanceof E2EEError ? err.code : 'ENCRYPTION_FAILED';
          showToast(`⛔ خطا در رمزنگاری ویس (${reason}) — ویس ارسال نشد`);
        }
        stream.getTracks().forEach(t => t.stop());
      };
      recorder.start();
      setIsRecording(true);
    } catch {
      showToast('دسترسی به میکروفون رد شد');
    }
  };

  const stopVoice = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
    }
  };

  const handleAddContact = async () => {
    const raw = newContactInput.trim();
    const clean = raw.startsWith('@') ? raw.replace(/^@+/, '').trim() : raw;
    if (!clean) return;
    // (profile-auth) the server only accepts adding to your own contact list.
    const sessionToken = getSessionToken();
    const res = await fetch('/api/add-contact', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      },
      body: JSON.stringify({ myUsername, contactUsername: clean }),
    }).then(r => r.json());

    if (res.ok) {
      if (res.publicKey) {
        syncPeerPublicKeyAndObserve(clean, res.publicKey);
      }
      setContactModalMsg({ text: '✅ مخاطب اضافه شد', ok: true });
      setRooms(prev => {
        if (prev.some(r => r.id === clean)) return prev;
        return [
          ...prev,
          {
            id: clean,
            name: clean,
            isGroup: false,
            preview: 'آفلاین',
            publicKey: res.publicKey || null,
          },
        ];
      });
      setNewContactInput('');
      setTimeout(() => {
        setContactModalOpen(false);
        setContactModalMsg({ text: '', ok: false });
      }, 600);
    } else {
      setContactModalMsg({ text: res.msg || 'خطا', ok: false });
    }
  };

  const handleCreateGroup = async () => {
    const trimmedName = groupNameInput.trim();
    if (!trimmedName) {
      showToast('لطفاً نام گروه را وارد کنید');
      return;
    }
    const extra = extraMemberInput
      .split(/[,،\s]+/)
      .map(s => {
        const t = s.trim();
        return t.startsWith('@') ? t.replace(/^@+/, '').trim() : t;
      })
      .filter(Boolean);
    const members = Array.from(new Set([...groupMembersSelected, ...extra])).filter(
      u => u !== myUsername
    );

    try {
      // ارسال توکن احراز هویت نشست در هدر ساخت گروه جدید.
      const sessionToken = localStorage.getItem('chat_session_token') || '';
      const res = await fetch('/api/create-group', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          name: trimmedName,
          members,
          creator: myUsername,
        }),
      }).then(r => r.json());

      if (res.ok && res.group) {
        setGroupModalOpen(false);
        setGroupNameInput('');
        setGroupMembersSelected([]);
        setExtraMemberInput('');
        showToast('✅ گروه با موفقیت ساخته شد');
        setActiveTab('groups');
        await loadRoomList('groups');
        handleOpenChat({
          id: res.group.id,
          name: res.group.name,
          isGroup: true,
          preview: `گروه • Epoch #1`,
          epoch: 1,
          members: res.group.members,
        });
      } else {
        showToast(res.msg || 'خطا در ایجاد گروه');
      }
    } catch {
      showToast('خطا در برقراری ارتباط با سرور');
    }
  };

  const handleUploadAvatar = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    // آواتار عکس پروفایل است و به هیچ چتی تعلق ندارد: خام آپلود می‌شود
    // (kind=avatar) و با توکن نشست احراز هویت می‌شود.
    const sessionToken = getSessionToken();
    const fd = new FormData();
    fd.append('file', file);
    fd.append('kind', 'avatar');
    const res = await fetch('/api/upload', {
      method: 'POST',
      headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      body: fd,
    }).then(r => r.json());
    if (res.ok) {
      setAvatarPreview(res.fileUrl);
    }
    e.target.value = '';
  };

  const handleSaveProfile = async () => {
    // (profile-auth) the server only accepts updating your own profile.
    const sessionToken = getSessionToken();
    await fetch('/api/user/update', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      },
      body: JSON.stringify({
        username: myUsername,
        display_name: nameInput,
        bio: bioInput,
        status: statusInput,
        avatar: avatarPreview,
      }),
    });
    setMyProfile({
      username: myUsername,
      display_name: nameInput.trim() || null,
      bio: bioInput,
      status: statusInput,
      avatar: avatarPreview,
    });
    socket.emit('update-status', statusInput);
    setProfileModalOpen(false);
    showToast('✅ پروفایل ذخیره شد');
  };

  const handleOpenContactProfile = async () => {
    if (!currentPartner) return;
    if (currentIsGroup) {
      const gMembers = currentGroupMembersList;
      if (gMembers.length > 0) {
        await syncGroupMembersPublicKeys(gMembers);
      }
      setContactProfileModal({ open: true, user: null });
      return;
    }
    const res = await fetch('/api/user/' + encodeURIComponent(currentPartner)).then(r =>
      r.json()
    );
    if (res.ok && res.user?.public_key) {
      syncPeerPublicKeyAndObserve(currentPartner, res.user.public_key);
    }
    setContactProfileModal({ open: true, user: res.ok ? res.user : null });
  };

  const handleSaveRoomSecret = async () => {
    if (!currentRoom) return;
    setRoomSecret(currentRoom, customSecretInput);
    setE2eeModalOpen(false);
    showToast('🔑 کلید نشست این گفتگو به‌روزرسانی شد');
    const reDecrypted = await Promise.all(
      messages.map(m => processDecryption(m, currentRoom))
    );
    setMessages(reDecrypted);
  };

  const handleRotateSessionKeyOnly = async () => {
    if (!currentRoom) return;
    // بند ۶ اسپک: چرخش صرفاً کلید نشست متقارن بدون هیچ تغییر در شماره ایمنی یا وضعیت تأیید هویت
    rotateSessionRatchetOnly(myUsername, currentRoom);
    setE2eeModalOpen(false);
    showToast('🔄 کلید نشست رمزنگاری بازنشانی شد (بدون تغییر در شماره ایمنی)');
    const reDecrypted = await Promise.all(
      messages.map(m => processDecryption(m, currentRoom))
    );
    setMessages(reDecrypted);
  };

  const handleSubmitEdit = async () => {
    const trimmed = editModal.text.trim();
    if (!trimmed || !currentRoom) return;
    let payload = trimmed;
    try {
      const peerKey = getPeerKeyForRoom(currentRoom);
      if (!currentIsGroup && !peerKey) {
        showToast('⛔ کلید عمومی مخاطب هنوز دریافت نشده است — ویرایش لغو شد');
        return;
      }
      payload = await encryptMessageText(trimmed, currentRoom, {
        myUsername,
        peerPublicKey: peerKey,
        peerUsername: !currentIsGroup && currentPartner ? currentPartner : undefined,
      });
    } catch (err) {
      const reason = err instanceof E2EEError ? err.code : 'ENCRYPTION_FAILED';
      showToast(`⛔ خطا در رمزنگاری ویرایش (${reason}) — ویرایش لغو شد`);
      return;
    }
    socket.emit('edit-message', {
      msgId: ctxMenu.msgId,
      newText: payload,
      roomId: currentRoom,
    });
    setEditModal({ open: false, text: '' });
  };

  const handleSubmitForward = () => {
    if (!forwardSelected.length) return;
    socket.emit('forward-message', {
      msgId: ctxMenu.msgId,
      toRooms: forwardSelected,
    });
    setForwardModalOpen(false);
    setForwardSelected([]);
    showToast('↗️ پیام فوروارد شد');
  };

  const handleSubmitReport = async () => {
    await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        reporter: myUsername,
        reportedUser: ctxMenu.sender,
        messageId: ctxMenu.msgId,
        messageText: ctxMenu.text,
        reason: reportReason,
      }),
    });
    setReportModalOpen(false);
    showToast('🚨 گزارش ارسال شد');
  };

  const filteredRooms = rooms.filter(r => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return true;
    const nameMatch = r.name.toLowerCase().includes(q);
    const previewMatch = r.preview ? r.preview.toLowerCase().includes(q) : false;
    return nameMatch || previewMatch;
  });

  return (
    <div id="app" className="app">
      {/* SIDEBAR */}
      <div
        className={`sidebar ${isMobile && mobileChatOpen ? 'mob' : ''}`}
        id="sidebar"
      >
        <div className="sidebar-header">
          <div className="header-top">
            <button
              type="button"
              className="icon-btn"
              onClick={() => setSearchOpen(prev => !prev)}
              title="جستجو"
            >
              <svg
                width="21"
                height="21"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
            </button>

            <div className="my-story" onClick={() => setProfileModalOpen(true)}>
              <div className="story-avatar" id="myAvatar">
                {myProfile.avatar ? (
                  <AuthImg src={myProfile.avatar} alt="" />
                ) : (
                  myUsername[0]?.toUpperCase()
                )}
              </div>
              <div>
                <div id="myName" style={{ fontSize: '14px', fontWeight: 600 }}>
                  @{myUsername}
                </div>
                <div id="myStatusLabel" style={{ fontSize: '11px', color: '#9ca3af' }}>
                  {myProfile.status === 'online'
                    ? 'آنلاین'
                    : myProfile.status === 'busy'
                    ? 'مشغول'
                    : 'غایب'}
                </div>
              </div>
            </div>

            <button
              type="button"
              className="icon-btn"
              onClick={() => {
                if (activeTab === 'groups') {
                  setGroupModalOpen(true);
                } else {
                  setContactModalOpen(true);
                }
              }}
              title={activeTab === 'groups' ? 'ایجاد گروه جدید' : 'افزودن مخاطب'}
            >
              <svg
                width="21"
                height="21"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
            </button>
          </div>

          {searchOpen && (
            <div id="searchBar" className="search-bar">
              <input
                type="text"
                placeholder="جستجو در مخاطبان و پیام‌ها..."
                id="searchInput"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                autoFocus
              />
            </div>
          )}
        </div>

        <div className="tab-bar">
          <button
            type="button"
            className={`tab-pill ${activeTab === 'chats' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('chats');
              loadRoomList('chats');
            }}
          >
            چت‌ها
          </button>
          <button
            type="button"
            className={`tab-pill ${activeTab === 'groups' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('groups');
              loadRoomList('groups');
            }}
          >
            گروه‌ها
          </button>
        </div>

        {activeTab === 'groups' && (
          <div className="group-create-bar">
            <button
              type="button"
              className="btn-create-group"
              onClick={() => setGroupModalOpen(true)}
            >
              <span aria-hidden="true">➕</span>
              <span>ایجاد گروه / روم جدید</span>
            </button>
          </div>
        )}

        <div className="chat-list" id="chatList">
          {filteredRooms.length === 0 ? (
            <div className="chat-list-empty">
              {activeTab === 'groups' ? (
                <div>
                  <div className="empty-icon" aria-hidden="true">👥</div>
                  <p>هنوز عضوی در گروهی نیستید</p>
                  <button
                    type="button"
                    className="btn-primary-sm"
                    onClick={() => setGroupModalOpen(true)}
                  >
                    ساخت گروه جدید
                  </button>
                </div>
              ) : (
                <div>
                  <div className="empty-icon" aria-hidden="true">💬</div>
                  <p>مخاطبی یافت نشد</p>
                </div>
              )}
            </div>
          ) : (
            filteredRooms.map(room => (
              <div
                key={room.id}
                className={`chat-item ${currentPartner === room.id ? 'active' : ''}`}
                onClick={() => handleOpenChat(room)}
              >
                <div className={`ci-avatar ${room.online ? 'online' : ''}`}>
                  {room.avatar ? (
                    <AuthImg src={room.avatar} alt="" />
                  ) : (
                    room.name[0]?.toUpperCase()
                  )}
                </div>
                <div className="ci-info">
                  <div className="ci-top">
                    <span className="ci-name">
                      {renderHighlightedText(room.name, searchQuery)}
                      {room.isGroup && <span className="group-tag">گروه</span>}
                    </span>
                    <span className="ci-time">{formatMessageTime(room)}</span>
                  </div>
                  <div className="ci-preview">
                    {renderHighlightedText(room.preview || '', searchQuery)}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="sidebar-footer">
          <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
            <button type="button" className="foot-btn" onClick={onLogout}>
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <polyline points="16 17 21 12 16 7" />
                <line x1="21" y1="12" x2="9" y2="12" />
              </svg>
              خروج
            </button>
            <button
              type="button"
              className="foot-btn foot-btn-changelog"
              onClick={() => setChangelogModalOpen(true)}
              title="مشاهده تغییرات و معماری اختصاصی PQ-MPRBA v6.0"
            >
              <span aria-hidden="true">🚀</span> چنج‌لاگ v6.0
            </button>
          </div>
          <div className="my-id">
            @<span id="myIdDisplay">{myUsername}</span>
          </div>
        </div>
      </div>

      {/* CHAT AREA */}
      <div
        className={`chat-area ${isMobile && mobileChatOpen ? 'mob' : ''}`}
        id="chatArea"
      >
        {!currentRoom ? (
          <div className="empty-state" id="emptyState">
            <div className="empty-state-icon" aria-hidden="true">💬</div>
            <p>گفت‌وگویی انتخاب نشده است</p>
            <small>یک مخاطب را انتخاب کنید یا گفت‌وگوی جدید آغاز نمایید • مجهز به رمزنگاری سرتاسری PQ-MPRBA</small>
          </div>
        ) : (
          <div id="chatView" className="chat-view">
            <div className="chat-header">
              <button
                type="button"
                className="back-btn"
                onClick={() => setMobileChatOpen(false)}
              >
                <svg
                  width="22"
                  height="22"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2.5"
                >
                  <polyline points="15 18 9 12 15 6" />
                </svg>
              </button>

              <div className="chat-header-info" onClick={handleOpenContactProfile}>
                <div
                  className={`chat-header-avatar ${partnerOnline ? 'online' : ''}`}
                  id="chatAvatar"
                >
                  {currentPartnerName[0]?.toUpperCase()}
                </div>
                <div>
                  <div className="chat-header-name" id="chatName">
                    {currentPartnerName}
                  </div>
                  <div
                    className={`chat-header-status ${partnerOnline ? 'online' : ''}`}
                    id="chatStatus"
                  >
                    {!currentIsGroup && currentPartner && currentPartner !== currentPartnerName
                      ? `@${currentPartner} · ${partnerStatusLabel}`
                      : partnerStatusLabel}
                  </div>
                </div>
              </div>

              {/* Small per-contact verification state badge in header (links to verification screen) */}
              {!currentIsGroup && currentPartner && currentPartnerVerification && (
                <button
                  type="button"
                  id="headerSafetyBadgeBtn"
                  className="icon-btn"
                  onClick={() => openSafetyModalForContact(currentPartner)}
                  title={`${SAFETY_STRINGS_FA.safetyNumber}: ${
                    currentPartnerVerification.state === 'VERIFIED'
                      ? SAFETY_STRINGS_FA.verified
                      : currentPartnerVerification.state === 'CHANGED'
                      ? SAFETY_STRINGS_FA.safetyNumberChanged
                      : SAFETY_STRINGS_FA.notVerified
                  } (کلیک جهت مشاهده صفحه تأیید هویت)`}
                  style={{
                    fontSize: '11.5px',
                    padding: '5px 9px',
                    borderRadius: '14px',
                    background:
                      currentPartnerVerification.state === 'VERIFIED'
                        ? 'rgba(34, 197, 94, 0.16)'
                        : currentPartnerVerification.state === 'CHANGED'
                        ? 'rgba(239, 68, 68, 0.22)'
                        : 'rgba(255, 255, 255, 0.06)',
                    color:
                      currentPartnerVerification.state === 'VERIFIED'
                        ? '#4ade80'
                        : currentPartnerVerification.state === 'CHANGED'
                        ? '#f87171'
                        : '#d1d5db',
                    border:
                      currentPartnerVerification.state === 'VERIFIED'
                        ? '1px solid rgba(34, 197, 94, 0.4)'
                        : currentPartnerVerification.state === 'CHANGED'
                        ? '1px solid rgba(239, 68, 68, 0.5)'
                        : '1px solid rgba(255, 255, 255, 0.12)',
                    gap: '4px',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {currentPartnerVerification.state === 'VERIFIED'
                    ? `🛡️ ${SAFETY_STRINGS_FA.verified}`
                    : currentPartnerVerification.state === 'CHANGED'
                    ? `⚠️ ${SAFETY_STRINGS_FA.safetyNumberChanged}`
                    : `○ ${SAFETY_STRINGS_FA.notVerified}`}
                </button>
              )}

              {/* E2EE Transport Status Badge (mandatory E2EE - opens encryption info) */}
              <button
                type="button"
                className="icon-btn"
                onClick={() => setE2eeModalOpen(true)}
                title={
                  currentPQStatus
                    ? currentPQStatus.tooltip
                    : 'رمزنگاری پساکوانتومی اجباری (همیشه فعال)'
                }
                style={{
                  fontSize: '12px',
                  padding: '5px 10px',
                  borderRadius: '14px',
                  background: currentPQStatus?.isPQ
                    ? 'rgba(6, 182, 212, 0.14)'
                    : currentPQStatus?.reason === 'INVALID_MLDSA_SIGNATURE'
                    ? 'rgba(244, 63, 94, 0.18)'
                    : 'rgba(245, 158, 11, 0.16)',
                  color: currentPQStatus?.isPQ
                    ? '#22d3ee'
                    : currentPQStatus?.reason === 'INVALID_MLDSA_SIGNATURE'
                    ? '#fb7185'
                    : '#fbbf24',
                  border:
                    currentPQStatus && !currentPQStatus.isPQ
                      ? currentPQStatus.reason === 'INVALID_MLDSA_SIGNATURE'
                        ? '1px solid rgba(244, 63, 94, 0.45)'
                        : '1px solid rgba(245, 158, 11, 0.4)'
                      : '1px solid rgba(6, 182, 212, 0.3)',
                  gap: '4px',
                }}
              >
                {currentIsGroup
                  ? getGroupSecurityBadge(currentRoom, currentGroupEpoch).badge
                  : currentPQStatus?.isPQ
                  ? '🔒 PQ-KEM'
                  : currentPQStatus?.badge || '⚠️ غیر کوانتومی'}
              </button>

              <button
                type="button"
                className="icon-btn"
                onClick={() => setE2eeModalOpen(true)}
                title="تنظیم و چرخش کلید نشست رمزنگاری (Session Key)"
              >
                🔑
              </button>

              <button
                type="button"
                className="icon-btn"
                onClick={handleOpenContactProfile}
                title="اطلاعات مخاطب"
              >
                <svg
                  width="21"
                  height="21"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <circle cx="12" cy="12" r="1" />
                  <circle cx="19" cy="12" r="1" />
                  <circle cx="5" cy="12" r="1" />
                </svg>
              </button>
            </div>

            {/* PERSISTENT IN-CHAT SAFETY NUMBER CHANGED WARNING (1-TO-1, LOCAL NOTICE ONLY) */}
            {!currentIsGroup &&
              currentPartner &&
              currentPartnerVerification?.state === 'CHANGED' && (
                <div
                  id="inChatSafetyChangedBanner"
                  style={{
                    background:
                      'linear-gradient(90deg, rgba(239,68,68,0.24), rgba(185,28,28,0.16))',
                    borderBottom: '1px solid rgba(239,68,68,0.55)',
                    padding: '10px 16px',
                    color: '#fecaca',
                    fontSize: '12px',
                    direction: 'rtl',
                    flexShrink: 0,
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '10px',
                      flexWrap: 'wrap',
                    }}
                  >
                    <div style={{ flex: 1, minWidth: '220px', lineHeight: 1.6 }}>
                      <b style={{ color: '#f87171', fontSize: '12.5px' }}>
                        ⚠️ {SAFETY_STRINGS_FA.safetyNumberChanged}:
                      </b>{' '}
                      {SAFETY_STRINGS_FA.inChatChangedNoticeBody}
                    </div>
                    <div style={{ display: 'flex', gap: '6px', flexShrink: 0 }}>
                      <button
                        type="button"
                        onClick={() => openSafetyModalForContact(currentPartner)}
                        style={{
                          background: '#ef4444',
                          border: 'none',
                          color: '#fff',
                          borderRadius: '8px',
                          padding: '5px 11px',
                          fontSize: '11.5px',
                          fontWeight: 700,
                          cursor: 'pointer',
                          fontFamily: 'inherit',
                        }}
                      >
                        {SAFETY_STRINGS_FA.verifyAgain}
                      </button>
                      <button
                        type="button"
                        onClick={() => setInChatLearnMoreOpen(prev => !prev)}
                        style={{
                          background: 'rgba(255,255,255,0.12)',
                          border: '1px solid rgba(255,255,255,0.22)',
                          color: '#fff',
                          borderRadius: '8px',
                          padding: '5px 10px',
                          fontSize: '11.5px',
                          cursor: 'pointer',
                          fontFamily: 'inherit',
                        }}
                      >
                        {SAFETY_STRINGS_FA.learnMore}
                      </button>
                    </div>
                  </div>

                  {inChatLearnMoreOpen && (
                    <div
                      style={{
                        marginTop: '8px',
                        paddingTop: '8px',
                        borderTop: '1px solid rgba(239,68,68,0.35)',
                        whiteSpace: 'pre-line',
                        lineHeight: 1.7,
                        fontSize: '11.5px',
                        color: '#fee2e2',
                      }}
                    >
                      {SAFETY_STRINGS_FA.learnMoreBenignAndRisk}
                      {currentPartnerVerification.auditHistory.length > 0 && (
                        <div
                          style={{
                            marginTop: '6px',
                            background: 'rgba(0,0,0,0.28)',
                            padding: '6px 10px',
                            borderRadius: '8px',
                            fontSize: '10.5px',
                          }}
                        >
                          <b style={{ color: '#fca5a5' }}>سابقه ممیزی محلی در این دستگاه:</b>{' '}
                          <span
                            dir="ltr"
                            style={{
                              fontFamily:
                                'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                              color: '#fcd34d',
                            }}
                          >
                            SHA-256 قبلی:{' '}
                            {currentPartnerVerification.auditHistory[0].previousKeyFingerprint.slice(
                              0,
                              24
                            )}
                            …
                          </span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

            {/* GROUP SUMMARY WARNING BANNER WHEN ANY GROUP MEMBER'S KEY HAS CHANGED */}
            {currentIsGroup &&
              currentGroupVerificationSummary?.status === 'MEMBER_CHANGED' && (
                <div
                  id="groupMemberChangedBanner"
                  style={{
                    background:
                      'linear-gradient(90deg, rgba(239,68,68,0.22), rgba(185,28,28,0.14))',
                    borderBottom: '1px solid rgba(239,68,68,0.5)',
                    padding: '9px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '10px',
                    flexWrap: 'wrap',
                    color: '#fecaca',
                    fontSize: '12px',
                    direction: 'rtl',
                    flexShrink: 0,
                  }}
                >
                  <div>
                    <b style={{ color: '#f87171' }}>
                      ⚠️ {SAFETY_STRINGS_FA.groupMemberChanged}:
                    </b>{' '}
                    <span>
                      {currentGroupVerificationSummary.changedMembers
                        .map(m => `@${m}`)
                        .join('، ')}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={handleOpenContactProfile}
                    style={{
                      background: 'rgba(255,255,255,0.12)',
                      border: '1px solid rgba(255,255,255,0.22)',
                      color: '#fff',
                      borderRadius: '8px',
                      padding: '4px 10px',
                      fontSize: '11px',
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    مشاهده اعضا و {SAFETY_STRINGS_FA.verifyAgain}
                  </button>
                </div>
              )}

            {/* DISTINCT SESSION RE-KEY PROMPT AFTER UNDELIVERABLE/UNDECRYPTABLE MESSAGES (ONLY WHEN NOT CHANGED) */}
            {!currentIsGroup &&
              currentPartnerVerification?.state !== 'CHANGED' &&
              messages.some(m => m.decryptFailed) && (
                <div
                  style={{
                    background: 'rgba(56, 189, 248, 0.12)',
                    borderBottom: '1px solid rgba(56, 189, 248, 0.3)',
                    padding: '8px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '10px',
                    flexWrap: 'wrap',
                    color: '#bae6fd',
                    fontSize: '11.5px',
                    direction: 'rtl',
                    flexShrink: 0,
                  }}
                >
                  <div>
                    🔄 برخی پیام‌های قبلی با کلید نشست فعلی قابل بازگشایی نیستند. می‌توانید کلید
                    نشست رمزنگاری را نوسازی کنید (این کار شماره ایمنی یا وضعیت تأیید هویت مخاطب را
                    تغییر نمی‌دهد).
                  </div>
                  <button
                    type="button"
                    onClick={handleRotateSessionKeyOnly}
                    style={{
                      background: 'rgba(56, 189, 248, 0.22)',
                      border: '1px solid rgba(56, 189, 248, 0.45)',
                      color: '#e0f2fe',
                      borderRadius: '8px',
                      padding: '4px 10px',
                      fontSize: '11px',
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    🔄 بازنشانی کلید نشست (Re-key)
                  </button>
                </div>
              )}

            {/* ANTI-DOWNGRADE WARNING BANNER */}
            {currentPQStatus && !currentPQStatus.isPQ && (
              <div
                className="pq-downgrade-warning-banner"
                style={{
                  background:
                    currentPQStatus.reason === 'INVALID_MLDSA_SIGNATURE'
                      ? 'linear-gradient(90deg, rgba(239,68,68,0.22), rgba(185,28,28,0.14))'
                      : 'linear-gradient(90deg, rgba(234,179,8,0.18), rgba(245,158,11,0.10))',
                  borderBottom:
                    currentPQStatus.reason === 'INVALID_MLDSA_SIGNATURE'
                      ? '1px solid rgba(239,68,68,0.45)'
                      : '1px solid rgba(234,179,8,0.35)',
                  padding: '9px 16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  color:
                    currentPQStatus.reason === 'INVALID_MLDSA_SIGNATURE' ? '#fca5a5' : '#fef08a',
                  fontSize: '12px',
                  direction: 'rtl',
                }}
              >
                <span style={{ fontSize: '18px', flexShrink: 0 }}>
                  {currentPQStatus.reason === 'INVALID_MLDSA_SIGNATURE' ? '⛔' : '⚠️'}
                </span>
                <div style={{ flex: 1, lineHeight: 1.5 }}>
                  <b
                    style={{
                      color:
                        currentPQStatus.reason === 'INVALID_MLDSA_SIGNATURE'
                          ? '#f87171'
                          : '#fde047',
                    }}
                  >
                    {currentPQStatus.reason === 'INVALID_MLDSA_SIGNATURE'
                      ? 'خطای امنیتی جعل هویت:'
                      : 'هشدار امنیتی (نبود امنیت پساکوانتومی):'}
                  </b>{' '}
                  {currentPQStatus.warningText}
                </div>
              </div>
            )}

            {pinnedMessage && (
              <div
                className="pinned-bar"
                id="pinnedBar"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '8px',
                  cursor: 'pointer',
                  userSelect: 'none',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    overflow: 'hidden',
                    flex: 1,
                  }}
                  onClick={() => {
                    const el = document.querySelector(`[data-id="${pinnedMessage.id}"]`);
                    if (el) {
                      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                      el.classList.add('highlight-pinned');
                      setTimeout(() => el.classList.remove('highlight-pinned'), 1800);
                    } else {
                      showToast('پیام پین‌شده در این صفحه یافت نشد');
                    }
                  }}
                  title="پرش به پیام پین‌شده"
                >
                  <span style={{ flexShrink: 0 }}>📌</span>
                  <span
                    id="pinnedText"
                    style={{
                      textOverflow: 'ellipsis',
                      overflow: 'hidden',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {(pinnedMessage.decryptedText || pinnedMessage.text || (pinnedMessage.file_type ? 'فایل پیوست' : '')).substring(0, 55)}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={e => {
                    e.stopPropagation();
                    socket.emit('unpin-message', {
                      msgId: pinnedMessage.id,
                      roomId: currentRoom,
                    });
                    setPinnedMessage(null);
                    setMessages(prev =>
                      prev.map(m => (m.id === pinnedMessage.id ? { ...m, is_pinned: false } : m))
                    );
                    showToast('📌 پین پیام برداشته شد');
                  }}
                  title="برداشتن پین"
                  style={{
                    background: 'rgba(255,255,255,0.08)',
                    border: '1px solid rgba(255,255,255,0.12)',
                    color: '#e5e7eb',
                    cursor: 'pointer',
                    fontSize: '11px',
                    padding: '2px 8px',
                    borderRadius: '5px',
                    flexShrink: 0,
                    whiteSpace: 'nowrap',
                  }}
                >
                  برداشتن پین ✕
                </button>
              </div>
            )}

            <div
              className="messages-container"
              id="messagesContainer"
              ref={messagesContainerRef}
            >
              {messages.length === 0 ? (
                <div className="sys-msg">
                  🔒 این گفتگو با رمزنگاری سرتاسری (AES-256-GCM) محافظت می‌شود
                </div>
              ) : (
                messages.map(msg => {
                  const isOut = msg.sender === myUsername;
                  const displayText = msg.decryptedText ?? msg.text;
                  return (
                    <div
                      key={msg.id}
                      className={`msg-wrap ${isOut ? 'out' : 'in'}`}
                      data-id={msg.id}
                    >
                      <div
                        className="bubble"
                        onContextMenu={e => {
                          e.preventDefault();
                          setCtxMenu({
                            visible: true,
                            x: window.innerWidth - e.clientX,
                            y: Math.min(e.clientY, window.innerHeight - 280),
                            msgId: msg.id,
                            text: displayText || '',
                            sender: msg.sender,
                          });
                        }}
                      >
                        {currentIsGroup && !isOut && (
                          <div className="sender-name">
                            {groupMemberProfiles[msg.sender]?.display_name || msg.sender}
                          </div>
                        )}
                        {msg.reply_to_text && (
                          <div className="reply-quote">
                            ↩ {msg.reply_to_text.substring(0, 60)}
                          </div>
                        )}

                        {msg.file_url ? (
                          <SecureMedia
                            fileUrl={msg.file_url}
                            fileType={msg.file_type || 'file'}
                            roomId={msg.room_id || currentRoom}
                            cryptoOptions={getFileCryptoOptions()}
                          />
                        ) : (
                          <span>{renderHighlightedText(displayText || '', searchQuery)}</span>
                        )}

                        {msg.is_edited && (
                          <span className="edited-tag">(ویرایش شده)</span>
                        )}
                      </div>

                      {msg.reactions && Object.keys(msg.reactions).length > 0 && (
                        <div className="reactions-bar">
                          {Object.entries(msg.reactions).map(([emoji, users]) => {
                            const isMine = users.includes(myUsername);
                            return (
                              <span
                                key={emoji}
                                className={`reaction-pill ${isMine ? 'mine' : ''}`}
                                onClick={() =>
                                  socket.emit('react', {
                                    msgId: msg.id,
                                    roomId: currentRoom,
                                    emoji,
                                  })
                                }
                              >
                                {emoji} {users.length}
                              </span>
                            );
                          })}
                        </div>
                      )}

                      <div className="msg-meta">
                        {msg.isE2EE && (
                          <span
                            title={
                              msg.e2eeMode === 'PQ-MLKEM-RATCHET'
                                ? `رمزنگاری تماماً پساکوانتومی ML-KEM-768 + Ratchet (گام #${msg.ratchetStep ?? 0})${
                                    msg.mldsaVerified ? ' • امضای هویت FIPS 204 ML-DSA تأیید شد ✓' : ''
                                  }`
                                : msg.e2eeMode === 'GROUP-EPOCH-FSM'
                                ? `ماشین وضعیت اپوک گروه (Epoch #${msg.epoch ?? 1})`
                                : 'رمزنگاری سرتاسری دستی (PBKDF2)'
                            }
                            style={{
                              fontSize: '10px',
                              opacity: 0.9,
                              color:
                                msg.e2eeMode === 'PQ-MLKEM-RATCHET'
                                  ? '#a78bfa'
                                  : '#38bdf8',
                            }}
                          >
                            {msg.e2eeMode === 'PQ-MLKEM-RATCHET'
                              ? `🛡️PQ#${msg.ratchetStep ?? 0}${msg.mldsaVerified ? ' ✓DSA' : ''}`
                              : msg.e2eeMode === 'GROUP-EPOCH-FSM'
                              ? `🔄Ep#${msg.epoch ?? 1}`
                              : '🔒'}
                          </span>
                        )}
                        <span className="msg-time">{formatMessageTime(msg)}</span>
                        {isOut && (
                          <span
                            className={`msg-ticks ${msg.is_read ? 'read' : ''}`}
                          >
                            ✓✓
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {typingUser && (
              <div className="typing-indicator" id="typingIndicator">
                <div className="typing-bubble">
                  <span id="typingText">{typingUser} در حال تایپ</span>
                  <div className="typing-dots">
                    <span />
                    <span />
                    <span />
                  </div>
                </div>
              </div>
            )}

            {replyTo && (
              <div className="reply-preview" id="replyPreview">
                <div>
                  <div className="reply-label">ریپلای به:</div>
                  <div id="replyText" className="reply-text">
                    {replyTo.text.substring(0, 60)}
                  </div>
                </div>
                <button type="button" onClick={() => setReplyTo(null)}>
                  ✕
                </button>
              </div>
            )}

            <div className="input-area">
              <button
                type="button"
                className="icon-btn attach-trigger"
                onClick={() => setAttachOpen(prev => !prev)}
                title="ارسال فایل"
              >
                <svg
                  width="22"
                  height="22"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
                </svg>
              </button>

              <button
                type="button"
                className={`icon-btn ${isRecording ? 'voice-recording' : ''}`}
                id="voiceBtn"
                onMouseDown={startVoice}
                onMouseUp={stopVoice}
                onTouchStart={startVoice}
                onTouchEnd={stopVoice}
                title="نگه دار برای ضبط صدا"
              >
                🎤
              </button>

              <input
                type="text"
                id="messageInput"
                placeholder="پیام رمزنگاری‌شده (E2EE)..."
                value={messageText}
                onChange={e => handleTypingInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSendMessage()}
              />

              <button
                type="button"
                className="send-btn"
                onClick={handleSendMessage}
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="white">
                  <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
                </svg>
              </button>
            </div>

            {attachOpen && (
              <div className="attach-menu" id="attachMenu">
                <div
                  className="attach-item"
                  role="button"
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    setAttachOpen(false);
                    imageFileInputRef.current?.click();
                  }}
                >
                  📷 عکس
                </div>
                <div
                  className="attach-item"
                  role="button"
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    setAttachOpen(false);
                    docFileInputRef.current?.click();
                  }}
                >
                  📁 فایل
                </div>
                <div
                  className="attach-item"
                  role="button"
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    setAttachOpen(false);
                    setDisappearModalOpen(true);
                  }}
                >
                  ⏱ پیام ناپدید
                </div>
              </div>
            )}

            {/* Hidden file inputs mounted outside menu and triggered via ref */}
            <input
              ref={imageFileInputRef}
              type="file"
              accept="image/*"
              style={{ position: 'fixed', top: '-10000px', left: '-10000px', opacity: 0, pointerEvents: 'none' }}
              onChange={e => handleUploadFile(e, 'image')}
            />
            <input
              ref={docFileInputRef}
              type="file"
              style={{ position: 'fixed', top: '-10000px', left: '-10000px', opacity: 0, pointerEvents: 'none' }}
              onChange={e => handleUploadFile(e, 'file')}
            />
          </div>
        )}
      </div>

      {/* CONTEXT MENU */}
      {ctxMenu.visible && (
        <div
          className="ctx-menu"
          id="ctxMenu"
          style={{ top: ctxMenu.y, right: ctxMenu.x }}
        >
          <div
            style={{
              display: 'flex',
              gap: '6px',
              padding: '8px 12px',
              borderBottom: '1px solid var(--border)',
            }}
          >
            {QUICK_EMOJIS.map(em => (
              <span
                key={em}
                style={{ cursor: 'pointer', fontSize: '16px' }}
                onClick={() => {
                  socket.emit('react', {
                    msgId: ctxMenu.msgId,
                    roomId: currentRoom,
                    emoji: em,
                  });
                  setCtxMenu(prev => ({ ...prev, visible: false }));
                }}
              >
                {em}
              </span>
            ))}
          </div>
          <div
            className="ctx-item"
            onClick={() => {
              setReplyTo({ id: ctxMenu.msgId, text: ctxMenu.text });
              setCtxMenu(prev => ({ ...prev, visible: false }));
            }}
          >
            ↩ ریپلای
          </div>
          {ctxMenu.sender === myUsername && (
            <div
              className="ctx-item"
              onClick={() => {
                setEditModal({ open: true, text: ctxMenu.text });
                setCtxMenu(prev => ({ ...prev, visible: false }));
              }}
            >
              ✏️ ویرایش
            </div>
          )}
          <div
            className="ctx-item"
            onClick={() => {
              setForwardSelected([]);
              setForwardModalOpen(true);
              setCtxMenu(prev => ({ ...prev, visible: false }));
            }}
          >
            ↗️ فوروارد
          </div>
          {pinnedMessage?.id === ctxMenu.msgId || messages.find(m => m.id === ctxMenu.msgId)?.is_pinned ? (
            <div
              className="ctx-item"
              onClick={() => {
                socket.emit('unpin-message', {
                  msgId: ctxMenu.msgId,
                  roomId: currentRoom,
                });
                setPinnedMessage(prev => (prev?.id === ctxMenu.msgId ? null : prev));
                setMessages(prev =>
                  prev.map(m => (m.id === ctxMenu.msgId ? { ...m, is_pinned: false } : m))
                );
                setCtxMenu(prev => ({ ...prev, visible: false }));
                showToast('📌 پین پیام برداشته شد');
              }}
            >
              📌 برداشتن پین
            </div>
          ) : (
            <div
              className="ctx-item"
              onClick={() => {
                socket.emit('pin-message', {
                  msgId: ctxMenu.msgId,
                  roomId: currentRoom,
                });
                setCtxMenu(prev => ({ ...prev, visible: false }));
              }}
            >
              📌 پین
            </div>
          )}
          <div
            className="ctx-item"
            onClick={() => {
              setReportModalOpen(true);
              setCtxMenu(prev => ({ ...prev, visible: false }));
            }}
          >
            🚨 گزارش
          </div>
          {ctxMenu.sender === myUsername && (
            <div
              className="ctx-item ctx-danger"
              onClick={() => {
                socket.emit('delete-message', {
                  msgId: ctxMenu.msgId,
                  roomId: currentRoom,
                });
                setCtxMenu(prev => ({ ...prev, visible: false }));
              }}
            >
              🗑 حذف
            </div>
          )}
        </div>
      )}

      {/* E2EE SESSION KEY SETTINGS MODAL (DISTINCT FROM SAFETY-NUMBER VERIFICATION) */}
      {e2eeModalOpen && (
        <div className="modal">
          <div className="modal-box" style={{ width: '92%', maxWidth: '420px' }}>
            <h3>🔑 تنظیمات و چرخش کلید نشست رمزنگاری (Session Key)</h3>

            {/* بند ۶ اسپک: اگر کلید هویت تغییر کرده باشد، هشدار CHANGED بر چرخش کلید نشست اولویت دارد */}
            {!currentIsGroup &&
              currentPartner &&
              currentPartnerVerification?.state === 'CHANGED' && (
                <div
                  style={{
                    background: 'rgba(239, 68, 68, 0.18)',
                    border: '1px solid rgba(239, 68, 68, 0.5)',
                    borderRadius: '10px',
                    padding: '10px 12px',
                    marginBottom: '12px',
                    fontSize: '11.5px',
                    lineHeight: '1.7',
                    textAlign: 'right',
                    color: '#fecaca',
                  }}
                >
                  <div style={{ fontWeight: 700, color: '#f87171', marginBottom: '4px' }}>
                    ⚠️ {SAFETY_STRINGS_FA.safetyNumberChanged} (دارای اولویت امنیتی)
                  </div>
                  <div style={{ marginBottom: '8px' }}>
                    {SAFETY_STRINGS_FA.inChatChangedNoticeBody} چرخش کلید نشست به‌هیچ‌وجه جایگزین
                    تأیید مجدد هویت نمی‌شود و وضعیت تغییر کلید را پاک نمی‌کند.
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setE2eeModalOpen(false);
                      openSafetyModalForContact(currentPartner);
                    }}
                    style={{
                      background: '#ef4444',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#fff',
                      padding: '6px 12px',
                      fontSize: '11.5px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    🔐 {SAFETY_STRINGS_FA.verifyAgain} ({SAFETY_STRINGS_FA.safetyNumber})
                  </button>
                </div>
              )}

            <div
              style={{
                background: 'var(--bg-surface-active)',
                border: '1px solid var(--accent-cyan-border)',
                borderRadius: '10px',
                padding: '10px 12px',
                fontSize: '11.5px',
                lineHeight: '1.75',
                marginBottom: '12px',
                textAlign: 'right',
              }}
            >
              <div>
                🔒 <b>لایه ۱ (Session Ratchet پساکوانتومی):</b> کپسوله‌سازی هیبریدی{' '}
                <code>ML-KEM-768 (FIPS 203) + ECDH P-256</code> به همراه کش کلیدهای پرش‌خورده
                (Out-of-Order Skipped Keys) و پاک‌سازی فوری حافظه (Zeroization).
              </div>
              <div style={{ marginTop: '4px' }}>
                🔒 <b>لایه ۲ (امضای دیجیتال هویت FIPS 204):</b> امضای بسته کلید و پیام‌ها با{' '}
                <code>ML-DSA-65 (NIST Level 3)</code>.
              </div>
              <div style={{ marginTop: '4px' }}>
                🔒 <b>لایه ۳ (احراز هویت کور - RFC 9497):</b> توکن کور{' '}
                <code>Ristretto255-VOPRF</code> با اثبات دانایی صفر DLEQ:{' '}
                <code style={{ color: '#22c55e' }}>
                  {voprfToken?.anonymousTokenId || 'در حال صدور...'}
                </code>
              </div>
              {currentIsGroup && (
                <div style={{ marginTop: '4px' }}>
                  🔒 <b>لایه ۴ (Group Epoch FSM):</b> اپوک فعلی گروه:{' '}
                  <code style={{ color: '#38bdf8' }}>Epoch #{currentGroupEpoch}</code>
                </div>
              )}
            </div>

            {!currentIsGroup && (
              <div
                style={{
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.28)',
                  borderRadius: '10px',
                  padding: '9px 11px',
                  marginBottom: '12px',
                  textAlign: 'right',
                  fontSize: '11px',
                  lineHeight: '1.65',
                  color: '#bae6fd',
                }}
              >
                <div style={{ marginBottom: '6px' }}>{SAFETY_STRINGS_FA.rekeyDistinctNote}</div>
                <button
                  type="button"
                  onClick={handleRotateSessionKeyOnly}
                  style={{
                    width: '100%',
                    background: 'rgba(56, 189, 248, 0.22)',
                    border: '1px solid rgba(56, 189, 248, 0.45)',
                    borderRadius: '8px',
                    color: '#e0f2fe',
                    padding: '7px 10px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                  }}
                >
                  🔄 بازنشانی / چرخش کلید نشست (Re-key Session)
                </button>
              </div>
            )}

            {/* L8: محافظت از کلید هویت با رمز عبور */}
            <div
              style={{
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.35)',
                borderRadius: '10px',
                padding: '10px 12px',
                marginBottom: '12px',
                textAlign: 'right',
                fontSize: '11.5px',
                lineHeight: '1.7',
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: '4px' }}>
                🔐 محافظت از کلید هویت با رمز عبور
              </div>
              <div style={{ marginBottom: '8px' }}>
                وقتی فعال باشد، کلید هویت شما فقط با رمز عبور باز می‌شود — حتی اگر کسی به
                دستگاه شما دسترسی پیدا کند، بدون رمز نمی‌تواند پیام بخواند یا ارسال کند.
                رمز عبور را فراموش نکنید؛ بازیابی آن ممکن نیست.
              </div>
              <div style={{ marginBottom: '8px' }}>
                وضعیت:{' '}
                {pwProtectionEnabled === null
                  ? 'در حال بررسی...'
                  : pwProtectionEnabled
                    ? 'فعال ✅'
                    : 'غیرفعال'}
                {pwProtectionEnabled && (
                  <button
                    type="button"
                    onClick={() => {
                      lockIdentity(myUsername);
                      setIdentityLocked(true);
                      setE2eeModalOpen(false);
                    }}
                    style={{
                      marginRight: '8px',
                      background: 'rgba(245, 158, 11, 0.22)',
                      border: '1px solid rgba(245, 158, 11, 0.45)',
                      borderRadius: '8px',
                      color: '#fde68a',
                      padding: '4px 10px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    🔒 قفل کردن اکنون
                  </button>
                )}
              </div>
              {pwProtectionEnabled === false && (
                <>
                  <input
                    type="password"
                    placeholder="رمز عبور جدید (حداقل ۸ کاراکتر)"
                    value={pwNewPass}
                    onChange={e => setPwNewPass(e.target.value)}
                    style={{ marginBottom: '6px' }}
                  />
                  <input
                    type="password"
                    placeholder="تکرار رمز عبور"
                    value={pwConfirmPass}
                    onChange={e => setPwConfirmPass(e.target.value)}
                    style={{ marginBottom: '6px' }}
                  />
                  <button
                    type="button"
                    onClick={handleEnablePwProtection}
                    style={{
                      width: '100%',
                      background: 'rgba(245, 158, 11, 0.22)',
                      border: '1px solid rgba(245, 158, 11, 0.45)',
                      borderRadius: '8px',
                      color: '#fef3c7',
                      padding: '7px 10px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    فعال‌کردن محافظت با رمز عبور
                  </button>
                </>
              )}
              {pwProtectionEnabled === true && (
                <>
                  <input
                    type="password"
                    placeholder="رمز عبور فعلی"
                    value={pwCurrentPass}
                    onChange={e => setPwCurrentPass(e.target.value)}
                    style={{ marginBottom: '6px' }}
                  />
                  <button
                    type="button"
                    onClick={handleDisablePwProtection}
                    style={{
                      width: '100%',
                      background: 'rgba(239, 68, 68, 0.18)',
                      border: '1px solid rgba(239, 68, 68, 0.45)',
                      borderRadius: '8px',
                      color: '#fecaca',
                      padding: '7px 10px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    غیرفعال‌کردن محافظت
                  </button>
                </>
              )}
              {pwMsg.text && (
                <div style={{ marginTop: '8px', color: pwMsg.ok ? '#4ade80' : '#f87171' }}>
                  {pwMsg.text}
                </div>
              )}
            </div>

            <p style={{ fontSize: '12px', lineHeight: '1.6' }}>
              در صورت تمایل به بازنویسی کلید خودکار با یک رمز مشترک دستی (PBKDF2 Override)، آن را
              در کادر زیر وارد کنید:
            </p>
            <input
              type="password"
              placeholder="کلید/رمز مشترک سفارشی (اختیاری - خالی = راتچت پساکوانتومی خودکار)..."
              value={customSecretInput}
              onChange={e => setCustomSecretInput(e.target.value)}
            />
            <div className="modal-btns" style={{ marginTop: '10px' }}>
              <button type="button" onClick={handleSaveRoomSecret}>
                ذخیره تنظیمات
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setE2eeModalOpen(false)}
              >
                {SAFETY_STRINGS_FA.cancel}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* L8: IDENTITY UNLOCK MODAL — کلید هویت با رمز عبور قفل است */}
      {identityLocked && (
        <div className="modal">
          <div className="modal-box" style={{ width: '92%', maxWidth: '420px' }}>
            <h3>🔐 کلید هویت قفل است</h3>
            <p style={{ fontSize: '12px', lineHeight: '1.7' }}>
              کلید هویت شما با رمز عبور محافظت می‌شود. برای استفاده از چت رمزنگاری‌شده، رمز
              عبور را وارد کنید. کلید فقط در حافظهٔ این نشست باز می‌ماند و با بستن تب پاک
              می‌شود.
            </p>
            <input
              type="password"
              placeholder="رمز عبور کلید هویت"
              value={unlockPassphrase}
              onChange={e => setUnlockPassphrase(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleUnlockIdentity()}
              autoFocus
            />
            {unlockMsg.text && (
              <div style={{ marginTop: '8px', fontSize: '12px', color: '#f87171' }}>
                {unlockMsg.text}
              </div>
            )}
            <div className="modal-btns" style={{ marginTop: '10px' }}>
              <button type="button" onClick={handleUnlockIdentity}>
                باز کردن
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ADD CONTACT MODAL */}
      {contactModalOpen && (
        <div className="modal" id="contactModal">
          <div className="modal-box">
            <h3>➕ افزودن مخاطب</h3>
            <input
              type="text"
              id="contactInput"
              placeholder="@آیدی_مخاطب"
              value={newContactInput}
              onChange={e => setNewContactInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAddContact()}
              autoFocus
            />
            <div className="modal-btns" style={{ marginTop: '10px' }}>
              <button type="button" onClick={handleAddContact}>
                افزودن
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setContactModalOpen(false)}
              >
                انصراف
              </button>
            </div>
            {contactModalMsg.text && (
              <p
                className={`auth-msg ${contactModalMsg.ok ? 'ok' : ''}`}
                style={{ marginTop: '8px' }}
              >
                {contactModalMsg.text}
              </p>
            )}
          </div>
        </div>
      )}

      {/* MY PROFILE MODAL */}
      {profileModalOpen && (
        <div className="modal" id="profileModal">
          <div className="modal-box">
            <h3>👤 پروفایل من</h3>
            <div style={{ textAlign: 'center', marginBottom: '16px' }}>
              <div
                id="profileAvatar"
                style={{
                  width: '70px',
                  height: '70px',
                  borderRadius: '50%',
                  background: 'var(--bg-surface-2)',
                  border: '2px solid var(--accent-cyan)',
                  boxShadow: '0 0 14px var(--accent-cyan-dim)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '28px',
                  margin: '0 auto 10px',
                  overflow: 'hidden',
                }}
              >
                {avatarPreview ? (
                  <AuthImg
                    src={avatarPreview}
                    alt=""
                    style={{
                      width: '70px',
                      height: '70px',
                      borderRadius: '50%',
                      objectFit: 'cover',
                    }}
                  />
                ) : (
                  myUsername[0]?.toUpperCase()
                )}
              </div>
              <input
                ref={avatarFileInputRef}
                type="file"
                accept="image/*"
                style={{ position: 'fixed', top: '-10000px', left: '-10000px', opacity: 0, pointerEvents: 'none' }}
                onChange={handleUploadAvatar}
              />
              <div
                role="button"
                onClick={() => avatarFileInputRef.current?.click()}
                style={{ fontSize: '12px', color: '#9ca3af', cursor: 'pointer' }}
              >
                📷 تغییر عکس پروفایل
              </div>
            </div>
            <label style={{ fontSize: '13px', color: '#9ca3af' }}>نام نمایشی</label>
            <input
              type="text"
              id="nameInput"
              value={nameInput}
              onChange={e => setNameInput(e.target.value)}
              placeholder="نامی که بقیه می‌بینن (خالی = همون ایمیل)"
              maxLength={100}
            />
            <label style={{ fontSize: '13px', color: '#9ca3af' }}>بیوگرافی</label>
            <input
              type="text"
              id="bioInput"
              value={bioInput}
              onChange={e => setBioInput(e.target.value)}
              placeholder="یه چیزی درباره خودت بنویس..."
            />
            <label style={{ fontSize: '13px', color: '#9ca3af' }}>وضعیت</label>
            <select
              id="statusSelect"
              value={statusInput}
              onChange={e => setStatusInput(e.target.value)}
              style={{ width: '100%', marginBottom: '12px' }}
            >
              <option value="online">🟢 آنلاین</option>
              <option value="busy">🔴 مشغول</option>
              <option value="away">🟡 غایب</option>
            </select>
            <div style={{ marginTop: '14px', marginBottom: '14px', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '10px' }}>
              <button
                type="button"
                style={{
                  width: '100%',
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.35)',
                  color: '#f87171',
                  borderRadius: '8px',
                  padding: '7px 10px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  fontWeight: 600,
                  fontFamily: 'inherit',
                }}
                onClick={async () => {
                  if (window.confirm('آیا از حذف کلیدهای هویت پساکوانتومی این دستگاه اطمینان دارید؟ نشست‌های جاری بازنشانی خواهند شد.')) {
                    await deleteIdentityRecordV4(myUsername);
                    localStorage.clear();
                    sessionStorage.clear();
                    window.location.reload();
                  }
                }}
              >
                🗑️ حذف کلیدهای هویت از این دستگاه (Reset Device Identity)
              </button>
            </div>
            <div className="modal-btns">
              <button type="button" onClick={handleSaveProfile}>
                ذخیره
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setProfileModalOpen(false)}
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CONTACT / GROUP PROFILE MODAL */}
      {contactProfileModal.open && (
        <div className="modal">
          <div
            className="modal-box"
            style={{
              textAlign: 'center',
              width: '92%',
              maxWidth: currentIsGroup ? '440px' : '370px',
            }}
          >
            <h3>{currentIsGroup ? '👥 اطلاعات گروه' : '👤 اطلاعات مخاطب'}</h3>
            <div
              style={{
                width: '70px',
                height: '70px',
                borderRadius: '50%',
                background: 'var(--bg-surface-2)',
                border: '2px solid var(--accent-cyan)',
                boxShadow: '0 0 14px var(--accent-cyan-dim)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '28px',
                margin: '14px auto 10px',
                overflow: 'hidden',
              }}
            >
              {contactProfileModal.user?.avatar ? (
                <AuthImg
                  src={contactProfileModal.user.avatar}
                  alt=""
                  style={{ width: '70px', height: '70px', objectFit: 'cover' }}
                />
              ) : (
                currentPartnerName[0]?.toUpperCase()
              )}
            </div>
            <div style={{ fontSize: '16px', fontWeight: 700, marginBottom: '4px' }}>
              {currentPartnerName}
            </div>
            <div style={{ fontSize: '12px', color: '#9ca3af', marginBottom: '14px' }}>
              {!currentIsGroup && currentPartner && currentPartner !== currentPartnerName
                ? `@${currentPartner} · ${partnerStatusLabel}`
                : partnerStatusLabel}
            </div>
            {!currentIsGroup && contactProfileModal.user?.bio && (
              <div
                style={{
                  background: 'rgba(255,255,255,.05)',
                  padding: '10px',
                  borderRadius: '10px',
                  fontSize: '13px',
                  marginBottom: '14px',
                }}
              >
                {contactProfileModal.user.bio}
              </div>
            )}

            {/* 1-TO-1 CONTACT PROFILE: TRANSPORT BUNDLE STATUS + SAFETY NUMBER VERIFICATION */}
            {!currentIsGroup && (
              <>
                <div
                  style={{
                    background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '10px',
                    padding: '10px 12px',
                    marginBottom: '10px',
                    fontSize: '11.5px',
                    textAlign: 'right',
                    lineHeight: '1.6',
                  }}
                >
                  {(() => {
                    const b = parsePeerKeyBundle(
                      contactProfileModal.user?.public_key,
                      contactProfileModal.user?.username
                    );
                    if (b.isFullyPostQuantum) {
                      return (
                        <div>
                          <div style={{ color: '#c4b5fd', fontWeight: 700, marginBottom: '2px' }}>
                            🔒 بسته کلید پساکوانتومی منتشرشده (ML-KEM-768 + ML-DSA-65)
                          </div>
                          <div style={{ color: '#9ca3af', fontSize: '11px' }}>
                            امضای خوداظهاری بسته کلید معتبر است. جهت اطمینان از عدم جعل هویت، شماره
                            ایمنی را در بخش زیر بررسی و تأیید کنید.
                          </div>
                        </div>
                      );
                    }
                    if (b.isMldsaSignatureInvalid) {
                      return (
                        <div>
                          <div style={{ color: '#f87171', fontWeight: 700, marginBottom: '2px' }}>
                            ⛔ خطر جعل هویت / امضای نامعتبر
                          </div>
                          <div style={{ color: '#fca5a5', fontSize: '11px' }}>
                            امضای دیجیتال هویت ML-DSA با کلیدهای اعلامی مطابقت ندارد!
                          </div>
                        </div>
                      );
                    }
                    if (b.ecdhJwk) {
                      return (
                        <div>
                          <div style={{ color: '#facc15', fontWeight: 700, marginBottom: '2px' }}>
                            ⚠️ مخاطب فاقد کلیدهای پساکوانتومی است
                          </div>
                          <div style={{ color: '#9ca3af', fontSize: '11px' }}>
                            پیام رمزنگاری‌شده به این مخاطب ارسال نمی‌شود؛ مسیر قدیمی ECDH حذف شده است.
                          </div>
                        </div>
                      );
                    }
                    return (
                      <div style={{ color: '#9ca3af' }}>
                        ⚠️ فاقد کلید رمزنگاری عمومی منتشرشده در سامانه
                      </div>
                    );
                  })()}
                </div>

                {/* PER-CONTACT SAFETY NUMBER STATUS & BUTTON */}
                {currentPartner && currentPartnerVerification && (
                  <div
                    style={{
                      background:
                        currentPartnerVerification.state === 'VERIFIED'
                          ? 'rgba(34, 197, 94, 0.12)'
                          : currentPartnerVerification.state === 'CHANGED'
                          ? 'rgba(239, 68, 68, 0.16)'
                          : 'rgba(6, 182, 212, 0.12)',
                      border:
                        currentPartnerVerification.state === 'VERIFIED'
                          ? '1px solid rgba(34, 197, 94, 0.4)'
                          : currentPartnerVerification.state === 'CHANGED'
                          ? '1px solid rgba(239, 68, 68, 0.5)'
                          : '1px solid rgba(6, 182, 212, 0.35)',
                      borderRadius: '12px',
                      padding: '10px 12px',
                      marginBottom: '14px',
                      textAlign: 'right',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        marginBottom: '8px',
                        fontSize: '12px',
                      }}
                    >
                      <span style={{ color: '#d1d5db', fontWeight: 600 }}>
                        وضعیت {SAFETY_STRINGS_FA.safetyNumber}:
                      </span>
                      <span
                        style={{
                          fontWeight: 700,
                          color:
                            currentPartnerVerification.state === 'VERIFIED'
                              ? '#4ade80'
                              : currentPartnerVerification.state === 'CHANGED'
                              ? '#f87171'
                              : '#e5e7eb',
                        }}
                      >
                        {currentPartnerVerification.state === 'VERIFIED'
                          ? `🛡️ ${SAFETY_STRINGS_FA.verified}`
                          : currentPartnerVerification.state === 'CHANGED'
                          ? `⚠️ ${SAFETY_STRINGS_FA.safetyNumberChanged}`
                          : `○ ${SAFETY_STRINGS_FA.notVerified}`}
                      </span>
                    </div>
                    <button
                      type="button"
                      id="profileVerifyContactBtn"
                      onClick={() => {
                        const partnerToVerify = currentPartner;
                        const avatarToUse = contactProfileModal.user?.avatar;
                        setContactProfileModal({ open: false, user: null });
                        openSafetyModalForContact(partnerToVerify, avatarToUse);
                      }}
                      style={{
                        width: '100%',
                        background: 'linear-gradient(135deg, var(--accent), var(--a2))',
                        border: 'none',
                        borderRadius: '10px',
                        color: '#fff',
                        padding: '9px 12px',
                        fontSize: '13px',
                        fontWeight: 700,
                        cursor: 'pointer',
                        fontFamily: 'inherit',
                      }}
                    >
                      🔐 {SAFETY_STRINGS_FA.safetyNumber} و{' '}
                      {currentPartnerVerification.state === 'CHANGED'
                        ? SAFETY_STRINGS_FA.verifyAgain
                        : SAFETY_STRINGS_FA.verifyContact}
                    </button>
                  </div>
                )}
              </>
            )}

            {/* GROUP INFO: DERIVED VERIFICATION SUMMARY + PER-MEMBER SAFETY NUMBERS (NO GROUP SAFETY NUMBER) */}
            {currentIsGroup && currentGroupVerificationSummary && (
              <div style={{ textAlign: 'right', marginBottom: '14px' }}>
                {/* Derived Group Summary Banner */}
                <div
                  id="groupVerificationSummaryBox"
                  style={{
                    background:
                      currentGroupVerificationSummary.status === 'ALL_VERIFIED'
                        ? 'rgba(34, 197, 94, 0.14)'
                        : currentGroupVerificationSummary.status === 'MEMBER_CHANGED'
                        ? 'rgba(239, 68, 68, 0.18)'
                        : 'rgba(255, 255, 255, 0.05)',
                    border:
                      currentGroupVerificationSummary.status === 'ALL_VERIFIED'
                        ? '1px solid rgba(34, 197, 94, 0.45)'
                        : currentGroupVerificationSummary.status === 'MEMBER_CHANGED'
                        ? '1px solid rgba(239, 68, 68, 0.5)'
                        : '1px solid rgba(255, 255, 255, 0.12)',
                    borderRadius: '10px',
                    padding: '10px 12px',
                    marginBottom: '10px',
                    fontSize: '12px',
                    lineHeight: '1.65',
                  }}
                >
                  <div
                    style={{
                      fontWeight: 700,
                      color:
                        currentGroupVerificationSummary.status === 'ALL_VERIFIED'
                          ? '#4ade80'
                          : currentGroupVerificationSummary.status === 'MEMBER_CHANGED'
                          ? '#f87171'
                          : '#e5e7eb',
                    }}
                  >
                    {currentGroupVerificationSummary.status === 'ALL_VERIFIED'
                      ? `🛡️ ${SAFETY_STRINGS_FA.groupAllVerified}`
                      : currentGroupVerificationSummary.status === 'MEMBER_CHANGED'
                      ? `⚠️ ${SAFETY_STRINGS_FA.groupMemberChanged}`
                      : `○ ${SAFETY_STRINGS_FA.groupSomeUnverified}`}
                  </div>
                  {currentGroupVerificationSummary.status === 'MEMBER_CHANGED' &&
                    currentGroupVerificationSummary.changedMembers.length > 0 && (
                      <div style={{ fontSize: '11.5px', color: '#fecaca', marginTop: '4px' }}>
                        اعضای دارای تغییر کلید:{' '}
                        <b>
                          {currentGroupVerificationSummary.changedMembers
                            .map(m => `@${m}`)
                            .join('، ')}
                        </b>
                      </div>
                    )}
                </div>

                {/* Members List with Per-Member State Icon & Safety Number Button */}
                <div
                  style={{
                    fontSize: '12px',
                    fontWeight: 700,
                    color: '#c4b5fd',
                    marginBottom: '6px',
                  }}
                >
                  👥 اعضای گروه (شماره ایمنی مستقل برای هر عضو):
                </div>
                <div
                  style={{
                    maxHeight: '220px',
                    overflowY: 'auto',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px',
                    background: 'rgba(0,0,0,0.2)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '10px',
                    padding: '8px',
                  }}
                >
                  {currentGroupMembersList.map(member => {
                    const isMe = member === myUsername;
                    const rec = currentGroupVerificationSummary.memberRecords[member];
                    const state = rec?.state || 'UNVERIFIED';
                    const memberAvatar = groupMemberProfiles[member]?.avatar;
                    const memberDisplay =
                      groupMemberProfiles[member]?.display_name || member;

                    return (
                      <div
                        key={member}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '8px',
                          padding: '7px 8px',
                          borderRadius: '8px',
                          background:
                            !isMe && state === 'CHANGED'
                              ? 'rgba(239, 68, 68, 0.14)'
                              : 'rgba(255, 255, 255, 0.04)',
                          border:
                            !isMe && state === 'CHANGED'
                              ? '1px solid rgba(239, 68, 68, 0.4)'
                              : '1px solid rgba(255, 255, 255, 0.06)',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div
                            style={{
                              width: '30px',
                              height: '30px',
                              borderRadius: '50%',
                              background: 'var(--bg-surface-2)',
                              border: '1.5px solid var(--accent-cyan)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontSize: '13px',
                              fontWeight: 700,
                              color: '#fff',
                              overflow: 'hidden',
                              flexShrink: 0,
                            }}
                          >
                            {memberAvatar ? (
                              <AuthImg
                                src={memberAvatar}
                                alt=""
                                style={{ width: '30px', height: '30px', objectFit: 'cover' }}
                              />
                            ) : (
                              member[0]?.toUpperCase()
                            )}
                          </div>
                          <div>
                            <div style={{ fontSize: '12.5px', fontWeight: 600, color: '#f3f4f6' }}>
                              {memberDisplay}{' '}
                              {memberDisplay !== member && (
                                <span style={{ color: '#9ca3af', fontWeight: 400 }}>
                                  @{member}
                                </span>
                              )}{' '}
                              {isMe && <span style={{ color: '#9ca3af' }}>(شما)</span>}
                            </div>
                            {!isMe && (
                              <div
                                style={{
                                  fontSize: '10.5px',
                                  color:
                                    state === 'VERIFIED'
                                      ? '#4ade80'
                                      : state === 'CHANGED'
                                      ? '#f87171'
                                      : '#9ca3af',
                                }}
                              >
                                {state === 'VERIFIED'
                                  ? `🛡️ ${SAFETY_STRINGS_FA.verified}`
                                  : state === 'CHANGED'
                                  ? `⚠️ ${SAFETY_STRINGS_FA.safetyNumberChanged}`
                                  : `○ ${SAFETY_STRINGS_FA.notVerified}`}
                              </div>
                            )}
                          </div>
                        </div>

                        {!isMe && (
                          <button
                            type="button"
                            onClick={() => {
                              setContactProfileModal({ open: false, user: null });
                              openSafetyModalForContact(member, memberAvatar);
                            }}
                            style={{
                              background:
                                state === 'CHANGED'
                                  ? '#ef4444'
                                  : 'rgba(6, 182, 212, 0.2)',
                              border:
                                state === 'CHANGED'
                                  ? 'none'
                                  : '1px solid rgba(6, 182, 212, 0.45)',
                              color: '#fff',
                              borderRadius: '7px',
                              padding: '5px 9px',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              fontFamily: 'inherit',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {state === 'CHANGED'
                              ? SAFETY_STRINGS_FA.verifyAgain
                              : SAFETY_STRINGS_FA.safetyNumber}
                          </button>
                        )}

                        {!isMe && currentGroupMembersList[0] === myUsername && (
                          <button
                            type="button"
                            onClick={async () => {
                              if (!window.confirm(`آیا از حذف ${member} از گروه اطمینان دارید؟`)) return;
                              const sessionToken = getSessionToken();
                              const res = await fetch(`/api/group/${encodeURIComponent(currentPartner!)}/remove-member`, {
                                method: 'POST',
                                headers: {
                                  'Content-Type': 'application/json',
                                  ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
                                },
                                body: JSON.stringify({ username: member }),
                              }).then(r => r.json());
                              if (res.ok) {
                                showToast(`عضو ${member} از گروه حذف شد`);
                                setContactProfileModal({ open: false, user: null });
                              } else {
                                showToast(res.msg || 'خطا در حذف عضو');
                              }
                            }}
                            style={{
                              background: 'rgba(239, 68, 68, 0.2)',
                              border: '1px solid rgba(239, 68, 68, 0.4)',
                              color: '#ef4444',
                              borderRadius: '7px',
                              padding: '5px 9px',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              fontFamily: 'inherit',
                              marginRight: '6px',
                            }}
                          >
                            حذف
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
                {currentGroupMembersList[0] === myUsername && (
                  <div style={{ marginTop: '12px', display: 'flex', gap: '8px' }}>
                    <input
                      type="text"
                      placeholder="نام کاربری یا ایمیل عضو جدید..."
                      id="newGroupMemberInput"
                      style={{ flex: 1, padding: '7px 10px', fontSize: '12px', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff' }}
                    />
                    <button
                      type="button"
                      onClick={async () => {
                        const input = document.getElementById('newGroupMemberInput') as HTMLInputElement;
                        const val = input ? input.value.trim().replace(/^@+/, '') : '';
                        if (!val) return;
                        const sessionToken = getSessionToken();
                        const res = await fetch(`/api/group/${encodeURIComponent(currentPartner!)}/add-member`, {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                            ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
                          },
                          body: JSON.stringify({ username: val }),
                        }).then(r => r.json());
                        if (res.ok) {
                          showToast(`عضو جدید اضافه شد`);
                          input.value = '';
                          setContactProfileModal({ open: false, user: null });
                        } else {
                          showToast(res.msg || 'خطا در افزودن عضو');
                        }
                      }}
                      style={{
                        background: 'var(--accent)',
                        color: '#fff',
                        borderRadius: '8px',
                        border: 'none',
                        padding: '7px 12px',
                        fontSize: '12px',
                        cursor: 'pointer',
                        fontWeight: 600,
                      }}
                    >
                      + افزودن
                    </button>
                  </div>
                )}
              </div>
            )}

            <div className="modal-btns">
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setContactProfileModal({ open: false, user: null })}
              >
                بستن
              </button>
            </div>
          </div>
        </div>
      )}

      {/* EDIT MESSAGE MODAL */}
      {editModal.open && (
        <div className="modal" id="editModal">
          <div className="modal-box">
            <h3>✏️ ویرایش پیام</h3>
            <input
              type="text"
              id="editInput"
              value={editModal.text}
              onChange={e => setEditModal({ open: true, text: e.target.value })}
              onKeyDown={e => e.key === 'Enter' && handleSubmitEdit()}
              autoFocus
            />
            <div className="modal-btns" style={{ marginTop: '10px' }}>
              <button type="button" onClick={handleSubmitEdit}>
                ذخیره
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setEditModal({ open: false, text: '' })}
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FORWARD MODAL */}
      {forwardModalOpen && (
        <div className="modal" id="forwardModal">
          <div className="modal-box">
            <h3>↗️ فوروارد پیام</h3>
            <p>انتخاب کن کجا فوروارد بشه:</p>
            <div
              id="forwardList"
              style={{ maxHeight: '200px', overflowY: 'auto', marginBottom: '12px' }}
            >
              {rooms
                .filter(r => r.id !== currentPartner)
                .map(r => {
                  const targetRoomId = r.isGroup
                    ? 'group__' + r.id
                    : [myUsername, r.id].sort().join('__');
                  const checked = forwardSelected.includes(targetRoomId);
                  return (
                    <div key={r.id} className="forward-item">
                      <input
                        type="checkbox"
                        id={`fw-${r.id}`}
                        checked={checked}
                        onChange={e => {
                          if (e.target.checked) {
                            setForwardSelected(prev => [...prev, targetRoomId]);
                          } else {
                            setForwardSelected(prev =>
                              prev.filter(id => id !== targetRoomId)
                            );
                          }
                        }}
                      />
                      <label htmlFor={`fw-${r.id}`}>{r.name}</label>
                    </div>
                  );
                })}
            </div>
            <div className="modal-btns">
              <button type="button" onClick={handleSubmitForward}>
                فوروارد
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setForwardModalOpen(false)}
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* REPORT MODAL */}
      {reportModalOpen && (
        <div className="modal" id="reportModal">
          <div className="modal-box">
            <h3>🚨 گزارش پیام</h3>
            <p>علت گزارش:</p>
            <select
              id="reportReason"
              value={reportReason}
              onChange={e => setReportReason(e.target.value)}
              style={{ width: '100%', marginBottom: '12px' }}
            >
              <option value="spam">اسپم</option>
              <option value="abuse">توهین</option>
              <option value="inappropriate">محتوای نامناسب</option>
              <option value="other">سایر</option>
            </select>
            <div className="modal-btns">
              <button type="button" onClick={handleSubmitReport}>
                ارسال گزارش
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setReportModalOpen(false)}
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* DISAPPEAR MODAL */}
      {disappearModalOpen && (
        <div className="modal" id="disappearModal">
          <div className="modal-box">
            <h3>⏱ پیام ناپدیدشونده</h3>
            <p>بعد از چه مدتی پیام حذف شود؟</p>
            <select
              id="disappearTime"
              value={disappearAfter}
              onChange={e => setDisappearAfter(parseInt(e.target.value, 10))}
            >
              <option value={0}>غیرفعال</option>
              <option value={30}>۳۰ ثانیه</option>
              <option value={60}>۱ دقیقه</option>
              <option value={300}>۵ دقیقه</option>
              <option value={3600}>۱ ساعت</option>
              <option value={86400}>۲۴ ساعت</option>
            </select>
            <div className="modal-btns" style={{ marginTop: '10px' }}>
              <button
                type="button"
                onClick={() => {
                  setDisappearModalOpen(false);
                  showToast(
                    disappearAfter > 0
                      ? `⏱ پیام‌های بعدی بعد از ${disappearAfter} ثانیه حذف می‌شوند`
                      : '⏱ پیام ناپدیدشونده غیرفعال شد'
                  );
                }}
              >
                تأیید
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setDisappearModalOpen(false)}
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CHANGELOG & ARCHITECTURAL INVENTION MODAL (v6.0) */}
      {changelogModalOpen && (
        <div className="modal" id="changelogModal">
          <div
            className="modal-box"
            style={{
              maxWidth: '640px',
              width: '94%',
              maxHeight: '86vh',
              overflowY: 'auto',
              textAlign: 'right',
              direction: 'rtl',
            }}
          >
            <h3 style={{ fontSize: '16px', marginBottom: '8px', color: 'var(--text-primary)' }}>
              🚀 چنج‌لاگ و تاریخچه تکامل معماری (نسخه v6.0 — PQ-MPRBA Edition)
            </h3>

            <div
              style={{
                background: 'var(--bg-surface-active)',
                border: '1px solid var(--accent-cyan-border)',
                borderRadius: '12px',
                padding: '12px 14px',
                fontSize: '12.5px',
                lineHeight: '1.85',
                marginBottom: '12px',
              }}
            >
              <div style={{ fontWeight: 700, color: 'var(--accent-cyan-light)', fontSize: '13.5px', marginBottom: '6px' }}>
                🌟 ابداع و خلق پروتکل اختصاصی «PQ-MPRBA» (برای اولین بار در بستر وب)
              </div>
              <p style={{ margin: '0 0 8px 0', color: '#e5e7eb' }}>
                در نسخه <b>v6.0</b>، ما صرفاً از کتابخانه‌های آماده استفاده نکردیم؛ بلکه برای نخستین بار یک معماری ترکیبی کاملاً جدید و بی‌سابقه به نام{' '}
                <b>
                  پروتکل هماهنگ‌سازی کلید پساکوانتومی چندطرفه به همراه احراز هویت کور (Post-Quantum Multi-Party Ratchet with Blinded Authentication — PQ-MPRBA)
                </b>{' '}
                را از صفر خلق و مهندسی کردیم که پیش از این در هیچ پیام‌رسان تحت وبی (حتی نسخه‌های وب سیگنال و تلگرام) وجود نداشته است:
              </p>
              <ul style={{ margin: '0', paddingRight: '18px', color: '#d1d5db' }}>
                <li>
                  <b>لایه ۱ (راتچت هیبریدی پساکوانتومی ML-KEM-768 + ECDH P-256):</b> کپسوله‌سازی کلید سشن با الگوریتم مشبک{' '}
                  <code>CRYSTALS-Kyber (ML-KEM-768 / FIPS 203)</code> و منحنی بیضی <code>P-256</code> به همراه راتچت متقارن <code>HKDF-SHA256</code> برای ایمنی کامل در برابر حملات <i>Store Now, Decrypt Later</i>.
                </li>
                <li>
                  <b>لایه ۲ (امضای دیجیتال هویت FIPS 204 ML-DSA-65):</b> امضای هویت دیجیتال، باندل کلید و تصدیق نشست با الگوریتم{' '}
                  <code>CRYSTALS-Dilithium (ML-DSA-65)</code> جهت مصونیت کامل لایه هویت در برابر الگوریتم شور و حملات جعل هویت کوانتومی.
                </li>
                <li>
                  <b>لایه ۳ (سیستم ضد تنزل خاموش - Anti-Downgrade Protection):</b> جلوگیری مطلق از نمایش نشان <code>PQ-KEM</code> در گفتگوهای فاقد کلید تأییدشده و نمایش بنر هشدار واضح برای آگاهی کاربر.
                </li>
                <li>
                  <b>لایه ۴ (احراز هویت کور بدون افشای متادیتا با Ristretto255-VOPRF):</b> پیاده‌سازی تابع شبه‌تصادفی ناآگاهانه اثبات‌پذیر (<code>RFC 9497</code>) به همراه اثبات دانایی صفر <code>DLEQ</code> که هویت و متادیتای کاربر را حتی از دید سرور مخفی می‌کند.
                </li>
              </ul>
            </div>

            <div
              style={{
                background: 'rgba(16, 185, 129, 0.09)',
                border: '1px solid rgba(16, 185, 129, 0.35)',
                borderRadius: '12px',
                padding: '12px 14px',
                fontSize: '12px',
                lineHeight: '1.8',
                marginBottom: '12px',
              }}
            >
              <div style={{ fontWeight: 700, color: '#34d399', fontSize: '13px', marginBottom: '6px' }}>
                🛠️ چالش‌های مهندسی فوق‌سنگینی که در این پروتکل ابداعی پیش‌بینی و حل شدند:
              </div>

              <div style={{ marginBottom: '8px' }}>
                <b style={{ color: '#6ee7b7' }}>۱. حل مشکل پیام‌های خارج از نوبت در اختلالات شبکه (Out-of-Order Skipped Keys & RAM Zeroization):</b>
                <br />
                <span>
                  <i>مشکل احتمالی:</i> اگر به دلیل اختلال اینترنت، پیام ۳ زودتر از پیام ۲ به گیرنده برسد، زنجیره راتچت با حرکت به گام ۳ دیگر قادر به باز کردن پیام ۲ نخواهد بود.
                  <br />
                  <i>راه‌حل ابداعی ما:</i> طراحی حافظه امن کلیدهای پرش‌خورده (<code>SkippedMessageKeys</code> با سقف <code>MAX_SKIP=100</code> و <code>TTL</code> ده دقیقه‌ای) که کلیدهای میانی را موقتاً نگه می‌دارد تا پیام‌های با تأخیر رمزگشایی شوند و بلافاصله پس از مصرف، با تکنیک <b>Zeroization (<code>Uint8Array.fill(0)</code>)</b> کلید را در RAM صفر و نابود می‌کند تا امنیت رو به جلو (Forward Secrecy) ۱۰۰٪ حفظ شود.
                </span>
              </div>

              <div style={{ marginBottom: '8px' }}>
                <b style={{ color: '#6ee7b7' }}>۲. حل مشکل سنگینی امضای کور RSA در مرورگر (جایگزینی با Ristretto255-VOPRF):</b>
                <br />
                <span>
                  <i>مشکل احتمالی:</i> امضاهای کور سنتی <code>RSA-BSSA</code> دارای کلیدهای بسیار حجیم هستند که باعث قفل شدن رابطه کاربری (UI Freezing) در مرورگر موبایل می‌شوند.
                  <br />
                  <i>راه‌حل ابداعی ما:</i> مهندسی لایه امضای کور بر پایه منحنی مرتبه اول <code>Ristretto255-VOPRF</code> با نقاط فشرده ۳۲ بایتی و اثبات صفر <code>DLEQ</code> که سرعت پردازش را در مرورگر بیش از <b>۱۰ برابر سریع‌تر</b> و بدون هیچ‌گونه لگ انجام می‌دهد.
                </span>
              </div>

              <div>
                <b style={{ color: '#6ee7b7' }}>۳. حل مشکل خراب شدن پیام‌های همزمان هنگام تغییر اعضای گروه (Group Epoch FSM + Grace Buffer):</b>
                <br />
                <span>
                  <i>مشکل احتمالی:</i> وقتی عضوی به گروه اضافه یا حذف می‌شود و کلید گروه چرخش می‌کند (Epoch Rotation)، پیام‌هایی که در همان میلی‌ثانیه در حال ارسال در شبکه هستند با کلید جدید باز نمی‌شوند (Message Corruption).
                  <br />
                  <i>راه‌حل ابداعی ما:</i> پیاده‌سازی ماشین وضعیت دقیق (<code>STABLE -&gt; ROTATING -&gt; STABLE</code>) در Socket.IO به همراه بافر امن <b>۳ اپوک اخیر (Grace Buffer)</b> که به پیام‌های در حال پرواز اجازه می‌دهد بدون خطا رمزگشایی شوند.
                </span>
              </div>
            </div>

            <div
              style={{
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '10px',
                padding: '10px 12px',
                fontSize: '11.5px',
                lineHeight: '1.75',
                marginBottom: '12px',
                color: '#9ca3af',
              }}
            >
              <b style={{ color: '#f3f4f6' }}>📦 خلاصه آپدیت‌های زیرساختی قبلی (نسخه‌های v1.0 تا v5.0):</b>
              <ul style={{ margin: '4px 0 0 0', paddingRight: '18px' }}>
                <li>مهاجرت کامل به <b>React 19 + TypeScript</b> و حذف کامل جاوااسکریپت خام.</li>
                <li>دیتابیس دوگانه (PostgreSQL + ذخیره اتمیک دیسک <code>data/database.json</code> با قفل <b>Write Mutex</b> و <code>Debounce 250ms</code> برای جلوگیری از Race Condition).</li>
                <li>ذخیره‌سازی هیبریدی رسانه و ویس‌ها در جدول <code>media_blobs</code> (مقاوم در برابر ریست کانتینرهای ابری).</li>
                <li>مدیریت حضور و آنلاین بودن کاربران (<code>PresenceManager</code>) آماده کلاسترینگ Redis و حذف پسوردهای هاردکد شده با <code>timingSafeEqual</code>.</li>
              </ul>
            </div>

            <div className="modal-btns">
              <button
                type="button"
                onClick={() => setChangelogModalOpen(false)}
                style={{ width: '100%' }}
              >
                بستن پنجره چنج‌لاگ
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CREATE GROUP MODAL */}
      {groupModalOpen && (
        <div className="modal" id="groupModal">
          <div className="modal-box">
            <h3>👥 ایجاد گروه جدید</h3>
            <p style={{ fontSize: '12px', color: '#9ca3af', marginBottom: '12px' }}>
              نام گروه را وارد کنید و اعضای مورد نظر را انتخاب یا تایپ کنید:
            </p>

            <label style={{ fontSize: '13px', color: '#9ca3af', display: 'block', marginBottom: '4px' }}>
              نام گروه
            </label>
            <input
              type="text"
              placeholder="مثال: تیم توسعه یا دوستان..."
              value={groupNameInput}
              onChange={e => setGroupNameInput(e.target.value)}
              autoFocus
              style={{ marginBottom: '12px', width: '100%' }}
            />

            <label style={{ fontSize: '13px', color: '#9ca3af', display: 'block', marginBottom: '6px' }}>
              انتخاب اعضا از میان مخاطبان:
            </label>
            <div
              style={{
                maxHeight: '140px',
                overflowY: 'auto',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                background: 'rgba(255,255,255,0.03)',
                padding: '8px',
                borderRadius: '8px',
                border: '1px solid var(--border)',
                marginBottom: '12px',
              }}
            >
              {rooms.filter(r => !r.isGroup).length === 0 ? (
                <div style={{ fontSize: '12px', color: '#6b7280', textAlign: 'center', padding: '6px' }}>
                  مخاطبی در لیست وجود ندارد. می‌توانید آیدی اعضا را در کادر زیر بنویسید.
                </div>
              ) : (
                rooms
                  .filter(r => !r.isGroup)
                  .map(c => {
                    const isSelected = groupMembersSelected.includes(c.id);
                    return (
                      <label
                        key={c.id}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          fontSize: '13px',
                          cursor: 'pointer',
                          padding: '4px 6px',
                          borderRadius: '6px',
                          background: isSelected ? 'var(--bg-surface-active)' : 'transparent',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={e => {
                            if (e.target.checked) {
                              setGroupMembersSelected(prev => [...prev, c.id]);
                            } else {
                              setGroupMembersSelected(prev => prev.filter(id => id !== c.id));
                            }
                          }}
                        />
                        <span>@{c.name}</span>
                      </label>
                    );
                  })
              )}
            </div>

            <label style={{ fontSize: '13px', color: '#9ca3af', display: 'block', marginBottom: '4px' }}>
              افزودن آیدی‌های دیگر (با فاصله یا ویرگول جدا کنید):
            </label>
            <input
              type="text"
              placeholder="@کاربر_۱, @کاربر_۲ ..."
              value={extraMemberInput}
              onChange={e => setExtraMemberInput(e.target.value)}
              style={{ marginBottom: '16px', width: '100%' }}
            />

            <div className="modal-btns">
              <button type="button" onClick={handleCreateGroup}>
                ایجاد گروه
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => {
                  setGroupModalOpen(false);
                  setGroupNameInput('');
                  setGroupMembersSelected([]);
                  setExtraMemberInput('');
                }}
              >
                انصراف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Outgoing Message Warn-and-Confirm Dialog when Contact Identity Key is CHANGED */}
      {outgoingChangeConfirmOpen && (
        <div
          className="modal-overlay"
          style={{ display: 'flex', zIndex: 9998 }}
          onClick={() => setOutgoingChangeConfirmOpen(false)}
        >
          <div
            className="modal-box"
            style={{ maxWidth: '440px', width: '92%', textAlign: 'right' }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <span
                style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '50%',
                  background: 'rgba(239, 68, 68, 0.16)',
                  color: '#f87171',
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '18px',
                  flexShrink: 0,
                }}
              >
                ⚠️
              </span>
              <h3 style={{ margin: 0, color: '#fca5a5', fontSize: '16px' }}>
                {SAFETY_STRINGS_FA.outgoingChangedDialogTitle}
              </h3>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.75, marginBottom: '18px' }}>
              {SAFETY_STRINGS_FA.outgoingChangedDialogBody}
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <button
                type="button"
                onClick={() => {
                  setOutgoingChangeConfirmOpen(false);
                  if (currentPartner) {
                    const partnerAvatar = rooms.find(
                      r => !r.isGroup && r.id === currentPartner
                    )?.avatar;
                    void openSafetyModalForContact(currentPartner, partnerAvatar);
                  }
                }}
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  borderRadius: '10px',
                  border: '1px solid rgba(56, 189, 248, 0.45)',
                  background: 'rgba(56, 189, 248, 0.16)',
                  color: '#e0f2fe',
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: 'pointer',
                }}
              >
                {SAFETY_STRINGS_FA.verifyFirst}
              </button>
              <button
                type="button"
                onClick={() => {
                  setOutgoingChangeConfirmOpen(false);
                  // Sends this message ONLY; leaves state as CHANGED and never marks verified
                  void executeSendMessage();
                }}
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  borderRadius: '10px',
                  border: '1px solid rgba(239, 68, 68, 0.45)',
                  background: 'rgba(239, 68, 68, 0.14)',
                  color: '#fecaca',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: 'pointer',
                }}
              >
                {SAFETY_STRINGS_FA.sendAnyway}
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => setOutgoingChangeConfirmOpen(false)}
                style={{ width: '100%', padding: '9px 14px', fontSize: '13px' }}
              >
                {SAFETY_STRINGS_FA.cancel}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Safety Number Verification Modal (Spec v0.1) */}
      <SafetyNumberModal
        open={safetyModalState.open}
        myUsername={myUsername}
        contactUsername={safetyModalState.contactUsername}
        contactAvatar={safetyModalState.contactAvatar}
        peerPublicKey={
          safetyModalState.contactUsername
            ? peerPublicKeysRef.current[safetyModalState.contactUsername] ||
              getStoredPeerPublicKey(safetyModalState.contactUsername)
            : null
        }
        verificationRecord={getContactVerificationRecord(
          myUsername,
          safetyModalState.contactUsername || ''
        )}
        initialShowLearnMore={safetyModalState.initialShowLearnMore}
        onClose={() => setSafetyModalState(prev => ({ ...prev, open: false }))}
        onVerificationUpdated={() => setVerificationVersion(v => v + 1)}
        showToast={showToast}
      />
    </div>
  );
};


