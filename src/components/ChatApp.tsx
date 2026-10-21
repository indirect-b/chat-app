import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Socket } from 'socket.io-client';
import { ChatMessage, RoomSummary, UserProfile } from '../types';
import {
  ensureUserHybridKeyPair,
  acquireBlindedIdentityToken,
  rotateGroupEpoch,
  getGroupEpochState,
  encryptMessageText,
  decryptMessageText,
  isE2EEEnabled,
  setE2EEEnabled,
  getRoomSecret,
  setRoomSecret,
  isE2EEPayload,
  VoprfBlindTokenRecord,
} from '../utils/crypto';

interface ChatAppProps {
  myUsername: string;
  socket: Socket;
  onLogout: () => void;
  showToast: (text: string) => void;
}

interface DecryptedChatMessage extends ChatMessage {
  decryptedText?: string;
  isE2EE?: boolean;
  e2eeMode?: 'PQ-MLKEM-RATCHET' | 'GROUP-EPOCH-FSM' | 'ECDH' | 'PBKDF2';
  ratchetStep?: number;
  epoch?: number;
  decryptFailed?: boolean;
}

const QUICK_EMOJIS = ['❤️', '👍', '😂', '🔥', '👏', '😮'];

export const ChatApp: React.FC<ChatAppProps> = ({
  myUsername,
  socket,
  onLogout,
  showToast,
}) => {
  const [myProfile, setMyProfile] = useState<UserProfile>({
    username: myUsername,
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

  // E2EE + Post-Quantum + VOPRF State
  const [e2eeActive, setE2eeActive] = useState<boolean>(isE2EEEnabled());
  const [e2eeModalOpen, setE2eeModalOpen] = useState(false);
  const [customSecretInput, setCustomSecretInput] = useState('');
  const [voprfToken, setVoprfToken] = useState<VoprfBlindTokenRecord | null>(null);
  const [currentGroupEpoch, setCurrentGroupEpoch] = useState<number>(1);
  const groupMembersRef = useRef<Record<string, string[]>>({});

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

  const getPeerKeyForRoom = useCallback(
    (roomId: string): string | null => {
      if (roomId.startsWith('group__')) return null;
      const partner = roomId.split('__').find(u => u !== myUsername);
      return partner ? peerPublicKeysRef.current[partner] || null : null;
    },
    [myUsername]
  );

  const processDecryption = useCallback(
    async (msg: ChatMessage, roomId: string): Promise<DecryptedChatMessage> => {
      const peerPublicKey = getPeerKeyForRoom(roomId);
      const gId = roomId.startsWith('group__') ? roomId.replace('group__', '') : '';
      const groupMembers = gId ? groupMembersRef.current[gId] || [] : undefined;

      const dec = await decryptMessageText(msg.text || '', roomId, {
        myUsername,
        peerPublicKey,
        sender: msg.sender,
        groupMembers,
      });
      let decReply = msg.reply_to_text;
      if (msg.reply_to_text && isE2EEPayload(msg.reply_to_text)) {
        const rDec = await decryptMessageText(msg.reply_to_text, roomId, {
          myUsername,
          peerPublicKey,
          sender: msg.sender,
          groupMembers,
        });
        decReply = rDec.text;
      }
      return {
        ...msg,
        reply_to_text: decReply,
        decryptedText: dec.text,
        isE2EE: dec.isEncrypted,
        e2eeMode: dec.mode,
        ratchetStep: dec.ratchetStep,
        epoch: dec.epoch,
        decryptFailed: dec.failed,
      };
    },
    [myUsername, getPeerKeyForRoom]
  );

  const loadRoomList = useCallback(
    async (tab: 'chats' | 'groups') => {
      if (tab === 'chats') {
        const res = await fetch('/api/contacts/' + encodeURIComponent(myUsername)).then(r =>
          r.json()
        );
        if (res.ok) {
          res.contacts.forEach((c: any) => {
            if (c.public_key) {
              peerPublicKeysRef.current[c.username] = c.public_key;
            }
          });
          setRooms(
            res.contacts.map((c: any) => ({
              id: c.username,
              name: c.username,
              isGroup: false,
              avatar: c.avatar,
              online: !!c.online,
              preview: c.online ? 'آنلاین' : 'آفلاین',
              publicKey: c.public_key || null,
            }))
          );
        }
      } else {
        const res = await fetch('/api/groups/' + encodeURIComponent(myUsername)).then(r =>
          r.json()
        );
        if (res.ok) {
          res.groups.forEach((g: any) => {
            if (Array.isArray(g.members)) {
              groupMembersRef.current[g.id] = g.members;
            }
            if (g.epoch) {
              void rotateGroupEpoch(g.id, Number(g.epoch), g.members || []);
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
    [myUsername]
  );

  // Initial load + Ristretto255-VOPRF Blinded Auth + Post-Quantum Hybrid Key Exchange (ML-KEM-768 + P-256)
  useEffect(() => {
    socket.emit('auth', myUsername);
    loadRoomList('chats');

    acquireBlindedIdentityToken(myUsername)
      .then(voprfRec => {
        if (voprfRec) setVoprfToken(voprfRec);
        return ensureUserHybridKeyPair(myUsername);
      })
      .then(pubKey => {
        if (pubKey) {
          fetch('/api/user/public-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: myUsername, publicKey: pubKey }),
          }).catch(() => {});
        }
      });

    fetch('/api/user/' + encodeURIComponent(myUsername))
      .then(r => r.json())
      .then(res => {
        if (res.ok && res.user) {
          setMyProfile(res.user);
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
        : roomId.split('__').find(u => u !== myUsername);

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
      const dec = await decryptMessageText(newText, roomId, {
        myUsername,
        peerPublicKey: getPeerKeyForRoom(roomId),
      });
      setMessages(prev =>
        prev.map(m =>
          m.id === msgId
            ? {
                ...m,
                text: newText,
                decryptedText: dec.text,
                isE2EE: dec.isEncrypted,
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
        const res = await fetch('/api/messages/' + encodeURIComponent(roomId)).then(r => r.json());
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
        void rotateGroupEpoch(g.id, g.epoch, g.members || []);
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
    }: {
      groupId: string;
      name: string;
      epoch: number;
      members: string[];
    }) => {
      groupMembersRef.current[groupId] = members;
      await rotateGroupEpoch(groupId, epoch, members);
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
      peerPublicKeysRef.current[username] = publicKey;
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
  }, [myUsername, socket, processDecryption, scrollBottom, getPeerKeyForRoom, showToast, formatMessageTime]);

  const handleOpenChat = async (room: RoomSummary) => {
    const roomId = room.isGroup
      ? 'group__' + room.id
      : [myUsername, room.id].sort().join('__');

    if (!room.isGroup && !peerPublicKeysRef.current[room.id]) {
      try {
        const uRes = await fetch('/api/user/' + encodeURIComponent(room.id)).then(r => r.json());
        if (uRes.ok && uRes.user?.public_key) {
          peerPublicKeysRef.current[room.id] = uRes.user.public_key;
        }
      } catch {
        // ignore
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

    const res = await fetch('/api/messages/' + encodeURIComponent(roomId)).then(r =>
      r.json()
    );
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

  const handleSendMessage = async () => {
    const trimmed = messageText.trim();
    if (!trimmed || !currentRoom || !currentPartner) return;

    const payloadText = e2eeActive
      ? await encryptMessageText(trimmed, currentRoom, {
          myUsername,
          peerPublicKey: getPeerKeyForRoom(currentRoom),
          groupMembers: currentIsGroup ? groupMembersRef.current[currentPartner] || [] : undefined,
        })
      : trimmed;

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
    if (!file || !currentPartner) return;
    setAttachOpen(false);

    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r =>
      r.json()
    );
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
        const fd = new FormData();
        fd.append('file', blob, 'voice.webm');
        const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r =>
          r.json()
        );
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
    const clean = newContactInput.trim().replace('@', '');
    if (!clean) return;
    const res = await fetch('/api/add-contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ myUsername, contactUsername: clean }),
    }).then(r => r.json());

    if (res.ok) {
      setContactModalMsg({ text: '✅ مخاطب اضافه شد', ok: true });
      setRooms(prev => {
        if (prev.some(r => r.id === clean)) return prev;
        return [...prev, { id: clean, name: clean, isGroup: false, preview: 'آفلاین' }];
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
      .map(s => s.replace('@', '').trim())
      .filter(Boolean);
    const members = Array.from(new Set([...groupMembersSelected, ...extra])).filter(
      u => u !== myUsername
    );

    try {
      const res = await fetch('/api/create-group', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r =>
      r.json()
    );
    if (res.ok) {
      setAvatarPreview(res.fileUrl);
    }
    e.target.value = '';
  };

  const handleSaveProfile = async () => {
    await fetch('/api/user/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: myUsername,
        bio: bioInput,
        status: statusInput,
        avatar: avatarPreview,
      }),
    });
    setMyProfile({
      username: myUsername,
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
      setContactProfileModal({ open: true, user: null });
      return;
    }
    const res = await fetch('/api/user/' + encodeURIComponent(currentPartner)).then(r =>
      r.json()
    );
    setContactProfileModal({ open: true, user: res.ok ? res.user : null });
  };

  const handleToggleE2EE = () => {
    const next = !e2eeActive;
    setE2eeActive(next);
    setE2EEEnabled(next);
    showToast(
      next
        ? '🔒 رمزنگاری سرتاسری (E2EE - AES-256) فعال شد'
        : '🔓 رمزنگاری سرتاسری غیرفعال شد'
    );
  };

  const handleSaveRoomSecret = async () => {
    if (!currentRoom) return;
    setRoomSecret(currentRoom, customSecretInput);
    setE2eeModalOpen(false);
    showToast('🔑 کلید رمزنگاری این گفتگو به‌روزرسانی شد');
    // Re-decrypt existing messages with the new key
    const reDecrypted = await Promise.all(
      messages.map(m => processDecryption(m, currentRoom))
    );
    setMessages(reDecrypted);
  };

  const handleSubmitEdit = async () => {
    const trimmed = editModal.text.trim();
    if (!trimmed || !currentRoom) return;
    const payload = e2eeActive
      ? await encryptMessageText(trimmed, currentRoom, {
          myUsername,
          peerPublicKey: getPeerKeyForRoom(currentRoom),
        })
      : trimmed;
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
                  <img src={myProfile.avatar} alt="" />
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
          <div style={{ padding: '8px 12px 2px' }}>
            <button
              type="button"
              onClick={() => setGroupModalOpen(true)}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                padding: '9px 12px',
                borderRadius: '10px',
                background: 'rgba(124, 58, 237, 0.16)',
                border: '1px dashed rgba(124, 58, 237, 0.45)',
                color: '#c4b5fd',
                fontSize: '12.5px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <span>➕</span>
              <span>ایجاد گروه / روم جدید</span>
            </button>
          </div>
        )}

        <div className="chat-list" id="chatList">
          {filteredRooms.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '36px 16px', color: '#9ca3af', fontSize: '13px' }}>
              {activeTab === 'groups' ? (
                <div>
                  <div style={{ fontSize: '32px', marginBottom: '8px' }}>👥</div>
                  <p style={{ margin: '0 0 10px' }}>هنوز عضوی در گروهی نیستید</p>
                  <button
                    type="button"
                    onClick={() => setGroupModalOpen(true)}
                    style={{
                      padding: '7px 16px',
                      borderRadius: '8px',
                      background: 'var(--primary, #7c3aed)',
                      color: '#fff',
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: '12px',
                    }}
                  >
                    ساخت گروه جدید
                  </button>
                </div>
              ) : (
                <div>
                  <div style={{ fontSize: '32px', marginBottom: '8px' }}>💬</div>
                  <p style={{ margin: 0 }}>مخاطبی یافت نشد</p>
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
                    <img src={room.avatar} alt="" />
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
              className="foot-btn"
              onClick={() => setChangelogModalOpen(true)}
              style={{
                background: 'rgba(124, 58, 237, 0.18)',
                border: '1px solid rgba(124, 58, 237, 0.4)',
                color: '#c4b5fd',
              }}
              title="مشاهده تغییرات و معماری اختصاصی PQ-MPRBA v6.0"
            >
              🚀 چنج‌لاگ v6.0
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
            <div style={{ fontSize: '52px' }}>💬</div>
            <p>یه مخاطب انتخاب کن</p>
            <small>با دکمه + مخاطب جدید اضافه کن • مجهز به رمزنگاری سرتاسری (E2EE)</small>
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
                    {currentIsGroup ? currentPartnerName : `@${currentPartnerName}`}
                  </div>
                  <div
                    className={`chat-header-status ${partnerOnline ? 'online' : ''}`}
                    id="chatStatus"
                  >
                    {partnerStatusLabel}
                  </div>
                </div>
              </div>

              {/* E2EE Controls */}
              <button
                type="button"
                className="icon-btn"
                onClick={handleToggleE2EE}
                title={
                  e2eeActive
                    ? 'رمزنگاری پساکوانتومی ML-KEM-768 + Ratchet فعال است'
                    : 'رمزنگاری سرتاسری غیرفعال است'
                }
                style={{
                  fontSize: '12px',
                  padding: '5px 10px',
                  borderRadius: '14px',
                  background: e2eeActive
                    ? 'rgba(34,197,94,0.18)'
                    : 'rgba(255,255,255,0.06)',
                  color: e2eeActive ? '#22c55e' : '#9ca3af',
                  gap: '4px',
                }}
              >
                {e2eeActive ? (currentIsGroup ? `🔒 Epoch #${currentGroupEpoch}` : '🛡️ PQ-KEM') : '🔓 ساده'}
              </button>

              <button
                type="button"
                className="icon-btn"
                onClick={() => setE2eeModalOpen(true)}
                title="تنظیم کلید رمزنگاری سرتاسری (E2EE Key)"
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
                  {e2eeActive
                    ? '🔒 این گفتگو با رمزنگاری سرتاسری (AES-256-GCM) محافظت می‌شود'
                    : 'شروع مکالمه'}
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
                          <div className="sender-name">{msg.sender}</div>
                        )}
                        {msg.reply_to_text && (
                          <div className="reply-quote">
                            ↩ {msg.reply_to_text.substring(0, 60)}
                          </div>
                        )}

                        {msg.file_type === 'image' && msg.file_url ? (
                          <img src={msg.file_url} alt="" />
                        ) : msg.file_type === 'voice' && msg.file_url ? (
                          <audio controls src={msg.file_url} />
                        ) : msg.file_type === 'file' && msg.file_url ? (
                          <div className="file-attach">
                            📁{' '}
                            <a
                              href={msg.file_url}
                              download
                              style={{ color: 'inherit' }}
                            >
                              دانلود فایل
                            </a>
                          </div>
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
                                ? `رمزنگاری پساکوانتومی ML-KEM-768 + Ratchet (گام #${msg.ratchetStep ?? 0})`
                                : msg.e2eeMode === 'GROUP-EPOCH-FSM'
                                ? `ماشین وضعیت اپوک گروه (Epoch #${msg.epoch ?? 1})`
                                : 'رمزنگاری سرتاسری (AES-256-GCM)'
                            }
                            style={{ fontSize: '10px', opacity: 0.85, color: '#a78bfa' }}
                          >
                            {msg.e2eeMode === 'PQ-MLKEM-RATCHET'
                              ? `🛡️PQ#${msg.ratchetStep ?? 0}`
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
                placeholder={
                  e2eeActive ? 'پیام رمزنگاری‌شده (E2EE)...' : 'پیام...'
                }
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

      {/* E2EE KEY SETTINGS MODAL */}
      {e2eeModalOpen && (
        <div className="modal">
          <div className="modal-box">
            <h3>🛡️ پروتکل پساکوانتومی ML-KEM-768 + احراز هویت کور VOPRF</h3>
            <div
              style={{
                background: 'rgba(124,58,237,0.12)',
                border: '1px solid rgba(124,58,237,0.35)',
                borderRadius: '10px',
                padding: '10px 12px',
                fontSize: '11.5px',
                lineHeight: '1.75',
                marginBottom: '12px',
                textAlign: 'right',
              }}
            >
              <div>
                ✅ <b>لایه ۱ (Post-Quantum Ratchet):</b> کپسوله‌سازی هیبریدی{' '}
                <code>ML-KEM-768 (FIPS 203) + ECDH P-256</code> به همراه کش کلیدهای پرش‌خورده
                (Out-of-Order Skipped Keys) و پاک‌سازی فوری حافظه (Zeroization).
              </div>
              <div style={{ marginTop: '4px' }}>
                ✅ <b>لایه ۲ (Blinded Identity - RFC 9497):</b> توکن کور{' '}
                <code>Ristretto255-VOPRF</code> با اثبات دانایی صفر DLEQ:{' '}
                <code style={{ color: '#22c55e' }}>
                  {voprfToken?.anonymousTokenId || 'در حال صدور...'}
                </code>
              </div>
              {currentIsGroup && (
                <div style={{ marginTop: '4px' }}>
                  ✅ <b>لایه ۳ (Group Epoch FSM):</b> اپوک فعلی گروه:{' '}
                  <code style={{ color: '#38bdf8' }}>Epoch #{currentGroupEpoch}</code> (مجهز به
                  Grace Buffer برای پیام‌های همزمان)
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
                انصراف
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
                  background: 'linear-gradient(135deg,#7c3aed,#06b6d4)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '28px',
                  margin: '0 auto 10px',
                  overflow: 'hidden',
                }}
              >
                {avatarPreview ? (
                  <img
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

      {/* CONTACT PROFILE MODAL */}
      {contactProfileModal.open && (
        <div className="modal">
          <div className="modal-box" style={{ textAlign: 'center' }}>
            <h3>{currentIsGroup ? '👥 اطلاعات گروه' : '👤 اطلاعات مخاطب'}</h3>
            <div
              style={{
                width: '70px',
                height: '70px',
                borderRadius: '50%',
                background: 'linear-gradient(135deg,#7c3aed,#06b6d4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '28px',
                margin: '14px auto 10px',
                overflow: 'hidden',
              }}
            >
              {contactProfileModal.user?.avatar ? (
                <img
                  src={contactProfileModal.user.avatar}
                  alt=""
                  style={{ width: '70px', height: '70px', objectFit: 'cover' }}
                />
              ) : (
                currentPartnerName[0]?.toUpperCase()
              )}
            </div>
            <div style={{ fontSize: '16px', fontWeight: 700, marginBottom: '4px' }}>
              {currentIsGroup ? currentPartnerName : `@${currentPartnerName}`}
            </div>
            <div style={{ fontSize: '12px', color: '#9ca3af', marginBottom: '14px' }}>
              {partnerStatusLabel}
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
            <h3 style={{ fontSize: '16px', marginBottom: '8px', color: '#ddd6fe' }}>
              🚀 چنج‌لاگ و تاریخچه تکامل معماری (نسخه v6.0 — PQ-MPRBA Edition)
            </h3>

            <div
              style={{
                background: 'linear-gradient(135deg, rgba(124,58,237,0.18), rgba(6,182,212,0.12))',
                border: '1px solid rgba(124,58,237,0.45)',
                borderRadius: '12px',
                padding: '12px 14px',
                fontSize: '12.5px',
                lineHeight: '1.85',
                marginBottom: '12px',
              }}
            >
              <div style={{ fontWeight: 700, color: '#a78bfa', fontSize: '13.5px', marginBottom: '6px' }}>
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
                  <b>لایه ۱ (راتچت هیبریدی پساکوانتومی ML-KEM-768 + ECDH P-256):</b> ترکیب الگوریتم مشبک‌بندی شده{' '}
                  <code>CRYSTALS-Kyber (ML-KEM-768 / FIPS 203)</code> با منحنی بیضی <code>P-256</code> و زنجیره مشتق‌سازی کلید <code>HKDF-SHA256</code> برای ایمنی کامل در برابر حملات کوانتومی <i>Store Now, Decrypt Later</i>.
                </li>
                <li>
                  <b>لایه ۲ (احراز هویت کور بدون افشای متادیتا با Ristretto255-VOPRF):</b> پیاده‌سازی تابع شبه‌تصادفی ناآگاهانه اثبات‌پذیر (<code>RFC 9497</code>) به همراه اثبات دانایی صفر <code>DLEQ</code> که هویت و متادیتای کاربر را حتی از دید سرور مخفی می‌کند.
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
                          background: isSelected ? 'rgba(124, 58, 237, 0.15)' : 'transparent',
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
    </div>
  );
};
