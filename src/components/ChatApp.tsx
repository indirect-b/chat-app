import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Socket } from 'socket.io-client';
import { ChatMessage, RoomSummary, UserProfile } from '../types';
import {
  ensureUserECDHKeyPair,
  encryptMessageText,
  decryptMessageText,
  isE2EEEnabled,
  setE2EEEnabled,
  getRoomSecret,
  setRoomSecret,
  isE2EEPayload,
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

  // E2EE State
  const [e2eeActive, setE2eeActive] = useState<boolean>(isE2EEEnabled());
  const [e2eeModalOpen, setE2eeModalOpen] = useState(false);
  const [customSecretInput, setCustomSecretInput] = useState('');

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
      const dec = await decryptMessageText(msg.text || '', roomId, {
        myUsername,
        peerPublicKey,
      });
      let decReply = msg.reply_to_text;
      if (msg.reply_to_text && isE2EEPayload(msg.reply_to_text)) {
        const rDec = await decryptMessageText(msg.reply_to_text, roomId, {
          myUsername,
          peerPublicKey,
        });
        decReply = rDec.text;
      }
      return {
        ...msg,
        reply_to_text: decReply,
        decryptedText: dec.text,
        isE2EE: dec.isEncrypted,
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
          setRooms(
            res.groups.map((g: any) => ({
              id: g.id,
              name: g.name,
              isGroup: true,
              preview: 'گروه',
            }))
          );
        }
      }
    },
    [myUsername]
  );

  // Initial load + Automatic ECDH (P-256) Asymmetric Key Exchange
  useEffect(() => {
    socket.emit('auth', myUsername);
    loadRoomList('chats');

    ensureUserECDHKeyPair(myUsername).then(pubKey => {
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

    const onMsgDeleted = ({ roomId, msgId }: { roomId: string; msgId: string }) => {
      if (roomId !== currentRoomRef.current) return;
      setMessages(prev => prev.filter(m => m.id !== msgId));
    };

    const onMsgPinned = ({ roomId, msgId }: { roomId: string; msgId: string }) => {
      if (roomId !== currentRoomRef.current) return;
      setMessages(prev => {
        const found = prev.find(m => m.id === msgId) || null;
        if (found) setPinnedMessage(found);
        return prev.map(m => ({ ...m, is_pinned: m.id === msgId }));
      });
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

    const onNewGroup = (g: { id: string; name: string }) => {
      setRooms(prev => {
        if (prev.some(r => r.id === g.id)) return prev;
        return [...prev, { id: g.id, name: g.name, isGroup: true, preview: 'گروه' }];
      });
    };

    const onPeerKeyUpdated = ({ username, publicKey }: { username: string; publicKey: string }) => {
      peerPublicKeysRef.current[username] = publicKey;
    };

    socket.on('new-message', onNewMessage);
    socket.on('read', onRead);
    socket.on('msg-edited', onMsgEdited);
    socket.on('msg-deleted', onMsgDeleted);
    socket.on('msg-pinned', onMsgPinned);
    socket.on('msg-reaction', onMsgReaction);
    socket.on('typing', onTyping);
    socket.on('contact-online', onContactOnline);
    socket.on('contact-offline', onContactOffline);
    socket.on('contact-status', onContactStatus);
    socket.on('new-group', onNewGroup);
    socket.on('peer-key-updated', onPeerKeyUpdated);

    return () => {
      socket.off('new-message', onNewMessage);
      socket.off('read', onRead);
      socket.off('msg-edited', onMsgEdited);
      socket.off('msg-deleted', onMsgDeleted);
      socket.off('msg-pinned', onMsgPinned);
      socket.off('msg-reaction', onMsgReaction);
      socket.off('typing', onTyping);
      socket.off('contact-online', onContactOnline);
      socket.off('contact-offline', onContactOffline);
      socket.off('contact-status', onContactStatus);
      socket.off('new-group', onNewGroup);
      socket.off('peer-key-updated', onPeerKeyUpdated);
    };
  }, [myUsername, socket, processDecryption, scrollBottom, getPeerKeyForRoom]);

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
    setPartnerStatusLabel(room.isGroup ? 'گروه گفتگو' : room.online ? 'آنلاین' : 'آفلاین');
    setCustomSecretInput(getRoomSecret(roomId));
    if (isMobile) setMobileChatOpen(true);

    const res = await fetch('/api/messages/' + encodeURIComponent(roomId)).then(r =>
      r.json()
    );
    if (res.ok && Array.isArray(res.messages)) {
      const decryptedList = await Promise.all(
        res.messages.map((m: ChatMessage) => processDecryption(m, roomId))
      );
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

  const filteredRooms = rooms.filter(r =>
    r.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

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
              onClick={() => setContactModalOpen(true)}
              title="افزودن مخاطب"
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
                placeholder="جستجو..."
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

        <div className="chat-list" id="chatList">
          {filteredRooms.map(room => (
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
                    {room.name}
                    {room.isGroup && <span className="group-tag">گروه</span>}
                  </span>
                  <span className="ci-time">{room.time || ''}</span>
                </div>
                <div className="ci-preview">{room.preview || ''}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="sidebar-footer">
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
                    ? 'رمزنگاری سرتاسری فعال است (کلیک برای تغییر)'
                    : 'رمزنگاری سرتاسری غیرفعال است'
                }
                style={{
                  fontSize: '13px',
                  padding: '5px 10px',
                  borderRadius: '14px',
                  background: e2eeActive
                    ? 'rgba(34,197,94,0.18)'
                    : 'rgba(255,255,255,0.06)',
                  color: e2eeActive ? '#22c55e' : '#9ca3af',
                  gap: '4px',
                }}
              >
                {e2eeActive ? '🔒 E2EE' : '🔓 ساده'}
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
              <div className="pinned-bar" id="pinnedBar">
                📌{' '}
                <span id="pinnedText">
                  {(pinnedMessage.decryptedText || pinnedMessage.text || '').substring(
                    0,
                    50
                  )}
                </span>
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
                          <span>{displayText}</span>
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
                            title="رمزنگاری سرتاسری (AES-256-GCM)"
                            style={{ fontSize: '10px', opacity: 0.75 }}
                          >
                            🔒
                          </span>
                        )}
                        <span className="msg-time">{msg.time}</span>
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
                <label className="attach-item">
                  📷 عکس
                  <input
                    type="file"
                    accept="image/*"
                    onChange={e => handleUploadFile(e, 'image')}
                    hidden
                  />
                </label>
                <label className="attach-item">
                  📁 فایل
                  <input
                    type="file"
                    onChange={e => handleUploadFile(e, 'file')}
                    hidden
                  />
                </label>
                <div
                  className="attach-item"
                  onClick={() => {
                    setAttachOpen(false);
                    setDisappearModalOpen(true);
                  }}
                >
                  ⏱ پیام ناپدید
                </div>
              </div>
            )}
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
            <h3>🔐 رمزنگاری سرتاسری پیشرفته (ECDH + AES-256-GCM)</h3>
            <p style={{ fontSize: '12.5px', lineHeight: '1.7' }}>
              در گفتگوهای خصوصی، تبادل کلید به صورت کاملاً خودکار با پروتکل{' '}
              <b>Diffie-Hellman (ECDH P-256)</b> انجام می‌شود (بدون نیاز به رمز دستی). در صورت
              تمایل می‌توانید یک رمز مشترک سفارشی (PBKDF2 Override) نیز تنظیم کنید:
            </p>
            <input
              type="password"
              placeholder="کلید/رمز مشترک سفارشی (اختیاری - خالی = ECDH خودکار)..."
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
              <label style={{ fontSize: '12px', color: '#9ca3af', cursor: 'pointer' }}>
                📷 تغییر عکس پروفایل
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleUploadAvatar}
                  hidden
                />
              </label>
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
    </div>
  );
};
