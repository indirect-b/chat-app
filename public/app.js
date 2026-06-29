const socket = io();
let myUsername = '';
let currentRoom = null;
let currentPartner = null;
let currentIsGroup = false;
let replyTo = null;
let typingTimer = null;
let isTyping = false;
let isMobile = window.innerWidth <= 700;
let verifiedBaleId = '';
let disappearAfter = 0;
let ctxMsgId = null;
let ctxRoomId = null;
let ctxMsgText = '';
let ctxMsgSender = '';
let mediaRecorder = null;
let audioChunks = [];
let resendInterval = null;
let allRooms = [];

// ===== INIT =====
window.onload = async () => {
  const modeRes = await fetch('/api/settings/mode').then(r => r.json());
  if (modeRes.mode === 'maintenance') {
    document.getElementById('maintenanceScreen').classList.remove('hidden');
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('maintMsg').textContent = modeRes.msg;
    return;
  }

  // بررسی ورود موقت ادمین (Login As)
  const adminLoginUser = sessionStorage.getItem('adminLoginToken');
  if (adminLoginUser) {
    sessionStorage.removeItem('adminLoginToken');
    document.getElementById('authScreen').classList.remove('hidden');
    enterApp(adminLoginUser);
    return;
  }

  // geoip-lite حذف شد - مستقیم وارد صفحه ورود میشیم
  document.getElementById('authScreen').classList.remove('hidden');
};

// ===== AUTH =====
function showStep(n) {
  document.querySelectorAll('.auth-box').forEach(e => e.classList.add('hidden'));
  document.getElementById('step' + n).classList.remove('hidden');
}

function setMsg(id, text, isOk) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'auth-msg' + (isOk ? ' ok' : '');
}

async function sendOTP() {
  const baleId = document.getElementById('baleIdInput').value.trim().replace('@', '');
  if (!baleId) return;
  const res = await fetch('/api/send-otp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baleId })
  }).then(r => r.json());

  if (res.ok) {
    verifiedBaleId = baleId;
    if (res.needStart) {
      setMsg('msg1', '⚠️ ابتدا به ربات بله /start بزن', false);
    } else {
      setMsg('msg1', res.msg, true);
      setTimeout(() => { showStep(2); startResendTimer(); }, 800);
    }
  } else setMsg('msg1', res.msg, false);
}

function startResendTimer() {
  let sec = 60;
  document.getElementById('resendBtn').disabled = true;
  document.getElementById('resendTimer').textContent = sec;
  resendInterval = setInterval(() => {
    sec--;
    document.getElementById('resendTimer').textContent = sec;
    if (sec <= 0) {
      clearInterval(resendInterval);
      document.getElementById('resendBtn').disabled = false;
      document.getElementById('resendBtn').textContent = 'ارسال مجدد کد';
    }
  }, 1000);
}

async function resendOTP() {
  await sendOTP();
  startResendTimer();
}

async function verifyOTP() {
  const code = document.getElementById('otpInput').value.trim();
  if (code.length !== 6) { setMsg('msg2', 'کد ۶ رقمی وارد کن', false); return; }
  const res = await fetch('/api/verify-otp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baleId: verifiedBaleId, code })
  }).then(r => r.json());

  if (!res.ok) { setMsg('msg2', res.msg, false); return; }

  if (!res.isNew) {
    setMsg('msg2', '✅ خوش آمدی!', true);
    setTimeout(() => enterApp(res.username), 600);
  } else {
    document.getElementById('idPreview').textContent = '@' + verifiedBaleId;
    const rulesRes = await fetch('/api/settings/rules').then(r => r.json());
    document.getElementById('rulesText').textContent = rulesRes.rules || 'قوانینی تنظیم نشده';
    showStep(3);
  }
}

function toggleRegBtn() {
  const btn = document.getElementById('regBtn');
  btn.disabled = !document.getElementById('rulesCheck').checked;
  btn.classList.toggle('btn-disabled', btn.disabled);
}

async function register() {
  const res = await fetch('/api/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baleId: verifiedBaleId })
  }).then(r => r.json());
  if (res.ok) { setMsg('msg3', '✅ حساب ساخته شد!', true); setTimeout(() => enterApp(res.username), 600); }
  else setMsg('msg3', res.msg, false);
}

async function showRules() {
  const res = await fetch('/api/settings/rules').then(r => r.json());
  document.getElementById('rulesText').textContent = res.rules || 'قوانینی تنظیم نشده';
  document.getElementById('rulesModal').classList.remove('hidden');
}

function enterApp(username) {
  myUsername = username;
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  document.getElementById('myAvatar').textContent = username[0].toUpperCase();
  document.getElementById('myName').textContent = '@' + username;
  document.getElementById('myIdDisplay').textContent = username;
  socket.emit('auth', username);
  loadContacts();
  loadGroups();
}

// ===== CONTACTS =====
async function loadContacts() {
  const res = await fetch('/api/contacts/' + myUsername).then(r => r.json());
  if (!res.ok) return;
  res.contacts.forEach(c => addChatItem(c.username, false, false, null, c.avatar));
}

async function loadGroups() {
  const res = await fetch('/api/groups/' + myUsername).then(r => r.json());
  if (!res.ok) return;
  res.groups.forEach(g => addChatItem(g.name, false, true, g.id));
}

function addChatItem(name, online, isGroup, groupId, avatar) {
  const id = isGroup ? groupId : name;
  if (document.getElementById('ci-' + id)) return;
  allRooms.push({ id, name, isGroup });
  const div = document.createElement('div');
  div.className = 'chat-item';
  div.id = 'ci-' + id;
  const avatarHtml = avatar
    ? `<img src="${avatar}" alt=""/>`
    : name[0].toUpperCase();
  div.innerHTML = `
    <div class="ci-avatar ${online ? 'online' : ''}" id="av-${id}">${avatarHtml}</div>
    <div class="ci-info">
      <div class="ci-top">
        <span class="ci-name">${name}${isGroup ? '<span class="group-tag">گروه</span>' : ''}</span>
        <span class="ci-time" id="ct-${id}"></span>
      </div>
      <div class="ci-preview" id="cp-${id}">${isGroup ? 'گروه' : (online ? 'آنلاین' : 'آفلاین')}</div>
    </div>`;
  div.onclick = () => openChat(id, name, isGroup);
  document.getElementById('chatList').appendChild(div);
}

function showAddContact() {
  document.getElementById('contactModal').classList.remove('hidden');
  document.getElementById('contactInput').focus();
}

async function addContact() {
  const val = document.getElementById('contactInput').value.trim().replace('@', '');
  if (!val) return;
  const res = await fetch('/api/add-contact', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ myUsername, contactUsername: val })
  }).then(r => r.json());
  const msg = document.getElementById('contactMsg');
  if (res.ok) {
    msg.style.color = '#22c55e'; msg.textContent = '✅ مخاطب اضافه شد';
    addChatItem(val, false, false);
    document.getElementById('contactInput').value = '';
    setTimeout(() => closeModal('contactModal'), 800);
  } else { msg.style.color = '#ef4444'; msg.textContent = res.msg; }
}

// ===== OPEN CHAT =====
async function openChat(id, name, isGroup) {
  currentPartner = id;
  currentIsGroup = isGroup;
  currentRoom = isGroup ? 'group__' + id : [myUsername, id].sort().join('__');
  replyTo = null; cancelReply();
  document.getElementById('emptyState').classList.add('hidden');
  document.getElementById('chatView').classList.remove('hidden');
  document.getElementById('chatAvatar').textContent = name[0].toUpperCase();
  document.getElementById('chatName').textContent = (isGroup ? '' : '@') + name;
  document.getElementById('chatStatus').textContent = 'آفلاین';
  document.getElementById('chatStatus').className = 'chat-header-status';
  document.querySelectorAll('.chat-item').forEach(e => e.classList.remove('active'));
  document.getElementById('ci-' + id)?.classList.add('active');
  if (isMobile) { document.getElementById('chatArea').classList.add('mob'); document.getElementById('sidebar').classList.add('mob'); }

  const res = await fetch('/api/messages/' + currentRoom).then(r => r.json());
  const c = document.getElementById('messagesContainer');
  c.innerHTML = '';
  if (!res.messages.length) c.innerHTML = '<div class="sys-msg">🔒 شروع مکالمه</div>';
  else { res.messages.forEach(renderMsg); scrollBottom(); }

  // pinned
  const pinned = res.messages.find(m => m.is_pinned);
  if (pinned) showPinnedBar(pinned);

  document.getElementById('messageInput').focus();
}

function goBack() {
  if (isMobile) { document.getElementById('chatArea').classList.remove('mob'); document.getElementById('sidebar').classList.remove('mob'); }
}

// ===== RENDER MESSAGE =====
function renderMsg(msg) {
  if (msg.is_deleted) return;
  const c = document.getElementById('messagesContainer');
  const isOut = msg.sender === myUsername;
  const w = document.createElement('div');
  w.className = 'msg-wrap ' + (isOut ? 'out' : 'in');
  w.dataset.id = msg.id;
  w.dataset.text = msg.text || '';
  w.dataset.sender = msg.sender;

  const replyHtml = msg.reply_to_text ? `<div class="reply-quote">↩ ${esc(msg.reply_to_text.substring(0, 60))}</div>` : '';
  const senderHtml = currentIsGroup && !isOut ? `<div class="sender-name">${msg.sender}</div>` : '';
  const ticks = isOut ? `<span class="msg-ticks ${msg.read ? 'read' : ''}">✓✓</span>` : '';
  const editedTag = msg.is_edited ? '<span class="edited-tag">(ویرایش شده)</span>' : '';

  let contentHtml = '';
  if (msg.file_type === 'image' && msg.file_url) {
    contentHtml = `<img src="${msg.file_url}" onclick="window.open('${msg.file_url}')"/>`;
  } else if (msg.file_type === 'voice' && msg.file_url) {
    contentHtml = `<audio controls src="${msg.file_url}"></audio>`;
  } else if (msg.file_type === 'file' && msg.file_url) {
    contentHtml = `<div class="file-attach">📁 <a href="${msg.file_url}" download style="color:inherit">دانلود فایل</a></div>`;
  } else {
    contentHtml = esc(msg.text || '');
  }

  const reactionsHtml = renderReactions(msg.reactions || {}, msg.id);

  w.innerHTML = `
    <div class="bubble" oncontextmenu="showCtx(event,'${msg.id}','${esc(msg.text || '')}','${msg.sender}')">
      ${senderHtml}${replyHtml}${contentHtml}${editedTag}
    </div>
    ${reactionsHtml}
    <div class="msg-meta"><span class="msg-time">${msg.time}</span>${ticks}</div>`;

  c.appendChild(w);
}

function renderReactions(reactions, msgId) {
  if (!reactions || !Object.keys(reactions).length) return '';
  const pills = Object.entries(reactions).map(([emoji, users]) => {
    const isMine = users.includes(myUsername);
    return `<span class="reaction-pill ${isMine ? 'mine' : ''}" onclick="react('${msgId}','${emoji}')">${emoji} ${users.length}</span>`;
  }).join('');
  return `<div class="reactions-bar" id="reactions-${msgId}">${pills}</div>`;
}

function showPinnedBar(msg) {
  document.getElementById('pinnedBar').classList.remove('hidden');
  document.getElementById('pinnedText').textContent = (msg.text || '').substring(0, 50);
}

// ===== SEND MESSAGE =====
async function sendMessage() {
  const input = document.getElementById('messageInput');
  const text = input.value.trim();
  if (!text || !currentRoom) return;
  socket.emit('send-message', {
    to: currentPartner, text, isGroup: currentIsGroup,
    replyToId: replyTo?.id, replyToText: replyTo?.text,
    disappearAfter: disappearAfter || 0
  });
  input.value = '';
  input.focus();
  cancelReply();
  if (isTyping) { isTyping = false; socket.emit('typing', { to: currentPartner, isGroup: currentIsGroup, isTyping: false }); }
}

// ===== FILE UPLOAD =====
async function uploadFile(input, type) {
  const file = input.files[0];
  if (!file) return;
  document.getElementById('attachMenu').classList.add('hidden');
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r => r.json());
  if (res.ok) {
    socket.emit('send-message', {
      to: currentPartner, text: '', fileUrl: res.fileUrl, fileType: res.fileType,
      isGroup: currentIsGroup, replyToId: replyTo?.id, replyToText: replyTo?.text
    });
    cancelReply();
  }
}

async function uploadAvatar(input) {
  const file = input.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r => r.json());
  if (res.ok) {
    document.getElementById('profileAvatar').innerHTML = `<img src="${res.fileUrl}" style="width:70px;height:70px;border-radius:50%;object-fit:cover"/>`;
    document.getElementById('profileAvatar').dataset.avatarUrl = res.fileUrl;
    const av = document.getElementById('myAvatar');
    av.innerHTML = `<img src="${res.fileUrl}"/>`;
  }
}

// ===== VOICE =====
async function startVoice() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    audioChunks = [];
    mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
    mediaRecorder.onstop = async () => {
      const blob = new Blob(audioChunks, { type: 'audio/webm' });
      const fd = new FormData();
      fd.append('file', blob, 'voice.webm');
      const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r => r.json());
      if (res.ok) {
        socket.emit('send-message', { to: currentPartner, text: '', fileUrl: res.fileUrl, fileType: 'voice', isGroup: currentIsGroup });
      }
      stream.getTracks().forEach(t => t.stop());
    };
    mediaRecorder.start();
    document.getElementById('voiceBtn').classList.add('voice-recording');
  } catch (e) {
    alert('دسترسی به میکروفون رد شد');
  }
}

function stopVoice() {
  if (mediaRecorder && mediaRecorder.state !== 'inactive') {
    mediaRecorder.stop();
    document.getElementById('voiceBtn').classList.remove('voice-recording');
  }
}

// ===== CONTEXT MENU =====
function showCtx(e, msgId, text, sender) {
  e.preventDefault();
  ctxMsgId = msgId;
  ctxRoomId = currentRoom;
  ctxMsgText = text;
  ctxMsgSender = sender;
  const menu = document.getElementById('ctxMenu');
  menu.classList.remove('hidden');
  menu.style.top = Math.min(e.clientY, window.innerHeight - 250) + 'px';
  menu.style.right = (window.innerWidth - e.clientX) + 'px';

  // hide edit/delete if not mine
  const isOut = sender === myUsername;
  menu.querySelectorAll('.ctx-item')[1].style.display = isOut ? '' : 'none';
  menu.querySelectorAll('.ctx-item')[5].style.display = isOut ? '' : 'none';
}

document.addEventListener('click', e => {
  if (!e.target.closest('.ctx-menu')) document.getElementById('ctxMenu').classList.add('hidden');
  if (!e.target.closest('.attach-menu') && !e.target.closest('.icon-btn')) document.getElementById('attachMenu').classList.add('hidden');
});

function ctxReply() {
  replyTo = { id: ctxMsgId, text: ctxMsgText };
  document.getElementById('replyPreview').classList.remove('hidden');
  document.getElementById('replyText').textContent = ctxMsgText.substring(0, 60);
  document.getElementById('messageInput').focus();
  document.getElementById('ctxMenu').classList.add('hidden');
}

function ctxEdit() {
  document.getElementById('editInput').value = ctxMsgText;
  document.getElementById('editModal').classList.remove('hidden');
  document.getElementById('ctxMenu').classList.add('hidden');
}

function submitEdit() {
  const newText = document.getElementById('editInput').value.trim();
  if (!newText) return;
  socket.emit('edit-message', { msgId: ctxMsgId, newText, roomId: ctxRoomId });
  closeModal('editModal');
}

function ctxForward() {
  document.getElementById('ctxMenu').classList.add('hidden');
  const list = document.getElementById('forwardList');
  list.innerHTML = allRooms.filter(r => r.id !== currentPartner).map(r => `
    <div class="forward-item">
      <input type="checkbox" value="${r.isGroup ? 'group__' + r.id : [myUsername, r.id].sort().join('__')}" id="fw-${r.id}"/>
      <label for="fw-${r.id}">${r.name}</label>
    </div>`).join('');
  document.getElementById('forwardModal').classList.remove('hidden');
}

function submitForward() {
  const checked = [...document.querySelectorAll('#forwardList input:checked')].map(i => i.value);
  if (!checked.length) return;
  socket.emit('forward-message', { msgId: ctxMsgId, toRooms: checked });
  closeModal('forwardModal');
}

function ctxPin() {
  socket.emit('pin-message', { msgId: ctxMsgId, roomId: ctxRoomId });
  document.getElementById('ctxMenu').classList.add('hidden');
}

function ctxReport() {
  document.getElementById('ctxMenu').classList.add('hidden');
  document.getElementById('reportModal').classList.remove('hidden');
}

async function submitReport() {
  const reason = document.getElementById('reportReason').value;
  await fetch('/api/report', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reporter: myUsername, reportedUser: ctxMsgSender, messageId: ctxMsgId, messageText: ctxMsgText, reason })
  });
  closeModal('reportModal');
  alert('✅ گزارش ارسال شد');
}

function ctxDelete() {
  socket.emit('delete-message', { msgId: ctxMsgId, roomId: ctxRoomId });
  document.getElementById('ctxMenu').classList.add('hidden');
}

function react(msgId, emoji) {
  socket.emit('react', { msgId, roomId: currentRoom, emoji });
}

// ===== PROFILE =====
async function showProfile() {
  const res = await fetch('/api/user/' + myUsername).then(r => r.json());
  if (res.ok) {
    document.getElementById('bioInput').value = res.user.bio || '';
    document.getElementById('statusSelect').value = res.user.status || 'online';
    if (res.user.avatar) {
      document.getElementById('profileAvatar').innerHTML = `<img src="${res.user.avatar}" style="width:70px;height:70px;border-radius:50%;object-fit:cover"/>`;
      document.getElementById('profileAvatar').dataset.avatarUrl = res.user.avatar;
    } else {
      document.getElementById('profileAvatar').textContent = myUsername[0].toUpperCase();
    }
  }
  document.getElementById('profileModal').classList.remove('hidden');
}

async function saveProfile() {
  const bio = document.getElementById('bioInput').value;
  const status = document.getElementById('statusSelect').value;
  const avatar = document.getElementById('profileAvatar').dataset.avatarUrl || null;
  await fetch('/api/user/update', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: myUsername, bio, status, avatar })
  });
  socket.emit('update-status', status);
  document.getElementById('myStatusLabel').textContent = status === 'online' ? 'آنلاین' : status === 'busy' ? 'مشغول' : 'غایب';
  closeModal('profileModal');
}

// ===== DISAPPEAR =====
function showDisappear() {
  document.getElementById('attachMenu').classList.add('hidden');
  document.getElementById('disappearModal').classList.remove('hidden');
}

function setDisappear() {
  disappearAfter = parseInt(document.getElementById('disappearTime').value);
  closeModal('disappearModal');
  if (disappearAfter > 0) alert(`پیام‌های بعدی بعد از ${disappearAfter} ثانیه حذف میشن`);
}

// ===== ATTACH =====
function toggleAttach() {
  document.getElementById('attachMenu').classList.toggle('hidden');
}

// ===== TYPING =====
function handleTyping() {
  if (!currentPartner) return;
  if (!isTyping) { isTyping = true; socket.emit('typing', { to: currentPartner, isGroup: currentIsGroup, isTyping: true }); }
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => { isTyping = false; socket.emit('typing', { to: currentPartner, isGroup: currentIsGroup, isTyping: false }); }, 1500);
}

// ===== SOCKET EVENTS =====
socket.on('auth-ok', () => {});

socket.on('blocked', (data) => {
  document.getElementById('app').classList.add('hidden');
  document.getElementById('authScreen').classList.add('hidden');
  const screen = document.getElementById('maintenanceScreen');
  screen.classList.remove('hidden');
  screen.querySelector('div').innerHTML = `
    <div style="font-size:60px">🚫</div>
    <h1>حساب مسدود شد</h1>
    <p>علت: ${data.block_reason || 'تخلف'}</p>
    <p>${data.block_type === 'permanent' ? 'مسدودیت دائمی' : 'مسدودیت موقت تا ' + new Date(data.block_until).toLocaleDateString('fa-IR')}</p>`;
});

socket.on('new-message', ({ roomId, msg }) => {
  const partnerId = roomId.startsWith('group__') ? roomId.replace('group__', '') : roomId.split('__').find(u => u !== myUsername);
  const preview = document.getElementById('cp-' + partnerId);
  const time = document.getElementById('ct-' + partnerId);
  if (preview) preview.textContent = msg.text || (msg.file_type === 'image' ? '📷 عکس' : msg.file_type === 'voice' ? '🎤 ویس' : '📁 فایل');
  if (time) time.textContent = msg.time;
  if (roomId !== currentRoom) return;
  document.querySelector('.sys-msg')?.remove();
  renderMsg(msg);
  scrollBottom();
  if (msg.sender !== myUsername) socket.emit('read', { roomId, msgId: msg.id });
});

socket.on('read', ({ roomId, msgId }) => {
  if (roomId !== currentRoom) return;
  const t = document.querySelector('[data-id="' + msgId + '"] .msg-ticks');
  if (t) t.classList.add('read');
});

socket.on('msg-edited', ({ roomId, msgId, newText }) => {
  if (roomId !== currentRoom) return;
  const w = document.querySelector('[data-id="' + msgId + '"]');
  if (w) {
    const bubble = w.querySelector('.bubble');
    const replyHtml = bubble.querySelector('.reply-quote')?.outerHTML || '';
    const senderHtml = bubble.querySelector('.sender-name')?.outerHTML || '';
    bubble.innerHTML = senderHtml + replyHtml + esc(newText) + '<span class="edited-tag">(ویرایش شده)</span>';
    w.dataset.text = newText;
  }
});

socket.on('msg-deleted', ({ roomId, msgId }) => {
  if (roomId !== currentRoom) return;
  document.querySelector('[data-id="' + msgId + '"]')?.remove();
});

socket.on('msg-pinned', ({ roomId, msgId }) => {
  if (roomId !== currentRoom) return;
  const w = document.querySelector('[data-id="' + msgId + '"]');
  if (w) showPinnedBar({ text: w.dataset.text });
});

socket.on('msg-reaction', ({ roomId, msgId, reactions }) => {
  if (roomId !== currentRoom) return;
  const existing = document.getElementById('reactions-' + msgId);
  const html = renderReactions(reactions, msgId);
  if (existing) existing.outerHTML = html;
  else {
    const w = document.querySelector('[data-id="' + msgId + '"]');
    if (w) w.querySelector('.msg-meta').insertAdjacentHTML('beforebegin', html);
  }
});

socket.on('typing', ({ roomId, username, isTyping }) => {
  if (roomId !== currentRoom) return;
  const ind = document.getElementById('typingIndicator');
  if (isTyping) { document.getElementById('typingText').textContent = username + ' در حال تایپ'; ind.classList.remove('hidden'); scrollBottom(); }
  else ind.classList.add('hidden');
});

socket.on('contact-online', u => {
  document.getElementById('av-' + u)?.classList.add('online');
  const p = document.getElementById('cp-' + u);
  if (p && p.textContent === 'آفلاین') p.textContent = 'آنلاین';
  if (currentPartner === u) { document.getElementById('chatStatus').textContent = 'آنلاین'; document.getElementById('chatStatus').className = 'chat-header-status online'; document.getElementById('chatAvatar').classList.add('online'); }
});

socket.on('contact-offline', u => {
  document.getElementById('av-' + u)?.classList.remove('online');
  const p = document.getElementById('cp-' + u);
  if (p && p.textContent === 'آنلاین') p.textContent = 'آفلاین';
  if (currentPartner === u) { document.getElementById('chatStatus').textContent = 'آفلاین'; document.getElementById('chatStatus').className = 'chat-header-status'; document.getElementById('chatAvatar').classList.remove('online'); }
});

socket.on('contact-status', ({ username, status }) => {
  if (currentPartner === username) {
    const s = status === 'online' ? 'آنلاین' : status === 'busy' ? 'مشغول' : 'غایب';
    document.getElementById('chatStatus').textContent = s;
  }
});

socket.on('new-group', g => addChatItem(g.name, false, true, g.id));
socket.on('kicked', () => { alert('شما اخراج شدید!'); logout(); });
socket.on('server-maintenance', ({ msg }) => {
  document.getElementById('maintenanceScreen').classList.remove('hidden');
  document.getElementById('maintMsg').textContent = msg;
  document.getElementById('app').classList.add('hidden');
});
socket.on('server-normal', () => { document.getElementById('maintenanceScreen').classList.add('hidden'); document.getElementById('app').classList.remove('hidden'); });
socket.on('announcement', ({ text, imageUrl }) => {
  document.getElementById('announceText').textContent = text;
  const img = document.getElementById('announceImg');
  if (imageUrl) { img.src = imageUrl; img.classList.remove('hidden'); } else img.classList.add('hidden');
  document.getElementById('announceOverlay').classList.remove('hidden');
});

// ===== UTILS =====
function scrollBottom() { const c = document.getElementById('messagesContainer'); c.scrollTop = c.scrollHeight; }
function esc(t) { return (t || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
function cancelReply() { replyTo = null; document.getElementById('replyPreview').classList.add('hidden'); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }
function closeAnnounce() { document.getElementById('announceOverlay').classList.add('hidden'); }
function toggleSearch() { document.getElementById('searchBar').classList.toggle('hidden'); if (!document.getElementById('searchBar').classList.contains('hidden')) document.getElementById('searchInput').focus(); }
function searchContacts() { const q = document.getElementById('searchInput').value.toLowerCase(); document.querySelectorAll('.chat-item').forEach(el => { el.style.display = el.querySelector('.ci-name').textContent.toLowerCase().includes(q) ? '' : 'none'; }); }
function switchTab(tab, btn) { document.querySelectorAll('.tab-pill').forEach(b => b.classList.remove('active')); btn.classList.add('active'); document.getElementById('chatList').innerHTML = ''; allRooms = []; if (tab === 'chats') loadContacts(); else loadGroups(); }
function logout() { myUsername = ''; currentRoom = null; document.getElementById('app').classList.add('hidden'); document.getElementById('chatList').innerHTML = ''; document.getElementById('authScreen').classList.remove('hidden'); showStep(1); location.reload(); }
window.addEventListener('resize', () => { isMobile = window.innerWidth <= 700; });
