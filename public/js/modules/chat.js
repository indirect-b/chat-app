import { state } from '../state.js';
import { socket } from '../socket.js';
import { esc, scrollBottom, closeModal, showToast } from '../utils.js';
import { openEditModal, openForwardModal, openReportModal, openDisappearModal } from '../components/Modals.js';

export async function openChat(id, name, isGroup) {
  state.currentPartner = id;
  state.currentIsGroup = isGroup;
  state.currentRoom = isGroup ? 'group__' + id : [state.myUsername, id].sort().join('__');
  state.replyTo = null;
  cancelReply();

  document.getElementById('emptyState')?.classList.add('hidden');
  document.getElementById('chatView')?.classList.remove('hidden');
  const avEl = document.getElementById('chatAvatar');
  if (avEl) avEl.textContent = name[0] ? name[0].toUpperCase() : '?';
  const nameEl = document.getElementById('chatName');
  if (nameEl) nameEl.textContent = (isGroup ? '' : '@') + name;
  const stEl = document.getElementById('chatStatus');
  if (stEl) {
    stEl.textContent = isGroup ? 'گروه' : 'آفلاین';
    stEl.className = 'chat-header-status';
  }

  document.querySelectorAll('.chat-item').forEach(e => e.classList.remove('active'));
  document.getElementById('ci-' + id)?.classList.add('active');

  if (state.isMobile) {
    document.getElementById('chatArea')?.classList.add('mob');
    document.getElementById('sidebar')?.classList.add('mob');
  }

  const res = await fetch('/api/messages/' + state.currentRoom).then(r => r.json());
  const c = document.getElementById('messagesContainer');
  if (!c) return;
  c.innerHTML = '';
  if (!res.messages.length) {
    c.innerHTML = '<div class="sys-msg">🔒 شروع مکالمه</div>';
  } else {
    res.messages.forEach(renderMsg);
    scrollBottom();
  }

  const pinned = res.messages.find(m => m.is_pinned);
  if (pinned) showPinnedBar(pinned);
  else document.getElementById('pinnedBar')?.classList.add('hidden');

  document.getElementById('messageInput')?.focus();
}

export function goBack() {
  if (state.isMobile) {
    document.getElementById('chatArea')?.classList.remove('mob');
    document.getElementById('sidebar')?.classList.remove('mob');
  }
}

export function renderMsg(msg) {
  if (msg.is_deleted) return;
  const c = document.getElementById('messagesContainer');
  if (!c) return;
  const isOut = msg.sender === state.myUsername;
  const w = document.createElement('div');
  w.className = 'msg-wrap ' + (isOut ? 'out' : 'in');
  w.dataset.id = msg.id;
  w.dataset.text = msg.text || '';
  w.dataset.sender = msg.sender;

  const replyHtml = msg.reply_to_text ? `<div class="reply-quote">↩ ${esc(msg.reply_to_text.substring(0, 60))}</div>` : '';
  const senderHtml = state.currentIsGroup && !isOut ? `<div class="sender-name">${esc(msg.sender)}</div>` : '';
  const ticks = isOut ? `<span class="msg-ticks ${msg.is_read || msg.read ? 'read' : ''}">✓✓</span>` : '';
  const editedTag = msg.is_edited ? '<span class="edited-tag">(ویرایش شده)</span>' : '';

  let contentHtml = '';
  if (msg.file_type === 'image' && msg.file_url) {
    contentHtml = `<img src="${esc(msg.file_url)}" alt=""/>`;
  } else if (msg.file_type === 'voice' && msg.file_url) {
    contentHtml = `<audio controls src="${esc(msg.file_url)}"></audio>`;
  } else if (msg.file_type === 'file' && msg.file_url) {
    contentHtml = `<div class="file-attach">📁 <a href="${esc(msg.file_url)}" download style="color:inherit">دانلود فایل</a></div>`;
  } else {
    contentHtml = esc(msg.text || '');
  }

  const reactionsHtml = renderReactions(msg.reactions || {}, msg.id);

  w.innerHTML = `
    <div class="bubble" oncontextmenu="showCtx(event,'${msg.id}','${esc(msg.text || '')}','${esc(msg.sender)}')">
      ${senderHtml}${replyHtml}${contentHtml}${editedTag}
    </div>
    ${reactionsHtml}
    <div class="msg-meta"><span class="msg-time">${esc(msg.time || '')}</span>${ticks}</div>`;

  c.appendChild(w);
}

export function renderReactions(reactions, msgId) {
  if (!reactions || !Object.keys(reactions).length) return '';
  const pills = Object.entries(reactions).map(([emoji, users]) => {
    const isMine = users.includes(state.myUsername);
    return `<span class="reaction-pill ${isMine ? 'mine' : ''}" onclick="react('${msgId}','${emoji}')">${emoji} ${users.length}</span>`;
  }).join('');
  return `<div class="reactions-bar" id="reactions-${msgId}">${pills}</div>`;
}

export function showPinnedBar(msg) {
  const bar = document.getElementById('pinnedBar');
  const txt = document.getElementById('pinnedText');
  if (bar && txt) {
    bar.classList.remove('hidden');
    txt.textContent = (msg.text || '').substring(0, 50);
  }
}

export async function sendMessage() {
  const input = document.getElementById('messageInput');
  const text = input?.value.trim() || '';
  if (!text || !state.currentRoom) return;

  socket.emit('send-message', {
    to: state.currentPartner,
    text,
    isGroup: state.currentIsGroup,
    replyToId: state.replyTo?.id,
    replyToText: state.replyTo?.text,
    disappearAfter: state.disappearAfter || 0
  });

  input.value = '';
  input.focus();
  cancelReply();
  if (state.isTyping) {
    state.isTyping = false;
    socket.emit('typing', { to: state.currentPartner, isGroup: state.currentIsGroup, isTyping: false });
  }
}

export function showCtx(e, msgId, text, sender) {
  e.preventDefault();
  state.ctxMsgId = msgId;
  state.ctxRoomId = state.currentRoom;
  state.ctxMsgText = text;
  state.ctxMsgSender = sender;

  const menu = document.getElementById('ctxMenu');
  if (!menu) return;
  menu.classList.remove('hidden');
  menu.style.top = Math.min(e.clientY, window.innerHeight - 250) + 'px';
  menu.style.right = (window.innerWidth - e.clientX) + 'px';

  const isOut = sender === state.myUsername;
  const items = menu.querySelectorAll('.ctx-item');
  if (items[1]) items[1].style.display = isOut ? '' : 'none';
  if (items[5]) items[5].style.display = isOut ? '' : 'none';
}

export function ctxReply() {
  state.replyTo = { id: state.ctxMsgId, text: state.ctxMsgText };
  document.getElementById('replyPreview')?.classList.remove('hidden');
  const rText = document.getElementById('replyText');
  if (rText) rText.textContent = state.ctxMsgText.substring(0, 60);
  document.getElementById('messageInput')?.focus();
  document.getElementById('ctxMenu')?.classList.add('hidden');
}

export function cancelReply() {
  state.replyTo = null;
  document.getElementById('replyPreview')?.classList.add('hidden');
}

export function ctxEdit() {
  document.getElementById('ctxMenu')?.classList.add('hidden');
  openEditModal(state.ctxMsgText);
}

export function submitEdit() {
  const newText = document.getElementById('editInput')?.value.trim() || '';
  if (!newText) return;
  socket.emit('edit-message', { msgId: state.ctxMsgId, newText, roomId: state.ctxRoomId });
  closeModal('editModal');
}

export function ctxForward() {
  document.getElementById('ctxMenu')?.classList.add('hidden');
  const itemsHtml = state.allRooms
    .filter(r => r.id !== state.currentPartner)
    .map(r => `
      <div class="forward-item">
        <input type="checkbox" value="${r.isGroup ? 'group__' + r.id : [state.myUsername, r.id].sort().join('__')}" id="fw-${r.id}"/>
        <label for="fw-${r.id}">${esc(r.name)}</label>
      </div>`)
    .join('');
  openForwardModal(itemsHtml);
}

export function submitForward() {
  const checked = [...document.querySelectorAll('#forwardList input:checked')].map(i => i.value);
  if (!checked.length) return;
  socket.emit('forward-message', { msgId: state.ctxMsgId, toRooms: checked });
  closeModal('forwardModal');
  showToast('پیام فوروارد شد');
}

export function ctxPin() {
  socket.emit('pin-message', { msgId: state.ctxMsgId, roomId: state.ctxRoomId });
  document.getElementById('ctxMenu')?.classList.add('hidden');
}

export function ctxReport() {
  document.getElementById('ctxMenu')?.classList.add('hidden');
  openReportModal();
}

export async function submitReport() {
  const reason = document.getElementById('reportReason')?.value || 'other';
  await fetch('/api/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      reporter: state.myUsername,
      reportedUser: state.ctxMsgSender,
      messageId: state.ctxMsgId,
      messageText: state.ctxMsgText,
      reason
    })
  });
  closeModal('reportModal');
  showToast('✅ گزارش ارسال شد');
}

export function ctxDelete() {
  socket.emit('delete-message', { msgId: state.ctxMsgId, roomId: state.ctxRoomId });
  document.getElementById('ctxMenu')?.classList.add('hidden');
}

export function react(msgId, emoji) {
  socket.emit('react', { msgId, roomId: state.currentRoom, emoji });
}

export function showDisappear() {
  document.getElementById('attachMenu')?.classList.add('hidden');
  openDisappearModal(state.disappearAfter);
}

export function setDisappear() {
  state.disappearAfter = parseInt(document.getElementById('disappearTime')?.value || '0');
  closeModal('disappearModal');
  if (state.disappearAfter > 0) {
    showToast(`⏱ پیام‌های بعدی بعد از ${state.disappearAfter} ثانیه حذف می‌شوند`);
  } else {
    showToast('⏱ پیام ناپدیدشونده غیرفعال شد');
  }
}

export function toggleAttach() {
  document.getElementById('attachMenu')?.classList.toggle('hidden');
}

export function handleTyping() {
  if (!state.currentPartner) return;
  if (!state.isTyping) {
    state.isTyping = true;
    socket.emit('typing', { to: state.currentPartner, isGroup: state.currentIsGroup, isTyping: true });
  }
  clearTimeout(state.typingTimer);
  state.typingTimer = setTimeout(() => {
    state.isTyping = false;
    socket.emit('typing', { to: state.currentPartner, isGroup: state.currentIsGroup, isTyping: false });
  }, 1500);
}
