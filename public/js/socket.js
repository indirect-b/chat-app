import { state } from './state.js';
import { esc, scrollBottom, showToast } from './utils.js';
import { renderMsg, renderReactions, showPinnedBar } from './modules/chat.js';
import { addChatItem } from './modules/contacts.js';
import { logout } from './modules/auth.js';
import { renderBlockedScreen, renderMaintenanceScreen, openAnnounceModal } from './components/Modals.js';
import { mountAppView } from './components/AppView.js';
import { loadContacts, loadGroups } from './modules/contacts.js';

export const socket = window.io();

export function initSocketListeners() {
  socket.on('auth-ok', () => {});

  socket.on('blocked', (data) => {
    renderBlockedScreen(data);
  });

  socket.on('new-message', ({ roomId, msg }) => {
    const partnerId = roomId.startsWith('group__')
      ? roomId.replace('group__', '')
      : roomId.split('__').find(u => u !== state.myUsername);

    const preview = document.getElementById('cp-' + partnerId);
    const time = document.getElementById('ct-' + partnerId);
    if (preview) {
      preview.textContent = msg.text || (msg.file_type === 'image' ? '📷 عکس' : msg.file_type === 'voice' ? '🎤 ویس' : '📁 فایل');
    }
    if (time) time.textContent = msg.time;
    if (roomId !== state.currentRoom) return;

    document.querySelector('.sys-msg')?.remove();
    renderMsg(msg);
    scrollBottom();
    if (msg.sender !== state.myUsername) {
      socket.emit('read', { roomId, msgId: msg.id });
    }
  });

  socket.on('read', ({ roomId, msgId }) => {
    if (roomId !== state.currentRoom) return;
    const t = document.querySelector('[data-id="' + msgId + '"] .msg-ticks');
    if (t) t.classList.add('read');
  });

  socket.on('msg-edited', ({ roomId, msgId, newText }) => {
    if (roomId !== state.currentRoom) return;
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
    if (roomId !== state.currentRoom) return;
    document.querySelector('[data-id="' + msgId + '"]')?.remove();
  });

  socket.on('msg-pinned', ({ roomId, msgId }) => {
    if (roomId !== state.currentRoom) return;
    const w = document.querySelector('[data-id="' + msgId + '"]');
    if (w) showPinnedBar({ text: w.dataset.text });
  });

  socket.on('msg-reaction', ({ roomId, msgId, reactions }) => {
    if (roomId !== state.currentRoom) return;
    const existing = document.getElementById('reactions-' + msgId);
    const html = renderReactions(reactions, msgId);
    if (existing) existing.outerHTML = html;
    else {
      const w = document.querySelector('[data-id="' + msgId + '"]');
      if (w) w.querySelector('.msg-meta')?.insertAdjacentHTML('beforebegin', html);
    }
  });

  socket.on('typing', ({ roomId, username, isTyping }) => {
    if (roomId !== state.currentRoom) return;
    const ind = document.getElementById('typingIndicator');
    if (!ind) return;
    if (isTyping) {
      document.getElementById('typingText').textContent = username + ' در حال تایپ';
      ind.classList.remove('hidden');
      scrollBottom();
    } else {
      ind.classList.add('hidden');
    }
  });

  socket.on('contact-online', u => {
    document.getElementById('av-' + u)?.classList.add('online');
    const p = document.getElementById('cp-' + u);
    if (p && p.textContent === 'آفلاین') p.textContent = 'آنلاین';
    if (state.currentPartner === u) {
      const st = document.getElementById('chatStatus');
      if (st) {
        st.textContent = 'آنلاین';
        st.className = 'chat-header-status online';
      }
      document.getElementById('chatAvatar')?.classList.add('online');
    }
  });

  socket.on('contact-offline', u => {
    document.getElementById('av-' + u)?.classList.remove('online');
    const p = document.getElementById('cp-' + u);
    if (p && p.textContent === 'آنلاین') p.textContent = 'آفلاین';
    if (state.currentPartner === u) {
      const st = document.getElementById('chatStatus');
      if (st) {
        st.textContent = 'آفلاین';
        st.className = 'chat-header-status';
      }
      document.getElementById('chatAvatar')?.classList.remove('online');
    }
  });

  socket.on('contact-status', ({ username, status }) => {
    if (state.currentPartner === username) {
      const s = status === 'online' ? 'آنلاین' : status === 'busy' ? 'مشغول' : 'غایب';
      const st = document.getElementById('chatStatus');
      if (st) st.textContent = s;
    }
  });

  socket.on('new-group', g => addChatItem(g.name, false, true, g.id));

  socket.on('kicked', () => {
    showToast('شما از سرور اخراج شدید!');
    logout();
  });

  socket.on('server-maintenance', ({ msg }) => {
    renderMaintenanceScreen(msg);
  });

  socket.on('server-normal', () => {
    if (state.myUsername) {
      mountAppView(state.myUsername);
      loadContacts();
      loadGroups();
    } else {
      location.reload();
    }
  });

  socket.on('announcement', ({ text, imageUrl }) => {
    openAnnounceModal(text, imageUrl);
  });
}
