import { state } from '../state.js';
import { closeModal } from '../utils.js';
import { openContactModal, openContactProfileModal } from '../components/Modals.js';
import { openChat } from './chat.js';

export async function loadContacts() {
  if (!state.myUsername) return;
  const res = await fetch('/api/contacts/' + state.myUsername).then(r => r.json());
  if (!res.ok) return;
  res.contacts.forEach(c => addChatItem(c.username, false, false, null, c.avatar));
}

export async function loadGroups() {
  if (!state.myUsername) return;
  const res = await fetch('/api/groups/' + state.myUsername).then(r => r.json());
  if (!res.ok) return;
  res.groups.forEach(g => addChatItem(g.name, false, true, g.id));
}

export function addChatItem(name, online, isGroup, groupId, avatar) {
  const id = isGroup ? groupId : name;
  if (document.getElementById('ci-' + id)) return;
  const chatList = document.getElementById('chatList');
  if (!chatList) return;

  state.allRooms.push({ id, name, isGroup });
  const div = document.createElement('div');
  div.className = 'chat-item';
  div.id = 'ci-' + id;
  const avatarHtml = avatar
    ? `<img src="${avatar}" alt=""/>`
    : (name[0] ? name[0].toUpperCase() : '?');

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
  chatList.appendChild(div);
}

export function showAddContact() {
  openContactModal();
}

export async function addContact() {
  const input = document.getElementById('contactInput');
  const val = input?.value.trim().replace('@', '') || '';
  if (!val) return;

  const res = await fetch('/api/add-contact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ myUsername: state.myUsername, contactUsername: val })
  }).then(r => r.json());

  const msg = document.getElementById('contactMsg');
  if (res.ok) {
    if (msg) {
      msg.style.color = '#22c55e';
      msg.textContent = '✅ مخاطب اضافه شد';
    }
    addChatItem(val, false, false);
    if (input) input.value = '';
    setTimeout(() => closeModal('contactModal'), 600);
  } else if (msg) {
    msg.style.color = '#ef4444';
    msg.textContent = res.msg;
  }
}

export async function showContactProfile() {
  if (!state.currentPartner) return;
  if (state.currentIsGroup) {
    const groupName = document.getElementById('chatName')?.textContent || state.currentPartner;
    openContactProfileModal(null, true, groupName);
    return;
  }
  const res = await fetch('/api/user/' + state.currentPartner).then(r => r.json());
  openContactProfileModal(res.ok ? res.user : null, false, state.currentPartner);
}

export function toggleSearch() {
  const bar = document.getElementById('searchBar');
  if (!bar) return;
  bar.classList.toggle('hidden');
  if (!bar.classList.contains('hidden')) {
    document.getElementById('searchInput')?.focus();
  }
}

export function searchContacts() {
  const q = (document.getElementById('searchInput')?.value || '').toLowerCase();
  document.querySelectorAll('.chat-item').forEach(el => {
    const nameText = el.querySelector('.ci-name')?.textContent.toLowerCase() || '';
    el.style.display = nameText.includes(q) ? '' : 'none';
  });
}

export function switchTab(tab, btn) {
  document.querySelectorAll('.tab-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const list = document.getElementById('chatList');
  if (list) list.innerHTML = '';
  state.allRooms = [];
  if (tab === 'chats') loadContacts();
  else loadGroups();
}
