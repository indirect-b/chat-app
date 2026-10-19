import { state } from '../state.js';
import { socket } from '../socket.js';
import { closeModal, showToast } from '../utils.js';
import { openProfileModal } from '../components/Modals.js';

export async function showProfile() {
  if (!state.myUsername) return;
  const res = await fetch('/api/user/' + state.myUsername).then(r => r.json());
  openProfileModal(res.ok ? res.user : null, state.myUsername);
}

export async function saveProfile() {
  const bio = document.getElementById('bioInput')?.value || '';
  const status = document.getElementById('statusSelect')?.value || 'online';
  const avatar = document.getElementById('profileAvatar')?.dataset.avatarUrl || null;

  await fetch('/api/user/update', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: state.myUsername, bio, status, avatar })
  });

  socket.emit('update-status', status);
  const label = document.getElementById('myStatusLabel');
  if (label) {
    label.textContent = status === 'online' ? 'آنلاین' : status === 'busy' ? 'مشغول' : 'غایب';
  }
  closeModal('profileModal');
  showToast('پروفایل ذخیره شد');
}
