export function esc(t) {
  return (t || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function scrollBottom() {
  const c = document.getElementById('messagesContainer');
  if (c) c.scrollTop = c.scrollHeight;
}

export function showToast(message, duration = 2600) {
  const root = document.getElementById('toastRoot');
  if (!root) return;
  const el = document.createElement('div');
  el.className = 'toast-msg';
  el.textContent = message;
  root.appendChild(el);
  setTimeout(() => {
    el.remove();
  }, duration);
}

export function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.remove();
}
