import { state } from '../state.js';
import { socket } from '../socket.js';
import { showToast } from '../utils.js';
import { cancelReply } from './chat.js';

export async function uploadFile(input, type) {
  const file = input.files?.[0];
  if (!file || !state.currentPartner) return;
  document.getElementById('attachMenu')?.classList.add('hidden');

  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r => r.json());
  if (res.ok) {
    socket.emit('send-message', {
      to: state.currentPartner,
      text: '',
      fileUrl: res.fileUrl,
      fileType: res.fileType || type,
      isGroup: state.currentIsGroup,
      replyToId: state.replyTo?.id,
      replyToText: state.replyTo?.text,
      disappearAfter: state.disappearAfter || 0
    });
    cancelReply();
  } else {
    showToast(res.msg || 'خطا در آپلود فایل');
  }
}

export async function uploadAvatar(input) {
  const file = input.files?.[0];
  if (!file) return;
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r => r.json());
  if (res.ok) {
    const pAv = document.getElementById('profileAvatar');
    if (pAv) {
      pAv.innerHTML = `<img src="${res.fileUrl}" style="width:70px;height:70px;border-radius:50%;object-fit:cover"/>`;
      pAv.dataset.avatarUrl = res.fileUrl;
    }
    const myAv = document.getElementById('myAvatar');
    if (myAv) {
      myAv.innerHTML = `<img src="${res.fileUrl}" alt=""/>`;
    }
  }
}

export async function startVoice() {
  if (!state.currentPartner) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    state.mediaRecorder = new MediaRecorder(stream);
    state.audioChunks = [];
    state.mediaRecorder.ondataavailable = e => state.audioChunks.push(e.data);
    state.mediaRecorder.onstop = async () => {
      const blob = new Blob(state.audioChunks, { type: 'audio/webm' });
      const fd = new FormData();
      fd.append('file', blob, 'voice.webm');
      const res = await fetch('/api/upload', { method: 'POST', body: fd }).then(r => r.json());
      if (res.ok) {
        socket.emit('send-message', {
          to: state.currentPartner,
          text: '',
          fileUrl: res.fileUrl,
          fileType: 'voice',
          isGroup: state.currentIsGroup,
          disappearAfter: state.disappearAfter || 0
        });
      }
      stream.getTracks().forEach(t => t.stop());
    };
    state.mediaRecorder.start();
    document.getElementById('voiceBtn')?.classList.add('voice-recording');
  } catch (e) {
    showToast('دسترسی به میکروفون رد شد');
  }
}

export function stopVoice() {
  if (state.mediaRecorder && state.mediaRecorder.state !== 'inactive') {
    state.mediaRecorder.stop();
    document.getElementById('voiceBtn')?.classList.remove('voice-recording');
  }
}
