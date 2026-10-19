import { state, saveSession, clearSession } from '../state.js';
import { socket } from '../socket.js';
import { mountAppView } from '../components/AppView.js';
import { mountAuthView } from '../components/AuthView.js';
import { openRulesModal } from '../components/Modals.js';
import { loadContacts, loadGroups } from './contacts.js';

export function showStep(n) {
  document.querySelectorAll('.auth-box').forEach(e => e.classList.add('hidden'));
  document.getElementById('step' + n)?.classList.remove('hidden');
}

export function setMsg(id, text, isOk) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = text;
  el.className = 'auth-msg' + (isOk ? ' ok' : '');
}

export async function quickTestLogin(targetUser) {
  let username = targetUser;
  if (!username) {
    const inputVal = document.getElementById('baleIdInput')?.value.trim().replace('@', '');
    username = inputVal || 'کاربر_۱';
  }
  setMsg('msg1', 'در حال ورود سریع...', true);
  try {
    const res = await fetch('/api/quick-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    }).then(r => r.json());

    if (res.ok) {
      setMsg('msg1', '✅ با موفقیت وارد شدید!', true);
      setTimeout(() => enterApp(res.username), 200);
    } else {
      setMsg('msg1', res.msg || 'خطا در ورود تستی', false);
    }
  } catch (err) {
    setMsg('msg1', 'خطا در برقراری ارتباط با سرور', false);
  }
}

export async function sendOTP() {
  const baleId = document.getElementById('baleIdInput')?.value.trim().replace('@', '');
  if (!baleId) return;
  const res = await fetch('/api/send-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baleId })
  }).then(r => r.json());

  if (res.ok) {
    state.verifiedBaleId = baleId;
    if (res.needStart) {
      setMsg('msg1', '⚠️ ابتدا <a href="https://ble.ir/Optcodebot" target="_blank" style="color:#9d5cff">@Optcodebot</a> را در بله استارت کن', false);
    } else {
      setMsg('msg1', res.msg, true);
      if (res.msg && res.msg.includes('آزمایشی')) {
        const match = res.msg.match(/\d{6}/);
        if (match) {
          setTimeout(() => {
            const desc = document.getElementById('step2desc');
            if (desc) desc.textContent = res.msg;
            const otpInp = document.getElementById('otpInput');
            if (otpInp) otpInp.value = match[0];
          }, 400);
        }
      }
      setTimeout(() => { showStep(2); startResendTimer(); }, 800);
    }
  } else {
    setMsg('msg1', res.msg, false);
  }
}

export function startResendTimer() {
  let sec = 60;
  const resendBtn = document.getElementById('resendBtn');
  const resendTimer = document.getElementById('resendTimer');
  if (resendBtn) resendBtn.disabled = true;
  if (resendTimer) resendTimer.textContent = sec;
  clearInterval(state.resendInterval);
  state.resendInterval = setInterval(() => {
    sec--;
    const tEl = document.getElementById('resendTimer');
    if (tEl) tEl.textContent = sec;
    if (sec <= 0) {
      clearInterval(state.resendInterval);
      const bEl = document.getElementById('resendBtn');
      if (bEl) {
        bEl.disabled = false;
        bEl.textContent = 'ارسال مجدد کد';
      }
    }
  }, 1000);
}

export async function resendOTP() {
  await sendOTP();
  startResendTimer();
}

export async function verifyOTP() {
  const code = document.getElementById('otpInput')?.value.trim() || '';
  if (code.length !== 6) {
    setMsg('msg2', 'کد ۶ رقمی وارد کن', false);
    return;
  }
  const res = await fetch('/api/verify-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baleId: state.verifiedBaleId, code })
  }).then(r => r.json());

  if (!res.ok) {
    setMsg('msg2', res.msg, false);
    return;
  }

  if (!res.isNew) {
    setMsg('msg2', '✅ خوش آمدی!', true);
    setTimeout(() => enterApp(res.username), 500);
  } else {
    const preview = document.getElementById('idPreview');
    if (preview) preview.textContent = '@' + state.verifiedBaleId;
    showStep(3);
  }
}

export function toggleRegBtn() {
  const btn = document.getElementById('regBtn');
  const chk = document.getElementById('rulesCheck');
  if (!btn || !chk) return;
  btn.disabled = !chk.checked;
  btn.classList.toggle('btn-disabled', btn.disabled);
}

export async function register() {
  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baleId: state.verifiedBaleId })
  }).then(r => r.json());
  if (res.ok) {
    setMsg('msg3', '✅ حساب ساخته شد!', true);
    setTimeout(() => enterApp(res.username), 500);
  } else {
    setMsg('msg3', res.msg, false);
  }
}

export async function showRules() {
  const res = await fetch('/api/settings/rules').then(r => r.json());
  openRulesModal(res.rules || 'قوانینی تنظیم نشده');
}

export async function enterApp(username) {
  state.myUsername = username;
  state.allRooms = [];
  saveSession(username);

  // رندر پویا: حذف کامل صفحه لاگین از DOM و ساختن محیط اصلی پیام‌رسان
  mountAppView(username);

  socket.emit('auth', username);
  loadContacts();
  loadGroups();

  // دریافت آواتار و وضعیت کاربر
  try {
    const userRes = await fetch('/api/user/' + username).then(r => r.json());
    if (userRes.ok && userRes.user) {
      if (userRes.user.avatar) {
        const av = document.getElementById('myAvatar');
        if (av) av.innerHTML = `<img src="${userRes.user.avatar}" alt=""/>`;
      }
      const stLabel = document.getElementById('myStatusLabel');
      if (stLabel && userRes.user.status) {
        stLabel.textContent = userRes.user.status === 'online' ? 'آنلاین' : userRes.user.status === 'busy' ? 'مشغول' : 'غایب';
      }
    }
  } catch (e) {
    // ignore
  }
}

export function logout() {
  clearSession();
  state.myUsername = '';
  state.currentRoom = null;
  state.currentPartner = null;
  state.allRooms = [];
  mountAuthView();
  location.reload();
}
