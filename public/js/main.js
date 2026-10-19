import { getSavedSession, clearSession } from './state.js';
import { closeModal } from './utils.js';
import { initSocketListeners } from './socket.js';
import { mountAuthView } from './components/AuthView.js';
import { renderMaintenanceScreen } from './components/Modals.js';
import {
  showStep,
  quickTestLogin,
  sendOTP,
  resendOTP,
  verifyOTP,
  toggleRegBtn,
  register,
  showRules,
  enterApp,
  logout
} from './modules/auth.js';
import {
  showAddContact,
  addContact,
  showContactProfile,
  toggleSearch,
  searchContacts,
  switchTab
} from './modules/contacts.js';
import {
  openChat,
  goBack,
  sendMessage,
  showCtx,
  ctxReply,
  cancelReply,
  ctxEdit,
  submitEdit,
  ctxForward,
  submitForward,
  ctxPin,
  ctxReport,
  submitReport,
  ctxDelete,
  react,
  showDisappear,
  setDisappear,
  toggleAttach,
  handleTyping
} from './modules/chat.js';
import {
  uploadFile,
  uploadAvatar,
  startVoice,
  stopVoice
} from './modules/media.js';
import {
  showProfile,
  saveProfile
} from './modules/profile.js';

// اتصال توابع به window برای فراخوانی در رویدادهای رابط کاربری
Object.assign(window, {
  showStep,
  quickTestLogin,
  sendOTP,
  resendOTP,
  verifyOTP,
  toggleRegBtn,
  register,
  showRules,
  logout,
  showAddContact,
  addContact,
  showContactProfile,
  toggleSearch,
  searchContacts,
  switchTab,
  openChat,
  goBack,
  sendMessage,
  showCtx,
  ctxReply,
  cancelReply,
  ctxEdit,
  submitEdit,
  ctxForward,
  submitForward,
  ctxPin,
  ctxReport,
  submitReport,
  ctxDelete,
  react,
  showDisappear,
  setDisappear,
  toggleAttach,
  handleTyping,
  uploadFile,
  uploadAvatar,
  startVoice,
  stopVoice,
  showProfile,
  saveProfile,
  closeModal,
  closeAnnounce: () => closeModal('announceOverlay')
});

// بستن منوی راست‌کلیک و ضمیمه با کلیک بیرون
document.addEventListener('click', e => {
  if (!e.target.closest('.ctx-menu')) {
    document.getElementById('ctxMenu')?.classList.add('hidden');
  }
  if (!e.target.closest('.attach-menu') && !e.target.closest('.icon-btn')) {
    document.getElementById('attachMenu')?.classList.add('hidden');
  }
});

// راه‌اندازی شنونده‌های سوکت
initSocketListeners();

// راه‌اندازی اولیه اپلیکیشن (SPA Bootstrap)
async function bootstrap() {
  try {
    const modeRes = await fetch('/api/settings/mode').then(r => r.json());
    if (modeRes.mode === 'maintenance') {
      renderMaintenanceScreen(modeRes.msg);
      return;
    }
  } catch (e) {
    // ignore network error on startup
  }

  // ۱. بررسی ورود موقت ادمین (Login As)
  const adminLoginUser = sessionStorage.getItem('adminLoginToken');
  if (adminLoginUser) {
    sessionStorage.removeItem('adminLoginToken');
    await enterApp(adminLoginUser);
    return;
  }

  // ۲. بررسی نشست ذخیره‌شده در LocalStorage (مشابه تلگرام وب)
  const savedUser = getSavedSession();
  if (savedUser) {
    try {
      const check = await fetch('/api/user/' + encodeURIComponent(savedUser)).then(r => r.json());
      if (check.ok && check.user) {
        await enterApp(savedUser);
        return;
      } else {
        clearSession();
      }
    } catch (e) {
      // fallback to auth view
    }
  }

  // ۳. اگر کاربر لاگین نیست، فقط صفحه احراز هویت در DOM ساخته شود
  mountAuthView();
}

window.addEventListener('DOMContentLoaded', bootstrap);
