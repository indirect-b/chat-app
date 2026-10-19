const SESSION_KEY = 'chat_session_user';

export const state = {
  myUsername: '',
  currentRoom: null,
  currentPartner: null,
  currentIsGroup: false,
  replyTo: null,
  typingTimer: null,
  isTyping: false,
  isMobile: window.innerWidth <= 700,
  verifiedBaleId: '',
  disappearAfter: 0,
  ctxMsgId: null,
  ctxRoomId: null,
  ctxMsgText: '',
  ctxMsgSender: '',
  mediaRecorder: null,
  audioChunks: [],
  resendInterval: null,
  allRooms: [],
};

// مدیریت نشست محلی (Local Storage) به سبک تلگرام وب
export function saveSession(username) {
  try {
    localStorage.setItem(SESSION_KEY, username);
  } catch (e) {
    // ignore storage errors
  }
}

export function getSavedSession() {
  try {
    return localStorage.getItem(SESSION_KEY) || '';
  } catch (e) {
    return '';
  }
}

export function clearSession() {
  try {
    localStorage.removeItem(SESSION_KEY);
  } catch (e) {
    // ignore storage errors
  }
}

window.addEventListener('resize', () => {
  state.isMobile = window.innerWidth <= 700;
});
