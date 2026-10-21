import React, { useState, useEffect, useCallback, Suspense } from 'react';
import { io, Socket } from 'socket.io-client';
import { AuthScreen } from './components/AuthScreen';
import { BlockedInfo } from './types';

const ChatApp = React.lazy(() =>
  import('./components/ChatApp').then(m => ({ default: m.ChatApp }))
);

const SESSION_KEY = 'chat_session_user';
const socketInstance: Socket = io({ transports: ['websocket'] });

function hasStoredSessionCandidate(): boolean {
  try {
    if (typeof window !== 'undefined' && window.location.pathname === '/terms') {
      return false;
    }
    return Boolean(
      sessionStorage.getItem('adminLoginToken') || localStorage.getItem(SESSION_KEY)
    );
  } catch {
    return false;
  }
}

export const App: React.FC = () => {
  const isTermsRoute =
    typeof window !== 'undefined' && window.location.pathname === '/terms';
  const [initializing, setInitializing] = useState<boolean>(() => hasStoredSessionCandidate());
  const [username, setUsername] = useState<string>('');
  const [maintenance, setMaintenance] = useState<{ active: boolean; msg: string }>({
    active: false,
    msg: '',
  });
  const [blocked, setBlocked] = useState<BlockedInfo | null>(null);
  const [announcement, setAnnouncement] = useState<{
    text: string;
    imageUrl?: string;
  } | null>(null);
  const [toasts, setToasts] = useState<{ id: number; text: string }[]>([]);

  const showToast = useCallback((text: string) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, text }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 2800);
  }, []);

  const handleAuthenticated = useCallback((user: string) => {
    try {
      localStorage.setItem(SESSION_KEY, user);
    } catch {
      // ignore
    }
    setUsername(user);
  }, []);

  const handleLogout = useCallback(() => {
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch {
      // ignore
    }
    setUsername('');
    window.location.reload();
  }, []);

  useEffect(() => {
    const onBlocked = (data: BlockedInfo) => setBlocked(data || {});
    const onKicked = () => {
      showToast('شما از سرور اخراج شدید!');
      handleLogout();
    };
    const onServerMaint = ({ msg }: { msg: string }) => {
      setMaintenance({
        active: true,
        msg: msg || 'سرور در حال به‌روزرسانی است. لطفاً بعداً مراجعه کنید.',
      });
    };
    const onServerNormal = () => {
      setMaintenance({ active: false, msg: '' });
    };
    const onAnnouncement = (data: { text: string; imageUrl?: string }) => {
      setAnnouncement(data);
    };

    socketInstance.on('blocked', onBlocked);
    socketInstance.on('kicked', onKicked);
    socketInstance.on('server-maintenance', onServerMaint);
    socketInstance.on('server-normal', onServerNormal);
    socketInstance.on('announcement', onAnnouncement);

    return () => {
      socketInstance.off('blocked', onBlocked);
      socketInstance.off('kicked', onKicked);
      socketInstance.off('server-maintenance', onServerMaint);
      socketInstance.off('server-normal', onServerNormal);
      socketInstance.off('announcement', onAnnouncement);
    };
  }, [handleLogout, showToast]);

  useEffect(() => {
    if (isTermsRoute) return;

    async function bootstrap() {
      // ۱. بررسی ورود موقت ادمین (Login As)
      try {
        const adminTokenUser = sessionStorage.getItem('adminLoginToken');
        if (adminTokenUser) {
          sessionStorage.removeItem('adminLoginToken');
          handleAuthenticated(adminTokenUser);
          setInitializing(false);
          return;
        }
      } catch {
        // ignore
      }

      // ۲. بررسی نشست ذخیره‌شده در LocalStorage
      try {
        const saved = localStorage.getItem(SESSION_KEY);
        if (saved) {
          try {
            const res = await fetch('/api/settings/mode', {
              headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'x-session-user': saved,
              },
            });
            if (res.status === 503) {
              const modeRes = await res.json().catch(() => ({}));
              setMaintenance({
                active: true,
                msg: modeRes.msg || 'سرور در حال به‌روزرسانی است.',
              });
              setInitializing(false);
              return;
            }
          } catch {
            // ignore
          }

          const check = await fetch('/api/user/' + encodeURIComponent(saved)).then(r =>
            r.json()
          );
          if (check.ok && check.user) {
            setUsername(saved);
            setInitializing(false);
            return;
          } else {
            localStorage.removeItem(SESSION_KEY);
          }
        }
      } catch {
        // ignore
      }

      setInitializing(false);
    }

    bootstrap();
  }, [handleAuthenticated, isTermsRoute]);

  const skipLink = (
    <a href="#main-content" className="skip-link">
      پرش به محتوای اصلی
    </a>
  );

  if (isTermsRoute) {
    return (
      <>
        {skipLink}
        <div className="terms-screen">
          <div className="terms-box">
            <header className="auth-logo">
              <div className="logo-circle" aria-hidden="true">📋</div>
              <h1>قوانین و مقررات پیام‌رسان</h1>
              <p>لطفاً پیش از استفاده از سامانه، موارد زیر را مطالعه فرمایید</p>
            </header>

            <main id="main-content" tabIndex={-1}>
              <ul className="terms-list">
                <li>
                  <strong>۱. احترام متقابل:</strong> رعایت ادب و احترام به سایر کاربران در تمامی گفتگوهای خصوصی و گروهی الزامی است و هرگونه توهین یا تهدید موجب مسدودیت حساب خواهد شد.
                </li>
                <li>
                  <strong>۲. ممنوعیت هرزنامه (اسپم):</strong> ارسال پیام‌های تبلیغاتی ناخواسته، پیام‌های تکراری خودکار و ایجاد مزاحمت برای کاربران ممنوع است.
                </li>
                <li>
                  <strong>۳. محتوای غیرقانونی و آسیب‌زا:</strong> انتشار هرگونه محتوای خلاف قوانین، بدافزار، فیشینگ، کلاهبرداری یا محتوای آسیب‌زا اکیداً ممنوع است.
                </li>
                <li>
                  <strong>۴. حفاظت از حساب کاربری:</strong> مسئولیت حفظ امنیت حساب بر عهده کاربر است. هرگز کد تأیید یک‌بارمصرف (OTP) دریافتی در بله یا کلیدهای امنیتی خود را در اختیار دیگران قرار ندهید.
                </li>
                <li>
                  <strong>۵. حریم خصوصی و رمزنگاری سرتاسری (E2EE):</strong> پیام‌های شما در این سامانه با رمزنگاری سرتاسری پساکوانتومی محافظت می‌شوند؛ به طوری که تنها فرستنده و گیرنده قادر به رمزگشایی و مطالعه محتوای پیام‌ها هستند.
                </li>
              </ul>

              <a href="/" className="terms-back-link">
                بازگشت به صفحه اصلی پیام‌رسان
              </a>
            </main>

            <footer className="auth-footer">
              <nav aria-label="پیوندهای پاصفحه" className="auth-footer-group">
                <span>🔒 رمزنگاری سرتاسری</span>
                <a href="/" className="link-btn">
                  صفحه ورود
                </a>
              </nav>
            </footer>
          </div>
        </div>
      </>
    );
  }

  if (blocked) {
    const untilText =
      blocked.block_type === 'permanent'
        ? 'مسدودیت دائمی'
        : blocked.block_until
        ? 'مسدودیت موقت تا ' + new Date(blocked.block_until).toLocaleDateString('fa-IR')
        : 'مسدودیت حساب';

    return (
      <>
        {skipLink}
        <main id="main-content" className="full-screen" tabIndex={-1}>
          <div className="maint-box">
            <div style={{ fontSize: '60px' }} aria-hidden="true">🚫</div>
            <h1>حساب مسدود شد</h1>
            <p>علت: {blocked.block_reason || 'تخلف'}</p>
            <p>{untilText}</p>
          </div>
        </main>
      </>
    );
  }

  if (maintenance.active) {
    return (
      <>
        {skipLink}
        <main id="main-content" className="full-screen" tabIndex={-1}>
          <div className="maint-box">
            <div style={{ fontSize: '60px' }} aria-hidden="true">🔧</div>
            <h1>در حال به‌روزرسانی</h1>
            <p id="maintMsg">{maintenance.msg}</p>
          </div>
        </main>
      </>
    );
  }

  if (initializing) {
    return (
      <>
        {skipLink}
        <main id="main-content" className="auth-screen" tabIndex={-1} aria-busy="true" />
      </>
    );
  }

  return (
    <>
      {skipLink}
      {!username ? (
        <AuthScreen onAuthenticated={handleAuthenticated} />
      ) : (
        <Suspense fallback={<main id="main-content" className="auth-screen" tabIndex={-1} aria-busy="true" />}>
          <main id="main-content" tabIndex={-1}>
            <ChatApp
              myUsername={username}
              socket={socketInstance}
              onLogout={handleLogout}
              showToast={showToast}
            />
          </main>
        </Suspense>
      )}

      {announcement && (
        <div className="announce-overlay" id="announceOverlay">
          <div className="announce-box">
            <div className="announce-header">📢 اطلاع‌رسانی</div>
            {announcement.imageUrl && (
              <img
                id="announceImg"
                src={announcement.imageUrl}
                alt=""
                className="announce-img"
              />
            )}
            <p id="announceText">{announcement.text}</p>
            <button type="button" onClick={() => setAnnouncement(null)}>
              متوجه شدم
            </button>
          </div>
        </div>
      )}

      <div id="toastRoot">
        {toasts.map(t => (
          <div key={t.id} className="toast-msg">
            {t.text}
          </div>
        ))}
      </div>
    </>
  );
};
