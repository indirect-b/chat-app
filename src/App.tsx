import React, { useState, useEffect, useCallback, Suspense } from 'react';
import type { Socket } from 'socket.io-client';
import { BlockedInfo } from './types';

const AuthScreen = React.lazy(() =>
  import('./components/AuthScreen').then(m => ({ default: m.AuthScreen }))
);
const TermsScreen = React.lazy(() =>
  import('./components/TermsScreen').then(m => ({ default: m.TermsScreen }))
);
const ChatApp = React.lazy(() =>
  import('./components/ChatApp').then(m => ({ default: m.ChatApp }))
);

const SESSION_KEY = 'chat_session_user';

const ROUTE_META: Record<string, { title: string; description: string }> = {
  '/': {
    title: 'پیام‌رسان',
    description:
      'پیام‌رسان امن و سریع با رمزنگاری سرتاسری برای گفت‌وگوی خصوصی و بلادرنگ با دوستان و خانواده.',
  },
  '/login': {
    title: 'ورود به حساب | پیام‌رسان',
    description:
      'ورود امن به پیام‌رسان با آیدی بله و کد تأیید یک‌بارمصرف؛ گفت‌وگوی خصوصی با رمزنگاری سرتاسری.',
  },
  '/terms': {
    title: 'قوانین پیام‌رسان | پیام‌رسان',
    description:
      'قوانین و مقررات پیام‌رسان را بخوانید؛ شرایط استفاده، حریم خصوصی، حقوق داده و حذف حساب کاربری را بدانید.',
  },
};

function updateDocumentMeta(pathname: string) {
  if (typeof document === 'undefined') return;
  const meta = ROUTE_META[pathname] || ROUTE_META['/'];
  document.title = meta.title;
  const descEl = document.querySelector('meta[name="description"]');
  if (descEl) descEl.setAttribute('content', meta.description);
  const ogTitleEl = document.querySelector('meta[property="og:title"]');
  if (ogTitleEl) ogTitleEl.setAttribute('content', meta.title);
  const ogDescEl = document.querySelector('meta[property="og:description"]');
  if (ogDescEl) ogDescEl.setAttribute('content', meta.description);
}

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
  const [pathname, setPathname] = useState<string>(() => {
    const p = typeof window !== 'undefined' ? window.location.pathname : '/';
    updateDocumentMeta(p);
    return p;
  });
  const isTermsRoute = pathname === '/terms';
  const [initializing, setInitializing] = useState<boolean>(() => hasStoredSessionCandidate());
  const [username, setUsername] = useState<string>('');
  const [socket, setSocket] = useState<Socket | null>(null);
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

  const handleNavigate = useCallback((nextPath: string) => {
    if (typeof window !== 'undefined' && window.location.pathname !== nextPath) {
      window.history.pushState({}, '', nextPath);
    }
    updateDocumentMeta(nextPath);
    setPathname(nextPath);
  }, []);

  useEffect(() => {
    updateDocumentMeta(pathname);
  }, [pathname]);

  useEffect(() => {
    const onPopState = () => {
      const p = window.location.pathname;
      updateDocumentMeta(p);
      setPathname(p);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const showToast = useCallback((text: string) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, text }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 2800);
  }, []);

  const handleAuthenticated = useCallback(
    (user: string) => {
      try {
        localStorage.setItem(SESSION_KEY, user);
      } catch {
        // ignore
      }
      setUsername(user);
      if (pathname === '/login') {
        handleNavigate('/');
      }
    },
    [handleNavigate, pathname]
  );

  const handleLogout = useCallback(() => {
    try {
      localStorage.removeItem(SESSION_KEY);
      localStorage.removeItem('chat_session_token');
    } catch {
      // ignore
    }
    setUsername('');
    window.location.reload();
  }, []);

  useEffect(() => {
    if (isTermsRoute) return;
    let activeSocket: Socket | null = null;
    let cancelled = false;

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

    import('socket.io-client').then(({ io }) => {
      if (cancelled) return;
      activeSocket = io({ transports: ['websocket'] });
      activeSocket.on('blocked', onBlocked);
      activeSocket.on('kicked', onKicked);
      activeSocket.on('server-maintenance', onServerMaint);
      activeSocket.on('server-normal', onServerNormal);
      activeSocket.on('announcement', onAnnouncement);
      setSocket(activeSocket);
    });

    return () => {
      cancelled = true;
      if (activeSocket) {
        activeSocket.off('blocked', onBlocked);
        activeSocket.off('kicked', onKicked);
        activeSocket.off('server-maintenance', onServerMaint);
        activeSocket.off('server-normal', onServerNormal);
        activeSocket.off('announcement', onAnnouncement);
        activeSocket.disconnect();
      }
    };
  }, [handleLogout, showToast, isTermsRoute]);

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
        <Suspense
          fallback={
            <main id="main-content" className="terms-screen" tabIndex={-1} aria-busy="true">
              <h1>قوانین و مقررات پیام‌رسان</h1>
            </main>
          }
        >
          <TermsScreen onNavigate={handleNavigate} />
        </Suspense>
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
            <div style={{ fontSize: '60px' }} aria-hidden="true">
              🚫
            </div>
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
            <div style={{ fontSize: '60px' }} aria-hidden="true">
              🔧
            </div>
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
      {!username || pathname === '/login' ? (
        <Suspense
          fallback={
            <main id="main-content" className="auth-screen" tabIndex={-1} aria-busy="true">
              <h1>پیام‌رسان</h1>
            </main>
          }
        >
          <AuthScreen onAuthenticated={handleAuthenticated} />
        </Suspense>
      ) : socket ? (
        <Suspense
          fallback={
            <main id="main-content" className="auth-screen" tabIndex={-1} aria-busy="true" />
          }
        >
          <main id="main-content" tabIndex={-1}>
            <ChatApp
              myUsername={username}
              socket={socket}
              onLogout={handleLogout}
              showToast={showToast}
            />
          </main>
        </Suspense>
      ) : (
        <main id="main-content" className="auth-screen" tabIndex={-1} aria-busy="true" />
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
