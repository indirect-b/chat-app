import React, { useState, useEffect, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import { AuthScreen } from './components/AuthScreen';
import { ChatApp } from './components/ChatApp';
import { BlockedInfo } from './types';

const SESSION_KEY = 'chat_session_user';
const socketInstance: Socket = io();

export const App: React.FC = () => {
  const [initializing, setInitializing] = useState(true);
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
    async function bootstrap() {
      try {
        const modeRes = await fetch('/api/settings/mode').then(r => r.json());
        if (modeRes.mode === 'maintenance') {
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

      // ۱. بررسی ورود موقت ادمین (Login As)
      const adminTokenUser = sessionStorage.getItem('adminLoginToken');
      if (adminTokenUser) {
        sessionStorage.removeItem('adminLoginToken');
        handleAuthenticated(adminTokenUser);
        setInitializing(false);
        return;
      }

      // ۲. بررسی نشست ذخیره‌شده در LocalStorage
      try {
        const saved = localStorage.getItem(SESSION_KEY);
        if (saved) {
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
  }, [handleAuthenticated]);

  if (initializing) {
    return null;
  }

  if (blocked) {
    const untilText =
      blocked.block_type === 'permanent'
        ? 'مسدودیت دائمی'
        : blocked.block_until
        ? 'مسدودیت موقت تا ' + new Date(blocked.block_until).toLocaleDateString('fa-IR')
        : 'مسدودیت حساب';

    return (
      <div id="maintenanceScreen" className="full-screen">
        <div className="maint-box">
          <div style={{ fontSize: '60px' }}>🚫</div>
          <h1>حساب مسدود شد</h1>
          <p>علت: {blocked.block_reason || 'تخلف'}</p>
          <p>{untilText}</p>
        </div>
      </div>
    );
  }

  if (maintenance.active) {
    return (
      <div id="maintenanceScreen" className="full-screen">
        <div className="maint-box">
          <div style={{ fontSize: '60px' }}>🔧</div>
          <h1>در حال به‌روزرسانی</h1>
          <p id="maintMsg">{maintenance.msg}</p>
        </div>
      </div>
    );
  }

  return (
    <>
      {!username ? (
        <AuthScreen onAuthenticated={handleAuthenticated} />
      ) : (
        <ChatApp
          myUsername={username}
          socket={socketInstance}
          onLogout={handleLogout}
          showToast={showToast}
        />
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
