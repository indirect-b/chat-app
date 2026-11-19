import React, { useState, useEffect, useRef } from 'react';

// Google Identity Services (loaded dynamically from accounts.google.com;
// the button is hidden entirely when there is no Client ID or the
// script fails to load). Minimal typing for the GIS button API only.
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (options: {
            client_id: string;
            callback?: (response: { credential: string }) => void;
            ux_mode?: string;
            login_uri?: string;
          }) => void;
          renderButton: (
            parent: HTMLElement,
            options: { theme?: string; size?: string; width?: number; text?: string }
          ) => void;
        };
      };
    };
  }
}

// Redirect-mode login URI: Google POSTs the credential back here.
// Must be registered as an Authorized redirect URI in the Google Cloud
// Console OAuth client, otherwise Google refuses the redirect.
const GOOGLE_REDIRECT_LOGIN_URI =
  'https://chatapp-server-1i2a.onrender.com/api/google-redirect';

interface AuthScreenProps {
  onAuthenticated: (username: string) => void;
}

// Google-only login: step 1 = Google button, step 4 = one-time recovery
// code display (new Google registrations), step 5 = recovery-code login.
// The Bale / email OTP flows were removed entirely.
type AuthStep = 1 | 4 | 5;

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthenticated }) => {
  const [step, setStep] = useState<AuthStep>(1);

  // One-time recovery code (shown once after a new Google registration,
  // or after a recovery login rotates it).
  const [recoveryCodeInput, setRecoveryCodeInput] = useState('');
  const [recoveryError, setRecoveryError] = useState('');
  const [issuedRecoveryCode, setIssuedRecoveryCode] = useState('');
  const [pendingAuthUsername, setPendingAuthUsername] = useState('');
  const [recoverySavedChecked, setRecoverySavedChecked] = useState(false);
  const [recoveryCopied, setRecoveryCopied] = useState(false);
  const [recoveryHeading, setRecoveryHeading] = useState('کد بازیابی یک‌بارمصرف شما');

  // Recovery-login identifier: the account's email (Google accounts) or
  // a legacy Bale ID (accounts created before Google-only login).
  const [accountId, setAccountId] = useState('');

  const [msg, setMsg] = useState<{ text: string; isOk: boolean }>({
    text: '',
    isOk: false,
  });

  // Google Sign-In (the only login method). The button renders only when
  // the server reports a Client ID AND the GIS script loaded successfully.
  const [googleClientId, setGoogleClientId] = useState<string | null>(null);
  const [googleReady, setGoogleReady] = useState(false);
  const googleBtnRef = useRef<HTMLDivElement | null>(null);
  const googleRenderedRef = useRef(false);
  // Guards the redirect-return handling below (runs once per mount).
  const redirectHandledRef = useRef(false);

  // Redirect-mode return: Google sent us back to /?session=<token>(&new=1).
  // Store the session, strip it from the address bar at once (the token
  // must never sit in the URL), then resolve the session owner — and a
  // pending one-time recovery code, if this login created the account.
  useEffect(() => {
    if (redirectHandledRef.current) return;
    const params = new URLSearchParams(window.location.search);
    const session = params.get('session');
    if (!session) return;
    redirectHandledRef.current = true;
    try {
      localStorage.setItem('chat_session_token', session);
    } catch {
      // ignore
    }
    window.history.replaceState(
      null,
      '',
      `${window.location.pathname}${window.location.hash}`
    );
    const isNew = params.get('new') === '1';
    void (async () => {
      try {
        const res = await fetch('/api/recovery-code-once', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionToken: session }),
        }).then(r => r.json());
        if (!res || !res.ok || !res.username) {
          setMsg({ text: 'ورود با گوگل ناموفق بود. لطفاً دوباره تلاش کنید.', isOk: false });
          return;
        }
        // New Google users get their one-time recovery code, shown once
        // (step 4), exactly like the previous registration flow.
        if (isNew && res.recoveryCode) {
          setIssuedRecoveryCode(res.recoveryCode);
          setPendingAuthUsername(res.username);
          setRecoverySavedChecked(false);
          setRecoveryCopied(false);
          setRecoveryHeading('کد بازیابی یک‌بارمصرف شما');
          setMsg({ text: '', isOk: false });
          setStep(4);
        } else {
          setMsg({ text: '✅ خوش آمدی!', isOk: true });
          setTimeout(() => onAuthenticated(res.username), 400);
        }
      } catch {
        setMsg({ text: 'ارتباط با سرور برقرار نشد. لطفاً دوباره تلاش کنید.', isOk: false });
      }
    })();
  }, [onAuthenticated]);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/config')
      .then(r => r.json())
      .then(cfg => {
        if (
          !cancelled &&
          cfg &&
          typeof cfg.googleClientId === 'string' &&
          cfg.googleClientId
        ) {
          setGoogleClientId(cfg.googleClientId);
        }
      })
      .catch(() => {
        // Config unreachable: the Google button stays hidden.
      });
    const GIS_SRC = 'https://accounts.google.com/gsi/client';
    if (document.querySelector(`script[src="${GIS_SRC}"]`)) {
      setGoogleReady(true);
      return () => {
        cancelled = true;
      };
    }
    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    script.defer = true;
    script.onload = () => {
      if (!cancelled) setGoogleReady(true);
    };
    script.onerror = () => {
      // GIS failed to load: the Google button stays hidden.
    };
    document.head.appendChild(script);
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!googleClientId || !googleReady || googleRenderedRef.current) return;
    const g = window.google;
    const el = googleBtnRef.current;
    if (!g || !el) return;
    g.accounts.id.initialize({
      // Redirect mode (not the popup): clicking the button navigates the
      // whole page to Google and Google POSTs the credential back to
      // /api/google-redirect. The popup return trip stalls on some mobile
      // browsers (blank gsi/transform tab); the redirect does not.
      client_id: googleClientId,
      ux_mode: 'redirect',
      login_uri: GOOGLE_REDIRECT_LOGIN_URI,
    });
    g.accounts.id.renderButton(el, {
      theme: 'outline',
      size: 'large',
      width: 320,
      text: 'signin_with',
    });
    googleRenderedRef.current = true;
  }, [googleClientId, googleReady]);

  const isValidEmailFormat = (value: string): boolean =>
    /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(value.trim().toLowerCase());

  const handleRecoverLogin = async () => {
    // The account identifier is the account's email (Google accounts) or
    // a legacy Bale ID (accounts created before Google-only login).
    const rawId = accountId.trim();
    let cleanId = '';
    if (rawId.includes('@')) {
      cleanId = rawId.toLowerCase();
      if (!isValidEmailFormat(cleanId)) {
        setRecoveryError('ایمیل معتبر وارد کنید.');
        return;
      }
    } else {
      cleanId = rawId.replace(/^@+/, '');
      if (!/^[a-zA-Z0-9_]{3,64}$/.test(cleanId)) {
        setRecoveryError('ایمیل یا آیدی حساب معتبر وارد کنید.');
        return;
      }
    }
    const cleanCode = recoveryCodeInput.trim();
    if (!cleanCode) {
      setRecoveryError('کد بازیابی یک‌بارمصرف را وارد کنید.');
      return;
    }
    setRecoveryError('');

    try {
      const response = await fetch('/api/recover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baleId: cleanId, recoveryCode: cleanCode }),
      });
      const res = await response.json();

      if (!res.ok) {
        setRecoveryError(res.msg || 'ایمیل/آیدی یا کد بازیابی نامعتبر است.');
        return;
      }

      if (res.sessionToken) {
        try {
          localStorage.setItem('chat_session_token', res.sessionToken);
        } catch {
          // ignore
        }
      }

      if (res.nextRecoveryCode) {
        setIssuedRecoveryCode(res.nextRecoveryCode);
        setPendingAuthUsername(res.username);
        setRecoverySavedChecked(false);
        setRecoveryCopied(false);
        setRecoveryHeading('کد بازیابی جدید (جایگزین کد مصرف‌شده)');
        setRecoveryCodeInput('');
        setStep(4);
      } else {
        onAuthenticated(res.username);
      }
    } catch {
      setRecoveryError('خطا در ارتباط با سرور هنگام بررسی کد بازیابی.');
    }
  };

  const handleCopyRecoveryCode = async () => {
    if (!issuedRecoveryCode) return;
    try {
      await navigator.clipboard.writeText(issuedRecoveryCode);
      setRecoveryCopied(true);
    } catch {
      setRecoveryCopied(false);
    }
  };

  return (
    <div id="authScreen" className="auth-screen">
      <div id={`step${step}`} className="auth-box">
        <header role="banner" aria-label="سربرگ صفحه" className="auth-banner">
          <a href="/" className="auth-brand">
            <span className="auth-brand-icon" aria-hidden="true">
              💬
            </span>
            <span className="auth-brand-name">سامانه پیام‌رسان</span>
          </a>
        </header>

        <main id="main-content" tabIndex={-1}>
          {step === 1 && (
            <>
              <div className="auth-logo">
                <div className="logo-circle" aria-hidden="true">
                  💬
                </div>
                <h1>پیام‌رسان</h1>
                <p>ورود با گوگل • مجهز به رمزنگاری E2EE</p>
              </div>
              {googleClientId && googleReady ? (
                <div
                  ref={googleBtnRef}
                  style={{ display: 'flex', justifyContent: 'center', marginBottom: '12px' }}
                />
              ) : (
                <p className="auth-msg" role="status">
                  ورود با گوگل فعلاً در دسترس نیست. لطفاً بعداً دوباره تلاش کنید.
                </p>
              )}
              <div className="auth-form">
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => {
                    setMsg({ text: '', isOk: false });
                    setRecoveryError('');
                    setStep(5);
                  }}
                >
                  🔑 ورود با کد بازیابی (در صورت عدم دسترسی به حساب گوگل)
                </button>
                <p
                  id="msg1"
                  role="status"
                  aria-live="polite"
                  className={`auth-msg ${msg.isOk ? 'ok' : ''}`}
                >
                  {msg.text}
                </p>
              </div>
            </>
          )}

          {step === 4 && (
            <>
              <div className="auth-logo">
                <div
                  className="logo-circle"
                  style={{ background: 'linear-gradient(135deg,#f59e0b,#ef4444)' }}
                  aria-hidden="true"
                >
                  🗝️
                </div>
                <h1>{recoveryHeading}</h1>
                <p>این کد فقط یک‌بار نمایش داده می‌شود و در سرور به‌صورت هش نگهداری می‌گردد.</p>
              </div>
              <div className="auth-form">
                <div
                  dir="ltr"
                  style={{
                    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                    fontSize: '14px',
                    letterSpacing: '1px',
                    padding: '14px 12px',
                    borderRadius: '12px',
                    background: 'rgba(245, 158, 11, 0.12)',
                    border: '1px solid rgba(245, 158, 11, 0.4)',
                    color: '#fef3c7',
                    textAlign: 'center',
                    wordBreak: 'break-all',
                    userSelect: 'all',
                  }}
                >
                  {issuedRecoveryCode}
                </div>
                <p className="input-hint">
                  اگر به حساب گوگل خود دسترسی ندارید، می‌توانید با این کد یک‌بارمصرف وارد حساب خود
                  شوید. پس از هر بار استفاده، کد جدیدی جایگزین آن می‌شود.
                </p>
                <button type="button" className="btn-ghost" onClick={handleCopyRecoveryCode}>
                  {recoveryCopied ? '✅ کپی شد' : '📋 کپی کد بازیابی'}
                </button>
                <div className="rules-check">
                  <input
                    type="checkbox"
                    id="recoverySavedCheck"
                    checked={recoverySavedChecked}
                    onChange={e => setRecoverySavedChecked(e.target.checked)}
                  />
                  <label htmlFor="recoverySavedCheck">
                    کد بازیابی را در جای امن ذخیره کردم
                  </label>
                </div>
                <button
                  type="button"
                  disabled={!recoverySavedChecked}
                  className={!recoverySavedChecked ? 'btn-disabled' : ''}
                  onClick={() => {
                    setIssuedRecoveryCode('');
                    onAuthenticated(pendingAuthUsername);
                  }}
                >
                  ادامه به پیام‌رسان
                </button>
              </div>
            </>
          )}

          {step === 5 && (
            <>
              <div className="auth-logo">
                <div
                  className="logo-circle"
                  style={{ background: 'linear-gradient(135deg,#06b6d4,#7c3aed)' }}
                  aria-hidden="true"
                >
                  🔑
                </div>
                <h1>ورود با کد بازیابی</h1>
                <p>در صورت عدم دسترسی به حساب گوگل از کد بازیابی یک‌بارمصرف استفاده کنید</p>
              </div>
              <form
                className="auth-form"
                noValidate
                onSubmit={e => {
                  e.preventDefault();
                  void handleRecoverLogin();
                }}
              >
                <label htmlFor="recoverAccountIdInput">
                  ایمیل یا آیدی حساب <span aria-hidden="true">*</span>
                </label>
                <input
                  type="text"
                  id="recoverAccountIdInput"
                  name="recoverAccountId"
                  placeholder="you@example.com"
                  dir="ltr"
                  autoComplete="username"
                  value={accountId}
                  onChange={e => {
                    setAccountId(e.target.value);
                    if (recoveryError) setRecoveryError('');
                  }}
                />
                <p className="input-hint">
                  ایمیل حساب گوگل خود، یا آیدی حساب‌های قدیمی را وارد کنید.
                </p>
                <label htmlFor="recoveryCodeInput">
                  کد بازیابی یک‌بارمصرف <span aria-hidden="true">*</span>
                </label>
                <input
                  type="text"
                  id="recoveryCodeInput"
                  name="recoveryCode"
                  dir="ltr"
                  placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                  autoComplete="off"
                  value={recoveryCodeInput}
                  onChange={e => {
                    setRecoveryCodeInput(e.target.value);
                    if (recoveryError) setRecoveryError('');
                  }}
                  style={{
                    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                    fontSize: '13px',
                    textAlign: 'center',
                  }}
                />
                <p
                  id="recoveryError"
                  role="alert"
                  aria-live="assertive"
                  className={`field-error ${recoveryError ? 'visible' : ''}`}
                >
                  {recoveryError}
                </p>
                <button type="submit">ورود با کد بازیابی</button>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => {
                    setRecoveryError('');
                    setStep(1);
                  }}
                >
                  برگشت به ورود با گوگل
                </button>
              </form>
            </>
          )}
        </main>

        <footer role="contentinfo" aria-label="پاصفحه" className="auth-footer">
          <nav aria-label="پیوندهای پاصفحه" className="auth-footer-nav">
            <a href="/terms" className="link-btn">
              قوانین پیام‌رسان
            </a>
            <span className="footer-sep" role="separator" aria-hidden="true">
              |
            </span>
            <a href="/privacy" className="link-btn">
              حریم خصوصی
            </a>
          </nav>
          <span className="footer-sep" role="separator" aria-hidden="true">
            |
          </span>
          <span className="footer-badge">🔒 رمزنگاری سرتاسری</span>
        </footer>
      </div>
    </div>
  );
};
