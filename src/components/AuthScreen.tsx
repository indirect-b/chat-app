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
            options: {
              theme?: string;
              size?: string;
              width?: number;
              text?: string;
              type?: string;
              shape?: string;
              logo_alignment?: string;
            }
          ) => void;
        };
      };
    };
  }
}

// Redirect-mode login URI: Google POSTs the credential back here.
// Must be registered as an Authorized redirect URI in the Google Cloud
// Console OAuth client, otherwise Google refuses the redirect.
export function getGoogleRedirectLoginUri(envOverride?: string): string {
  if (envOverride?.trim()) return envOverride.trim();
  if (typeof process !== 'undefined' && process.env?.GOOGLE_REDIRECT_URI?.trim()) {
    return process.env.GOOGLE_REDIRECT_URI.trim();
  }
  if (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_GOOGLE_REDIRECT_URI?.trim()) {
    return (import.meta as any).env.VITE_GOOGLE_REDIRECT_URI.trim();
  }
  return 'https://chatapp-server-1i2a.onrender.com/api/google-redirect';
}

export const GOOGLE_REDIRECT_LOGIN_URI = getGoogleRedirectLoginUri();

interface AuthScreenProps {
  onAuthenticated: (username: string) => void;
}

// Google-only login: step 1 = Google button, step 4 = one-time recovery
// code display (new Google registrations), step 5 = recovery-code login.
// The Bale / email OTP flows were removed entirely.
type AuthStep = 1 | 4 | 5;

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthenticated }) => {
  const [step, setStep] = useState<AuthStep>(1);
  const [isSubmitting, setIsSubmitting] = useState(false);

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
      type: 'standard',
      theme: 'outline',
      size: 'large',
      shape: 'pill',
      text: 'signin_with',
      width: 280,
      logo_alignment: 'left',
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
    setIsSubmitting(true);

    try {
      const response = await fetch('/api/recover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baleId: cleanId, recoveryCode: cleanCode }),
      });
      const res = await response.json();

      if (!res.ok) {
        setRecoveryError(res.msg || 'ایمیل/آیدی یا کد بازیابی نامعتبر است.');
        setIsSubmitting(false);
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
        setIsSubmitting(false);
        setStep(4);
      } else {
        setIsSubmitting(false);
        onAuthenticated(res.username);
      }
    } catch {
      setIsSubmitting(false);
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
      <div className="auth-ambient-glow" aria-hidden="true">
        <div className="ambient-nebula-blob blob-1" />
        <div className="ambient-nebula-blob blob-2" />
      </div>

      <div className="auth-layout-container">
        {/* RIGHT/TOP: Hero Showcase */}
        <section className="auth-hero-showcase" aria-label="معرفی پیام‌رسان">
          <div className="showcase-badge">
            <span className="badge-pulse-dot" aria-hidden="true" />
            <span>پروتکل اختصاصی PQ-MPRBA v6.5</span>
          </div>

          <div className="showcase-brand">
            <div className="showcase-logo-ring" aria-hidden="true">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z" />
                <path d="M12 8v4" />
                <circle cx="12" cy="16" r="1.25" fill="var(--accent-cyan)" />
              </svg>
            </div>
            <h1>پیام‌رسان امن کوانتومی</h1>
          </div>

          <p className="showcase-tagline">
            نخستین پیام‌رسان وب ایرانی مجهز به رمزنگاری پسا-کوانتومی هیبرید. پیام‌ها و فایل‌های شما حتی در برابر قدرتمندترین ابررایانه‌ها مصون هستند.
          </p>

          <div className="showcase-features">
            <div className="showcase-feature-item">
              <div className="feature-icon" aria-hidden="true">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z" />
                  <path d="m9 12 2 2 4-4" />
                </svg>
              </div>
              <div className="feature-text">
                <strong>رمزنگاری هیبرید NIST FIPS 203/204</strong>
                <span>ترکیب همزمان ML-KEM-768 و ECDH P-256 در هر پیام</span>
              </div>
            </div>
            <div className="showcase-feature-item">
              <div className="feature-icon" aria-hidden="true">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <div className="feature-text">
                <strong>حفظ صفر مطلق داده (Zero-Knowledge)</strong>
                <span>کلید خصوصی هرگز از مرورگر شما خارج یا در سرور ذخیره نمی‌شود</span>
              </div>
            </div>
            <div className="showcase-feature-item">
              <div className="feature-icon" aria-hidden="true">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                </svg>
              </div>
              <div className="feature-text">
                <strong>بلادرنگ و مستقل</strong>
                <span>ارتباط مستقیم سوکت رمزشده بدون وابستگی به سرورهای واسط</span>
              </div>
            </div>
          </div>

          <div className="showcase-status-chip">
            <span className="status-live-dot" aria-hidden="true" />
            <span>وضعیت شبکه: رمزنگاری فعال • سرور رندر آماده ارتباط</span>
          </div>
        </section>

        {/* LEFT/BOTTOM: Interactive Action Card */}
        <div id={`step${step}`} className="auth-box auth-card-panel">
          <header role="banner" aria-label="سربرگ ورود" className="auth-banner">
            <a href="/" className="auth-brand">
              <span className="auth-brand-icon-wrap" aria-hidden="true">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z" />
                  <path d="M12 8v4" />
                  <circle cx="12" cy="16" r="1" fill="currentColor" />
                </svg>
              </span>
              <span className="auth-brand-name">پیام‌رسان</span>
            </a>
            <div className="auth-security-badge" aria-label="رمزنگاری پسا-کوانتومی">
              <span className="badge-pulse-dot" aria-hidden="true" />
              <span>ML-KEM-768</span>
            </div>
          </header>

          <main id="main-content" tabIndex={-1}>
            {step === 1 && (
              <div className="auth-step-anim">
                <div className="auth-logo">
                  <h2>ورود به حساب کاربری</h2>
                  <p>برای ورود به گفت‌وگوهای رمزشده خود با حساب گوگل ادامه دهید.</p>
                </div>

                <div className="google-btn-container">
                  {googleClientId && googleReady ? (
                    <div
                      ref={googleBtnRef}
                      className="google-btn-wrapper"
                    />
                  ) : (
                    <div className="google-btn-loading" role="status">
                      <div className="quantum-spinner" aria-hidden="true">
                        <span className="spinner-track" />
                        <span className="spinner-arc" />
                      </div>
                      <span>در حال اتصال امن به درگاه گوگل...</span>
                    </div>
                  )}
                </div>

                <div className="auth-divider">
                  <span>یا ورود اضطراری</span>
                </div>

                <div className="auth-form">
                  <button
                    type="button"
                    className="btn-recovery-link"
                    onClick={() => {
                      setMsg({ text: '', isOk: false });
                      setRecoveryError('');
                      setStep(5);
                    }}
                  >
                    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <circle cx="7.5" cy="15.5" r="5.5" />
                      <path d="m21 2-9.6 9.6" />
                      <path d="m15.5 7.5 3 3L22 7l-3-3" />
                    </svg>
                    <span>ورود با کد بازیابی یک‌بارمصرف</span>
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
              </div>
            )}

          {step === 4 && (
            <div className="auth-step-anim">
              <div className="auth-logo">
                <div
                  className="logo-circle"
                  style={{ background: 'rgba(245, 158, 11, 0.15)', borderColor: '#f59e0b', boxShadow: '0 0 24px rgba(245, 158, 11, 0.3)' }}
                  aria-hidden="true"
                >
                  <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="7.5" cy="15.5" r="5.5" />
                    <path d="m21 2-9.6 9.6" />
                    <path d="m15.5 7.5 3 3L22 7l-3-3" />
                  </svg>
                </div>
                <h1>{recoveryHeading}</h1>
                <p>این کد فقط یک‌بار نمایش داده می‌شود و در سرور به‌صورت هش نگهداری می‌گردد.</p>
              </div>
              <div className="auth-form">
                <div
                  dir="ltr"
                  className="recovery-code-card"
                >
                  {issuedRecoveryCode}
                </div>
                <p className="input-hint">
                  اگر به حساب گوگل خود دسترسی ندارید، می‌توانید با این کد یک‌بارمصرف وارد حساب خود
                  شوید. پس از هر بار استفاده، کد جدیدی جایگزین آن می‌شود.
                </p>
                <button type="button" className="btn-recovery-copy" onClick={handleCopyRecoveryCode}>
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
                  className={`btn-primary-action ${!recoverySavedChecked ? 'btn-disabled' : ''}`}
                  onClick={() => {
                    setIssuedRecoveryCode('');
                    onAuthenticated(pendingAuthUsername);
                  }}
                >
                  ادامه به پیام‌رسان
                </button>
              </div>
            </div>
          )}

          {step === 5 && (
            <div className="auth-step-anim">
              <div className="auth-logo">
                <div
                  className="logo-circle"
                  style={{ background: 'var(--bg-surface-2)', borderColor: 'var(--accent-cyan)', boxShadow: '0 0 24px var(--accent-cyan-dim)' }}
                  aria-hidden="true"
                >
                  <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="7.5" cy="15.5" r="5.5" />
                    <path d="m21 2-9.6 9.6" />
                    <path d="m15.5 7.5 3 3L22 7l-3-3" />
                  </svg>
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
                  className="recovery-input-field"
                />
                <p
                  id="recoveryError"
                  role="alert"
                  aria-live="assertive"
                  className={`field-error ${recoveryError ? 'visible' : ''}`}
                >
                  {recoveryError}
                </p>
                <button
                  type="submit"
                  className={`btn-primary-action ${isSubmitting ? 'loading' : ''}`}
                  disabled={isSubmitting}
                >
                  {isSubmitting ? (
                    <span className="btn-loading-content">
                      <span className="btn-spinner" aria-hidden="true" />
                      <span>در حال بررسی کلید و ورود امن...</span>
                    </span>
                  ) : (
                    <span>ورود با کد بازیابی</span>
                  )}
                </button>
                <button
                  type="button"
                  className="btn-recovery-link"
                  onClick={() => {
                    setRecoveryError('');
                    setStep(1);
                  }}
                >
                  ← برگشت به ورود با گوگل
                </button>
              </form>
            </div>
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
  </div>
);
};
