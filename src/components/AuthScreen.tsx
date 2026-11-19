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
            callback: (response: { credential: string }) => void;
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

interface AuthScreenProps {
  onAuthenticated: (username: string) => void;
}

type AuthStep = 1 | 2 | 3 | 4 | 5;

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthenticated }) => {
  const [step, setStep] = useState<AuthStep>(1);
  const [baleId, setBaleId] = useState('');
  const [verifiedBaleId, setVerifiedBaleId] = useState('');
  const [otp, setOtp] = useState('');
  const [step2Desc, setStep2Desc] = useState('کد ارسال شده به بله رو وارد کن');
  const [resendTimer, setResendTimer] = useState(60);
  const [rulesChecked, setRulesChecked] = useState(false);
  const [rulesModalOpen, setRulesModalOpen] = useState(false);
  const [rulesText, setRulesText] = useState('');

  // Recovery code fallback (Item 3.1)
  const [recoveryCodeInput, setRecoveryCodeInput] = useState('');
  const [recoveryError, setRecoveryError] = useState('');
  const [issuedRecoveryCode, setIssuedRecoveryCode] = useState('');
  const [pendingAuthUsername, setPendingAuthUsername] = useState('');
  const [recoverySavedChecked, setRecoverySavedChecked] = useState(false);
  const [recoveryCopied, setRecoveryCopied] = useState(false);
  const [recoveryHeading, setRecoveryHeading] = useState('کد بازیابی یک‌بارمصرف شما');

  const [msg, setMsg] = useState<{ text: string; isOk: boolean; needStart?: boolean }>({
    text: '',
    isOk: false,
  });

  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, []);

  const startTimer = () => {
    setResendTimer(60);
    if (timerRef.current) window.clearInterval(timerRef.current);
    timerRef.current = window.setInterval(() => {
      setResendTimer(prev => {
        if (prev <= 1) {
          if (timerRef.current) window.clearInterval(timerRef.current);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  };

  const [baleIdError, setBaleIdError] = useState('');
  const [otpError, setOtpError] = useState('');

  // Email signup/login (alternative to Bale)
  const [authMethod, setAuthMethod] = useState<'bale' | 'email'>('bale');
  const [email, setEmail] = useState('');
  const [verifiedEmail, setVerifiedEmail] = useState('');
  const [emailError, setEmailError] = useState('');

  // Google Sign-In (primary login). The button renders only when the
  // server reports a Client ID AND the GIS script loaded successfully.
  const [googleClientId, setGoogleClientId] = useState<string | null>(null);
  const [googleReady, setGoogleReady] = useState(false);
  const googleBtnRef = useRef<HTMLDivElement | null>(null);
  const googleRenderedRef = useRef(false);

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
      client_id: googleClientId,
      callback: (response: { credential: string }) => {
        void handleGoogleLogin(response.credential);
      },
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

  const toggleBtnStyle = (active: boolean): React.CSSProperties => ({
    flex: 1,
    padding: '10px 0',
    borderRadius: '12px',
    border: active ? '1px solid #06b6d4' : '1px solid #374151',
    background: active ? 'rgba(6, 182, 212, 0.18)' : 'transparent',
    color: active ? '#67e8f9' : '#d1d5db',
    fontSize: '15px',
    fontWeight: 600,
    cursor: 'pointer',
  });

  const handleSendOTP = async () => {
    const clean = baleId.trim().replace(/^@+/, '');
    if (!clean) {
      const errText = 'لطفاً آیدی بله خود را وارد کنید.';
      setBaleIdError(errText);
      setMsg({ text: errText, isOk: false });
      return;
    }
    if (!/^[a-zA-Z0-9_]{3,64}$/.test(clean)) {
      const errText = 'آیدی بله نامعتبر است (حداقل ۳ کاراکتر انگلیسی، عدد یا زیرخط).';
      setBaleIdError(errText);
      setMsg({ text: errText, isOk: false });
      return;
    }
    setBaleIdError('');
    try {
      const res = await fetch('/api/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baleId: clean }),
      }).then(r => r.json());

      if (res.ok) {
        setVerifiedBaleId(clean);
        if (res.needStart) {
          setMsg({
            text: '',
            isOk: false,
            needStart: true,
          });
        } else {
          setMsg({ text: res.msg, isOk: true });
          if (res.msg && res.msg.includes('آزمایشی')) {
            const match = res.msg.match(/\d{6}/);
            if (match) {
              setStep2Desc(res.msg);
              setOtp(match[0]);
            }
          }
          setTimeout(() => {
            setMsg({ text: '', isOk: false });
            setOtpError('');
            setStep(2);
            startTimer();
          }, 600);
        }
      } else {
        const errText = res.msg || 'خطا در ارسال کد تأیید.';
        setBaleIdError(errText);
        setMsg({ text: errText, isOk: false });
      }
    } catch {
      const errText =
        'ارتباط با سرور یا سرویس بله برقرار نشد. در صورت داشتن کد بازیابی، از گزینه «ورود با کد بازیابی» استفاده کنید.';
      setBaleIdError(errText);
      setMsg({ text: errText, isOk: false });
    }
  };

  const handleSendEmailOTP = async () => {
    const clean = email.trim().toLowerCase();
    if (!clean || !isValidEmailFormat(clean)) {
      const errText = 'لطفاً یک ایمیل معتبر وارد کنید.';
      setEmailError(errText);
      setMsg({ text: errText, isOk: false });
      return;
    }
    setEmailError('');
    try {
      const res = await fetch('/api/request-email-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: clean }),
      }).then(r => r.json());

      if (res.ok) {
        setVerifiedEmail(clean);
        setStep2Desc('کد ارسال شده به ایمیل رو وارد کن');
        setMsg({ text: res.msg, isOk: true });
        setTimeout(() => {
          setMsg({ text: '', isOk: false });
          setOtpError('');
          setStep(2);
          startTimer();
        }, 600);
      } else {
        const errText = res.msg || 'خطا در ارسال کد تأیید.';
        setEmailError(errText);
        setMsg({ text: errText, isOk: false });
      }
    } catch {
      const errText = 'ارتباط با سرور برقرار نشد. لطفاً بعداً دوباره تلاش کنید.';
      setEmailError(errText);
      setMsg({ text: errText, isOk: false });
    }
  };

  const handleVerifyOTP = async () => {
    const cleanCode = otp.trim();
    if (!cleanCode) {
      const errText = 'لطفاً کد تأیید ۶ رقمی را وارد کنید.';
      setOtpError(errText);
      setMsg({ text: errText, isOk: false });
      return;
    }
    if (!/^\d{6}$/.test(cleanCode)) {
      const errText = 'کد تأیید باید یک عدد ۶ رقمی باشد.';
      setOtpError(errText);
      setMsg({ text: errText, isOk: false });
      return;
    }
    setOtpError('');
    const verifyUrl = authMethod === 'email' ? '/api/verify-email-otp' : '/api/verify-otp';
    const verifyBody =
      authMethod === 'email'
        ? { email: verifiedEmail, code: cleanCode }
        : { baleId: verifiedBaleId, code: cleanCode };
    const res = await fetch(verifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyBody),
    }).then(r => r.json());

    if (!res.ok) {
      const errText = res.msg || 'کد تأیید نادرست است.';
      setOtpError(errText);
      setMsg({ text: errText, isOk: false });
      return;
    }

    if (res.sessionToken) {
      try {
        localStorage.setItem('chat_session_token', res.sessionToken);
      } catch {
        // ignore
      }
    }

    if (!res.isNew) {
      setMsg({ text: '✅ خوش آمدی!', isOk: true });
      setTimeout(() => onAuthenticated(res.username), 400);
    } else {
      setMsg({ text: '', isOk: false });
      setStep(3);
    }
  };

  const handleGoogleLogin = async (idToken: string) => {
    try {
      const res = await fetch('/api/google-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }).then(r => r.json());

      if (!res.ok) {
        const errText = res.msg || 'ورود با گوگل ناموفق بود. لطفاً دوباره تلاش کنید.';
        setMsg({ text: errText, isOk: false });
        return;
      }

      if (res.sessionToken) {
        try {
          localStorage.setItem('chat_session_token', res.sessionToken);
        } catch {
          // ignore
        }
      }

      // New Google users get a one-time recovery code, shown exactly
      // like the Bale/email registration flow (step 4).
      if (res.isNew && res.recoveryCode) {
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
  };

  const handleRegister = async () => {
    const registerBody =
      authMethod === 'email' ? { email: verifiedEmail } : { baleId: verifiedBaleId };
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(registerBody),
    }).then(r => r.json());

    if (res.ok) {
      if (res.recoveryCode) {
        setIssuedRecoveryCode(res.recoveryCode);
        setPendingAuthUsername(res.username);
        setRecoverySavedChecked(false);
        setRecoveryCopied(false);
        setRecoveryHeading('کد بازیابی یک‌بارمصرف شما');
        setMsg({ text: '', isOk: false });
        setStep(4);
      } else {
        setMsg({ text: '✅ حساب ساخته شد!', isOk: true });
        setTimeout(() => onAuthenticated(res.username), 400);
      }
    } else {
      setMsg({ text: res.msg, isOk: false });
    }
  };

  const handleRecoverLogin = async () => {
    // Recovery login accepts the account identifier: Bale ID in Bale mode,
    // email address in email mode (the username of an email account is its email).
    const cleanId =
      authMethod === 'email'
        ? baleId.trim().toLowerCase()
        : baleId.trim().replace(/^@+/, '');
    const cleanCode = recoveryCodeInput.trim();
    if (authMethod === 'email') {
      if (!cleanId || !isValidEmailFormat(cleanId)) {
        setRecoveryError('ایمیل معتبر وارد کنید.');
        return;
      }
    } else if (!cleanId || !/^[a-zA-Z0-9_]{3,64}$/.test(cleanId)) {
      setRecoveryError('آیدی بله معتبر وارد کنید.');
      return;
    }
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
        setRecoveryError(res.msg || 'آیدی یا کد بازیابی نامعتبر است.');
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

  const handleOpenRules = async (e: React.MouseEvent) => {
    e.preventDefault();
    const res = await fetch('/api/settings/rules').then(r => r.json());
    setRulesText(res.rules || 'قوانینی تنظیم نشده');
    setRulesModalOpen(true);
  };

  const isBaleIdInvalid = Boolean(baleIdError);
  const isOtpInvalid = Boolean(otpError);

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
                <p>
                  {authMethod === 'email'
                    ? 'ورود با ایمیل • مجهز به رمزنگاری E2EE'
                    : 'ورود با آیدی بله • مجهز به رمزنگاری E2EE'}
                </p>
              </div>
              {googleClientId && googleReady && (
                <>
                  <div
                    ref={googleBtnRef}
                    style={{ display: 'flex', justifyContent: 'center', marginBottom: '12px' }}
                  />
                  <div className="test-login-divider" role="separator" aria-label="یا">
                    <span className="divider-line" aria-hidden="true" />
                    <span className="divider-text">یا</span>
                    <span className="divider-line" aria-hidden="true" />
                  </div>
                </>
              )}
              <div
                className="auth-method-toggle"
                role="tablist"
                aria-label="روش ورود"
                style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={authMethod === 'bale'}
                  onClick={() => {
                    setAuthMethod('bale');
                    setMsg({ text: '', isOk: false });
                    setEmailError('');
                  }}
                  style={toggleBtnStyle(authMethod === 'bale')}
                >
                  بله
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={authMethod === 'email'}
                  onClick={() => {
                    setAuthMethod('email');
                    setMsg({ text: '', isOk: false });
                    setBaleIdError('');
                  }}
                  style={toggleBtnStyle(authMethod === 'email')}
                >
                  ایمیل
                </button>
              </div>
              <form
                className="auth-form"
                noValidate
                onSubmit={e => {
                  e.preventDefault();
                  if (authMethod === 'email') {
                    handleSendEmailOTP();
                  } else {
                    handleSendOTP();
                  }
                }}
              >
                {authMethod === 'bale' ? (
                  <>
                <label htmlFor="baleIdInput">
                  آیدی بله <span aria-hidden="true">*</span>
                </label>
                <div className={`input-prefix ${isBaleIdInvalid ? 'input-invalid' : ''}`}>
                  <span aria-hidden="true">@</span>
                  <input
                    type="text"
                    id="baleIdInput"
                    name="baleId"
                    aria-label="آیدی بله"
                    required
                    aria-required="true"
                    aria-invalid={isBaleIdInvalid ? 'true' : 'false'}
                    aria-describedby="baleIdHint baleIdError"
                    placeholder="username123"
                    dir="ltr"
                    autoComplete="username"
                    value={baleId}
                    onChange={e => {
                      setBaleId(e.target.value);
                      if (baleIdError) setBaleIdError('');
                    }}
                  />
                </div>
                <p
                  id="baleIdError"
                  role="alert"
                  aria-live="assertive"
                  className={`field-error ${baleIdError ? 'visible' : ''}`}
                >
                  {baleIdError}
                </p>
                <p id="baleIdHint" className="input-hint">
                  آیدی بله خود را بدون <bdi dir="ltr">@</bdi> وارد کنید (مثال:{' '}
                  <bdi dir="ltr">username123</bdi>)
                </p>
                  </>
                ) : (
                  <>
                <label htmlFor="emailInput">
                  ایمیل <span aria-hidden="true">*</span>
                </label>
                <input
                  type="email"
                  id="emailInput"
                  name="email"
                  aria-label="ایمیل"
                  required
                  aria-required="true"
                  aria-invalid={emailError ? 'true' : 'false'}
                  aria-describedby="emailHint emailError"
                  placeholder="you@example.com"
                  dir="ltr"
                  autoComplete="email"
                  className={emailError ? 'input-invalid' : ''}
                  value={email}
                  onChange={e => {
                    setEmail(e.target.value);
                    if (emailError) setEmailError('');
                  }}
                />
                <p
                  id="emailError"
                  role="alert"
                  aria-live="assertive"
                  className={`field-error ${emailError ? 'visible' : ''}`}
                >
                  {emailError}
                </p>
                <p id="emailHint" className="input-hint">
                  کد تأیید ۶ رقمی به این ایمیل فرستاده می‌شود.
                </p>
                  </>
                )}
                <button type="submit">دریافت کد تأیید</button>

                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => {
                    setMsg({ text: '', isOk: false });
                    setRecoveryError('');
                    setStep(5);
                  }}
                >
                  {authMethod === 'email'
                    ? '🔑 ورود با کد بازیابی'
                    : '🔑 ورود با کد بازیابی (در صورت اختلال بله)'}
                </button>

                {authMethod === 'bale' && (
                  <>
                <div className="test-login-divider" role="separator" aria-label="یا">
                  <span className="divider-line" aria-hidden="true" />
                  <span className="divider-text">یا</span>
                  <span className="divider-line" aria-hidden="true" />
                </div>

                <a
                  href="https://ble.ir/Optcodebot"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="auth-bot-link"
                >
                  🤖 فعال‌سازی ربات کد تأیید در بله (<bdi dir="ltr">@Optcodebot</bdi>)
                </a>

                <p className="bale-signup-note">
                  «بله» پیام‌رسان ایرانی است که کد تأیید ورود به آن ارسال می‌شود. اگر حساب بله
                  ندارید، در{' '}
                  <a
                    href="https://ble.ir"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rules-link"
                  >
                    وب‌سایت رسمی بله (ble.ir)
                  </a>{' '}
                  ثبت‌نام کنید.
                </p>
                  </>
                )}

                {msg.needStart ? (
                  <p id="msg1" role="alert" className="auth-msg">
                    ⚠️ ابتدا{' '}
                    <a
                      href="https://ble.ir/Optcodebot"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="rules-link"
                    >
                      <bdi dir="ltr">@Optcodebot</bdi>
                    </a>{' '}
                    را در بله استارت کن
                  </p>
                ) : (
                  <p
                    id="msg1"
                    role="status"
                    aria-live="polite"
                    className={`auth-msg ${msg.isOk ? 'ok' : ''}`}
                  >
                    {msg.isOk ? msg.text : ''}
                  </p>
                )}
              </form>
            </>
          )}

          {step === 2 && (
            <>
              <div className="auth-logo">
                <div
                  className="logo-circle"
                  style={{ background: 'linear-gradient(135deg,#06b6d4,#7c3aed)' }}
                  aria-hidden="true"
                >
                  🔐
                </div>
                <h1>کد تأیید</h1>
                <p id="step2desc">{step2Desc}</p>
              </div>
              <form
                className="auth-form"
                noValidate
                onSubmit={e => {
                  e.preventDefault();
                  handleVerifyOTP();
                }}
              >
                <label htmlFor="otpInput">
                  کد تأیید ۶ رقمی <span aria-hidden="true">*</span>
                </label>
                <input
                  type="text"
                  id="otpInput"
                  name="otp"
                  aria-label="کد تأیید ۶ رقمی"
                  required
                  aria-required="true"
                  aria-invalid={isOtpInvalid ? 'true' : 'false'}
                  aria-describedby="otpError"
                  className={isOtpInvalid ? 'input-invalid' : ''}
                  placeholder="● ● ● ● ● ●"
                  maxLength={6}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  style={{ textAlign: 'center', letterSpacing: '10px', fontSize: '24px' }}
                  value={otp}
                  onChange={e => {
                    setOtp(e.target.value);
                    if (otpError) setOtpError('');
                  }}
                />
                <p
                  id="otpError"
                  role="alert"
                  aria-live="assertive"
                  className={`field-error ${otpError ? 'visible' : ''}`}
                >
                  {otpError}
                </p>
                <button type="submit">تأیید</button>
                <button
                  type="button"
                  className="btn-ghost"
                  disabled={resendTimer > 0}
                  onClick={() => {
                    if (authMethod === 'email') {
                      handleSendEmailOTP();
                    } else {
                      handleSendOTP();
                    }
                    startTimer();
                  }}
                >
                  {resendTimer > 0 ? `ارسال مجدد (${resendTimer})` : 'ارسال مجدد کد'}
                </button>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => {
                    setMsg({ text: '', isOk: false });
                    setOtpError('');
                    setStep(1);
                  }}
                >
                  برگشت
                </button>
                <p
                  id="msg2"
                  role="status"
                  aria-live="polite"
                  className={`auth-msg ${msg.isOk ? 'ok' : ''}`}
                >
                  {msg.isOk ? msg.text : ''}
                </p>
              </form>
            </>
          )}

          {step === 3 && (
            <>
              <div className="auth-logo">
                <div
                  className="logo-circle"
                  style={{ background: 'linear-gradient(135deg,#22c55e,#06b6d4)' }}
                  aria-hidden="true"
                >
                  👋
                </div>
                <h1>خوش آمدی!</h1>
                <p>قبل از ورود قوانین را بخوانید</p>
              </div>
              <div className="auth-form">
                <div className="id-preview" id="idPreview">
                  {authMethod === 'email' ? (
                    <bdi dir="ltr">{verifiedEmail}</bdi>
                  ) : (
                    <bdi dir="ltr">@{verifiedBaleId}</bdi>
                  )}
                </div>
                <div className="rules-check">
                  <input
                    type="checkbox"
                    id="rulesCheck"
                    checked={rulesChecked}
                    onChange={e => setRulesChecked(e.target.checked)}
                  />
                  <label htmlFor="rulesCheck">
                    <button
                      type="button"
                      onClick={handleOpenRules}
                      className="rules-link"
                      style={{
                        background: 'none',
                        border: 'none',
                        padding: 0,
                        font: 'inherit',
                        cursor: 'pointer',
                      }}
                    >
                      قوانین
                    </button>{' '}
                    را خواندم و می‌پذیرم
                  </label>
                </div>
                <button
                  type="button"
                  id="regBtn"
                  onClick={handleRegister}
                  disabled={!rulesChecked}
                  className={!rulesChecked ? 'btn-disabled' : ''}
                >
                  ورود به پیام‌رسان
                </button>
                <p id="msg3" className={`auth-msg ${msg.isOk ? 'ok' : ''}`}>
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
                  در صورتی که سرویس بله در دسترس نباشد، می‌توانید با این کد یک‌بارمصرف وارد حساب خود
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
                    const user = pendingAuthUsername || verifiedBaleId;
                    setIssuedRecoveryCode('');
                    onAuthenticated(user);
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
                <p>در صورت عدم دسترسی به سرویس بله از کد بازیابی یک‌بارمصرف استفاده کنید</p>
              </div>
              <form
                className="auth-form"
                noValidate
                onSubmit={e => {
                  e.preventDefault();
                  void handleRecoverLogin();
                }}
              >
                <label htmlFor="recoverBaleIdInput">
                  {authMethod === 'email' ? 'ایمیل' : 'آیدی بله'}{' '}
                  <span aria-hidden="true">*</span>
                </label>
                <div className="input-prefix">
                  {authMethod === 'bale' && <span aria-hidden="true">@</span>}
                  <input
                    type="text"
                    id="recoverBaleIdInput"
                    name="recoverBaleId"
                    placeholder={authMethod === 'email' ? 'you@example.com' : 'username123'}
                    dir="ltr"
                    autoComplete="username"
                    value={baleId}
                    onChange={e => {
                      setBaleId(e.target.value);
                      if (recoveryError) setRecoveryError('');
                    }}
                  />
                </div>
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
                  برگشت به {authMethod === 'email' ? 'ورود با ایمیل' : 'ورود با بله'}
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

      {rulesModalOpen && (
        <div
          className="modal"
          id="rulesModal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="rulesModalTitle"
        >
          <div className="modal-box" style={{ maxWidth: '400px' }}>
            <h3 id="rulesModalTitle">📋 قوانین پیام‌رسان</h3>
            <div
              style={{
                whiteSpace: 'pre-wrap',
                fontSize: '14px',
                lineHeight: 1.7,
                color: '#d1d5db',
                margin: '14px 0',
                maxHeight: '300px',
                overflowY: 'auto',
              }}
            >
              {rulesText}
            </div>
            <button
              type="button"
              onClick={() => setRulesModalOpen(false)}
              style={{ width: '100%' }}
            >
              متوجه شدم
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
