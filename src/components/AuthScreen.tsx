import React, { useState, useEffect, useRef } from 'react';

interface AuthScreenProps {
  onAuthenticated: (username: string) => void;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthenticated }) => {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [baleId, setBaleId] = useState('');
  const [verifiedBaleId, setVerifiedBaleId] = useState('');
  const [otp, setOtp] = useState('');
  const [step2Desc, setStep2Desc] = useState('کد ارسال شده به بله رو وارد کن');
  const [resendTimer, setResendTimer] = useState(60);
  const [rulesChecked, setRulesChecked] = useState(false);
  const [rulesModalOpen, setRulesModalOpen] = useState(false);
  const [rulesText, setRulesText] = useState('');

  const [msg, setMsg] = useState<{ text: string; isOk: boolean; html?: boolean }>({
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

  const [baleIdInvalid, setBaleIdInvalid] = useState(false);

  const handleSendOTP = async () => {
    const clean = baleId.trim().replace('@', '');
    if (!clean) {
      setBaleIdInvalid(true);
      setMsg({ text: 'لطفاً آیدی بله خود را وارد کنید', isOk: false });
      return;
    }
    setBaleIdInvalid(false);
    const res = await fetch('/api/send-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baleId: clean }),
    }).then(r => r.json());

    if (res.ok) {
      setVerifiedBaleId(clean);
      if (res.needStart) {
        setMsg({
          text: '⚠️ ابتدا <a href="https://ble.ir/Optcodebot" target="_blank" rel="noopener noreferrer" style="color:#9d5cff">@Optcodebot</a> را در بله استارت کن',
          isOk: false,
          html: true,
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
          setStep(2);
          startTimer();
        }, 600);
      }
    } else {
      setBaleIdInvalid(true);
      setMsg({ text: res.msg, isOk: false });
    }
  };

  const handleVerifyOTP = async () => {
    const cleanCode = otp.trim();
    if (cleanCode.length !== 6) {
      setMsg({ text: 'کد ۶ رقمی وارد کن', isOk: false });
      return;
    }
    const res = await fetch('/api/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baleId: verifiedBaleId, code: cleanCode }),
    }).then(r => r.json());

    if (!res.ok) {
      setMsg({ text: res.msg, isOk: false });
      return;
    }

    if (!res.isNew) {
      setMsg({ text: '✅ خوش آمدی!', isOk: true });
      setTimeout(() => onAuthenticated(res.username), 400);
    } else {
      setMsg({ text: '', isOk: false });
      setStep(3);
    }
  };

  const handleRegister = async () => {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baleId: verifiedBaleId }),
    }).then(r => r.json());

    if (res.ok) {
      setMsg({ text: '✅ حساب ساخته شد!', isOk: true });
      setTimeout(() => onAuthenticated(res.username), 400);
    } else {
      setMsg({ text: res.msg, isOk: false });
    }
  };

  const handleOpenRules = async (e: React.MouseEvent) => {
    e.preventDefault();
    const res = await fetch('/api/settings/rules').then(r => r.json());
    setRulesText(res.rules || 'قوانینی تنظیم نشده');
    setRulesModalOpen(true);
  };

  const isBaleIdInvalid = baleIdInvalid || Boolean(msg.text && !msg.isOk);

  return (
    <main id="main-content" className="auth-screen" tabIndex={-1}>
      {step === 1 && (
        <div id="step1" className="auth-box">
          <header className="auth-logo">
            <div className="logo-circle" aria-hidden="true">💬</div>
            <h1>پیام‌رسان</h1>
            <p>ورود با آیدی بله • مجهز به رمزنگاری E2EE</p>
          </header>
          <div className="auth-form">
            <label htmlFor="baleIdInput">
              آیدی بله <span aria-hidden="true">*</span>
            </label>
            <div className={`input-prefix ${isBaleIdInvalid ? 'input-invalid' : ''}`}>
              <span aria-hidden="true">@</span>
              <input
                type="text"
                id="baleIdInput"
                aria-label="آیدی بله"
                required
                aria-required="true"
                aria-invalid={isBaleIdInvalid ? 'true' : 'false'}
                aria-describedby="baleIdHint msg1"
                placeholder="مثال: username123"
                autoComplete="username"
                value={baleId}
                onChange={e => {
                  setBaleId(e.target.value);
                  if (baleIdInvalid) setBaleIdInvalid(false);
                }}
                onKeyDown={e => e.key === 'Enter' && handleSendOTP()}
              />
            </div>
            <p id="baleIdHint" className="input-hint">
              آیدی بله خود را بدون @ وارد کنید (مثال: username123)
            </p>
            <button type="button" onClick={handleSendOTP}>
              دریافت کد تأیید
            </button>

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
              🤖 فعال‌سازی ربات کد تأیید در بله (@Optcodebot)
            </a>

            {msg.html ? (
              <p
                id="msg1"
                role="alert"
                className={`auth-msg ${msg.isOk ? 'ok' : ''}`}
                dangerouslySetInnerHTML={{ __html: msg.text }}
              />
            ) : (
              <p id="msg1" role="status" aria-live="polite" className={`auth-msg ${msg.isOk ? 'ok' : ''}`}>
                {msg.text}
              </p>
            )}
          </div>
          <footer className="auth-footer">
            <span>🔒 رمزنگاری سرتاسری</span>
            <button type="button" className="link-btn" onClick={handleOpenRules}>
              قوانین پیام‌رسان
            </button>
          </footer>
        </div>
      )}

      {step === 2 && (
        <div id="step2" className="auth-box">
          <header className="auth-logo">
            <div
              className="logo-circle"
              style={{ background: 'linear-gradient(135deg,#06b6d4,#7c3aed)' }}
              aria-hidden="true"
            >
              🔐
            </div>
            <h1>کد تأیید</h1>
            <p id="step2desc">{step2Desc}</p>
          </header>
          <div className="auth-form">
            <input
              type="text"
              id="otpInput"
              aria-label="کد تأیید"
              required
              aria-required="true"
              aria-invalid={Boolean(msg.text && !msg.isOk) ? 'true' : 'false'}
              placeholder="● ● ● ● ● ●"
              maxLength={6}
              style={{ textAlign: 'center', letterSpacing: '10px', fontSize: '24px' }}
              value={otp}
              onChange={e => setOtp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleVerifyOTP()}
            />
            <button type="button" onClick={handleVerifyOTP}>
              تأیید
            </button>
            <button
              type="button"
              className="btn-ghost"
              disabled={resendTimer > 0}
              onClick={() => {
                handleSendOTP();
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
                setStep(1);
              }}
            >
              برگشت
            </button>
            <p id="msg2" className={`auth-msg ${msg.isOk ? 'ok' : ''}`}>
              {msg.text}
            </p>
          </div>
        </div>
      )}

      {step === 3 && (
        <div id="step3" className="auth-box">
          <header className="auth-logo">
            <div
              className="logo-circle"
              style={{ background: 'linear-gradient(135deg,#22c55e,#06b6d4)' }}
              aria-hidden="true"
            >
              👋
            </div>
            <h1>خوش آمدی!</h1>
            <p>قبل از ورود قوانین را بخوانید</p>
          </header>
          <div className="auth-form">
            <div className="id-preview" id="idPreview">
              @{verifiedBaleId}
            </div>
            <div className="rules-check">
              <input
                type="checkbox"
                id="rulesCheck"
                checked={rulesChecked}
                onChange={e => setRulesChecked(e.target.checked)}
              />
              <label htmlFor="rulesCheck">
                <a href="#" onClick={handleOpenRules} className="rules-link">
                  قوانین
                </a>{' '}
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
        </div>
      )}

      {rulesModalOpen && (
        <div className="modal" id="rulesModal" role="dialog" aria-modal="true" aria-labelledby="rulesModalTitle">
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
    </main>
  );
};
