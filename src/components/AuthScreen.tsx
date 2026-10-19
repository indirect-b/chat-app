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

  const handleQuickTestLogin = async (targetUser?: string) => {
    const cleanInput = baleId.trim().replace('@', '');
    const username = targetUser || cleanInput || 'کاربر_۱';
    setMsg({ text: 'در حال ورود سریع...', isOk: true });
    try {
      const res = await fetch('/api/quick-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      }).then(r => r.json());

      if (res.ok) {
        setMsg({ text: '✅ با موفقیت وارد شدید!', isOk: true });
        setTimeout(() => onAuthenticated(res.username), 150);
      } else {
        setMsg({ text: res.msg || 'خطا در ورود تستی', isOk: false });
      }
    } catch {
      setMsg({ text: 'خطا در برقراری ارتباط با سرور', isOk: false });
    }
  };

  const handleSendOTP = async () => {
    const clean = baleId.trim().replace('@', '');
    if (!clean) return;
    const res = await fetch('/api/send-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baleId: clean }),
    }).then(r => r.json());

    if (res.ok) {
      setVerifiedBaleId(clean);
      if (res.needStart) {
        setMsg({
          text: '⚠️ ابتدا <a href="https://ble.ir/Optcodebot" target="_blank" style="color:#9d5cff">@Optcodebot</a> را در بله استارت کن',
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

  return (
    <div id="authScreen" className="auth-screen">
      {step === 1 && (
        <div id="step1" className="auth-box">
          <div className="auth-logo">
            <div className="logo-circle">💬</div>
            <h1>پیام‌رسان</h1>
            <p>ورود با آیدی بله • مجهز به رمزنگاری E2EE</p>
          </div>
          <div className="auth-form">
            <label>آیدی بله</label>
            <div className="input-prefix">
              <span>@</span>
              <input
                type="text"
                id="baleIdInput"
                placeholder="your_id"
                autoComplete="off"
                value={baleId}
                onChange={e => setBaleId(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSendOTP()}
              />
            </div>
            <button type="button" onClick={handleSendOTP}>
              دریافت کد تأیید
            </button>

            <div className="test-login-divider">
              <span>یا</span>
            </div>

            <button
              type="button"
              className="btn-test"
              onClick={() => handleQuickTestLogin()}
              title="ورود فوری بدون نیاز به کد تأیید"
            >
              ⚡ ورود سریع تستی (بدون نیاز به کد)
            </button>

            <div className="test-accounts-row">
              <button
                type="button"
                className="btn-ghost"
                onClick={() => handleQuickTestLogin('کاربر_۱')}
              >
                👤 اکانت ۱
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => handleQuickTestLogin('کاربر_۲')}
              >
                👤 اکانت ۲
              </button>
            </div>

            {msg.html ? (
              <p
                id="msg1"
                className={`auth-msg ${msg.isOk ? 'ok' : ''}`}
                dangerouslySetInnerHTML={{ __html: msg.text }}
              />
            ) : (
              <p id="msg1" className={`auth-msg ${msg.isOk ? 'ok' : ''}`}>
                {msg.text}
              </p>
            )}
          </div>
        </div>
      )}

      {step === 2 && (
        <div id="step2" className="auth-box">
          <div className="auth-logo">
            <div
              className="logo-circle"
              style={{ background: 'linear-gradient(135deg,#06b6d4,#7c3aed)' }}
            >
              🔐
            </div>
            <h1>کد تأیید</h1>
            <p id="step2desc">{step2Desc}</p>
          </div>
          <div className="auth-form">
            <input
              type="text"
              id="otpInput"
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
          <div className="auth-logo">
            <div
              className="logo-circle"
              style={{ background: 'linear-gradient(135deg,#22c55e,#06b6d4)' }}
            >
              👋
            </div>
            <h1>خوش آمدی!</h1>
            <p>قبل از ورود قوانین را بخوانید</p>
          </div>
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
        <div className="modal" id="rulesModal">
          <div className="modal-box" style={{ maxWidth: '400px' }}>
            <h3>📋 قوانین پیام‌رسان</h3>
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
