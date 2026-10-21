import React, { useState } from 'react';

const SESSION_KEY = 'chat_session_user';
const SESSION_TOKEN_KEY = 'chat_session_token';
const TERMS_ACK_KEY = 'chat_terms_acknowledged';

interface TermsScreenProps {
  onNavigate?: (path: string) => void;
}

export const TermsScreen: React.FC<TermsScreenProps> = ({ onNavigate }) => {
  const [sessionUser, setSessionUser] = useState<string>(() => {
    try {
      return localStorage.getItem(SESSION_KEY) || '';
    } catch {
      return '';
    }
  });
  const [sessionToken, setSessionToken] = useState<string>(() => {
    try {
      return localStorage.getItem(SESSION_TOKEN_KEY) || '';
    } catch {
      return '';
    }
  });
  const [actionStatus, setActionStatus] = useState<{ text: string; isError?: boolean } | null>(
    null
  );
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteOtp, setDeleteOtp] = useState('');

  const navigateTo = (path: string, e?: React.MouseEvent) => {
    if (e) e.preventDefault();
    if (onNavigate) {
      onNavigate(path);
    } else {
      window.location.href = path;
    }
  };

  const handleAcceptTerms = () => {
    try {
      localStorage.setItem(TERMS_ACK_KEY, 'true');
      localStorage.setItem('terms_accepted_at', new Date().toISOString());
    } catch {
      // ignore storage errors
    }
    navigateTo('/');
  };

  const handleExportData = async () => {
    if (!sessionUser || !sessionToken) {
      setActionStatus({ text: 'نشست کاربری معتبر نیست. لطفاً دوباره وارد شوید.', isError: true });
      return;
    }
    try {
      const res = await fetch('/api/account/export', {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      if (!res.ok) {
        setActionStatus({ text: 'خطا در دریافت اطلاعات حساب کاربری.', isError: true });
        return;
      }
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json;charset=utf-8',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `account-data-${sessionUser}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setActionStatus({ text: 'نسخه پشتیبان داده‌های حساب شما با موفقیت دریافت شد.' });
    } catch {
      setActionStatus({ text: 'خطا در ارتباط با سرور.', isError: true });
    }
  };

  const handleRequestDeleteOtp = async () => {
    if (!sessionUser || !sessionToken) {
      setActionStatus({ text: 'نشست کاربری معتبر نیست. لطفاً دوباره وارد شوید.', isError: true });
      return;
    }
    setConfirmDelete(true);
    try {
      const res = await fetch('/api/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baleId: sessionUser }),
      }).then(r => r.json());
      if (res.ok) {
        setActionStatus({
          text: res.msg || 'کد تأیید برای حذف حساب به بله شما ارسال شد.',
        });
      } else {
        setActionStatus({ text: res.msg || 'خطا در ارسال کد تأیید.', isError: true });
      }
    } catch {
      setActionStatus({ text: 'خطا در ارتباط با سرور.', isError: true });
    }
  };

  const handleDeleteAccount = async () => {
    if (!sessionUser || !sessionToken) return;
    const cleanOtp = deleteOtp.trim();
    if (!/^\d{6}$/.test(cleanOtp)) {
      setActionStatus({ text: 'لطفاً کد تأیید ۶ رقمی را وارد کنید.', isError: true });
      return;
    }
    try {
      const res = await fetch('/api/account/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ otp: cleanOtp }),
      }).then(r => r.json());

      if (res.ok) {
        try {
          localStorage.removeItem(SESSION_KEY);
          localStorage.removeItem(SESSION_TOKEN_KEY);
        } catch {
          // ignore
        }
        setSessionUser('');
        setSessionToken('');
        setDeleteOtp('');
        setConfirmDelete(false);
        setActionStatus({ text: 'حساب کاربری و داده‌های شما به طور کامل حذف شد.' });
      } else {
        setActionStatus({
          text: res.msg || 'کد تأیید نامعتبر یا منقضی است.',
          isError: true,
        });
      }
    } catch {
      setActionStatus({ text: 'خطا در ارتباط با سرور.', isError: true });
    }
  };

  return (
    <div className="terms-screen">
      <div className="terms-box">
        <header className="auth-banner">
          <div className="auth-brand">
            <span className="auth-brand-icon" aria-hidden="true">
              💬
            </span>
            <span className="auth-brand-name">پیام‌رسان</span>
          </div>
          <nav aria-label="ناوبری اصلی" className="auth-top-nav">
            <a href="/" className="link-btn" onClick={e => navigateTo('/', e)}>
              صفحه اصلی
            </a>
            <span className="footer-sep" aria-hidden="true">
              •
            </span>
            <a href="/login" className="link-btn" onClick={e => navigateTo('/login', e)}>
              صفحه ورود
            </a>
          </nav>
        </header>

        <main id="main-content" tabIndex={-1}>
          <div className="auth-logo">
            <div className="logo-circle" aria-hidden="true">
              📋
            </div>
            <h1>قوانین و مقررات پیام‌رسان</h1>
            <p>لطفاً پیش از استفاده از سامانه، موارد زیر را مطالعه فرمایید</p>
          </div>

          <div className="terms-list">
            <section>
              <h2 className="terms-section-title">۱. احترام متقابل:</h2>
              <p className="terms-section-desc">
                رعایت ادب و احترام به سایر کاربران در تمامی گفتگوهای خصوصی و گروهی الزامی است و
                هرگونه توهین یا تهدید موجب مسدودیت حساب خواهد شد.
              </p>
            </section>
            <section>
              <h2 className="terms-section-title">۲. ممنوعیت هرزنامه (اسپم):</h2>
              <p className="terms-section-desc">
                ارسال پیام‌های تبلیغاتی ناخواسته، پیام‌های تکراری خودکار و ایجاد مزاحمت برای کاربران
                ممنوع است.
              </p>
            </section>
            <section>
              <h2 className="terms-section-title">۳. محتوای غیرقانونی و آسیب‌زا:</h2>
              <p className="terms-section-desc">
                انتشار هرگونه محتوای خلاف قوانین، بدافزار، فیشینگ، کلاهبرداری یا محتوای آسیب‌زا
                اکیداً ممنوع است.
              </p>
            </section>
            <section>
              <h2 className="terms-section-title">۴. حفاظت از حساب کاربری:</h2>
              <p className="terms-section-desc">
                مسئولیت حفظ امنیت حساب بر عهده کاربر است. هرگز کد تأیید یک‌بارمصرف (OTP) دریافتی در
                بله یا کلیدهای امنیتی خود را در اختیار دیگران قرار ندهید.
              </p>
            </section>
            <section>
              <h2 className="terms-section-title">۵. حریم خصوصی و رمزنگاری سرتاسری (E2EE):</h2>
              <p className="terms-section-desc">
                پیام‌های شما در این سامانه با رمزنگاری سرتاسری پساکوانتومی محافظت می‌شوند؛ به طوری
                که تنها فرستنده و گیرنده قادر به رمزگشایی و مطالعه محتوای پیام‌ها هستند.
              </p>
            </section>
          </div>

          <section
            id="data-rights"
            className="terms-data-rights"
            aria-labelledby="dataRightsHeading"
          >
            <h2 id="dataRightsHeading" className="terms-section-title">
              ۶. حقوق داده، دریافت اطلاعات و حذف حساب کاربری
            </h2>
            <p className="terms-section-desc">
              کاربران در هر زمان حق دارند نسخه کامل داده‌های ذخیره شده خود (مشخصات حساب، فهرست
              مخاطبان و پیام‌ها) را دریافت کنند یا درخواست حذف دائمی حساب کاربری و کلیه داده‌های
              مرتبط را ثبت نمایند. همچنین در داخل گفتگوها می‌توانید هر پیام ارسالی خود را از طریق
              منوی پیام حذف کنید.
            </p>

            {sessionUser && sessionToken ? (
              <div className="data-rights-actions">
                <p className="data-rights-user">
                  حساب فعال: <bdi dir="ltr">@{sessionUser}</bdi>
                </p>
                <div className="data-rights-btn-row">
                  <button
                    type="button"
                    className="btn-secondary-outline"
                    onClick={handleExportData}
                  >
                    📥 دریافت نسخه داده‌های حساب (JSON)
                  </button>
                  {!confirmDelete ? (
                    <button
                      type="button"
                      className="btn-danger-outline"
                      onClick={handleRequestDeleteOtp}
                    >
                      🗑️ حذف دائمی حساب کاربری
                    </button>
                  ) : (
                    <>
                      <label htmlFor="deleteOtpInput" className="sr-only">
                        کد تأیید ۶ رقمی حذف حساب
                      </label>
                      <input
                        id="deleteOtpInput"
                        type="text"
                        inputMode="numeric"
                        maxLength={6}
                        dir="ltr"
                        placeholder="کد تأیید ۶ رقمی"
                        value={deleteOtp}
                        onChange={e => setDeleteOtp(e.target.value)}
                      />
                      <button
                        type="button"
                        className="btn-danger-confirm"
                        onClick={handleDeleteAccount}
                      >
                        تأیید حذف نهایی حساب و داده‌ها
                      </button>
                    </>
                  )}
                </div>
              </div>
            ) : (
              <p className="terms-section-note">
                برای دریافت خروجی داده‌ها یا حذف دائمی حساب خود به صورت خودکار، ابتدا از طریق{' '}
                <a href="/login" className="rules-link" onClick={e => navigateTo('/login', e)}>
                  صفحه ورود
                </a>{' '}
                وارد حساب کاربری خود شوید و سپس به همین بخش مراجعه نمایید.
              </p>
            )}

            {actionStatus && (
              <p
                role="status"
                aria-live="polite"
                className={`auth-msg ${actionStatus.isError ? '' : 'ok'}`}
                style={{ marginTop: '8px' }}
              >
                {actionStatus.text}
              </p>
            )}
          </section>

          <div className="terms-actions">
            <button
              type="button"
              id="acceptTermsBtn"
              className="terms-accept-btn"
              onClick={handleAcceptTerms}
            >
              قوانین و مقررات را خواندم و می‌پذیرم
            </button>
            <a
              href="/"
              className="terms-back-link"
              onClick={e => navigateTo('/', e)}
            >
              بازگشت به صفحه اصلی پیام‌رسان
            </a>
          </div>
        </main>

        <footer className="auth-footer">
          <nav aria-label="پیوندهای پاصفحه" className="auth-footer-nav">
            <a href="/" className="link-btn" onClick={e => navigateTo('/', e)}>
              صفحه اصلی
            </a>
            <span className="footer-sep" aria-hidden="true">
              •
            </span>
            <a href="/login" className="link-btn" onClick={e => navigateTo('/login', e)}>
              صفحه ورود
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
