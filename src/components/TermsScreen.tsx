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
  const [deleteRecoveryCode, setDeleteRecoveryCode] = useState('');

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

  // Account deletion is confirmed with the one-time recovery code
  // (the Bale OTP channel is gone). The code is verified server-side
  // against the stored scrypt hash; accounts created before recovery
  // codes existed have no hash and are deleted on the session alone.
  const handleRequestDelete = async () => {
    if (!sessionUser || !sessionToken) {
      setActionStatus({ text: 'نشست کاربری معتبر نیست. لطفاً دوباره وارد شوید.', isError: true });
      return;
    }
    setConfirmDelete(true);
  };

  const handleDeleteAccount = async () => {
    if (!sessionUser || !sessionToken) return;
    const cleanCode = deleteRecoveryCode.trim();
    if (!cleanCode) {
      setActionStatus({ text: 'لطفاً کد بازیابی یک‌بارمصرف خود را وارد کنید.', isError: true });
      return;
    }
    try {
      const res = await fetch('/api/account/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ code: cleanCode }),
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
        setDeleteRecoveryCode('');
        setConfirmDelete(false);
        setActionStatus({ text: 'حساب کاربری و داده‌های شما به طور کامل حذف شد.' });
      } else {
        setActionStatus({
          text: res.msg || 'کد بازیابی نامعتبر است.',
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
        <header role="banner" aria-label="سربرگ صفحه" className="auth-banner">
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
                مسئولیت حفظ امنیت حساب بر عهده کاربر است. هرگز کد بازیابی یک‌بارمصرف خود را در
                اختیار دیگران قرار ندهید.
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
              ۶. حقوق داده، دریافت اطلاعات و حذف حساب کاربری:
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
                  حساب فعال: <bdi dir="ltr">{sessionUser}</bdi>
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
                      onClick={handleRequestDelete}
                    >
                      🗑️ حذف دائمی حساب کاربری
                    </button>
                  ) : (
                    <>
                      <label htmlFor="deleteRecoveryCodeInput" className="sr-only">
                        کد بازیابی یک‌بارمصرف حذف حساب
                      </label>
                      <input
                        id="deleteRecoveryCodeInput"
                        type="text"
                        dir="ltr"
                        maxLength={39}
                        placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                        value={deleteRecoveryCode}
                        onChange={e => setDeleteRecoveryCode(e.target.value)}
                        style={{
                          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                          fontSize: '13px',
                          textAlign: 'center',
                        }}
                      />
                      <p className="terms-section-note">
                        برای تأیید حذف، کد بازیابی یک‌بارمصرف خود را وارد کنید (همان کدی که هنگام
                        ورود دریافت کردید).
                      </p>
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

        <footer role="contentinfo" aria-label="پاصفحه" className="auth-footer">
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
