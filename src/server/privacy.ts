// Privacy policy page (public, no login required).
// Served by Express at GET /privacy as a styled HTML document — one
// inline <style> block only, no scripts, no external resources, no user
// data, system fonts only. The route sets a page-specific CSP that
// allows inline styles and nothing else (style-src 'unsafe-inline',
// script-src 'none'), because the global Helmet CSP forbids them.
// Content is factual and mirrors what the code actually does; keep it
// in sync with the sign-in methods (Google Sign-In only; legacy Bale-ID
// accounts keep their Bale ID as their identifier) and the
// account-deletion endpoint (POST /api/account/delete, confirmed with
// the one-time recovery code).
export const PRIVACY_HTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Privacy Policy — chat-app | سیاست حریم خصوصی</title>
  <meta name="description" content="سیاست حریم خصوصی پیام‌رسان: چه داده‌ای جمع می‌کنیم و با آن چه می‌کنیم. Privacy policy of the chat app: what data we collect and what we do with it."/>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Tahoma, 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f0f1a, #16213e, #0f3460);
      background-attachment: fixed;
      color: #f0f0f0;
      line-height: 1.8;
      padding: 28px 16px 48px;
    }
    .page { max-width: 720px; margin: 0 auto; }
    .card {
      background: rgba(255, 255, 255, .05);
      border: 1px solid rgba(255, 255, 255, .1);
      border-radius: 24px;
      padding: 32px 28px;
      backdrop-filter: blur(20px);
    }
    .brand { text-align: center; margin-bottom: 24px; }
    .brand-icon {
      width: 68px; height: 68px;
      background: linear-gradient(135deg, #7c3aed, #06b6d4);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 14px;
      font-size: 28px;
      box-shadow: 0 0 40px rgba(124, 58, 237, .4);
    }
    h1 { font-size: 22px; font-weight: 700; text-align: center; }
    .updated {
      text-align: center; font-size: 12.5px; color: #9ca3af;
      margin-top: 6px;
    }
    .intro { text-align: center; color: #d1d5db; font-size: 14px; margin: 14px 0 4px; }
    h2 {
      font-size: 16px; font-weight: 700; color: #f0f0f0;
      margin: 26px 0 10px; padding-bottom: 8px;
      border-bottom: 1px solid rgba(255, 255, 255, .1);
    }
    h2::before {
      content: '';
      display: inline-block; width: 8px; height: 8px; border-radius: 50%;
      background: linear-gradient(135deg, #7c3aed, #06b6d4);
      margin-left: 8px; vertical-align: middle;
    }
    ul { list-style: none; display: flex; flex-direction: column; gap: 10px; }
    ul li {
      background: rgba(255, 255, 255, .04);
      border: 1px solid rgba(255, 255, 255, .08);
      border-radius: 12px;
      padding: 11px 14px;
      font-size: 14px; color: #e5e7eb;
    }
    p { font-size: 14px; color: #e5e7eb; }
    a { color: #67e8f9; }
    .badge {
      display: inline-block; font-size: 12px; font-weight: 600;
      color: #67e8f9; background: rgba(6, 182, 212, .12);
      border: 1px solid rgba(6, 182, 212, .35);
      border-radius: 999px; padding: 3px 12px; margin-top: 4px;
    }
    .divider {
      display: flex; align-items: center; gap: 10px;
      color: #9ca3af; font-size: 12px; margin: 34px 0 6px;
    }
    .divider::before, .divider::after {
      content: ''; flex: 1; height: 1px;
      background: rgba(255, 255, 255, .2);
    }
    .en { direction: ltr; text-align: left; }
    .en h2::before { margin-left: 0; margin-right: 8px; }
    .footer { text-align: center; margin-top: 26px; font-size: 13px; color: #9ca3af; }
    .footer a { color: #67e8f9; text-decoration: underline; }
  </style>
</head>
<body>
  <div class="page">
    <div class="card">
      <div class="brand">
        <div class="brand-icon">🔒</div>
        <h1>سیاست حریم خصوصی — پیام‌رسان</h1>
        <p class="updated">آخرین به‌روزرسانی: ۱۹ نوامبر ۲۰۲۶</p>
        <p class="intro">این صفحه توضیح می‌دهد پیام‌رسان چه داده‌ای جمع می‌کند و با آن چه می‌کند.</p>
        <span class="badge">🔒 رمزنگاری سرتاسری</span>
      </div>
      <h2>چه داده‌ای جمع می‌کنیم</h2>
      <ul>
        <li>شناسه‌ی ورود شما: آدرس ایمیل شما (با ورود با گوگل). حساب‌هایی که پیش از این با آیدی بله ساخته شده‌اند، همچنان با همان آیدی شناخته می‌شوند.</li>
        <li>پیام‌های شما: پیام‌ها روی سرور به‌صورت رمزگذاری‌شده ذخیره می‌شوند. سرور نمی‌تواند آن‌ها را بخواند، چون رمزنگاری سرتاسری است و کلیدها فقط روی دستگاه شما و دستگاه طرف مقابل است.</li>
        <li>کد بازیابی: فقط هش نمکی (scrypt) کد بازیابی یک‌بارمصرف شما ذخیره می‌شود؛ خود کد هرگز ذخیره نمی‌شود.</li>
        <li>ورود با گوگل: گوگل فقط آدرس ایمیل و نام شما را برای ساخت حساب در اختیار ما می‌گذارد.</li>
      </ul>
      <h2>داده‌ها کجا ذخیره می‌شوند</h2>
      <p>داده‌های حساب در پایگاه‌داده‌ی پیام‌رسان روی Render نگهداری می‌شوند.</p>
      <h2>حذف حساب</h2>
      <p>می‌توانید حسابتان را از داخل برنامه حذف کنید: صفحه‌ی قوانین، بخش حذف حساب؛ حذف با یک کد تأیید یک‌بارمصرف تأیید می‌شود و حساب، پیام‌های ارسالی و مخاطب‌های شما را از سرور پاک می‌کند.</p>
      <h2>ردیابی</h2>
      <p>این برنامه هیچ ابزار تحلیل (آنالیتیکس) و هیچ ردیاب تبلیغاتی ندارد.</p>
      <h2>تماس</h2>
      <p>برای سؤال درباره‌ی حریم خصوصی: <a href="mailto:indirectnebula6@gmail.com">indirectnebula6@gmail.com</a></p>
      <div class="divider"><span>English</span></div>
      <div class="en" lang="en">
        <div class="brand">
          <h1>Privacy Policy — chat-app</h1>
          <p class="updated">Last updated: 19 November 2026</p>
          <p class="intro">This page explains what data the chat app collects and what it does with it.</p>
        </div>
        <h2>What we collect</h2>
        <ul>
          <li>Your sign-in identifier: your email address (via Google Sign-In). Accounts created earlier with a Bale ID are still identified by that Bale ID.</li>
          <li>Your messages: messages are stored on the server in encrypted form. The server cannot read them, because they are end-to-end encrypted and the keys live only on your device and your contact's device.</li>
          <li>Your recovery code: only a salted (scrypt) hash of your one-time recovery code is stored; the code itself is never stored.</li>
          <li>Google Sign-In: Google shares only your email address and name with us, to create your account.</li>
        </ul>
        <h2>Where data is stored</h2>
        <p>Account data is kept in the app's database on Render.</p>
        <h2>Deleting your account</h2>
        <p>You can delete your account from inside the app (Terms page, account deletion); deletion is confirmed with a one-time code and removes your account, your sent messages and your contacts from the server.</p>
        <h2>Tracking</h2>
        <p>This app uses no analytics and no advertising trackers.</p>
        <h2>Contact</h2>
        <p>Privacy questions: <a href="mailto:indirectnebula6@gmail.com">indirectnebula6@gmail.com</a></p>
      </div>
      <div class="footer"><a href="/">بازگشت به پیام‌رسان</a></div>
    </div>
  </div>
</body>
</html>`;
