// Privacy policy page (public, no login required).
// Served by Express at GET /privacy as a plain HTML document — no scripts,
// no inline styles, no external resources — so it renders under the strict
// CSP (styleSrc 'self', no unsafe-inline). Content is factual and mirrors
// what the code actually does; keep it in sync with the sign-in methods
// (Bale / email OTP / Google Sign-In) and the account-deletion endpoint
// (POST /api/account/delete).
export const PRIVACY_HTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Privacy Policy — chat-app | سیاست حریم خصوصی</title>
  <meta name="description" content="سیاست حریم خصوصی پیام‌رسان: چه داده‌ای جمع می‌کنیم و با آن چه می‌کنیم. Privacy policy of the chat app: what data we collect and what we do with it."/>
</head>
<body>
  <main>
    <h1>سیاست حریم خصوصی — پیام‌رسان</h1>
    <p>آخرین به‌روزرسانی: ۱۹ نوامبر ۲۰۲۶</p>
    <p>این صفحه توضیح می‌دهد پیام‌رسان چه داده‌ای جمع می‌کند و با آن چه می‌کند.</p>
    <h2>چه داده‌ای جمع می‌کنیم</h2>
    <ul>
      <li>شناسه‌ی ورود شما: آیدی بله، یا آدرس ایمیل شما (با کد تأیید ایمیل یا با ورود با گوگل).</li>
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
    <hr/>
    <div dir="ltr" lang="en">
      <h1>Privacy Policy — chat-app</h1>
      <p>Last updated: 19 November 2026</p>
      <p>This page explains what data the chat app collects and what it does with it.</p>
      <h2>What we collect</h2>
      <ul>
        <li>Your sign-in identifier: your Bale ID, or your email address (via an email code or Google Sign-In).</li>
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
  </main>
</body>
</html>`;
