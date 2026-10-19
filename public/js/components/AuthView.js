export function mountAuthView() {
  const root = document.getElementById('root');
  if (!root) return;

  root.innerHTML = `
    <div id="authScreen" class="auth-screen">
      <div id="step1" class="auth-box">
        <div class="auth-logo">
          <div class="logo-circle">💬</div>
          <h1>پیام‌رسان</h1>
          <p>ورود با آیدی بله</p>
        </div>
        <div class="auth-form">
          <label>آیدی بله</label>
          <div class="input-prefix">
            <span>@</span>
            <input type="text" id="baleIdInput" placeholder="your_id" autocomplete="off" onkeydown="if(event.key==='Enter')sendOTP()"/>
          </div>
          <button onclick="sendOTP()">دریافت کد تأیید</button>
          
          <div class="test-login-divider">
            <span>یا</span>
          </div>
          
          <button type="button" class="btn-test" onclick="quickTestLogin()" title="ورود فوری بدون نیاز به کد تأیید">
            ⚡ ورود سریع تستی (بدون نیاز به کد)
          </button>

          <div class="test-accounts-row">
            <button type="button" class="btn-ghost" onclick="quickTestLogin('کاربر_۱')">👤 اکانت ۱</button>
            <button type="button" class="btn-ghost" onclick="quickTestLogin('کاربر_۲')">👤 اکانت ۲</button>
          </div>

          <p id="msg1" class="auth-msg"></p>
        </div>
      </div>

      <div id="step2" class="auth-box hidden">
        <div class="auth-logo">
          <div class="logo-circle" style="background:linear-gradient(135deg,#06b6d4,#7c3aed)">🔐</div>
          <h1>کد تأیید</h1>
          <p id="step2desc">کد ارسال شده به بله رو وارد کن</p>
        </div>
        <div class="auth-form">
          <input type="text" id="otpInput" placeholder="● ● ● ● ● ●" maxlength="6" style="text-align:center;letter-spacing:10px;font-size:24px" onkeydown="if(event.key==='Enter')verifyOTP()"/>
          <button onclick="verifyOTP()">تأیید</button>
          <button class="btn-ghost" id="resendBtn" onclick="resendOTP()" disabled>ارسال مجدد (<span id="resendTimer">60</span>)</button>
          <button class="btn-ghost" onclick="showStep(1)">برگشت</button>
          <p id="msg2" class="auth-msg"></p>
        </div>
      </div>

      <div id="step3" class="auth-box hidden">
        <div class="auth-logo">
          <div class="logo-circle" style="background:linear-gradient(135deg,#22c55e,#06b6d4)">👋</div>
          <h1>خوش آمدی!</h1>
          <p>قبل از ورود قوانین را بخوانید</p>
        </div>
        <div class="auth-form">
          <div class="id-preview" id="idPreview"></div>
          <div class="rules-check">
            <input type="checkbox" id="rulesCheck" onchange="toggleRegBtn()"/>
            <label for="rulesCheck">
              <a href="#" onclick="showRules();return false;" class="rules-link">قوانین</a> را خواندم و می‌پذیرم
            </label>
          </div>
          <button id="regBtn" onclick="register()" disabled class="btn-disabled">ورود به پیام‌رسان</button>
          <p id="msg3" class="auth-msg"></p>
        </div>
      </div>
    </div>
  `;
}
