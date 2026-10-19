import { esc, closeModal } from '../utils.js';

function getModalRoot() {
  return document.getElementById('modalRoot');
}

export function renderMaintenanceScreen(msg) {
  const root = document.getElementById('root');
  if (!root) return;
  root.innerHTML = `
    <div id="maintenanceScreen" class="full-screen">
      <div class="maint-box">
        <div style="font-size:60px">🔧</div>
        <h1>در حال به‌روزرسانی</h1>
        <p id="maintMsg">${esc(msg || 'سرور در حال به‌روزرسانی است. لطفاً بعداً مراجعه کنید.')}</p>
      </div>
    </div>
  `;
}

export function renderBlockedScreen(data = {}) {
  const root = document.getElementById('root');
  if (!root) return;
  const untilText = data.block_type === 'permanent'
    ? 'مسدودیت دائمی'
    : 'مسدودیت موقت تا ' + new Date(data.block_until).toLocaleDateString('fa-IR');

  root.innerHTML = `
    <div id="maintenanceScreen" class="full-screen">
      <div class="maint-box">
        <div style="font-size:60px">🚫</div>
        <h1>حساب مسدود شد</h1>
        <p>علت: ${esc(data.block_reason || 'تخلف')}</p>
        <p>${esc(untilText)}</p>
      </div>
    </div>
  `;
}

export function openRulesModal(rulesText) {
  closeModal('rulesModal');
  const container = getModalRoot();
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'rulesModal';
  wrap.innerHTML = `
    <div class="modal-box" style="max-width:400px">
      <h3>📋 قوانین پیام‌رسان</h3>
      <div id="rulesText" style="white-space:pre-wrap;font-size:14px;line-height:1.7;color:#d1d5db;margin:14px 0;max-height:300px;overflow-y:auto">${esc(rulesText || 'قوانینی تنظیم نشده')}</div>
      <button onclick="closeModal('rulesModal')" style="width:100%">متوجه شدم</button>
    </div>
  `;
  container.appendChild(wrap);
}

export function openContactModal() {
  closeModal('contactModal');
  const container = getModalRoot();
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'contactModal';
  wrap.innerHTML = `
    <div class="modal-box">
      <h3>➕ افزودن مخاطب</h3>
      <input type="text" id="contactInput" placeholder="@آیدی_مخاطب" onkeydown="if(event.key==='Enter')addContact()"/>
      <div class="modal-btns" style="margin-top:10px">
        <button onclick="addContact()">افزودن</button>
        <button class="btn-ghost" onclick="closeModal('contactModal')">انصراف</button>
      </div>
      <p id="contactMsg" class="auth-msg" style="margin-top:8px"></p>
    </div>
  `;
  container.appendChild(wrap);
  setTimeout(() => document.getElementById('contactInput')?.focus(), 50);
}

export function openProfileModal(user, myUsername) {
  closeModal('profileModal');
  const container = getModalRoot();
  if (!container) return;
  const avatarContent = user?.avatar
    ? `<img src="${esc(user.avatar)}" style="width:70px;height:70px;border-radius:50%;object-fit:cover"/>`
    : (myUsername[0] ? myUsername[0].toUpperCase() : '?');

  const statusVal = user?.status || 'online';
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'profileModal';
  wrap.innerHTML = `
    <div class="modal-box">
      <h3>👤 پروفایل من</h3>
      <div style="text-align:center;margin-bottom:16px">
        <div id="profileAvatar" data-avatar-url="${esc(user?.avatar || '')}" style="width:70px;height:70px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#06b6d4);display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 10px;overflow:hidden">${avatarContent}</div>
        <label style="font-size:12px;color:#9ca3af;cursor:pointer">
          📷 تغییر عکس پروفایل
          <input type="file" accept="image/*" onchange="uploadAvatar(this)" hidden/>
        </label>
      </div>
      <label style="font-size:13px;color:#9ca3af">بیوگرافی</label>
      <input type="text" id="bioInput" value="${esc(user?.bio || '')}" placeholder="یه چیزی درباره خودت بنویس..."/>
      <label style="font-size:13px;color:#9ca3af">وضعیت</label>
      <select id="statusSelect" style="width:100%;margin-bottom:12px">
        <option value="online" ${statusVal === 'online' ? 'selected' : ''}>🟢 آنلاین</option>
        <option value="busy" ${statusVal === 'busy' ? 'selected' : ''}>🔴 مشغول</option>
        <option value="away" ${statusVal === 'away' ? 'selected' : ''}>🟡 غایب</option>
      </select>
      <div class="modal-btns">
        <button onclick="saveProfile()">ذخیره</button>
        <button class="btn-ghost" onclick="closeModal('profileModal')">انصراف</button>
      </div>
    </div>
  `;
  container.appendChild(wrap);
}

export function openContactProfileModal(user, isGroup, partnerName) {
  closeModal('contactProfileModal');
  const container = getModalRoot();
  if (!container) return;

  const avatarContent = user?.avatar
    ? `<img src="${esc(user.avatar)}" style="width:70px;height:70px;border-radius:50%;object-fit:cover"/>`
    : (partnerName[0] ? partnerName[0].toUpperCase() : '?');

  const statusText = isGroup
    ? 'گروه گفتگو'
    : (user?.status === 'online' ? '🟢 آنلاین' : user?.status === 'busy' ? '🔴 مشغول' : '🟡 غایب / آفلاین');

  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'contactProfileModal';
  wrap.innerHTML = `
    <div class="modal-box" style="text-align:center">
      <h3>${isGroup ? '👥 اطلاعات گروه' : '👤 اطلاعات مخاطب'}</h3>
      <div style="width:70px;height:70px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#06b6d4);display:flex;align-items:center;justify-content:center;font-size:28px;margin:14px auto 10px;overflow:hidden">${avatarContent}</div>
      <div style="font-size:16px;font-weight:700;margin-bottom:4px">${isGroup ? esc(partnerName) : '@' + esc(partnerName)}</div>
      <div style="font-size:12px;color:#9ca3af;margin-bottom:14px">${statusText}</div>
      ${!isGroup && user?.bio ? `<div style="background:rgba(255,255,255,.05);padding:10px;border-radius:10px;font-size:13px;margin-bottom:14px">${esc(user.bio)}</div>` : ''}
      <div class="modal-btns">
        <button class="btn-ghost" onclick="closeModal('contactProfileModal')">بستن</button>
      </div>
    </div>
  `;
  container.appendChild(wrap);
}

export function openEditModal(currentText) {
  closeModal('editModal');
  const container = getModalRoot();
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'editModal';
  wrap.innerHTML = `
    <div class="modal-box">
      <h3>✏️ ویرایش پیام</h3>
      <input type="text" id="editInput" value="${esc(currentText)}" onkeydown="if(event.key==='Enter')submitEdit()"/>
      <div class="modal-btns" style="margin-top:10px">
        <button onclick="submitEdit()">ذخیره</button>
        <button class="btn-ghost" onclick="closeModal('editModal')">انصراف</button>
      </div>
    </div>
  `;
  container.appendChild(wrap);
  setTimeout(() => document.getElementById('editInput')?.focus(), 50);
}

export function openForwardModal(itemsHtml) {
  closeModal('forwardModal');
  const container = getModalRoot();
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'forwardModal';
  wrap.innerHTML = `
    <div class="modal-box">
      <h3>↗️ فوروارد پیام</h3>
      <p>انتخاب کن کجا فوروارد بشه:</p>
      <div id="forwardList" style="max-height:200px;overflow-y:auto;margin-bottom:12px">
        ${itemsHtml || '<p style="text-align:center;color:#6b7280">مخاطب دیگری وجود ندارد</p>'}
      </div>
      <div class="modal-btns">
        <button onclick="submitForward()">فوروارد</button>
        <button class="btn-ghost" onclick="closeModal('forwardModal')">انصراف</button>
      </div>
    </div>
  `;
  container.appendChild(wrap);
}

export function openReportModal() {
  closeModal('reportModal');
  const container = getModalRoot();
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'reportModal';
  wrap.innerHTML = `
    <div class="modal-box">
      <h3>🚨 گزارش پیام</h3>
      <p>علت گزارش:</p>
      <select id="reportReason" style="width:100%;margin-bottom:12px">
        <option value="spam">اسپم</option>
        <option value="abuse">توهین</option>
        <option value="inappropriate">محتوای نامناسب</option>
        <option value="other">سایر</option>
      </select>
      <div class="modal-btns">
        <button onclick="submitReport()">ارسال گزارش</button>
        <button class="btn-ghost" onclick="closeModal('reportModal')">انصراف</button>
      </div>
    </div>
  `;
  container.appendChild(wrap);
}

export function openDisappearModal(currentTimer = 0) {
  closeModal('disappearModal');
  const container = getModalRoot();
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = 'modal';
  wrap.id = 'disappearModal';
  wrap.innerHTML = `
    <div class="modal-box">
      <h3>⏱ پیام ناپدیدشونده</h3>
      <p>بعد از چه مدتی پیام حذف شود؟</p>
      <select id="disappearTime">
        <option value="0" ${currentTimer === 0 ? 'selected' : ''}>غیرفعال</option>
        <option value="30" ${currentTimer === 30 ? 'selected' : ''}>۳۰ ثانیه</option>
        <option value="60" ${currentTimer === 60 ? 'selected' : ''}>۱ دقیقه</option>
        <option value="300" ${currentTimer === 300 ? 'selected' : ''}>۵ دقیقه</option>
        <option value="3600" ${currentTimer === 3600 ? 'selected' : ''}>۱ ساعت</option>
        <option value="86400" ${currentTimer === 86400 ? 'selected' : ''}>۲۴ ساعت</option>
      </select>
      <div class="modal-btns" style="margin-top:10px">
        <button onclick="setDisappear()">تأیید</button>
        <button class="btn-ghost" onclick="closeModal('disappearModal')">انصراف</button>
      </div>
    </div>
  `;
  container.appendChild(wrap);
}

export function openAnnounceModal(text, imageUrl) {
  closeModal('announceOverlay');
  const container = getModalRoot();
  if (!container) return;
  const wrap = document.createElement('div');
  wrap.className = 'announce-overlay';
  wrap.id = 'announceOverlay';
  wrap.innerHTML = `
    <div class="announce-box">
      <div class="announce-header">📢 اطلاع‌رسانی</div>
      ${imageUrl ? `<img id="announceImg" src="${esc(imageUrl)}" alt="" class="announce-img"/>` : ''}
      <p id="announceText">${esc(text || '')}</p>
      <button onclick="closeAnnounce()">متوجه شدم</button>
    </div>
  `;
  container.appendChild(wrap);
}
