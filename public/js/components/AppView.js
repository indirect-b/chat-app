export function mountAppView(username) {
  const root = document.getElementById('root');
  if (!root) return;

  const initial = (username && username[0]) ? username[0].toUpperCase() : '?';

  root.innerHTML = `
    <div id="app" class="app">
      <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
          <div class="header-top">
            <button class="icon-btn" onclick="toggleSearch()" title="جستجو">
              <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            </button>
            <div class="my-story" onclick="showProfile()">
              <div class="story-avatar" id="myAvatar">${initial}</div>
              <div>
                <div id="myName" style="font-size:14px;font-weight:600">@${username}</div>
                <div id="myStatusLabel" style="font-size:11px;color:#9ca3af">آنلاین</div>
              </div>
            </div>
            <button class="icon-btn" onclick="showAddContact()" title="افزودن مخاطب">
              <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            </button>
          </div>
          <div id="searchBar" class="search-bar hidden">
            <input type="text" placeholder="جستجو..." id="searchInput" oninput="searchContacts()"/>
          </div>
        </div>
        <div class="tab-bar">
          <button class="tab-pill active" onclick="switchTab('chats',this)">چت‌ها</button>
          <button class="tab-pill" onclick="switchTab('groups',this)">گروه‌ها</button>
        </div>
        <div class="chat-list" id="chatList"></div>
        <div class="sidebar-footer">
          <button class="foot-btn" onclick="logout()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            خروج
          </button>
          <div class="my-id">@<span id="myIdDisplay">${username}</span></div>
        </div>
      </div>

      <div class="chat-area" id="chatArea">
        <div class="empty-state" id="emptyState">
          <div style="font-size:52px">💬</div>
          <p>یه مخاطب انتخاب کن</p>
          <small>با دکمه + مخاطب جدید اضافه کن</small>
        </div>

        <div id="chatView" class="chat-view hidden">
          <div class="chat-header">
            <button class="back-btn" onclick="goBack()">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"/></svg>
            </button>
            <div class="chat-header-info" onclick="showContactProfile()">
              <div class="chat-header-avatar" id="chatAvatar"></div>
              <div>
                <div class="chat-header-name" id="chatName"></div>
                <div class="chat-header-status" id="chatStatus">آفلاین</div>
              </div>
            </div>
            <button class="icon-btn" onclick="showContactProfile()" title="اطلاعات مخاطب">
              <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>
            </button>
          </div>

          <div class="pinned-bar hidden" id="pinnedBar">
            📌 <span id="pinnedText"></span>
          </div>

          <div class="messages-container" id="messagesContainer"></div>

          <div class="typing-indicator hidden" id="typingIndicator">
            <div class="typing-bubble">
              <span id="typingText">در حال تایپ</span>
              <div class="typing-dots"><span></span><span></span><span></span></div>
            </div>
          </div>

          <div class="reply-preview hidden" id="replyPreview">
            <div><div class="reply-label">ریپلای به:</div><div id="replyText" class="reply-text"></div></div>
            <button onclick="cancelReply()">✕</button>
          </div>

          <div class="input-area">
            <button class="icon-btn" onclick="toggleAttach()" title="ارسال فایل">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
            </button>
            <button class="icon-btn" id="voiceBtn" onmousedown="startVoice()" onmouseup="stopVoice()" ontouchstart="startVoice()" ontouchend="stopVoice()" title="نگه دار برای ضبط صدا">
              🎤
            </button>
            <input type="text" id="messageInput" placeholder="پیام..." oninput="handleTyping()" onkeydown="if(event.key==='Enter')sendMessage()"/>
            <button class="send-btn" onclick="sendMessage()">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
            </button>
          </div>

          <!-- Attach menu -->
          <div class="attach-menu hidden" id="attachMenu">
            <label class="attach-item">
              📷 عکس
              <input type="file" accept="image/*" onchange="uploadFile(this,'image')" hidden/>
            </label>
            <label class="attach-item">
              📁 فایل
              <input type="file" onchange="uploadFile(this,'file')" hidden/>
            </label>
            <div class="attach-item" onclick="showDisappear()">⏱ پیام ناپدید</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Context Menu -->
    <div class="ctx-menu hidden" id="ctxMenu">
      <div class="ctx-item" onclick="ctxReply()">↩ ریپلای</div>
      <div class="ctx-item" onclick="ctxEdit()">✏️ ویرایش</div>
      <div class="ctx-item" onclick="ctxForward()">↗️ فوروارد</div>
      <div class="ctx-item" onclick="ctxPin()">📌 پین</div>
      <div class="ctx-item" onclick="ctxReport()">🚨 گزارش</div>
      <div class="ctx-item ctx-danger" onclick="ctxDelete()">🗑 حذف</div>
    </div>
  `;
}
