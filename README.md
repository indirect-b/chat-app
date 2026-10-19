# 💬 Persian Real-Time Web Messenger (`chat-app`)

A full-stack, high-performance **Real-Time Web Messenger** engineered with a **Telegram-Web-inspired Modular Single Page Application (SPA)** architecture. Built on **Node.js**, **Express**, **Socket.IO**, and **PostgreSQL** (with an automatic zero-configuration **In-Memory Database Fallback**), this platform delivers instantaneous bi-directional communication, voice messaging, file sharing, group chats, disappearing messages, and a comprehensive administration suite tailored for RTL (Right-to-Left) Persian interfaces.

---

## 🌟 Key Features & Capabilities

### 👤 User & Messaging Features
* **Telegram-Web Style SPA Architecture:** Zero page reloads. Views and modals are dynamically mounted and unmounted in the DOM based on authentication state.
* **Persistent Client Sessions (`LocalStorage`):** Users remain logged in across browser refreshes (`F5`) and tab restarts until they explicitly log out.
* **Bale Messenger OTP Authentication:** Secure 6-digit One-Time Password (OTP) verification delivered directly via the Bale Bot API (`@Optcodebot`), plus a development OTP fallback when no bot token is configured.
* **Instant 1-Click Demo Login:** Built-in **Quick Test Login** (`⚡ ورود سریع تستی`) and pre-linked test accounts (`Account 1` & `Account 2`) for zero-effort multi-tab testing.
* **Real-Time Private & Group Chats:** Instant message delivery, live typing indicators (`در حال تایپ...`), online/offline presence tracking, custom status labels (`Online`, `Busy`, `Away`), and read receipts (`✓✓`).
* **Rich Media & Voice Messaging:**
  * Built-in browser voice recorder (`MediaRecorder` API) for hold-to-record voice notes (`.webm`).
  * Image and document uploads (up to 50MB) via `multer`.
* **Interactive Message Controls:**
  * **Reply:** Quoted message replies.
  * **Edit:** Real-time message editing with `(ویرایش شده)` indicators.
  * **Delete:** Instant message removal for all participants.
  * **Pin:** Pin important messages to the top header of any chat room.
  * **Forward:** Multi-select forwarding across contacts and groups.
  * **Emoji Reactions:** Interactive emoji reaction pills with live user counters.
  * **Disappearing Messages (Self-Destruct Timer):** Configurable auto-delete timers (`30s`, `1m`, `5m`, `1h`, `24h`).

### 🛡️ Admin Panel & Moderation Suite
* **Dedicated Admin Dashboard (`/panel-Tk_tokyo`):**
  * **Live Analytics & 7-Day Chart:** Track total users, online connections, active messages, groups, pending reports, and daily message volume over the past 7 days.
  * **User Moderation:** Block users permanently or temporarily (with automatic expiration and Bale Bot notifications), unblock users, or kick active socket sessions in real time.
  * **Impersonation ("Login As User"):** Generate one-time 30-second temporary tokens to inspect a user's session for troubleshooting.
  * **Group Management:** Create groups and assign members dynamically.
  * **Message Inspection & Deletion:** Browse recent messages grouped by room and delete inappropriate content.
  * **Abuse Report Management:** Review user-submitted reports (`spam`, `abuse`, `inappropriate`, `other`) and mark them resolved.
  * **Global Broadcasts & Maintenance Mode:** Send real-time pop-up announcements (with optional images) to all connected users and Bale subscribers, or toggle server-wide Maintenance Mode.

---

## 🏗️ System Architecture & Design Principles

### 1. Dynamic DOM Mounting (Security & Cleanliness)
Unlike traditional monolithic SPAs that hide the main application container using `display: none` (`.hidden`), this project uses **Dynamic DOM Mounting**:
* **Unauthenticated State:** When a user visits the app, `#root` **only** mounts `AuthView.js`. The chat sidebar, message containers, and modals **do not exist in the DOM**, preventing unauthenticated users from inspecting or unhiding the application shell via browser DevTools.
* **Authenticated State:** Upon login or session restoration, `AuthView` is completely destroyed and unmounted from memory, and `AppView.js` is dynamically constructed inside `#root`.
* **On-Demand Modals:** Pop-up dialogs (Profile, Contact Info, Forward, Edit, Report, Rules, Disappear Timer) are created inside `#modalRoot` **only at the moment they are opened** and are completely removed from the DOM when closed.

### 2. Resilient Dual-Mode Database Layer (`PostgreSQL` + `In-Memory Fallback`)
To prevent fatal server crashes (`Exited with status 1`) when `DATABASE_URL` is unconfigured or when a cloud PostgreSQL instance goes offline:
* `db.js` attempts to initialize a connection pool to PostgreSQL.
* If `DATABASE_URL` is omitted or unreachable, `db.js` seamlessly switches to `MemoryDatabase`—a custom in-memory SQL query engine that supports all application tables (`users`, `contacts`, `messages`, `groups`, `reports`, `settings`) and statistical queries without interrupting uptime.

---

## 📋 Changelog & Recent Architectural Upgrades

1. **Refactored Frontend into a Modular ES6 SPA (`public/js/` & `public/css/`):**
   * Replaced the monolithic `public/app.js` file with a structured hierarchy of ES Modules (`state.js`, `socket.js`, `utils.js`, `main.js`, `components/*`, and `modules/*`).
   * Split `public/style.css` into modular stylesheets (`base.css`, `auth.css`, `chat.css`, `modals.css`).
2. **Implemented Dynamic View & Modal Rendering:**
   * Stripped all hardcoded application HTML from `public/index.html`, leaving a clean shell (`#root`, `#modalRoot`, `#toastRoot`).
   * Created `AuthView.js`, `AppView.js`, and `Modals.js` for on-demand DOM lifecycle management.
3. **Added Client-Side Session Persistence (`LocalStorage`):**
   * Implemented `saveSession()`, `getSavedSession()`, and `clearSession()` in `state.js` so users stay logged in across page reloads.
4. **Added Instant Quick Demo Login (`/api/quick-login`):**
   * Added a 1-click test login button and two pre-connected demo accounts (`کاربر_۱` and `کاربر_۲`) that automatically add each other as contacts for immediate two-way chat testing.
   * Added a fallback OTP display when `BALE_BOT_TOKEN` is not set.
5. **Fixed Server Crash (`Exited with status 1`) & Hardened Backend Stability:**
   * Removed fatal `process.exit(1)` on database connection failure and implemented `MemoryDatabase` in `db.js`.
   * Updated server binding to `server.listen(config.PORT, '0.0.0.0')` for compatibility with Render, Docker, Cloud Run, and AI Studio.
   * Added global `uncaughtException` and `unhandledRejection` handlers and automatic creation of `public/uploads/`.
   * Replaced blocking `window.alert()` calls with non-blocking floating toast notifications (`showToast()`).
   * Completed the `showContactProfile()` modal to display contact avatars, bios, and online statuses.

---

## 📂 Complete Project Directory & File-by-File Breakdown

```text
/
├── server.js                       # Main Express HTTP server, REST API routes, Socket.IO engine, and Bale Bot polling
├── db.js                           # PostgreSQL Pool manager + automatic In-Memory SQL fallback engine (MemoryDatabase)
├── config.js                       # Centralized environment configuration (Port, Admin credentials, Bale API, Upload limits)
├── bale.js                         # HTTP client wrapper for Bale Bot API (sendMessage, sendPhoto, getUpdates)
├── package.json                    # Node.js dependencies and npm lifecycle scripts (dev, start, build)
├── metadata.json                   # Application metadata and capability definitions
├── .env.example                    # Template for environment variables
└── public/                         # Frontend static assets and modular SPA source code
    ├── index.html                  # Minimal SPA entry shell (#root, #modalRoot, #toastRoot)
    ├── style.css                   # Master stylesheet importing modular CSS files
    ├── admin.html                  # Standalone Admin Dashboard interface
    ├── uploads/                    # Directory for uploaded images, files, avatars, and voice recordings
    ├── css/                        # Modular CSS Architecture
    │   ├── base.css                # CSS variables, color palette, RTL resets, Vazirmatn typography, Toast styles
    │   ├── auth.css                # Styling for the 3-step login, OTP verification, and quick test login buttons
    │   ├── chat.css                # Styling for sidebar, contact list, chat header, message bubbles, and voice recorder
    │   └── modals.css              # Styling for dynamic modals, right-click context menu, maintenance & announcement overlays
    └── js/                         # Modular ES6 Frontend Architecture
        ├── main.js                 # Application bootstrapper, session auto-restore, global event bindings
        ├── state.js                # Reactive application state store and LocalStorage session persistence
        ├── socket.js               # Socket.IO client instance and real-time event listeners
        ├── utils.js                # Helper utilities (HTML escaping, auto-scroll, Toast notifications, modal closer)
        ├── components/             # Dynamic DOM Components
        │   ├── AuthView.js         # Renders the Login, OTP, and Rules acceptance screens
        │   ├── AppView.js          # Renders the Sidebar, Chat Window, Input Bar, and Context Menu after login
        │   └── Modals.js           # On-demand generator for all pop-up modals and full-screen overlays
        └── modules/                # Feature & Business Logic Modules
            ├── auth.js             # OTP flow, Quick Test Login, user registration, session initialization, logout
            ├── contacts.js         # Contact/group fetching, adding contacts, live search filter, tab switching, contact profile
            ├── chat.js             # Opening rooms, message rendering, sending, editing, deleting, pinning, forwarding, reactions
            ├── media.js            # File/image uploads, avatar uploads, and WebRTC/MediaRecorder voice note capture
            └── profile.js          # Fetching and saving user bio, avatar, and online/busy/away status
```

### Detailed File-by-File Logic

#### Backend Files
* **`server.js`**:
  * Configures Express middleware (`express.static`, `express.json`) and initializes `multer` storage in `public/uploads/`.
  * Runs `startBalePolling()` in the background when `BALE_BOT_TOKEN` is provided, listening for `/start` commands to map Bale usernames to `chat_id`s.
  * Exposes user REST endpoints (`/api/send-otp`, `/api/verify-otp`, `/api/register`, `/api/quick-login`, `/api/user/*`, `/api/contacts/*`, `/api/messages/*`, `/api/groups/*`, `/api/report`, `/api/upload`).
  * Exposes protected admin REST endpoints (`/api/admin/*`) verified via the `x-admin-token` request header.
  * Manages real-time Socket.IO events (`auth`, `send-message`, `edit-message`, `delete-message`, `pin-message`, `react`, `forward-message`, `typing`, `read`, `update-status`, `disconnect`) with $O(1)$ socket lookup maps (`onlineSockets` and `usernameToSocket`).
* **`db.js`**:
  * Defines the database schema (`users`, `contacts`, `messages`, `groups`, `reports`, `settings`) and performance indexes.
  * Implements `MemoryDatabase`, which parses and executes SQL operations in memory whenever PostgreSQL is unavailable.
* **`config.js`**:
  * Resolves `PORT` dynamically (`DEFAULT_APP_PORT` or `PORT` or `3000`), sets `ADMIN_PASSWORD` (default: `Tk_tokyo`), `ADMIN_PATH` (default: `/panel-Tk_tokyo`), `OTP_EXPIRE` (`120s`), and `MAX_FILE_SIZE` (`50MB`).
* **`bale.js`**:
  * Uses `axios` to communicate with `https://tapi.bale.ai/bot<TOKEN>` for sending OTP codes, administrative block/unblock alerts, and broadcast announcements.

---

## 🔌 API & Real-Time Event Reference

### REST API Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/send-otp` | Generates a 6-digit OTP and sends it via Bale Bot (or returns a test OTP in dev mode). |
| `POST` | `/api/verify-otp` | Validates the 6-digit OTP and checks if the user is new or existing. |
| `POST` | `/api/register` | Registers a newly verified user in the database. |
| `POST` | `/api/quick-login` | Instant passwordless test login; auto-creates the user and links demo contacts. |
| `GET` | `/api/user/:username` | Retrieves a user's public profile (`username`, `avatar`, `bio`, `status`). |
| `POST` | `/api/user/update` | Updates the authenticated user's bio, status, and avatar URL. |
| `GET` | `/api/contacts/:username` | Lists all contacts for a user along with their avatars and statuses. |
| `POST` | `/api/add-contact` | Adds a contact by username. |
| `GET` | `/api/messages/:roomId` | Fetches all non-deleted messages for a direct or group room. |
| `GET` | `/api/groups/:username` | Lists all groups where the user is a member. |
| `POST` | `/api/upload` | Uploads an image, voice recording, or general file (`multipart/form-data`). |
| `POST` | `/api/report` | Submits a moderation report against a message/user. |
| `GET` | `/api/settings/mode` | Returns current server mode (`normal` or `maintenance`). |
| `GET` | `/api/settings/rules` | Returns platform rules text. |

### Socket.IO Events
* **Client → Server:** `auth`, `send-message`, `edit-message`, `delete-message`, `pin-message`, `react`, `forward-message`, `typing`, `read`, `update-status`, `update-location`.
* **Server → Client:** `auth-ok`, `new-message`, `msg-edited`, `msg-deleted`, `msg-pinned`, `msg-reaction`, `typing`, `read`, `contact-online`, `contact-offline`, `contact-status`, `new-group`, `blocked`, `kicked`, `server-maintenance`, `server-normal`, `announcement`.

---

## 🚀 Installation, Configuration & Activation Guide

### Prerequisites
* **Node.js**: `v18.x` or `v22.x` (Recommended)
* **npm**: `v9.x` or higher
* **PostgreSQL**: Optional (The app runs out-of-the-box with its built-in In-Memory Database if PostgreSQL is not configured).

### Step 1: Clone the Repository
```bash
git clone https://github.com/indirect-b/chat-app.git
cd chat-app
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Configure Environment Variables
Create a `.env` file in the root directory by copying `.env.example`:
```bash
cp .env.example .env
```
Edit `.env` with your desired settings (all fields are optional for local development):
```env
# Server Port (defaults to 3000)
PORT=3000

# Admin Panel Security
ADMIN_PASSWORD=Tk_tokyo
ADMIN_PATH=/panel-Tk_tokyo

# Bale Messenger Bot Configuration (Leave empty for Dev/Test OTP mode)
BALE_API=https://tapi.bale.ai/bot
BALE_BOT_TOKEN=

# PostgreSQL Connection URI (Leave empty to use automatic In-Memory Database)
DATABASE_URL=postgresql://user:password@localhost:5432/chatdb

# Upload & OTP Settings
MAX_FILE_SIZE=52428800
OTP_EXPIRE=120
```

### Step 4: Start the Application
**Development Mode:**
```bash
npm run dev
```

**Production Mode:**
```bash
npm run build
npm start
```

### Step 5: Access the Application & Admin Panel
1. **Main Messenger Interface:**
   Open [http://localhost:3000](http://localhost:3000) in your browser.
   * Click **«⚡ ورود سریع تستی»** (Quick Test Login) or choose **«👤 اکانت ۱»** in Tab 1 and **«👤 اکانت ۲»** in Tab 2 to immediately test real-time two-way messaging.
2. **Admin Panel:**
   Open [http://localhost:3000/panel-Tk_tokyo](http://localhost:3000/panel-Tk_tokyo) (or your custom `ADMIN_PATH`) and log in using your `ADMIN_PASSWORD` (default: `Tk_tokyo`).