# 💬 Persian Real-Time Web Messenger (`chat-app`)

An enterprise-grade, full-stack **Real-Time Web Messenger** engineered with **React 19**, **TypeScript**, **Vite**, **Express**, **Socket.IO**, and **Client-Side End-to-End Encryption (E2EE)**. Built with a resilient **Dual-Mode Database Engine** (**PostgreSQL** + automatic **Persistent Disk-Backed Fallback** in `data/database.json`), this platform delivers instantaneous bi-directional communication, encrypted messaging, voice notes, file sharing, group chats, disappearing messages, and a full administration suite tailored for RTL (Right-to-Left) Persian interfaces.

---

## 🌟 Core Features & Enterprise Capabilities

### 🔐 1. Client-Side End-to-End Encryption (E2EE)
* **Web Crypto API (`AES-GCM 256-bit` + `PBKDF2` SHA-256):** Messages are encrypted directly inside the sender's browser before transmission over WebSockets (`e2ee:v1:<iv>:<ciphertext>`).
* **Zero Plaintext Exposure on Server:** When E2EE is active, the backend server and database store only the encrypted ciphertext—neither the server nor database administrators can read private messages.
* **Custom Room Passphrases (`🔑`):** Users can optionally set a shared secret passphrase per conversation to derive a custom 256-bit encryption key, or toggle E2EE (`🔒 E2EE` / `🔓 ساده`) directly from the chat header.

### 💾 2. Resilient Dual-Mode Database (`PostgreSQL` + `Persistent Disk Fallback`)
* **Primary Engine (`PostgreSQL`):** Connects via `pg.Pool` when a valid `DATABASE_URL` is provided.
* **Zero-Data-Loss Disk Fallback (`data/database.json`):** When `DATABASE_URL` is omitted or unreachable, `src/server/db.ts` automatically activates `PersistentFallbackDatabase`. Unlike volatile in-memory mocks, every `INSERT`, `UPDATE`, and `DELETE` operation is atomically persisted to `data/database.json` on disk—ensuring **zero data loss across server restarts**.

### ⚛️ 3. Full-Stack TypeScript & React 19 SPA Architecture
* **Strict Component Isolation:** Built with React 19 and TypeScript (`src/App.tsx`, `src/components/AuthScreen.tsx`, `src/components/ChatApp.tsx`). When unauthenticated, only `<AuthScreen />` is mounted in the DOM; `<ChatApp />` is mounted exclusively after authentication.
* **Persistent Client Sessions (`LocalStorage`):** Users remain logged in across page reloads (`F5`) and browser restarts until they explicitly log out.
* **Instant 1-Click Demo Login:** Includes a **Quick Test Login** button (`⚡ ورود سریع تستی`) and pre-linked test accounts (`👤 اکانت ۱` and `👤 اکانت ۲`) for immediate multi-tab real-time chat testing.

### 💬 4. Rich Real-Time Messaging & Media
* **Bi-Directional Socket.IO Engine:** Live typing indicators (`در حال تایپ...`), online/offline presence tracking, custom status indicators (`Online`, `Busy`, `Away`), and read receipts (`✓✓`).
* **Voice Recorder & File Sharing:** Hold-to-record voice notes (`.webm` via browser `MediaRecorder` API) and image/document uploads up to 50MB.
* **Interactive Message Actions:** Reply with quotes, real-time Edit (`ویرایش شده`), Delete, Pin to top header, Multi-room Forward, Emoji Reactions (`❤️ 👍 😂 🔥 👏 😮`), and Disappearing Message Timers (`30s`, `1m`, `5m`, `1h`, `24h`).

### 🛡️ 5. Administration & Moderation Dashboard (`/panel-Tk_tokyo`)
* **Live Analytics & 7-Day Activity Chart:** Monitor total users, online connections, active messages, groups, pending reports, and 7-day message volume.
* **User Moderation:** Permanent or temporary user bans (with automatic expiration and Bale Bot notifications), unblocking, and real-time socket kicking.
* **Admin Impersonation ("Login As"):** Generate 30-second one-time tokens to inspect user accounts.
* **Broadcasts & Maintenance Mode:** Push real-time announcements (with images) to all connected clients and Bale users, or toggle global server Maintenance Mode.

---

## 📋 Architectural Evolution & Changelog

1. **Migrated Full-Stack Codebase to React 19 + TypeScript + Vite:**
   * Converted backend (`server.ts`, `src/server/db.ts`, `src/server/config.ts`, `src/server/bale.ts`) and frontend (`src/App.tsx`, `src/components/*`, `src/utils/crypto.ts`, `src/types.ts`) to TypeScript.
   * Integrated Vite middleware into Express (`server.ts`) for unified single-port (`0.0.0.0:3000`) execution in development and static `dist/` serving in production.
2. **Implemented End-to-End Encryption (`src/utils/crypto.ts`):**
   * Added client-side `AES-GCM 256-bit` encryption with `PBKDF2` key derivation (`50,000` iterations, `SHA-256`) and per-room custom secret key support.
3. **Upgraded Database Fallback to Persistent Disk Storage (`src/server/db.ts`):**
   * Replaced volatile memory-only storage with `PersistentFallbackDatabase`, which automatically syncs all tables (`users`, `contacts`, `messages`, `groups`, `reports`, `settings`) to `data/database.json`.
4. **Added Session Persistence & 1-Click Test Authentication:**
   * Implemented `localStorage` session restoration and `/api/quick-login` with pre-connected demo accounts (`کاربر_۱` and `کاربر_۲`).
5. **Hardened Server Stability (Fixed `Exited with status 1`):**
   * Eliminated fatal startup crashes on database connection failures, enforced `0.0.0.0` host binding, and added global `uncaughtException` and `unhandledRejection` handlers.

---

## 📂 Project Directory Structure & File-by-File Breakdown

```text
/
├── server.ts                       # TypeScript Express + Socket.IO server & Vite middleware integration
├── index.html                      # Root SPA HTML entry point loading /src/main.tsx
├── vite.config.ts                  # Vite bundler & React plugin configuration
├── tsconfig.json                   # TypeScript compiler configuration
├── package.json                    # Dependencies and scripts (dev, start, build)
├── metadata.json                   # Application metadata
├── .env.example                    # Environment variables template
├── data/                           # Auto-generated directory for persistent fallback database
│   └── database.json               # Atomic JSON snapshot of all tables when PostgreSQL is offline
├── src/                            # TypeScript Source Code (Frontend + Backend Modules)
│   ├── main.tsx                    # React 19 DOM root mounting <App />
│   ├── App.tsx                     # Root component managing session, maintenance, blocked state & toasts
│   ├── types.ts                    # Shared TypeScript interfaces (UserProfile, ChatMessage, RoomSummary, etc.)
│   ├── utils/
│   │   └── crypto.ts               # Web Crypto API E2EE engine (AES-GCM 256-bit + PBKDF2 key derivation)
│   ├── components/
│   │   ├── AuthScreen.tsx          # 3-step Bale OTP login, 1-click Quick Test Login & Rules modal
│   │   └── ChatApp.tsx             # Main messenger UI, E2EE controls, voice recorder, modals & context menu
│   └── server/
│       ├── config.ts               # Strongly-typed server environment configuration
│       ├── db.ts                   # Dual-mode database engine (PostgreSQL Pool + PersistentFallbackDatabase)
│       └── bale.ts                 # TypeScript client for Bale Bot API (sendMessage, sendPhoto, getUpdates)
└── public/                         # Static Assets & Stylesheets
    ├── style.css                   # Master stylesheet importing modular CSS files
    ├── admin.html                  # Standalone Admin Dashboard interface
    ├── uploads/                    # Uploaded images, files, avatars, and voice notes (.webm)
    └── css/                        # Modular RTL Stylesheets
        ├── base.css                # CSS variables, color tokens, Vazirmatn typography & Toast styles
        ├── auth.css                # Login box, OTP input, and quick test login button styles
        ├── chat.css                # Sidebar, chat header, message bubbles, reactions & voice recorder styles
        └── modals.css              # Pop-up modals, context menu, maintenance & announcement overlay styles
```

---

## 🔌 REST API & Socket.IO Event Reference

### REST API Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/send-otp` | Generates a 6-digit OTP and sends it via Bale Bot (or returns a test OTP in dev mode). |
| `POST` | `/api/verify-otp` | Validates the 6-digit OTP and checks if the user is new or existing. |
| `POST` | `/api/register` | Registers a newly verified user in the database. |
| `POST` | `/api/quick-login` | Instant passwordless test login; auto-creates the user and links demo contacts. |
| `GET` | `/api/user/:username` | Retrieves a user's public profile (`username`, `avatar`, `bio`, `status`). |
| `POST` | `/api/user/update` | Updates the authenticated user's bio, status, and avatar URL. |
| `GET` | `/api/contacts/:username` | Lists all contacts for a user along with their avatars and online statuses. |
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
* **Node.js**: `v18.x` or `v22.x`
* **npm**: `v9.x` or higher
* **PostgreSQL**: Optional (Automatically uses persistent disk storage in `data/database.json` when not configured).

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/indirect-b/chat-app.git
cd chat-app
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
```env
PORT=3000
ADMIN_PASSWORD=Tk_tokyo
ADMIN_PATH=/panel-Tk_tokyo
BALE_API=https://tapi.bale.ai/bot
BALE_BOT_TOKEN=
DATABASE_URL=
MAX_FILE_SIZE=52428800
OTP_EXPIRE=120
```

### 3. Build & Run
```bash
# Start full-stack development server (TypeScript + Vite + Express)
npm run dev

# Build frontend production bundle
npm run build

# Start production server
npm start
```

### 4. Access the Messenger & Admin Panel
* **Messenger UI:** Open `http://localhost:3000`
* **Admin Dashboard:** Open `http://localhost:3000/panel-Tk_tokyo` (Default password: `Tk_tokyo`)