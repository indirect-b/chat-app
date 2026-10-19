# 💬 Persian Real-Time Web Messenger (`chat-app` v5.0)

An enterprise-grade, full-stack **Real-Time Web Messenger** engineered with **React 19**, **TypeScript**, **Vite**, **Express**, **Socket.IO**, and **Automatic ECDH (`P-256`) + `AES-GCM 256-bit` End-to-End Encryption (E2EE)**. Designed for zero-downtime cloud deployments, it features a **Dual-Mode Database Engine** (**PostgreSQL** + **Non-Blocking Debounced Atomic Disk Fallback** in `data/database.json`), **Hybrid Cloud-Safe Media Persistence**, **Cluster-Ready Socket Presence**, and **Timing-Safe Security Hardening**.

---

## 🌟 Core Features & Enterprise Architecture (v5.0)

### 🔐 1. Automatic ECDH (`P-256`) Key Exchange + `AES-GCM 256-bit` E2EE
* **Zero-Configuration Asymmetric Key Exchange (`ECDH P-256`):** Upon authentication, each client automatically generates an Elliptic Curve Diffie-Hellman (`P-256`) key pair via the browser's native Web Crypto API (`src/utils/crypto.ts`). The private key never leaves the browser, while the public JWK is published to `/api/user/public-key`.
* **Automatic Shared Secret Derivation:** In 1-on-1 conversations, both peers independently compute the exact same 256-bit `AES-GCM` shared key (`ECDH(MyPrivateKey, PeerPublicKey) === ECDH(PeerPrivateKey, MyPublicKey)`) without manually exchanging passphrases (`e2ee:ecdh:<iv>:<ciphertext>`).
* **Optional Custom Room Passphrase Override (`PBKDF2`):** For group chats or users who wish to add an extra layer of manual passphrase verification (`🔑`), `PBKDF2` (`50,000` iterations, `SHA-256`) derives a custom room key (`e2ee:v1:<iv>:<ciphertext>`).
* **Non-Blocking Media Pipeline:** Text messages and reply quotes are encrypted/decrypted via hardware-accelerated Web Crypto API while large media streams (up to 50MB) are streamed asynchronously without blocking the browser main thread or freezing mobile UIs.

### 💾 2. Concurrency-Safe Dual-Mode Database (`PostgreSQL` + `Atomic Mutex Disk Fallback`)
* **Primary Relational Engine (`PostgreSQL`):** Connects via `pg.Pool` when a valid `DATABASE_URL` is configured.
* **Non-Blocking Debounced Write Mutex (`src/server/db.ts`):** When `DATABASE_URL` is omitted or unreachable, `PersistentFallbackDatabase` is activated automatically. Instead of synchronous `fs.writeFileSync` calls that block the Node.js event loop or corrupt JSON under concurrent writes, all mutations are coalesced via a **250ms Debounced Write Mutex (`isFlushing` + `flushPending` queue)**.
* **Atomic Crash-Safe File Replacement:** Snapshots are written asynchronously (`fs.promises.writeFile`) to `data/database.json.tmp` and atomically renamed (`fs.promises.rename`) over `data/database.json`, preventing file corruption during concurrent messaging or unexpected server restarts.
* **Automatic Storage Pruning:** Automatically caps fallback history at `MAX_STORED_MESSAGES = 5000` to prevent unbounded JSON file growth.

### ☁️ 3. Hybrid Cloud-Safe Media Persistence (`media_blobs` + `/api/media/:id`)
* **Ephemeral Container Resilience (Render / Railway / Docker):** Cloud platforms with ephemeral filesystems wipe local folders (`public/uploads/`) on container redeployments.
* **Persistent Database Blob Storage (`STORAGE_MODE=hybrid`):** Voice notes (`.webm`), avatars, and images under `2MB` (`INLINE_MAX_BYTES`) are automatically persisted inside the `media_blobs` database table (`PostgreSQL` or `data/database.json`) and served with immutable cache headers via `GET /api/media/:id`. Files larger than `2MB` (up to `50MB`) stream directly from disk (`public/uploads/`).

### 🌐 4. Cluster-Ready Socket.IO Presence Layer (`src/server/presence.ts`)
* **Decoupled Presence Manager:** Replaced scattered in-memory socket objects with a dedicated `PresenceManager` (`src/server/presence.ts`) providing $O(1)$ bidirectional lookup (`socketId <-> username`) and `REDIS_URL` cluster mode readiness for horizontal multi-instance scaling.

### 🛡️ 5. Hardened Security & Zero Hardcoded Secrets (`src/server/config.ts`)
* **Zero Leaked Credentials:** Removed all hardcoded passwords and secret admin URLs from `.env.example` and source code.
* **Cryptographic Fallback Generation:** If `ADMIN_PASSWORD` is not provided in environment variables, `src/server/config.ts` generates a cryptographically secure random 32-character hex key (`crypto.randomBytes(16).toString('hex')`) at startup.
* **Timing-Safe Verification:** All admin authentication checks use `crypto.timingSafeEqual` (`verifyAdminSecret`) to prevent timing side-channel attacks, and `ADMIN_PATH` is strictly isolated on the server side (`server.ts`) so it never appears in frontend bundles.

---

## 📋 Architectural Evolution & Changelog

1. **Upgraded E2EE to Automatic Asymmetric Diffie-Hellman (`ECDH P-256`):**
   * Added automatic key pair generation (`ensureUserECDHKeyPair`), public key directory endpoints (`POST /api/user/public-key`), real-time `peer-key-updated` socket synchronization, and `ECDH` shared secret derivation in `src/utils/crypto.ts`.
2. **Engineered Non-Blocking Atomic Disk Fallback (`src/server/db.ts`):**
   * Eliminated race conditions and event-loop blocking by implementing an async write mutex, `250ms` write debouncing, atomic `.tmp` rename replacement, and automatic 5,000-message pruning.
3. **Added Hybrid Cloud-Safe Media Storage (`server.ts` & `src/server/db.ts`):**
   * Created the `media_blobs` table and `GET /api/media/:id` endpoint so voice notes, avatars, and images survive container restarts on Render, Railway, and Docker.
4. **Extracted Cluster-Ready Presence Service (`src/server/presence.ts`):**
   * Centralized online user tracking, socket mapping, and targeted user event emission (`presence.emitToUser`).
5. **Hardened Admin & Environment Security (`src/server/config.ts` & `.env.example`):**
   * Replaced default credentials with dynamic cryptographic secret generation and `crypto.timingSafeEqual` verification.

---

## 📂 Project Directory Structure & File-by-File Breakdown

```text
/
├── server.ts                       # Main Express + Socket.IO server, hybrid media endpoints & Vite integration
├── index.html                      # Root SPA HTML entry point loading /src/main.tsx
├── vite.config.ts                  # Vite bundler & React plugin configuration
├── tsconfig.json                   # TypeScript compiler configuration
├── package.json                    # Dependencies and scripts (dev, start, build)
├── metadata.json                   # Application metadata
├── .env.example                    # Clean, secret-free environment variables template
├── data/                           # Auto-generated directory for persistent fallback database
│   └── database.json               # Atomic, mutex-protected JSON snapshot when PostgreSQL is offline
├── src/                            # TypeScript Source Code (Frontend + Backend Modules)
│   ├── main.tsx                    # React 19 DOM root mounting <App />
│   ├── App.tsx                     # Root component managing session, maintenance, blocked state & toasts
│   ├── types.ts                    # Shared TypeScript interfaces (UserProfile, ChatMessage, RoomSummary, etc.)
│   ├── utils/
│   │   └── crypto.ts               # Web Crypto E2EE engine (Automatic ECDH P-256 + AES-GCM 256-bit + PBKDF2)
│   ├── components/
│   │   ├── AuthScreen.tsx          # 3-step Bale OTP login, 1-click Quick Test Login & Rules modal
│   │   └── ChatApp.tsx             # Main messenger UI, ECDH key sync, voice recorder, modals & context menu
│   └── server/
│       ├── config.ts               # Security-hardened config & timing-safe admin secret verification
│       ├── db.ts                   # Dual-mode database (PostgreSQL Pool + Atomic Mutex Disk Fallback)
│       ├── presence.ts             # Cluster-ready Socket.IO presence manager (O(1) lookup + Redis readiness)
│       └── bale.ts                 # TypeScript client for Bale Bot API (sendMessage, sendPhoto, getUpdates)
└── public/                         # Static Assets & Stylesheets
    ├── style.css                   # Master stylesheet importing modular CSS files
    ├── admin.html                  # Standalone Admin Dashboard interface
    ├── uploads/                    # Local stream directory for large file uploads
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
| `POST` | `/api/quick-login` | Instant passwordless test login; auto-creates user and links demo contacts. |
| `GET` | `/api/user/:username` | Retrieves a user's public profile and `ECDH P-256` `public_key`. |
| `POST` | `/api/user/public-key` | Publishes the user's `ECDH P-256` public JWK and notifies online contacts. |
| `POST` | `/api/user/update` | Updates the authenticated user's bio, status, and avatar URL. |
| `GET` | `/api/contacts/:username` | Lists all contacts with their avatars, online statuses, and `public_key`. |
| `POST` | `/api/add-contact` | Adds a contact by username and returns their `public_key`. |
| `GET` | `/api/messages/:roomId` | Fetches all non-deleted messages for a direct or group room. |
| `GET` | `/api/groups/:username` | Lists all groups where the user is a member. |
| `POST` | `/api/upload` | Hybrid file upload (`<= 2MB` persisted in `media_blobs`, `> 2MB` streamed to disk). |
| `GET` | `/api/media/:id` | Serves persistent cloud-safe media blobs with immutable caching and disk fallback. |
| `POST` | `/api/report` | Submits a moderation report against a message or user. |
| `GET` | `/api/settings/mode` | Returns current server mode (`normal` or `maintenance`). |
| `GET` | `/api/settings/rules` | Returns platform rules text. |

### Socket.IO Events
* **Client → Server:** `auth`, `send-message`, `edit-message`, `delete-message`, `pin-message`, `react`, `forward-message`, `typing`, `read`, `update-status`, `update-location`.
* **Server → Client:** `auth-ok`, `new-message`, `msg-edited`, `msg-deleted`, `msg-pinned`, `msg-reaction`, `typing`, `read`, `contact-online`, `contact-offline`, `contact-status`, `peer-key-updated`, `new-group`, `blocked`, `kicked`, `server-maintenance`, `server-normal`, `announcement`.

---

## 🚀 Installation, Configuration & Activation Guide

### Prerequisites
* **Node.js**: `v18.x` or `v22.x`
* **npm**: `v9.x` or higher
* **PostgreSQL**: Optional (Automatically uses atomic persistent disk storage in `data/database.json` when not configured).

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/indirect-b/chat-app.git
cd chat-app
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and set your custom secrets:
```bash
cp .env.example .env
```
```env
PORT=3000
ADMIN_PASSWORD=your_strong_admin_secret
ADMIN_PATH=/admin-console
BALE_API=https://tapi.bale.ai/bot
BALE_BOT_TOKEN=
DATABASE_URL=
REDIS_URL=
STORAGE_MODE=hybrid
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
* **Admin Dashboard:** Open `http://localhost:3000/admin-console` (or the custom path configured in `ADMIN_PATH`).