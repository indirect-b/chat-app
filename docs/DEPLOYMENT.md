# Deployment, Operations & Backup Runbook

**Version:** `6.1.0`

This guide covers deploying `chat-app`, backing up and restoring both PostgreSQL and the atomic JSON fallback database, operating maintenance mode, monitoring Bale OTP health, and architectural limitations.

---

## 1. Prerequisites & Environment Variables

- **Runtime:** Node.js `>= 20` (tested on Node `22.x`).
- **Build & Start:**
  ```bash
  npm ci
  npm run build
  npm start
  ```
- **Required / Optional Environment Variables** (see `.env.example` for defaults):
  - `PORT` — HTTP server port (default `3000`).
  - `DATABASE_URL` — PostgreSQL connection string. If omitted, the server automatically runs with the atomic JSON fallback file (`./data/database.json`).
  - `BALE_BOT_TOKEN` — Bale bot API token for OTP delivery.
  - `BALE_BOT_USERNAME` — Public bot handle shown on the login screen.
  - `ADMIN_USERNAME` / `ADMIN_PASSWORD` — Admin dashboard credentials (`/admin`).
  - `VOPRF_SECRET_KEY` — Optional stable server secret for Ristretto255-VOPRF evaluation.
  - `CORS_ORIGIN` — Allowed origin(s) in production.

---

## 2. Database Backup & Restore

### 2.1 PostgreSQL (Production — `DATABASE_URL` set)

The PostgreSQL schema includes `users` (including `public_key` and `recovery_code_hash`), `messages`, `groups`, `group_members`, `group_epochs`, `settings`, `contact_nicknames`, `archived_chats`, and `deleted_chats`.

**Create an encrypted-ready custom-format backup:**
```bash
export BACKUP_FILE="chatapp_pg_$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump --format=custom --no-owner --no-acl "$DATABASE_URL" -f "$BACKUP_FILE"
```

**Verify backup integrity before storing off-host:**
```bash
pg_restore --list "$BACKUP_FILE" | head -n 30
```

**Restore into a fresh database:**
```bash
# Stop the application or enable maintenance mode first to prevent concurrent writes.
pg_restore --clean --if-exists --no-owner --no-acl --dbname="$DATABASE_URL" "$BACKUP_FILE"
```

> **Note on E2EE backups:** Server database backups contain ciphertext, public keys, and `scrypt`-hashed recovery codes — never users' private identity keys (which live only in each user's local IndexedDB). Restoring the database preserves encrypted message history and user accounts, but users still require their local device keys to decrypt historical 1:1 PQ messages.

### 2.2 Atomic JSON Fallback (`DATABASE_URL` unset)

When `DATABASE_URL` is not configured, `PersistentFallbackDatabase` (`src/server/db.ts`) persists state atomically (write to `.tmp` + `fs.renameSync`) to `data/database.json` (plus uploaded attachments in `uploads/`).

**Backup:**
```bash
# Recommended: enable maintenance mode or stop the server for a point-in-time snapshot
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p backups
cp -p data/database.json "backups/database_${TIMESTAMP}.json"
tar -czf "backups/uploads_${TIMESTAMP}.tar.gz" uploads/ 2>/dev/null || true
```

**Restore:**
```bash
# 1. Stop the running Node.js server process
# 2. Verify JSON syntax before restoring
node -e "JSON.parse(require('fs').readFileSync('backups/database_YYYYMMDDTHHMMSSZ.json', 'utf8')); console.log('JSON OK')"
# 3. Replace the database file atomically and restore uploads
cp -p "backups/database_YYYYMMDDTHHMMSSZ.json" data/database.json.restore
mv data/database.json.restore data/database.json
tar -xzf "backups/uploads_YYYYMMDDTHHMMSSZ.tar.gz"
# 4. Restart the server
npm start
```

---

## 3. Maintenance Mode

Maintenance mode is controlled from the admin panel (`/admin`) or via `POST /api/admin/settings/mode` (`{ "mode": "maintenance" | "normal" }`) and persisted in the `settings` table (`app_mode`).

**Observable behavior when `mode === "maintenance"`:**
- Unauthenticated visitors calling `GET /api/settings/mode` receive HTTP `503` with `{ "maintenance": true }` (never full admin settings).
- Authenticated users calling `GET /api/settings/mode` receive HTTP `200` with `{ "ok": true, "mode": "maintenance", "maintenance": true }`.
- The login screen (`AuthScreen.tsx`) displays the maintenance notice banner and blocks normal login until maintenance mode is lifted.
- Admin login (`/admin`) remains accessible so operators can exit maintenance mode.

---

## 4. Health Monitoring & Bale OTP Fallback

### 4.1 Health Check Endpoint (`GET /api/health`)

`GET /api/health` returns JSON with server version, database mode, and Bale API health status:
```json
{
  "ok": true,
  "version": "6.1.0",
  "database": "postgres",
  "bale": {
    "configured": true,
    "healthy": true,
    "lastCheckedAt": 1763520000000,
    "lastError": null,
    "consecutiveFailures": 0
  }
}
```

- On startup and every 5 minutes, the server calls `bale.checkBaleHealth()` (`GET https://tapi.bale.ai/bot<TOKEN>/getMe`, 5-second timeout).
- Any failure is logged with an ISO timestamp (`[Bale Health] ...`) and increments `consecutiveFailures`.
- When `BALE_BOT_TOKEN` is configured and `bale.healthy` is `false`, `GET /api/health` returns HTTP `503` (`"ok": false`) so external uptime monitors can alert immediately.

### 4.2 Bale Fallback Recovery Codes

If Bale OTP delivery is unavailable:
- Every newly registered user receives a **one-time 128-bit recovery code** (`XXXX-XXXX-...-XXXX`) shown once during registration.
- Only its salted `scrypt` hash (`N=16384, r=8, p=1`) is stored in `users.recovery_code_hash`.
- Users can log in without Bale via the login page's **"ورود با کد بازیابی اضطراری (بدون نیاز به بله)"** option (`POST /api/recover`).
- `POST /api/recover` enforces a strict sliding-window rate limit (**5 attempts per 15 minutes per IP AND per username**), rejects blocked accounts, establishes a verified server session token, and **immediately rotates** the user's recovery code (invalidating the used code and displaying a fresh one-time replacement code).

---

## 5. Architecture Limitations & Future Work

- **Centralized Server:** `chat-app` currently runs as a single centralized Express + Socket.IO server with a central database. All client code, public-key directory lookups, and message relays pass through this server.
- **P2P / Federation (Future Work):** Peer-to-peer transport (e.g., WebRTC data channels with decentralized signaling) and federated multi-server deployment (Matrix/ActivityPub-style server-to-server relay with independent origin trust) are **not implemented** in `v6.1.0` and remain future architectural work.
- **Horizontal Scaling:** In-memory session stores (`userSessions`, `otps`) and `RecoveryRateLimiter` buckets are process-local. Running more than one server replica requires migrating these stores to Redis or PostgreSQL first.
