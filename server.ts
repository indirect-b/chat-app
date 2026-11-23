// sync checkpoint — no behavior change (verified)
import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { config, verifyAdminSecret } from './src/server/config';
import * as bale from './src/server/bale';
import { pool, init, isUsingFallback, getDbEngine } from './src/server/db';
import { presence } from './src/server/presence';
import {
  getRoomId,
  resolveMediaAccess,
  canUploadToRoom,
  isRoomMember,
  deleteMediaIfUnreferenced,
  extractMediaId,
} from './src/server/media';
import {
  checkRoomReadAccess,
  checkOwnGroupsAccess,
  checkOwnUsername,
  canActOnMessage,
} from './src/server/roomAccess';
import {
  validateUploadFile,
  readFileHead,
  verifyStoredMime,
  ALLOWED_UPLOAD_EXTENSIONS,
} from './src/server/uploadPolicy';
import { issueAdminSession, verifyAdminSession, adminLoginLimiter } from './src/server/adminAuth';
import {
  SlidingWindowLimiter,
  rateLimitMiddleware,
  getClientIp,
} from './src/server/rateLimit';
import { emitToRoom } from './src/server/roomEmit';
import { parseMsg, safeParseMembers, safeParseReactions } from './src/server/messageParse';
import {
  generateRecoveryCode,
  hashRecoveryCode,
  verifyRecoveryCode,
  canDeleteWithCode,
  RecoveryRateLimiter,
} from './src/server/recovery';
import {
  getGoogleClientId,
  isGoogleConfigured,
  verifyGoogleIdToken,
  parseGoogleCsrfCookie,
  checkGoogleRedirectRequest,
  buildGoogleRedirectUrl,
  PendingRecoveryCodes,
  parseCookies,
  GOOGLE_DISABLED_MSG,
  GOOGLE_LOGIN_FAILED_MSG,
} from './src/server/google';
import { PRIVACY_HTML } from './src/server/privacy';
import {
  resolveGoogleProfileSync,
  resolveProfileUpdate,
  type GoogleProfile,
} from './src/server/profileSync';

const APP_VERSION = '6.5.0';
const recoverRateLimiter = new RecoveryRateLimiter(5, 15 * 60 * 1000);
const googleLoginLimiter = new RecoveryRateLimiter(20, 15 * 60 * 1000);
const voprfRateLimiter = new RecoveryRateLimiter(60, 60 * 1000);

// Round 5 (M7): sliding-window limiters. Global /api/ budget is generous;
// the tight buckets sit on the abuse-prone routes. Per-user write buckets
// are separate instances so each route gets its own budget.
const apiGlobalLimiter = new SlidingWindowLimiter(300, 60 * 1000);
const userLookupLimiter = new SlidingWindowLimiter(60, 60 * 1000);
const healthLimiter = new SlidingWindowLimiter(30, 60 * 1000);
const uploadLimiter = new SlidingWindowLimiter(20, 15 * 60 * 1000);
const reportLimiter = new SlidingWindowLimiter(10, 15 * 60 * 1000);
const addContactLimiter = new SlidingWindowLimiter(30, 15 * 60 * 1000);
const userUpdateLimiter = new SlidingWindowLimiter(30, 15 * 60 * 1000);
const createGroupLimiter = new SlidingWindowLimiter(30, 15 * 60 * 1000);

// کلید سرور برای پروتکل احراز هویت کور Ristretto255-VOPRF (RFC 9497)
// در صورت وجود VOPRF_SEED اختصاصی (۳۲ بایت Base64) از آن استفاده می‌شود؛ در غیاب
// آن، مشتق HKDF از رمز مدیر با salt ثابت — نه یک SHA-256 مستقیم از رمز.
function resolveVoprfSeed(): Uint8Array {
  const envSeed = process.env.VOPRF_SEED;
  if (envSeed) {
    try {
      const decoded = new Uint8Array(Buffer.from(envSeed, 'base64'));
      if (decoded.length === 32) return decoded;
    } catch {
      // fall through to HKDF derivation
    }
  }
  // L7(c): falling back to an ADMIN_PASSWORD-derived VOPRF key. Loud
  // warning — Render must set VOPRF_SEED (startup is NOT hard-failed,
  // which would break the live deploy).
  console.warn(
    '⚠️ [Security] VOPRF_SEED is not set — the VOPRF key is derived from ADMIN_PASSWORD (admin-password compromise = VOPRF-key compromise); set VOPRF_SEED in Render env'
  );
  return hkdf(
    sha256,
    new TextEncoder().encode(config.ADMIN_PASSWORD),
    new TextEncoder().encode('PersianMessenger-VOPRF-Seed-Salt-v2'),
    new TextEncoder().encode('PersianMessenger-Ristretto255-VOPRF-v2'),
    32
  );
}
const voprfSeed = resolveVoprfSeed();
const serverVoprfKeys = ristretto255_oprf.voprf.deriveKeyPair(
  voprfSeed,
  new TextEncoder().encode('PersianMessenger-Ristretto255-VOPRF-v2')
);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://accounts.google.com'],
        styleSrc: ["'self'"],
        fontSrc: ["'self'", 'data:'],
        imgSrc: ["'self'", 'data:', 'blob:', 'https://lh3.googleusercontent.com'],
        mediaSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: [
          "'self'",
          'wss://chatapp-server-1i2a.onrender.com',
          'https://accounts.google.com',
        ],
        frameSrc: ["'self'", 'https://accounts.google.com'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: {
      action: 'deny',
    },
    xContentTypeOptions: true,
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin',
    },
  })
);

// L1: helmet 8 removed the permissionsPolicy option, so the header is set
// directly. camera / microphone / geolocation / payment are all disabled.
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
});

const server = http.createServer(app);
const io = new SocketIOServer(server);

app.use(express.json({ limit: '5mb' }));
// Google posts the redirect-mode credential as application/x-www-form-urlencoded
// (credential + g_csrf_token) to /api/google-redirect — JSON parsing alone
// would leave req.body empty for that route.
app.use(express.urlencoded({ extended: false }));

// M7: global API budget — 300 req/min/IP on every /api/ route.
app.use('/api/', rateLimitMiddleware(apiGlobalLimiter, (req) => getClientIp(req)));

// آپلود فایل با پشتیبانی ترکیبی (Hybrid Cloud-Safe Media Storage + Disk Stream)
// توجه: مسیر عمومی /uploads حذف شده — فایل‌ها فقط از طریق /api/media با
// احراز هویت و بررسی عضویت در چت سرو می‌شوند (به بخش MEDIA در پایین نگاه کن).
// H1(b): uploads live OUTSIDE public/ (data/uploads) so the production
// express.static(publicPath) can never serve them publicly.
const uploadsDir = path.join(process.cwd(), 'data/uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({
  storage,
  limits: { fileSize: config.MAX_FILE_SIZE },
  // H1(a): extension allowlist enforced BEFORE the file is written.
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_UPLOAD_EXTENSIONS.has(path.extname(file.originalname).toLowerCase())) {
      (_req as any).uploadRejected = true;
      cb(null, false);
    } else {
      cb(null, true);
    }
  },
});

/** Delete one uploaded file from the data/uploads disk store (H1(d)). */
async function unlinkUploadFile(mediaId: string): Promise<void> {
  await fs.promises.unlink(path.join(uploadsDir, path.basename(mediaId)));
}

// متغیرهای درون‌حافظه‌ای توکن‌های موقت
const adminTokens: Record<string, { username: string; expire: number; adminAt: number }> = {};
export const userSessions: Record<string, { username: string; expire: number }> = {};

export async function saveUserSession(token: string, username: string, expireMs: number): Promise<void> {
  userSessions[token] = { username, expire: expireMs };
  try {
    const expiresAt = new Date(expireMs).toISOString();
    await pool.query(
      'INSERT INTO sessions (token, username, expires_at) VALUES ($1, $2, $3)',
      [token, username, expiresAt]
    );
  } catch (e: any) {
    console.warn('⚠️ اخطار در ذخیره سشن در دیتابیس:', e?.message || e);
  }
}

export async function removeUserSession(token: string): Promise<void> {
  delete userSessions[token];
  try {
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  } catch (e: any) {
    console.warn('⚠️ اخطار در حذف سشن از دیتابیس:', e?.message || e);
  }
}

export async function removeAllUserSessions(username: string): Promise<void> {
  for (const [tok, sess] of Object.entries(userSessions)) {
    if (sess.username === username) {
      delete userSessions[tok];
    }
  }
  try {
    await pool.query('DELETE FROM sessions WHERE username = $1', [username]);
  } catch (e: any) {
    console.warn('⚠️ اخطار در حذف سشن‌های کاربر از دیتابیس:', e?.message || e);
  }
}

/**
 * Revoke every session of a user EXCEPT the kept token (round 5, M2).
 * Used on recovery-code reissue: revoking the current session would log
 * the user out mid-flow and break subsequent REST calls, so it is kept.
 */
export async function removeAllUserSessionsExcept(
  username: string,
  keepToken: string
): Promise<void> {
  for (const [tok, sess] of Object.entries(userSessions)) {
    if (sess.username === username && tok !== keepToken) {
      delete userSessions[tok];
    }
  }
  try {
    await pool.query('DELETE FROM sessions WHERE username = $1 AND token <> $2', [
      username,
      keepToken,
    ]);
  } catch (e: any) {
    console.warn('⚠️ اخطار در حذف سشن‌های دیگر کاربر از دیتابیس:', e?.message || e);
  }
}

/** Extract the raw session token from Authorization Bearer or the cookie. */
export function getSessionToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  const raw = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (raw && typeof raw === 'string') {
    const match = raw.match(/^Bearer\s+(.+)$/i);
    if (match) return match[1].trim();
  }
  if (req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.session_token) return cookies.session_token;
  }
  return null;
}

export async function restoreSessionsFromDb(): Promise<void> {
  try {
    const { rows } = await pool.query('SELECT * FROM sessions');
    const now = Date.now();
    for (const r of rows) {
      const expire = r.expires_at ? new Date(r.expires_at).getTime() : now + 7 * 24 * 3600 * 1000;
      if (expire > now) {
        userSessions[r.token] = { username: r.username, expire };
      }
    }
  } catch {
    // ignore
  }
}

/**
 * پاک‌سازی سشن‌های منقضی (DP-11، راند ۳): سطرهای منقضی از دیتابیس و
 * ورودی‌های منقضی از حافظه حذف می‌شوند تا جدول sessions بی‌نهایت رشد نکند.
 * در استارتاپ و هر ساعت یک بار اجرا می‌شود.
 */
export async function purgeExpiredSessions(): Promise<void> {
  const now = Date.now();
  for (const [tok, sess] of Object.entries(userSessions)) {
    if (sess.expire <= now) {
      delete userSessions[tok];
    }
  }
  try {
    await pool.query('DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < NOW()');
  } catch (e: any) {
    console.warn('⚠️ اخطار در پاک‌سازی سشن‌های منقضی:', e?.message || e);
  }
}

/**
 * Resolve the session username for a request — async since round 5 (H3).
 * A blocked user resolves to null on EVERY REST route (their token is
 * worthless the moment the block lands), and a DB error inside the block
 * check fails CLOSED (null) rather than letting a possibly-blocked user
 * through. All call sites await this.
 */
async function getSessionUsername(req: Request): Promise<string | null> {
  const token = getSessionToken(req);
  if (!token) return null;
  const session = userSessions[token];
  if (!session) return null;
  if (Date.now() > session.expire) {
    delete userSessions[token];
    void removeUserSession(token);
    return null;
  }
  try {
    if (await isUserBlocked(session.username)) return null;
  } catch (e: any) {
    console.error('❌ خطا در بررسی مسدودیت کاربر (fail-closed):', e?.message || e);
    return null;
  }
  return session.username;
}

async function getSetting(key: string): Promise<string | null> {
  const { rows } = await pool.query('SELECT value FROM settings WHERE key = $1', [key]);
  return rows.length ? rows[0].value : null;
}

async function setSetting(key: string, value: string): Promise<void> {
  await pool.query(
    'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2',
    [key, value]
  );
}

/**
 * Admin auth (round 5, H4): ONLY a valid admin session token issued by
 * POST /api/admin/login is accepted in x-admin-token. The raw admin
 * password no longer works as a bearer token.
 */
function isAdmin(req: Request): boolean {
  const headerToken = req.headers['x-admin-token'];
  const token = Array.isArray(headerToken) ? headerToken[0] : headerToken;
  if (!token || typeof token !== 'string') return false;
  return verifyAdminSession(token);
}



async function isUserBlocked(username: string): Promise<boolean> {
  const { rows } = await pool.query(
    'SELECT is_blocked, block_type, block_until FROM users WHERE username = $1',
    [username]
  );
  const user = rows[0];
  if (!user || !user.is_blocked) return false;
  if (user.block_type === 'permanent') return true;
  if (user.block_type === 'temporary' && user.block_until) {
    if (new Date(user.block_until) > new Date()) return true;
    await pool.query(
      'UPDATE users SET is_blocked=0, block_type=NULL, block_until=NULL WHERE username=$1',
      [username]
    );
    return false;
  }
  return false;
}

// ===== HYBRID PERSISTENT FILE UPLOAD & MEDIA SERVING =====
// Media E2EE: the client encrypts file bytes with the room key BEFORE upload,
// so the server only ever sees ciphertext and stores it as-is (never decrypts).
// Backward compat: media uploaded before this change is RAW (the server never
// had the key, so it cannot retro-encrypt). It stays readable only to members
// of its chat (resolved through the linking message) — access-controlled but
// NOT encrypted. New media is both encrypted and access-controlled.
app.post(
  '/api/upload',
  async (req: Request, res: Response, next: express.NextFunction) => {
    // Auth runs BEFORE multer parses the body, so an unauthenticated upload
    // never writes a file to disk.
    if (!(await getSessionUsername(req))) {
      return res.status(401).json({ ok: false, msg: 'unauthorized' });
    }
    next();
  },
  // M7: 20 uploads / 15 min per user.
  rateLimitMiddleware(
    uploadLimiter,
    async (req) => (await getSessionUsername(req)) || getClientIp(req)
  ),
  upload.single('file'),
  async (req: Request, res: Response) => {
    const sessionUser = await getSessionUsername(req);
    if (!sessionUser) return res.status(401).json({ ok: false, msg: 'unauthorized' });
    if ((req as any).uploadRejected) {
      return res.status(400).json({ ok: false, msg: 'نوع فایل مجاز نیست' });
    }
    if (!req.file) return res.status(400).json({ ok: false, msg: 'فایل آپلود نشد' });
    // H1(a): magic-bytes validation of the written temp file. A rejected
    // file is deleted from disk before any response is sent.
    const ext = path.extname(req.file.originalname).toLowerCase();
    const uploadCheck = validateUploadFile(ext, await readFileHead(req.file.path), req.file.mimetype);
    if (!uploadCheck.ok) {
      // Read the reason before the await below (narrowing does not survive it).
      const reason = uploadCheck.reason;
      try {
        await fs.promises.unlink(req.file.path);
      } catch {
        // ignore
      }
      return res.status(400).json({ ok: false, msg: reason });
    }
    const kind = String((req.body as any)?.kind || '');
    const roomId = String((req.body as any)?.room_id || '');

    // Avatars have no room: they are public profile pictures, stored raw.
    // Chat media requires a room and membership in it.
    let roomIdToStore: string | null = null;
    if (kind === 'avatar') {
      roomIdToStore = null;
    } else {
      if (!roomId) return res.status(400).json({ ok: false, msg: 'room_id is required' });
      if (
        !(await canUploadToRoom(sessionUser, roomId, (sql, params) => pool.query(sql, params)))
      ) {
        // Fail closed: do not keep the uploaded file for a forbidden room.
        try {
          await fs.promises.unlink(req.file.path);
        } catch {
          // ignore
        }
        return res.status(403).json({ ok: false, msg: 'not a member of this room' });
      }
      roomIdToStore = roomId;
    }

    // Whether the bytes are encrypted is decided from the bytes themselves
    // (PQF1 magic — must match FILE_ENCRYPTION_MAGIC in src/utils/crypto.ts),
    // never from a client claim: a raw file is stored as raw, an encrypted
    // file as encrypted. Avatars are always raw.
    const isEncrypted = kind === 'avatar' ? 0 : uploadCheck.isEncrypted ? 1 : 0;

    let fileType = 'file';
    if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) fileType = 'image';
    else if (['.mp3', '.ogg', '.wav', '.webm', '.m4a'].includes(ext)) fileType = 'voice';
    else if (['.mp4', '.mov', '.avi'].includes(ext)) fileType = 'video';

    const mediaId = req.file.filename;
    // The file URL is ALWAYS the authenticated route — never the old public
    // /uploads path (which no longer exists).
    const fileUrl = `/api/media/${mediaId}`;

    // A metadata row is ALWAYS written (even for disk files), so /api/media
    // can enforce membership and report the encryption flag. Inline files
    // (<2MB, non-disk mode) also store their bytes in the row.
    const inline =
      config.STORAGE_MODE !== 'disk' && req.file.size <= config.INLINE_MAX_BYTES;
    try {
      const base64Data = inline
        ? (await fs.promises.readFile(req.file.path)).toString('base64')
        : null;
      await pool.query(
        'INSERT INTO media_blobs (id, mime_type, data_base64, room_id, is_encrypted, uploaded_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [
          mediaId,
          // H1(a): store the SERVER-VERIFIED mime, never the client claim.
          uploadCheck.verifiedMime,
          base64Data,
          roomIdToStore,
          isEncrypted,
          sessionUser,
          new Date().toISOString(),
        ]
      );
    } catch {
      // If the row insert fails, the bytes stay on disk and /api/media
      // resolves the room through the linking message instead.
    }

    res.json({
      ok: true,
      fileUrl,
      fileType,
      originalName: req.file.originalname,
      isEncrypted: isEncrypted === 1,
    });
  }
);

app.get('/api/media/:id', async (req: Request, res: Response) => {
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false, msg: 'unauthorized' });
  const mediaId = String(req.params.id);
  const access = await resolveMediaAccess(mediaId, sessionUser, (sql, params) =>
    pool.query(sql, params)
  );
  if (access.status === 'forbidden') {
    return res.status(403).json({ ok: false, msg: 'not a member of this chat' });
  }
  if (access.status === 'not-found') return res.status(404).send('Media not found');

  // Backward compat (see the comment above /api/upload): pre-change media is
  // RAW but members-only; new media is encrypted. The header tells the client
  // whether to decrypt. Cache is private: these bytes are per-chat, never
  // shared-cacheable.
  const encryptedHeader = access.isEncrypted ? '1' : '0';
  if (access.blob && access.blob.data_base64) {
    const buffer = Buffer.from(access.blob.data_base64, 'base64');
    // H1(c): Content-Type is the SERVER-VERIFIED mime (a legacy stored
    // client claim such as text/html is never served verbatim) and the
    // file is always an attachment, never inline. In-app rendering is
    // unaffected: the client fetches via fetch() + URL.createObjectURL
    // and picks the element from the message's fileType.
    res.setHeader('Content-Type', verifyStoredMime(access.blob.mime_type));
    res.setHeader('Content-Disposition', 'attachment');
    res.setHeader('X-Media-Encrypted', encryptedHeader);
    res.setHeader('Cache-Control', 'private, max-age=3600, must-revalidate');
    return res.send(buffer);
  }

  const diskFile = path.join(uploadsDir, path.basename(mediaId));
  if (fs.existsSync(diskFile)) {
    // H1(c): disk-only legacy file — mime unknown, serve as octet-stream.
    res.setHeader('Content-Type', verifyStoredMime(access.blob ? access.blob.mime_type : null));
    res.setHeader('Content-Disposition', 'attachment');
    res.setHeader('X-Media-Encrypted', encryptedHeader);
    res.setHeader('Cache-Control', 'private, max-age=3600, must-revalidate');
    return res.sendFile(diskFile);
  }
  return res.status(404).send('Media not found');
});

// ===== PUBLIC CLIENT CONFIG (Google Client ID is public, not a secret) =====
app.get('/api/config', (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  res.json({ googleClientId: getGoogleClientId() });
});

// ===== HEALTH CHECK (Bale API + DB telemetry) =====
app.get('/api/health', rateLimitMiddleware(healthLimiter, (req) => getClientIp(req)), async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  let dbOk = true;
  try {
    await pool.query('SELECT COUNT(*) as c FROM users');
  } catch {
    dbOk = false;
  }
  const baleStatus = bale.getBaleHealthStatus();
  // L2: unauthenticated callers get only {ok} (the 503-on-degraded status
  // stays); version / uptime / DB / Bale telemetry stay behind admin auth.
  // The DB check itself stays — it is what makes health meaningful.
  if (!isAdmin(req)) {
    return res.status(dbOk ? 200 : 503).json({ ok: dbOk });
  }
  return res.status(dbOk ? 200 : 503).json({
    ok: dbOk,
    version: APP_VERSION,
    uptimeSec: Math.floor(process.uptime()),
    database: !dbOk ? 'degraded' : isUsingFallback() ? 'fallback' : 'ok',
    bale: {
      configured: baleStatus.configured,
      reachable: baleStatus.reachable,
      consecutiveFailures: baleStatus.consecutiveFailures,
      lastCheckedAt: baleStatus.lastCheckedAt,
      lastErrorAt: baleStatus.lastErrorAt,
    },
  });
});

// ===== GOOGLE SIGN-IN (primary login; env-gated) =====

/**
 * One-time recovery codes for redirect logins. The recovery code must
 * never travel in a URL, so a new redirect login stores its code here
 * keyed by session token (10-minute expiry) and the client fetches it
 * exactly once via POST /api/recovery-code-once. The popup flow does
 * not use this store — it returns the code directly in its JSON reply.
 */
const pendingRecoveryCodes = new PendingRecoveryCodes();

/**
 * Shared Google sign-in completion, used by BOTH /api/google-login
 * (popup JSON) and /api/google-redirect (form POST + 302). Verifies
 * nothing itself — the caller must have verified the ID token and
 * checked the block list first. Creates the user atomically when new
 * (same one-time recovery code as every other registration path) and
 * issues a 7-day session token. The recovery code is returned to the
 * caller; it is the caller's job to deliver it safely (JSON reply for
 * popup, one-time fetch for redirect — never in a URL).
 *
 * Google profile sync: the token's display name and photo become the
 * chat profile by default. A new user is created with them (flags 0).
 * An existing user gets them refreshed ONLY for fields they never
 * edited manually (name_custom / avatar_custom = 0) — a manual edit
 * always wins and is never overwritten by a later login.
 */
async function completeGoogleSignIn(
  email: string,
  profile: GoogleProfile = { name: null, picture: null }
): Promise<{
  sessionToken: string;
  username: string;
  isNew: boolean;
  recoveryCode?: string;
}> {
  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [email]);
  let recoveryCode: string | undefined;
  let isNew = rows.length === 0;
  if (isNew) {
    recoveryCode = generateRecoveryCode();
    const recoveryCodeHash = await hashRecoveryCode(recoveryCode);
    try {
      await pool.query(
        'INSERT INTO users (username, bale_chat_id, joined_at, recovery_code_hash, email, display_name, avatar, name_custom, avatar_custom) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
        [email, null, new Date().toISOString(), recoveryCodeHash, email, profile.name, profile.picture, 0, 0]
      );
    } catch {
      isNew = false;
      recoveryCode = undefined;
    }
  }
  if (!isNew) {
    const { rows: stored } = await pool.query(
      'SELECT display_name, avatar, name_custom, avatar_custom FROM users WHERE username = $1',
      [email]
    );
    const merged = resolveGoogleProfileSync(stored[0] || {}, profile);
    if (merged) {
      await pool.query('UPDATE users SET display_name=$1, avatar=$2 WHERE username=$3', [
        merged.display_name,
        merged.avatar,
        email,
      ]);
    }
  }

  const sessionToken = uuidv4();
  const sessionExpire = Date.now() + 7 * 24 * 60 * 60 * 1000;
  await saveUserSession(sessionToken, email, sessionExpire);

  return { sessionToken, username: email, isNew, recoveryCode };
}

app.post('/api/google-login', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  const clientIp = (req.ip || (req.socket && req.socket.remoteAddress) || 'unknown').toString();
  const limit = googleLoginLimiter.checkAndConsume(clientIp, 'google-login');
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSec));
    return res.status(429).json({ ok: false, msg: 'Too many requests' });
  }
  if (!isGoogleConfigured()) return res.json({ ok: false, msg: GOOGLE_DISABLED_MSG });
  const idToken = String((req.body || {}).idToken || '').trim();
  if (!idToken) return res.json({ ok: false, msg: GOOGLE_LOGIN_FAILED_MSG });

  // توکن ID گوگل سمت سرور با کلیدهای گوگل بررسی می‌شود؛ در هر خطایی
  // (امضای نامعتبر، audience اشتباه، توکن منقضی، ایمیل تأییدنشده) پیام
  // کلی برمی‌گردد و هیچ جزئیاتی به بیرون درز نمی‌کند.
  let verified: { email: string; profile: GoogleProfile };
  try {
    verified = await verifyGoogleIdToken(idToken);
  } catch {
    return res.json({ ok: false, msg: GOOGLE_LOGIN_FAILED_MSG });
  }
  const email = verified.email;

  // M3(a): a blocked account gets the SAME generic failure as invalid
  // credentials — the block status must not leak.
  if (await isUserBlocked(email)) {
    return res.json({ ok: false, msg: GOOGLE_LOGIN_FAILED_MSG });
  }

  // گوگل خودش مالکیت ایمیل را اثبات کرده است؛ کاربر تازه اتمیک ساخته
  // می‌شود (ثبت‌نام جداگانه‌ای وجود ندارد) و کد بازیابی فقط همین‌بار نمایش داده می‌شود.
  const { sessionToken, username, isNew, recoveryCode } = await completeGoogleSignIn(
    email,
    verified.profile
  );

  res.cookie('session_token', sessionToken, {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.json({
    ok: true,
    isNew,
    username,
    sessionToken,
    ...(recoveryCode ? { recoveryCode } : {}),
  });
});

// Google Sign-In in redirect mode (ux_mode 'redirect'): Google POSTs the
// credential as a form to this endpoint instead of returning it to a
// popup. The popup return trip stalls on some mobile browsers (blank
// accounts.google.com/gsi/transform tab), while a full-page redirect
// always comes back. NOTE: this login_uri must be registered as an
// Authorized redirect URI in the Google Cloud Console OAuth client,
// otherwise Google refuses the redirect (redirect_uri_mismatch).
app.post('/api/google-redirect', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  res.setHeader('Referrer-Policy', 'no-referrer');
  const clientIp = (req.ip || (req.socket && req.socket.remoteAddress) || 'unknown').toString();
  const limit = googleLoginLimiter.checkAndConsume(clientIp, 'google-login');
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSec));
    return res.status(429).send('Too many requests');
  }
  if (!isGoogleConfigured()) {
    return res.status(403).send(GOOGLE_DISABLED_MSG);
  }
  const body = (req.body || {}) as Record<string, unknown>;
  const credential = String(body.credential || '').trim();
  const csrfField = String(body.g_csrf_token || '').trim();
  const csrfCookie = parseGoogleCsrfCookie(req.headers.cookie);
  // Gate first: missing credential is a malformed request (400); a
  // missing or mismatched CSRF token fails closed (403). No token is
  // issued unless the gate passes.
  const gate = checkGoogleRedirectRequest({ credential, csrfField, csrfCookie });
  if (gate === 'bad_request') {
    return res.status(400).send(GOOGLE_LOGIN_FAILED_MSG);
  }
  if (gate === 'forbidden') {
    return res.status(403).send(GOOGLE_LOGIN_FAILED_MSG);
  }

  let verified: { email: string; profile: GoogleProfile };
  try {
    verified = await verifyGoogleIdToken(credential);
  } catch {
    return res.status(403).send(GOOGLE_LOGIN_FAILED_MSG);
  }
  const email = verified.email;

  // M3(a): same status/message as an invalid credential — no block leak.
  if (await isUserBlocked(email)) {
    return res.status(403).send(GOOGLE_LOGIN_FAILED_MSG);
  }

  const { sessionToken, isNew, recoveryCode } = await completeGoogleSignIn(
    email,
    verified.profile
  );
  if (isNew && recoveryCode) {
    pendingRecoveryCodes.store(sessionToken, recoveryCode, Date.now());
  }

  res.cookie('session_token', sessionToken, {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  // The session token rides in the URL only for this one hop; the
  // client stores it and strips it from the address bar immediately
  // (history.replaceState). The recovery code NEVER appears in a URL.
  return res.redirect(302, buildGoogleRedirectUrl(sessionToken, isNew));
});

// One-time fetch of the recovery code issued by a redirect login.
// The client calls this once after storing the session token; the code
// is returned at most once and then burned. The response also carries
// the session owner's username so the client can finish the login
// without the username ever appearing in a URL.
app.post('/api/recovery-code-once', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  const sessionToken = String((req.body || {}).sessionToken || '').trim();
  const session = sessionToken ? userSessions[sessionToken] : undefined;
  if (!session || Date.now() > session.expire) {
    return res.json({ ok: false });
  }
  const code = pendingRecoveryCodes.take(sessionToken, Date.now());
  if (!code) {
    return res.json({ ok: true, username: session.username });
  }
  return res.json({ ok: true, username: session.username, recoveryCode: code });
});

app.post('/api/recover', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  const { baleId, recoveryCode } = req.body || {};
  const key = String(baleId || '').toLowerCase().replace(/^@+/, '').trim();
  const code = String(recoveryCode || '').trim();

  const clientIp =
    (typeof req.ip === 'string' && req.ip) ||
    req.socket?.remoteAddress ||
    'unknown';

  const limit = recoverRateLimiter.checkAndConsume(clientIp, key || 'empty');
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSec));
    return res.status(429).json({
      ok: false,
      msg: 'تعداد تلاش‌های ناموفق بیش از حد مجاز است. لطفاً دقایقی دیگر دوباره تلاش کنید.',
    });
  }

  if (!key || !code) {
    return res.status(400).json({ ok: false, msg: 'آیدی بله و کد بازیابی الزامی است.' });
  }

  const { rows } = await pool.query(
    'SELECT username, recovery_code_hash FROM users WHERE username = $1',
    [key]
  );
  const user = rows[0];
  if (!user || !user.recovery_code_hash) {
    return res.status(401).json({ ok: false, msg: 'آیدی یا کد بازیابی نامعتبر است.' });
  }

  // M3(a): same generic 401 as an invalid code — no block leak.
  if (await isUserBlocked(key)) {
    return res.status(401).json({ ok: false, msg: 'آیدی یا کد بازیابی نامعتبر است.' });
  }

  const valid = await verifyRecoveryCode(code, user.recovery_code_hash);
  if (!valid) {
    return res.status(401).json({ ok: false, msg: 'آیدی یا کد بازیابی نامعتبر است.' });
  }

  // مصرف یک‌بارمصرف کد و چرخش فوری به کد بازیابی جدید (فقط هش scrypt جدید ذخیره می‌شود)
  const nextRecoveryCode = generateRecoveryCode();
  const nextHash = await hashRecoveryCode(nextRecoveryCode);
  await pool.query('UPDATE users SET recovery_code_hash=$1 WHERE username=$2', [nextHash, key]);

  // M2: a recovery means the old credentials may be compromised — revoke
  // ALL existing sessions BEFORE issuing the new one.
  await removeAllUserSessions(key);

  const sessionToken = uuidv4();
  const sessionExpire = Date.now() + 7 * 24 * 60 * 60 * 1000;
  await saveUserSession(sessionToken, key, sessionExpire);

  res.cookie('session_token', sessionToken, {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return res.json({
    ok: true,
    username: key,
    sessionToken,
    nextRecoveryCode,
  });
});

app.post('/api/quick-login', (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  return res.status(403).json({ ok: false, msg: 'ورود سریع تستی غیرفعال شده است' });
});

// M2: logout — revoke the token (Bearer or cookie) and clear the cookie.
app.post('/api/logout', async (req: Request, res: Response) => {
  const token = getSessionToken(req);
  if (token) await removeUserSession(token);
  res.clearCookie('session_token', { httpOnly: true, sameSite: 'lax' });
  res.json({ ok: true });
});

// ===== RISTRETTO255-VOPRF BLINDED IDENTITY EVALUATION (RFC 9497) =====
app.post('/api/voprf/evaluate', (req: Request, res: Response) => {
  const clientIp = (req.ip || (req.socket && req.socket.remoteAddress) || 'unknown').toString();
  const limit = voprfRateLimiter.checkAndConsume(clientIp, 'voprf');
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSec));
    return res.status(429).json({ ok: false, msg: 'Too many requests' });
  }
  try {
    const { blindedB64 } = req.body;
    if (!blindedB64) return res.status(400).json({ ok: false });
    const blindedBytes = new Uint8Array(Buffer.from(blindedB64, 'base64'));
    const { evaluated, proof } = ristretto255_oprf.voprf.blindEvaluate(
      serverVoprfKeys.secretKey,
      serverVoprfKeys.publicKey,
      blindedBytes
    );
    res.json({
      ok: true,
      evaluatedB64: Buffer.from(evaluated).toString('base64'),
      proofB64: Buffer.from(proof).toString('base64'),
      serverPublicKeyB64: Buffer.from(serverVoprfKeys.publicKey).toString('base64'),
    });
  } catch {
    // جلوگیری از انتشار جزئیات خطای داخلی سرور به پاسخ کلاینت.
    res.status(400).json({ ok: false });
  }
});

// ===== USER & HYBRID POST-QUANTUM PUBLIC KEY DIRECTORY =====
app.get('/api/user/:username', rateLimitMiddleware(userLookupLimiter, (req) => getClientIp(req)), async (req: Request, res: Response) => {
  const { rows } = await pool.query(
    'SELECT username, display_name, avatar, bio, status, public_key FROM users WHERE username = $1',
    [req.params.username]
  );
  if (!rows.length) return res.json({ ok: false });
  res.json({ ok: true, user: rows[0] });
});

app.post('/api/user/public-key', async (req: Request, res: Response) => {
  const { username, publicKey } = req.body;
  if (!username || !publicKey || typeof publicKey !== 'string') return res.json({ ok: false });
  if (publicKey.length < 50 || publicKey.length > 32768) {
    return res.status(400).json({ ok: false, msg: 'invalid public key bundle length' });
  }
  try {
    const parsed = JSON.parse(publicKey);
    if (!parsed || typeof parsed !== 'object' || !parsed.ecdhJwk || typeof parsed.ecdhJwk !== 'object') {
      return res.status(400).json({ ok: false, msg: 'invalid public key bundle format' });
    }
  } catch {
    return res.status(400).json({ ok: false, msg: 'malformed bundle json' });
  }
  // فقط کاربر احراز هویت شده با نشست معتبر امکان ثبت و تغییر باندل را دارد؛
  // در غیر این صورت هر کسی می‌توانست باندل هر کاربری را جایگزین کند.
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser || sessionUser !== username) {
    return res.status(401).json({ ok: false, msg: 'unauthorized' });
  }
  await pool.query('UPDATE users SET public_key=$1 WHERE username=$2', [publicKey, username]);

  // اطلاع‌رسانی کلید عمومی جدید به مخاطبان آنلاین برای رمزنگاری خودکار ECDH
  const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [username]);
  contacts.forEach(({ contact }: any) => {
    presence.emitToUser(io, contact, 'peer-key-updated', { username, publicKey });
  });

  res.json({ ok: true });
});

// صدور مجدد کد بازیابی برای کاربر احراز هویت شده
app.post(['/api/auth/reissue-recovery-code', '/api/reissue-recovery-code'], async (req: Request, res: Response) => {
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false, msg: 'unauthorized' });
  const newCode = generateRecoveryCode();
  const hash = await hashRecoveryCode(newCode);
  await pool.query('UPDATE users SET recovery_code_hash = $1 WHERE username = $2', [hash, sessionUser]);
  // M2: revoke all OTHER sessions for this user, but KEEP the current one
  // — revoking it would log the user out mid-flow and break subsequent
  // REST calls.
  const currentToken = getSessionToken(req);
  if (currentToken) await removeAllUserSessionsExcept(sessionUser, currentToken);
  res.json({ ok: true, recoveryCode: newCode });
});

// ===== GROUP EPOCH KEY PACKETS =====
// بسته کلید اپوک گروه: توزیع‌کننده (سازنده گروه) کلید تصادفی اپوک را با
// ML-KEM-768 به هر عضو کپسوله می‌کند؛ سرور فقط کپسول‌ها را نگه می‌دارد و
// جابه‌جا می‌کند و کلید را نمی‌بیند.
app.post('/api/group/:id/epoch-packet', async (req: Request, res: Response) => {
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false });
  const { epoch, keys, sig } = req.body as { epoch?: unknown; keys?: unknown; sig?: unknown };
  if (typeof epoch !== 'number' || !Number.isSafeInteger(epoch) || epoch < 1 || epoch > Number.MAX_SAFE_INTEGER) {
    return res.json({ ok: false, msg: 'invalid epoch' });
  }
  if (!keys || typeof keys !== 'object' || Array.isArray(keys)) {
    return res.json({ ok: false, msg: 'invalid keys' });
  }
  const keyEntries = Object.entries(keys as Record<string, unknown>);
  if (keyEntries.length > 200) {
    return res.json({ ok: false, msg: 'too many key entries' });
  }
  for (const [u, ct] of keyEntries) {
    if (typeof u !== 'string' || !u || typeof ct !== 'string' || ct.length > 2048 || !/^[A-Za-z0-9+/=]+$/.test(ct)) {
      return res.json({ ok: false, msg: 'invalid key entry' });
    }
  }
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [req.params.id]);
  // M3(b): 'group not found' and 'not a member' return the identical
  // {ok:false} shape — no oracle.
  if (!rows.length) return res.json({ ok: false });
  // L7(e): a corrupt members row fails closed with the generic shape.
  const members = safeParseMembers(rows[0].members);
  if (!members) return res.json({ ok: false });
  if (!members.includes(sessionUser)) return res.json({ ok: false });
  // H2: انحصار چرخش اپوک به توزیع‌کننده گروه (عضو اول)
  if (members[0] !== sessionUser) {
    return res.status(403).json({ ok: false, msg: 'only group distributor can post epoch packets' });
  }

  // H2: تأیید امضای دیجیتال ML-DSA-65 توزیع‌کننده بر روی بسته اپوک.
  // راند ۳: امضا همیشه لازم است — اگر باندل توزیع‌کننده کلید ML-DSA نداشت
  // یا اصلاً باندلی ذخیره نشده بود، بسته رد می‌شود (پیش‌تر در این حالت‌ها
  // بررسی کاملاً رد می‌شد و بستهٔ بدون امضا پذیرفته می‌شد). همهٔ هویت‌های
  // فعال v4 کلید ML-DSA دارند و باندل در هر ورود منتشر می‌شود، پس این
  // سخت‌گیری حساب‌های قدیمیِ فعال را نمی‌شکند.
  const userRes = await pool.query('SELECT public_key FROM users WHERE username = $1', [sessionUser]);
  if (!userRes.rows.length || !userRes.rows[0].public_key) {
    return res.status(403).json({ ok: false, msg: 'distributor ML-DSA key unavailable' });
  }
  try {
    const parsedBundle = JSON.parse(userRes.rows[0].public_key);
    if (!parsedBundle.mldsaPubB64) {
      return res.status(403).json({ ok: false, msg: 'distributor ML-DSA key unavailable' });
    }
    if (typeof sig !== 'string' || !sig) {
      return res.status(403).json({ ok: false, msg: 'distributor ML-DSA signature required' });
    }
    const mldsaPub = Buffer.from(parsedBundle.mldsaPubB64, 'base64');
    const sigBytes = Buffer.from(sig, 'base64');
    const sortedMembers = [...members].sort().join(',');
    const sortedKeys = Object.keys(keys as Record<string, string>)
      .sort()
      .map(k => `${k}=${(keys as Record<string, string>)[k]}`)
      .join('&');
    const signTarget = new TextEncoder().encode(`MLDSA-EPOCH-PACKET-v1:${epoch}:${sortedMembers}:${sortedKeys}`);
    const valid = ml_dsa65.verify(sigBytes, signTarget, mldsaPub);
    if (!valid) {
      return res.status(403).json({ ok: false, msg: 'invalid distributor ML-DSA signature on epoch packet' });
    }
  } catch {
    return res.status(403).json({ ok: false, msg: 'failed to verify distributor signature' });
  }

  // DP-10: جلوگیری از rollback اپوک
  const rawPrev = await getSetting(`group_epoch_packet_${req.params.id}`);
  if (rawPrev) {
    try {
      const prev = JSON.parse(rawPrev);
      if (typeof prev.epoch === 'number' && epoch <= prev.epoch) {
        return res.json({ ok: false, msg: 'epoch must be greater than current epoch' });
      }
    } catch {}
  }
  const packet = { epoch, keys, sig: typeof sig === 'string' ? sig : undefined, postedBy: sessionUser, postedAt: new Date().toISOString() };
  await setSetting(`group_epoch_packet_${req.params.id}`, JSON.stringify(packet));
  // پخش فوری به اعضای آنلاین
  members.forEach(m => {
    presence.emitToUser(io, m, 'group-epoch-rotated', {
      groupId: req.params.id,
      name: rows[0].name,
      epoch,
      members,
      epochKeys: keys,
    });
  });
  res.json({ ok: true });
});

app.get('/api/group/:id/epoch-packet', async (req: Request, res: Response) => {
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.json({ ok: false });
  // L7(e): a corrupt members row fails closed with the generic shape.
  const members = safeParseMembers(rows[0].members);
  if (!members) return res.json({ ok: false });
  if (!members.includes(sessionUser)) return res.json({ ok: false });
  const raw = await getSetting(`group_epoch_packet_${req.params.id}`);
  if (!raw) return res.json({ ok: false });
  try {
    const packet = JSON.parse(raw);
    res.json({ ok: true, epoch: packet.epoch, keys: packet.keys });
  } catch {
    res.json({ ok: false });
  }
});

app.post('/api/user/update', rateLimitMiddleware(userUpdateLimiter, async (req) => (await getSessionUsername(req)) || getClientIp(req)), async (req: Request, res: Response) => {
  // A user may only update their OWN profile: without this check anyone
  // could overwrite any user's bio, status and avatar by posting a username.
  // The display name is editable here too; a value that actually differs
  // from the stored one raises the matching custom flag, so later Google
  // logins stop overwriting that field (a save that changes nothing
  // leaves the flags — and future Google sync — untouched).
  const { username, bio, status, avatar, display_name } = req.body || {};
  const access = checkOwnUsername(await getSessionUsername(req), String(username ?? ''));
  if (access !== 'ok') {
    return res.status(403).json({ ok: false, msg: 'unauthorized' });
  }
  // M7: length caps (bio ≤1000, status ≤100). The avatar allowlist is
  // enforced inside resolveProfileUpdate (single enforcement point, L7a).
  if (typeof bio === 'string' && bio.length > 1000) {
    return res.status(400).json({ ok: false, msg: 'bio too long' });
  }
  if (typeof status === 'string' && status.length > 100) {
    return res.status(400).json({ ok: false, msg: 'status too long' });
  }
  const { rows } = await pool.query(
    'SELECT display_name, avatar, name_custom, avatar_custom FROM users WHERE username = $1',
    [username]
  );
  const merged = resolveProfileUpdate(rows[0] || {}, {
    display_name: 'display_name' in (req.body || {}) ? display_name : undefined,
    avatar: 'avatar' in (req.body || {}) ? avatar : undefined,
  });
  await pool.query(
    'UPDATE users SET bio=$1, status=$2, avatar=$3, display_name=$4, name_custom=$5, avatar_custom=$6 WHERE username=$7',
    [
      bio || '',
      status || 'online',
      merged.avatar,
      merged.display_name,
      merged.name_custom,
      merged.avatar_custom,
      username,
    ]
  );
  res.json({ ok: true });
});

app.post('/api/add-contact', rateLimitMiddleware(addContactLimiter, async (req) => (await getSessionUsername(req)) || getClientIp(req)), async (req: Request, res: Response) => {
  // A user may only add contacts to their OWN list — otherwise anyone could
  // insert contact rows for any account (and harvest public keys in return).
  const { myUsername, contactUsername } = req.body || {};
  const access = checkOwnUsername(await getSessionUsername(req), String(myUsername ?? ''));
  if (access !== 'ok') {
    return res.status(403).json({ ok: false, msg: 'unauthorized' });
  }
  const { rows } = await pool.query('SELECT username, public_key FROM users WHERE username = $1', [
    contactUsername,
  ]);
  if (!rows.length) return res.json({ ok: false, msg: 'این آیدی وجود ندارد' });
  if (myUsername === contactUsername) return res.json({ ok: false, msg: 'نمی‌تونی خودت رو اضافه کنی' });
  await pool.query('INSERT INTO contacts (username, contact) VALUES ($1, $2) ON CONFLICT DO NOTHING', [
    myUsername,
    contactUsername,
  ]);
  res.json({ ok: true, publicKey: rows[0].public_key || null });
});

app.get('/api/contacts/:username', async (req: Request, res: Response) => {
  // A user may only list their OWN contacts: without this check anyone could
  // enumerate any user's contact list with public keys, statuses and online state.
  const access = checkOwnUsername(await getSessionUsername(req), String(req.params.username));
  if (access !== 'ok') {
    return res.status(403).json({ ok: false, msg: 'unauthorized' });
  }
  const { rows } = await pool.query(
    'SELECT c.contact, u.display_name, u.avatar, u.status, u.public_key FROM contacts c JOIN users u ON c.contact = u.username WHERE c.username = $1',
    [req.params.username]
  );
  res.json({
    ok: true,
    contacts: rows.map((r: any) => ({
      username: r.contact,
      display_name: r.display_name || null,
      avatar: r.avatar,
      status: r.status,
      public_key: r.public_key || null,
      online: presence.isOnline(r.contact),
    })),
  });
});

// ===== ROOM MESSAGES (access-controlled: session + membership) =====
// A room id is guessable (DM rooms are `user1__user2`, groups `group__<id>`),
// so the endpoint must not serve messages to anyone who knows the id.
// No session and non-member both get 403 (and so does an unknown room),
// so the response never leaks whether a room exists. Content stays E2EE.
app.get('/api/messages/:roomId', async (req: Request, res: Response) => {
  const roomId = String(req.params.roomId);
  const access = await checkRoomReadAccess(await getSessionUsername(req), roomId, (sql, params) =>
    pool.query(sql, params)
  );
  if (access !== 'ok') {
    return res.status(403).json({ ok: false, msg: 'not a member of this chat' });
  }
  const { rows } = await pool.query(
    'SELECT * FROM messages WHERE room_id = $1 AND is_deleted = 0 ORDER BY timestamp ASC',
    [roomId]
  );
  res.json({ ok: true, messages: rows.map(parseMsg) });
});

app.get('/api/groups/:username', async (req: Request, res: Response) => {
  // A user may only list their own groups: the session username must equal
  // the username in the URL, otherwise anyone could enumerate anyone's groups.
  const access = checkOwnGroupsAccess(await getSessionUsername(req), String(req.params.username));
  if (access !== 'ok') {
    return res.status(403).json({ ok: false, msg: 'unauthorized' });
  }
  const { rows } = await pool.query('SELECT * FROM groups');
  const targetUser = decodeURIComponent(String(req.params.username)).trim();
  const myGroups = rows.filter((g: any) => {
    try {
      const members: string[] = JSON.parse(g.members);
      return members.some(m => m.toLowerCase() === targetUser.toLowerCase() || m === targetUser);
    } catch {
      return false;
    }
  });
  // M7: limit/offset pagination over the filtered result (default 50,
  // max 100). No Postgres-only LIKE query — the fallback DB answers only
  // its known SQL shapes, so filtering stays in JS.
  const limit = Math.min(Math.max(parseInt(String(req.query.limit ?? '50'), 10) || 50, 1), 100);
  const offset = Math.max(parseInt(String(req.query.offset ?? '0'), 10) || 0, 0);
  const page = myGroups.slice(offset, offset + limit);
  res.json({
    ok: true,
    total: myGroups.length,
    limit,
    offset,
    groups: page.map((g: any) => ({
      ...g,
      epoch: Number(g.epoch) || 1,
      members: safeParseMembers(g.members) ?? [],
    })),
  });
});

// ===== REPORT =====
// M4: requires a session; reporter is FORCED to the session user (the
// client-sent reporter is ignored); field lengths are capped; 10/15min
// per user. The client sends the Authorization header.
app.post(
  '/api/report',
  rateLimitMiddleware(
    reportLimiter,
    async (req) => (await getSessionUsername(req)) || getClientIp(req)
  ),
  async (req: Request, res: Response) => {
    const sessionUser = await getSessionUsername(req);
    if (!sessionUser) return res.status(401).json({ ok: false, msg: 'unauthorized' });
    const { reportedUser, messageId, messageText, reason } = req.body || {};
    const reported = String(reportedUser || '').slice(0, 256);
    const mid = String(messageId || '').slice(0, 256) || null;
    const mtext = String(messageText || '').slice(0, 2000) || null;
    const rsn = String(reason || '').slice(0, 500);
    if (!reported || !rsn) {
      return res.status(400).json({ ok: false, msg: 'reportedUser and reason are required' });
    }
    await pool.query(
      'INSERT INTO reports (id, reporter, reported_user, message_id, message_text, reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [uuidv4(), sessionUser, reported, mid, mtext, rsn, new Date().toISOString()]
    );
    res.json({ ok: true });
  }
);

// ===== ACCOUNT DATA EXPORT & ERASURE (DATA RIGHTS) =====
app.get('/api/account/export', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  const username = await getSessionUsername(req);
  if (!username) return res.status(401).json({ ok: false });

  const { rows: userRows } = await pool.query(
    'SELECT username, bio, status, joined_at, last_seen FROM users WHERE username = $1',
    [username]
  );
  if (!userRows.length) return res.status(401).json({ ok: false });

  const { rows: contacts } = await pool.query(
    'SELECT contact FROM contacts WHERE username = $1',
    [username]
  );
  const { rows: messages } = await pool.query(
    'SELECT id, room_id, sender, text, file_url, file_type, time, timestamp FROM messages WHERE sender = $1 AND is_deleted = 0 ORDER BY timestamp ASC',
    [username]
  );

  return res.json({
    exportedAt: new Date().toISOString(),
    account: userRows[0],
    contacts: contacts.map((c: any) => c.contact),
    sentMessages: messages,
  });
});

app.post('/api/account/delete', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  const username = await getSessionUsername(req);
  if (!username) return res.status(401).json({ ok: false, msg: 'ابتدا وارد حساب کاربری شوید.' });

  // Deletion is confirmed with the one-time recovery code (the Bale OTP
  // channel is gone). The code is verified against the stored scrypt
  // hash; accounts created before recovery codes existed have no hash
  // and fall back to the (already verified) session alone — see
  // canDeleteWithCode in src/server/recovery.ts.
  const submittedCode = String(req.body?.otp ?? req.body?.code ?? '').trim();
  const { rows: userRows } = await pool.query(
    'SELECT username, recovery_code_hash FROM users WHERE username = $1',
    [username]
  );
  if (!userRows.length) return res.status(404).json({ ok: false, msg: 'حساب کاربری یافت نشد.' });
  if (!(await canDeleteWithCode(userRows[0].recovery_code_hash, submittedCode))) {
    return res.status(403).json({ ok: false, msg: 'کد بازیابی نامعتبر است.' });
  }

  // H1(d): collect the user's media FIRST (own blobs + media linked from
  // their messages), then delete messages, then drop each blob only if no
  // remaining non-deleted message references it (forwards copy file_url).
  const ownBlobs = await pool.query('SELECT * FROM media_blobs WHERE uploaded_by = $1', [username]);
  const ownMsgFiles = await pool.query('SELECT file_url FROM messages WHERE sender = $1', [username]);
  const mediaIds = new Set<string>();
  for (const b of ownBlobs.rows as any[]) mediaIds.add(String(b.id));
  for (const m of ownMsgFiles.rows as any[]) {
    const mid = extractMediaId(m.file_url);
    if (mid) mediaIds.add(mid);
  }

  await pool.query('DELETE FROM messages WHERE sender = $1', [username]);
  await pool.query('DELETE FROM contacts WHERE username = $1 OR contact = $1', [username]);
  // H1(d): group memberships (no ghost member strings) and reports.
  const { rows: allGroups } = await pool.query('SELECT * FROM groups');
  for (const g of allGroups as any[]) {
    const members = safeParseMembers(g.members);
    if (members && members.includes(username)) {
      await pool.query('UPDATE groups SET members = $1 WHERE id = $2', [
        JSON.stringify(members.filter((m: string) => m !== username)),
        g.id,
      ]);
    }
  }
  await pool.query('DELETE FROM reports WHERE reporter = $1 OR reported_user = $1', [username]);
  await pool.query('DELETE FROM users WHERE username = $1', [username]);
  for (const mid of mediaIds) {
    await deleteMediaIfUnreferenced(mid, (sql, params) => pool.query(sql, params), unlinkUploadFile);
  }

  await removeAllUserSessions(username);

  return res.json({ ok: true });
});

// ===== SETTINGS =====
app.get('/api/settings/rules', async (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  res.json({ ok: true, rules: await getSetting('rules') });
});

app.get('/api/settings/mode', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');

  if (isAdmin(req)) {
    const mode = (await getSetting('server_mode')) || 'normal';
    const msg = await getSetting('maintenance_msg');
    return res.status(200).json({ ok: true, mode, msg });
  }

  // M3: a valid session proves the user — no spoofable X-Session-User
  // header, no 401-vs-200 existence oracle. Info: the 401 uses the
  // consistent JSON shape {ok:false, error:'unauthorized'}, not an empty body.
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }

  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [sessionUser]);
  if (!rows.length) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }

  const mode = (await getSetting('server_mode')) || 'normal';
  if (mode === 'maintenance') {
    const msg = await getSetting('maintenance_msg');
    return res.status(503).json({ mode: 'maintenance', msg });
  }

  return res.status(200).json({ mode: 'normal' });
});

// ===== ADMIN =====
// H4: rate-limited + lockout (5 failures / 15 min / IP, exponential
// backoff). Success issues a 30-minute admin session token; the password
// itself is never returned and never works as a bearer token again.
app.post('/api/admin/login', (req: Request, res: Response) => {
  const clientIp = getClientIp(req);
  const now = Date.now();
  const lock = adminLoginLimiter.check(clientIp, now);
  if (!lock.allowed) {
    res.setHeader('Retry-After', String(lock.retryAfterSec));
    return res
      .status(429)
      .json({ ok: false, msg: 'تلاش‌های ناموفق زیاد است؛ چند دقیقه دیگر تلاش کنید' });
  }
  if (!verifyAdminSecret((req.body || {}).password)) {
    adminLoginLimiter.recordFailure(clientIp, now);
    // Log the attempt (IP + time) — NEVER the password.
    console.warn(`[Admin] failed admin login from ${clientIp} at ${new Date(now).toISOString()}`);
    return res.json({ ok: false });
  }
  adminLoginLimiter.recordSuccess(clientIp);
  const { token: adminToken } = issueAdminSession(now);
  res.json({ ok: true, adminToken });
});

app.get('/api/admin/users', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM users ORDER BY joined_at DESC');
  res.json({ ok: true, users: rows });
});

app.get('/api/admin/reports', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM reports ORDER BY created_at DESC');
  res.json({ ok: true, reports: rows });
});

app.post('/api/admin/report-action', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { reportId, status } = req.body;
  await pool.query('UPDATE reports SET status = $1 WHERE id = $2', [status, reportId]);
  res.json({ ok: true });
});

app.post('/api/admin/block', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username, reason, blockType, blockUntil } = req.body || {};
  // L7(f): validate blockType / blockUntil (admin-only, but garbage must
  // not land in the row).
  if (blockType !== undefined && blockType !== 'permanent' && blockType !== 'temporary') {
    return res.status(400).json({ ok: false, msg: 'invalid blockType' });
  }
  if (blockUntil) {
    const parsedUntil = new Date(blockUntil);
    if (Number.isNaN(parsedUntil.getTime())) {
      return res.status(400).json({ ok: false, msg: 'invalid blockUntil' });
    }
  }
  await pool.query(
    'UPDATE users SET is_blocked=1, block_reason=$1, block_type=$2, block_until=$3 WHERE username=$4',
    [reason || '', blockType || 'permanent', blockUntil || null, username]
  );

  // H3: blocking revokes every session immediately (the block check inside
  // getSessionUsername is the second layer for tokens issued afterwards).
  await removeAllUserSessions(username);

  const { rows } = await pool.query('SELECT bale_chat_id FROM users WHERE username = $1', [username]);
  const user = rows[0];
  const sockId = presence.getSocketIdByUsername(username);
  if (sockId) {
    io.to(sockId).emit('blocked', { block_reason: reason, block_type: blockType, block_until: blockUntil });
    const s = io.sockets.sockets.get(sockId);
    if (s) s.disconnect(true);
  }

  if (user?.bale_chat_id) {
    let msg = `🚫 حساب شما مسدود شد.\n\nعلت: ${reason || 'تخلف'}\n`;
    if (blockType === 'temporary' && blockUntil) {
      msg += `نوع: موقت\nتا تاریخ: ${new Date(blockUntil).toLocaleDateString('fa-IR')}`;
    } else {
      msg += 'نوع: دائمی';
    }
    await bale.sendMessage(user.bale_chat_id, msg);
  }

  res.json({ ok: true });
});

app.post('/api/admin/unblock', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username } = req.body;
  await pool.query(
    'UPDATE users SET is_blocked=0, block_reason=NULL, block_type=NULL, block_until=NULL WHERE username=$1',
    [username]
  );

  const { rows } = await pool.query('SELECT bale_chat_id FROM users WHERE username = $1', [username]);
  const user = rows[0];
  if (user?.bale_chat_id) {
    await bale.sendMessage(user.bale_chat_id, '✅ مسدودیت حساب شما برداشته شد.');
  }
  res.json({ ok: true });
});

app.post('/api/admin/kick', (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username } = req.body;
  const sockId = presence.getSocketIdByUsername(username);
  if (sockId) {
    io.to(sockId).emit('kicked');
    const s = io.sockets.sockets.get(sockId);
    if (s) s.disconnect(true);
  }
  res.json({ ok: true });
});

app.delete('/api/admin/message', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { roomId, msgId } = req.body || {};
  const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1', [msgId]);
  await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msgId]);
  // H1(d): drop the media when no remaining non-deleted message uses it.
  if (rows.length && rows[0].file_url) {
    const mid = extractMediaId(rows[0].file_url);
    if (mid) await deleteMediaIfUnreferenced(mid, (sql, params) => pool.query(sql, params), unlinkUploadFile);
  }
  // M5: msg-deleted goes to room members only, not every socket.
  await emitToRoom(io, roomId, 'msg-deleted', { roomId, msgId }, (sql, params) =>
    pool.query(sql, params)
  );
  res.json({ ok: true });
});

app.post('/api/create-group', rateLimitMiddleware(createGroupLimiter, async (req) => (await getSessionUsername(req)) || getClientIp(req)), async (req: Request, res: Response) => {
  const { name, members, creator } = req.body;
  if (!name || !name.trim()) return res.json({ ok: false, msg: 'نام گروه را وارد کنید' });
  if (name.trim().length > 100) return res.status(400).json({ ok: false, msg: 'نام گروه بیش از حد طولانی است' });
  // ایجاد گروه صرفاً با شناسه کاربری معتبر انجام می‌شود.
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser || sessionUser !== creator) {
    return res.status(401).json({ ok: false });
  }
  const memberList = Array.isArray(members) ? members : [];
  // M7: max 100 members total; every member must exist as a user.
  const { rows: allUsers } = await pool.query('SELECT username FROM users');
  const existingUsers = new Set((allUsers as any[]).map((u) => u.username));
  const validMembers = memberList.filter((m: any) => typeof m === 'string' && existingUsers.has(m));
  const allMembers = Array.from(new Set([creator, ...validMembers].filter(Boolean)));
  if (allMembers.length > 100) {
    return res.status(400).json({ ok: false, msg: 'تعداد اعضای گروه بیش از حد مجاز است' });
  }
  const groupId = uuidv4();
  await pool.query('INSERT INTO groups (id, name, members, created_at) VALUES ($1,$2,$3,$4)', [
    groupId,
    name.trim(),
    JSON.stringify(allMembers),
    new Date().toISOString(),
  ]);
  const newGroupData = {
    id: groupId,
    name: name.trim(),
    members: allMembers,
    epoch: 1,
    created_at: new Date().toISOString(),
  };
  allMembers.forEach(m => {
    presence.emitToUser(io, m, 'new-group', newGroupData);
  });
  res.json({ ok: true, group: newGroupData, groupId });
});

app.post('/api/admin/create-group', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { name, members } = req.body || {};
  if (!name || typeof name !== 'string' || !name.trim() || name.trim().length > 100) {
    return res.status(400).json({ ok: false, msg: 'invalid group name' });
  }
  const memberList = Array.isArray(members) ? members.filter((m: any) => typeof m === 'string') : [];
  // M7: max 100 members; every member must exist as a user.
  const { rows: allUsers } = await pool.query('SELECT username FROM users');
  const existingUsers = new Set((allUsers as any[]).map((u) => u.username));
  const validMembers = Array.from(new Set(memberList.filter((m: string) => existingUsers.has(m))));
  if (validMembers.length > 100) {
    return res.status(400).json({ ok: false, msg: 'too many members' });
  }
  const groupId = uuidv4();
  await pool.query('INSERT INTO groups (id, name, members, created_at) VALUES ($1,$2,$3,$4)', [
    groupId,
    name.trim(),
    JSON.stringify(validMembers),
    new Date().toISOString(),
  ]);
  validMembers.forEach(m => {
    presence.emitToUser(io, m, 'new-group', { id: groupId, name: name.trim(), members: validMembers, epoch: 1 });
  });
  res.json({ ok: true, groupId });
});

app.post('/api/admin/add-to-group', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { groupId, username } = req.body;
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [groupId]);
  if (!rows.length) return res.json({ ok: false, msg: 'گروه یافت نشد' });
  const group = rows[0];
  // L7(e): a corrupt members row fails closed instead of throwing.
  const members = safeParseMembers(group.members);
  if (!members) return res.json({ ok: false, msg: 'گروه یافت نشد' });
  if (!members.includes(username)) members.push(username);
  const newEpoch = (Number(group.epoch) || 1) + 1;
  await pool.query('UPDATE groups SET members = $1, epoch = $2 WHERE id = $3', [
    JSON.stringify(members),
    newEpoch,
    groupId,
  ]);
  presence.emitToUser(io, username, 'new-group', {
    id: groupId,
    name: group.name,
    members,
    epoch: newEpoch,
  });
  // اطلاع‌رسانی چرخش اپوک گروه (Group Epoch Rotation FSM) به تمام اعضای گروه
  members.forEach(m => {
    presence.emitToUser(io, m, 'group-epoch-rotated', {
      groupId,
      name: group.name,
      epoch: newEpoch,
      members,
    });
  });
  res.json({ ok: true, epoch: newEpoch });
});

// اضافه کردن عضو جدید به گروه پس از ساخت توسط توزیع‌کننده (M6)
app.post('/api/group/:id/add-member', async (req: Request, res: Response) => {
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false, msg: 'unauthorized' });
  const { username } = req.body;
  if (!username || typeof username !== 'string') return res.status(400).json({ ok: false, msg: 'invalid username' });
  const cleanUser = username.trim().replace(/^@+/, '');
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.json({ ok: false, msg: 'group not found' });
  const group = rows[0];
  // L7(e): a corrupt members row fails closed instead of throwing.
  const members = safeParseMembers(group.members);
  if (!members) return res.json({ ok: false, msg: 'گروه یافت نشد' });
  if (members[0] !== sessionUser) return res.status(403).json({ ok: false, msg: 'only distributor can add members' });
  if (members.includes(cleanUser)) return res.json({ ok: true, msg: 'already member', members, epoch: group.epoch });
  members.push(cleanUser);
  const newEpoch = (Number(group.epoch) || 1) + 1;
  await pool.query('UPDATE groups SET members = $1, epoch = $2 WHERE id = $3', [
    JSON.stringify(members),
    newEpoch,
    req.params.id,
  ]);
  presence.emitToUser(io, cleanUser, 'new-group', {
    id: req.params.id,
    name: group.name,
    members,
    epoch: newEpoch,
  });
  members.forEach(m => {
    presence.emitToUser(io, m, 'group-epoch-rotated', {
      groupId: req.params.id,
      name: group.name,
      epoch: newEpoch,
      members,
    });
  });
  res.json({ ok: true, epoch: newEpoch, members });
});

// حذف عضو از گروه پس از ساخت توسط توزیع‌کننده (M6)
app.post('/api/group/:id/remove-member', async (req: Request, res: Response) => {
  const sessionUser = await getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false, msg: 'unauthorized' });
  const { username } = req.body;
  if (!username || typeof username !== 'string') return res.status(400).json({ ok: false, msg: 'invalid username' });
  const cleanUser = username.trim().replace(/^@+/, '');
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.json({ ok: false, msg: 'group not found' });
  const group = rows[0];
  // L7(e): a corrupt members row fails closed instead of throwing.
  const members = safeParseMembers(group.members);
  if (!members) return res.json({ ok: false, msg: 'گروه یافت نشد' });
  if (members[0] !== sessionUser) return res.status(403).json({ ok: false, msg: 'only distributor can remove members' });
  if (cleanUser === sessionUser) return res.status(400).json({ ok: false, msg: 'cannot remove distributor' });
  const idx = members.indexOf(cleanUser);
  if (idx === -1) return res.json({ ok: true, members, epoch: group.epoch });
  members.splice(idx, 1);
  const newEpoch = (Number(group.epoch) || 1) + 1;
  await pool.query('UPDATE groups SET members = $1, epoch = $2 WHERE id = $3', [
    JSON.stringify(members),
    newEpoch,
    req.params.id,
  ]);
  presence.emitToUser(io, cleanUser, 'group-removed', { id: req.params.id });
  members.forEach(m => {
    presence.emitToUser(io, m, 'group-epoch-rotated', {
      groupId: req.params.id,
      name: group.name,
      epoch: newEpoch,
      members,
    });
  });
  res.json({ ok: true, epoch: newEpoch, members });
});

app.get('/api/admin/groups', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM groups');
  res.json({
    ok: true,
    groups: rows.map((g: any) => ({ ...g, epoch: Number(g.epoch) || 1, members: safeParseMembers(g.members) ?? [] })),
  });
});

app.get('/api/admin/messages', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM messages WHERE is_deleted=0 ORDER BY timestamp DESC LIMIT 500');
  const grouped: Record<string, any[]> = {};
  rows.forEach((m: any) => {
    if (!grouped[m.room_id]) grouped[m.room_id] = [];
    grouped[m.room_id].push(parseMsg(m));
  });
  res.json({ ok: true, messages: grouped });
});

app.get('/api/admin/stats', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const totalUsers = (await pool.query('SELECT COUNT(*) as c FROM users')).rows[0].c;
  const onlineUsers = presence.getOnlineCount();
  const totalMessages = (await pool.query('SELECT COUNT(*) as c FROM messages WHERE is_deleted=0')).rows[0].c;
  const totalGroups = (await pool.query('SELECT COUNT(*) as c FROM groups')).rows[0].c;
  const pendingReports = (await pool.query("SELECT COUNT(*) as c FROM reports WHERE status='pending'")).rows[0].c;

  const daily: { date: string; count: number }[] = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().split('T')[0];
    const count = (
      await pool.query(
        "SELECT COUNT(*) as c FROM messages WHERE to_char(to_timestamp(timestamp/1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD') = $1",
        [dateStr]
      )
    ).rows[0].c;
    daily.push({ date: dateStr, count: parseInt(String(count), 10) });
  }

  res.json({
    ok: true,
    stats: {
      totalUsers: parseInt(String(totalUsers), 10),
      onlineUsers,
      totalMessages: parseInt(String(totalMessages), 10),
      totalGroups: parseInt(String(totalGroups), 10),
      pendingReports: parseInt(String(pendingReports), 10),
      daily,
    },
  });
});

app.post('/api/admin/announce', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { text, imageUrl } = req.body;
  if (!text) return res.json({ ok: false, msg: 'متن رو وارد کن' });
  io.emit('announcement', { text, imageUrl });

  const { rows } = await pool.query('SELECT bale_chat_id FROM users WHERE bale_chat_id IS NOT NULL');
  for (const u of rows) {
    if (imageUrl) await bale.sendPhoto(u.bale_chat_id, imageUrl, text);
    else await bale.sendMessage(u.bale_chat_id, `📢 اطلاع‌رسانی:\n\n${text}`);
  }
  res.json({ ok: true, sent: rows.length });
});

app.post('/api/admin/set-mode', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { mode, msg } = req.body || {};
  // L7(f): mode must be one of the two known values.
  if (mode !== 'normal' && mode !== 'maintenance') {
    return res.status(400).json({ ok: false, msg: 'invalid mode' });
  }
  await setSetting('server_mode', mode);
  if (msg) await setSetting('maintenance_msg', msg);
  if (mode === 'maintenance') io.emit('server-maintenance', { msg: msg || (await getSetting('maintenance_msg')) });
  else if (mode === 'normal') io.emit('server-normal');
  res.json({ ok: true });
});

app.post('/api/admin/set-rules', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  await setSetting('rules', req.body.rules || '');
  res.json({ ok: true });
});

app.post('/api/admin/login-as', (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username } = req.body;
  if (!username) return res.json({ ok: false, msg: 'آیدی کاربر رو وارد کن' });

  const token = uuidv4();
  adminTokens[token] = {
    username,
    expire: Date.now() + 30000,
    adminAt: Date.now(),
  };

  res.json({ ok: true, token, url: `/api/admin-login-as/${token}` });
});

app.get('/api/admin-login-as/:token', async (req: Request, res: Response) => {
  const token = String(req.params.token);
  const data = adminTokens[token];

  if (!data || Date.now() > data.expire) {
    if (data) delete adminTokens[token];
    // Info: a bogus/expired link is a 404 with the consistent JSON shape,
    // not a 200 HTML page.
    return res.status(404).json({ ok: false, error: 'Not Found' });
  }

  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [data.username]);
  delete adminTokens[token];
  if (!rows.length) {
    return res.send(
      `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>کاربر یافت نشد</title><link rel="stylesheet" href="/css/error.css"/></head><body><main><div class="error-icon" aria-hidden="true">❌</div><h1>کاربر یافت نشد</h1><p>کاربر مورد نظر وجود ندارد.</p></main></body></html>`
    );
  }

  const safeAttr = String(data.username).replace(/[^a-zA-Z0-9_.-]/g, '');
  res.send(
    `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>ورود موقت ادمین</title><link rel="stylesheet" href="/css/error.css"/></head><body data-admin-login-user="${safeAttr}"><script src="/js/admin-login-redirect.js" defer></script></body></html>`
  );
});

// مسیر پنل مدیریت فقط در سمت سرور تعریف شده و هیچ اثری از آن در باندل فرانت‌اند وجود ندارد
app.get(config.ADMIN_PATH, (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  res.sendFile(path.join(process.cwd(), 'public', 'admin.html'));
});

app.get('/favicon.ico', (_req: Request, res: Response) => {
  // Info: no favicon file exists in public/ — answer 204, not the 404 page.
  return res.status(204).end();
});

// L7(d): a FIXED canonical host — never reflect req host / x-forwarded-proto.
const CANONICAL_HOST = 'https://chatapp-server-1i2a.onrender.com';

app.get('/robots.txt', (_req: Request, res: Response) => {
  const baseUrl = CANONICAL_HOST;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(
    [
      'User-agent: *',
      'Allow: /',
      'Disallow: /api/',
      'Disallow: /admin-login/',
      'Disallow: /uploads/',
      'Disallow: /api/media/',
      'Disallow: /socket.io/',
      '',
      `Sitemap: ${baseUrl}/sitemap.xml`,
      '',
    ].join('\n')
  );
});

app.get('/sitemap.xml', (_req: Request, res: Response) => {
  const baseUrl = CANONICAL_HOST;
  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url>\n    <loc>${baseUrl}/</loc>\n    <changefreq>weekly</changefreq>\n    <priority>1.0</priority>\n  </url>\n</urlset>\n`
  );
});

// Privacy policy (public page, required e.g. by the Google OAuth consent
// screen). Styled HTML document with an inline <style> block only — no
// scripts, no external resources, no user data. The global Helmet CSP
// forbids inline styles, so this route overrides it with a tighter
// page-specific policy: inline styles allowed, everything else 'none'.
// This is safe precisely because the page has no scripts and no user data.
app.get('/privacy', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; base-uri 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; script-src 'none'; frame-ancestors 'none'; form-action 'none'"
  );
  res.send(PRIVACY_HTML);
});

// ===== SOCKET.IO =====
io.on('connection', async (socket) => {
  let currentUser: string | null = null;

  // M7: per-connection event throttle — max 30 events/sec; excess events
  // are dropped, never disconnecting the socket.
  let socketEventCount = 0;
  let socketEventWindowStart = Date.now();
  socket.use((_packet: any, next: (err?: Error) => void) => {
    const now = Date.now();
    if (now - socketEventWindowStart >= 1000) {
      socketEventWindowStart = now;
      socketEventCount = 0;
    }
    socketEventCount += 1;
    if (socketEventCount > 30) return; // drop silently
    next();
  });

  try {
    const mode = await getSetting('server_mode');
    if (mode === 'maintenance') {
      const msg = await getSetting('maintenance_msg');
      socket.emit('server-maintenance', { msg });
    }
  } catch {
    // ignore
  }

  socket.on('auth', async (authData: string | { username?: string; token?: string }) => {
    // احراز هویت سوکت با توکن نشست معتبر بررسی می‌شود؛
    // نام کاربریِ تنها قابل جعل است (جعل حضور و دریافت پیام‌های دیگران).
    const username = typeof authData === 'string' ? authData : authData?.username;
    const token = typeof authData === 'string' ? undefined : authData?.token;
    if (!username || !token) return;
    const session = userSessions[token];
    if (!session || session.username !== username || Date.now() > session.expire) return;
    if (await isUserBlocked(username)) {
      const { rows } = await pool.query(
        'SELECT block_reason, block_type, block_until FROM users WHERE username=$1',
        [username]
      );
      socket.emit('blocked', rows[0] || {});
      return;
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!rows.length) return;
    currentUser = username;
    presence.setOnline(socket.id, username);
    await pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [new Date().toISOString(), username]);

    const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [username]);
    contacts.forEach(({ contact }: any) => {
      presence.emitToUser(io, contact, 'contact-online', username);
    });

    socket.emit('auth-ok');
  });

  socket.on('update-location', () => {
    if (currentUser) {
      pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [new Date().toISOString(), currentUser]);
    }
  });

  socket.on('send-message', async (data: any) => {
    if (!currentUser) return;
    const { to, text, fileUrl, fileType, replyToId, replyToText, isGroup, disappearAfter } = data;
    // M7: message text cap (never truncate — the text is E2EE ciphertext).
    if (typeof text === 'string' && text.length > 50000) return;
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);

    if (!isGroup) {
      const { rows } = await pool.query('SELECT 1 FROM contacts WHERE username=$1 AND contact=$2', [
        currentUser,
        to,
      ]);
      if (!rows.length) return;
    } else {
      // H2: group send requires membership (previously only the DM branch
      // checked anything, so any authenticated user could post to any group).
      if (!(await isRoomMember(currentUser, roomId, (sql, params) => pool.query(sql, params)))) return;
    }

    // M7: disappearAfter clamped to [0, 604800]s (7 days) — huge values
    // used to overflow setTimeout and delete the message immediately.
    const disappearSecs = Math.min(Math.max(Number(disappearAfter) || 0, 0), 604800);
    const disappearAt = disappearSecs > 0 ? new Date(Date.now() + disappearSecs * 1000).toISOString() : null;

    const msg = {
      id: uuidv4(),
      room_id: roomId,
      sender: currentUser,
      text: text || '',
      file_url: fileUrl || null,
      file_type: fileType || null,
      reply_to_id: replyToId || null,
      reply_to_text: replyToText || null,
      reactions: '{}',
      is_edited: 0,
      is_deleted: 0,
      is_pinned: 0,
      is_read: 0,
      disappear_at: disappearAt,
      time: new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tehran' }),
      timestamp: Date.now(),
    };

    await pool.query(
      'INSERT INTO messages (id,room_id,sender,text,file_url,file_type,reply_to_id,reply_to_text,reactions,is_edited,is_deleted,is_pinned,is_read,disappear_at,time,timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)',
      [
        msg.id,
        msg.room_id,
        msg.sender,
        msg.text,
        msg.file_url,
        msg.file_type,
        msg.reply_to_id,
        msg.reply_to_text,
        msg.reactions,
        msg.is_edited,
        msg.is_deleted,
        msg.is_pinned,
        msg.is_read,
        msg.disappear_at,
        msg.time,
        msg.timestamp,
      ]
    );

    const parsedMsg = parseMsg(msg);

    if (isGroup) {
      const { rows } = await pool.query('SELECT members FROM groups WHERE id=$1', [to]);
      const members = rows.length ? safeParseMembers(rows[0].members) : null;
      if (members) {
        members.forEach((m: string) => {
          presence.emitToUser(io, m, 'new-message', { roomId, msg: parsedMsg });
        });
      }
    } else {
      socket.emit('new-message', { roomId, msg: parsedMsg });
      presence.emitToUser(io, to, 'new-message', { roomId, msg: parsedMsg });
    }

    if (disappearAt) {
      setTimeout(async () => {
        await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msg.id]);
        if (msg.file_url) {
          const mid = extractMediaId(msg.file_url);
          if (mid) {
            await deleteMediaIfUnreferenced(mid, (sql, params) => pool.query(sql, params), unlinkUploadFile);
          }
        }
        await emitToRoom(io, roomId, 'msg-deleted', { roomId, msgId: msg.id }, (sql, params) =>
          pool.query(sql, params)
        );
      }, disappearSecs * 1000);
    }
  });

  socket.on('edit-message', async ({ msgId, newText, roomId }: any) => {
    if (!currentUser) return;
    // M7: text cap (never truncate E2EE ciphertext).
    if (typeof newText !== 'string' || newText.length > 50000) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1 AND sender=$2', [msgId, currentUser]);
    if (!rows.length) return;
    await pool.query('UPDATE messages SET text=$1, is_edited=1 WHERE id=$2', [newText, msgId]);
    await emitToRoom(io, roomId, 'msg-edited', { roomId, msgId, newText }, (sql, params) =>
      pool.query(sql, params)
    );
  });

  socket.on('delete-message', async ({ msgId, roomId }: any) => {
    if (!currentUser) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1 AND sender=$2', [msgId, currentUser]);
    if (!rows.length) return;
    await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msgId]);
    // H1(d): drop the media when no remaining non-deleted message uses it.
    if (rows[0].file_url) {
      const mid = extractMediaId(rows[0].file_url);
      if (mid) await deleteMediaIfUnreferenced(mid, (sql, params) => pool.query(sql, params), unlinkUploadFile);
    }
    await emitToRoom(io, roomId, 'msg-deleted', { roomId, msgId }, (sql, params) =>
      pool.query(sql, params)
    );
  });

  socket.on('pin-message', async ({ msgId, roomId }: any) => {
    if (!currentUser) return;
    // H2: the message must belong to the room and the sender must be a member.
    if (!(await canActOnMessage(currentUser, msgId, roomId, (sql, params) => pool.query(sql, params)))) return;
    await pool.query('UPDATE messages SET is_pinned=0 WHERE room_id=$1', [roomId]);
    await pool.query('UPDATE messages SET is_pinned=1 WHERE id=$1', [msgId]);
    await emitToRoom(io, roomId, 'msg-pinned', { roomId, msgId }, (sql, params) =>
      pool.query(sql, params)
    );
  });

  socket.on('unpin-message', async ({ msgId, roomId }: any) => {
    if (!currentUser) return;
    // H2: same membership rule as pin — by message, or by room when only
    // a room id is given.
    if (msgId) {
      if (!(await canActOnMessage(currentUser, msgId, roomId, (sql, params) => pool.query(sql, params)))) return;
      await pool.query('UPDATE messages SET is_pinned=0 WHERE id=$1', [msgId]);
    }
    if (roomId) {
      if (!(await isRoomMember(currentUser, roomId, (sql, params) => pool.query(sql, params)))) return;
      await pool.query('UPDATE messages SET is_pinned=0 WHERE room_id=$1', [roomId]);
    }
    if (!msgId && !roomId) return;
    await emitToRoom(io, roomId, 'msg-unpinned', { roomId, msgId }, (sql, params) =>
      pool.query(sql, params)
    );
  });

  socket.on('create-group', async ({ name, members }: any) => {
    if (!currentUser || !name || !name.trim() || name.trim().length > 100) return;
    const memberList = Array.isArray(members) ? members : [];
    // M7: max 100 members total; every member must exist as a user.
    const { rows: allUsers } = await pool.query('SELECT username FROM users');
    const existingUsers = new Set((allUsers as any[]).map((u) => u.username));
    const validMembers = memberList.filter((m: any) => typeof m === 'string' && existingUsers.has(m));
    const allMembers = Array.from(new Set([currentUser, ...validMembers].filter(Boolean)));
    if (allMembers.length > 100) return;
    const groupId = uuidv4();
    await pool.query('INSERT INTO groups (id, name, members, created_at) VALUES ($1,$2,$3,$4)', [
      groupId,
      name.trim(),
      JSON.stringify(allMembers),
      new Date().toISOString(),
    ]);
    const newGroupData = {
      id: groupId,
      name: name.trim(),
      members: allMembers,
      epoch: 1,
      created_at: new Date().toISOString(),
    };
    allMembers.forEach(m => {
      presence.emitToUser(io, m, 'new-group', newGroupData);
    });
    socket.emit('group-created', newGroupData);
  });

  socket.on('react', async ({ msgId, roomId, emoji }: any) => {
    if (!currentUser) return;
    // M7: emoji cap. H2: the message must belong to the room, sender member.
    if (typeof emoji !== 'string' || !emoji || emoji.length > 16) return;
    if (!(await canActOnMessage(currentUser, msgId, roomId, (sql, params) => pool.query(sql, params)))) return;
    const { rows } = await pool.query('SELECT reactions FROM messages WHERE id=$1', [msgId]);
    if (!rows.length) return;
    // L7(e): corrupt reactions JSON degrades to {} instead of throwing.
    const reactions: Record<string, string[]> = safeParseReactions(rows[0].reactions);
    if (!reactions[emoji]) reactions[emoji] = [];
    const idx = reactions[emoji].indexOf(currentUser);
    if (idx === -1) reactions[emoji].push(currentUser);
    else reactions[emoji].splice(idx, 1);
    if (reactions[emoji].length === 0) delete reactions[emoji];
    await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2', [JSON.stringify(reactions), msgId]);
    await emitToRoom(io, roomId, 'msg-reaction', { roomId, msgId, reactions }, (sql, params) =>
      pool.query(sql, params)
    );
  });

  socket.on('forward-message', async (data: any) => {
    if (!currentUser || !data || typeof data !== 'object') return;
    const { msgId, toRooms } = data;
    if (typeof msgId !== 'string' || !Array.isArray(toRooms) || toRooms.length === 0 || toRooms.length > 50) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1', [msgId]);
    if (!rows.length) return;
    const orig = rows[0];
    // M5: a deleted original must not be resurrected into another room.
    if (orig.is_deleted) return;
    const canReadOrig = await isRoomMember(currentUser, orig.room_id, (sql, params) => pool.query(sql, params));
    if (!canReadOrig) return;

    for (const roomId of toRooms) {
      if (typeof roomId !== 'string' || !roomId) continue;
      const canWriteDest = await isRoomMember(currentUser, roomId, (sql, params) => pool.query(sql, params));
      if (!canWriteDest) continue;
      const newMsg = {
        id: uuidv4(),
        room_id: roomId,
        sender: currentUser,
        text: orig.text,
        file_url: orig.file_url,
        file_type: orig.file_type,
        reply_to_id: null,
        reply_to_text: null,
        reactions: '{}',
        is_edited: 0,
        is_deleted: 0,
        is_pinned: 0,
        is_read: 0,
        disappear_at: null,
        time: new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tehran' }),
        timestamp: Date.now(),
      };
      await pool.query(
        'INSERT INTO messages (id,room_id,sender,text,file_url,file_type,reply_to_id,reply_to_text,reactions,is_edited,is_deleted,is_pinned,is_read,disappear_at,time,timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)',
        [
          newMsg.id,
          newMsg.room_id,
          newMsg.sender,
          newMsg.text,
          newMsg.file_url,
          newMsg.file_type,
          newMsg.reply_to_id,
          newMsg.reply_to_text,
          newMsg.reactions,
          newMsg.is_edited,
          newMsg.is_deleted,
          newMsg.is_pinned,
          newMsg.is_read,
          newMsg.disappear_at,
          newMsg.time,
          newMsg.timestamp,
        ]
      );
      await emitToRoom(io, roomId, 'new-message', { roomId, msg: parseMsg(newMsg) }, (sql, params) =>
        pool.query(sql, params)
      );
    }
  });

  socket.on('typing', async ({ to, isGroup, isTyping }: any) => {
    if (!currentUser) return;
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);
    if (isGroup) {
      // H2: group typing requires membership.
      if (!(await isRoomMember(currentUser, roomId, (sql, params) => pool.query(sql, params)))) return;
      const { rows } = await pool.query('SELECT members FROM groups WHERE id=$1', [to]);
      const members = rows.length ? safeParseMembers(rows[0].members) : null;
      if (members) {
        members.forEach((m: string) => {
          if (m !== currentUser) {
            presence.emitToUser(io, m, 'typing', { roomId, username: currentUser, isTyping });
          }
        });
      }
    } else {
      // H2: DM typing requires a contacts row (same check send-message uses).
      const { rows } = await pool.query('SELECT 1 FROM contacts WHERE username=$1 AND contact=$2', [
        currentUser,
        to,
      ]);
      if (!rows.length) return;
      presence.emitToUser(io, to, 'typing', { roomId, username: currentUser, isTyping });
    }
  });

  socket.on('read', async ({ roomId, msgId }: any) => {
    // H2: read previously needed no auth at all — now it requires a
    // session AND membership, and the message must belong to the room.
    if (!currentUser || !msgId) return;
    if (!(await canActOnMessage(currentUser, msgId, roomId, (sql, params) => pool.query(sql, params)))) return;
    await pool.query('UPDATE messages SET is_read=1 WHERE id=$1', [msgId]);
    await emitToRoom(io, roomId, 'read', { roomId, msgId }, (sql, params) =>
      pool.query(sql, params)
    );
  });

  socket.on('update-status', async (status: string) => {
    if (!currentUser) return;
    // M7: status cap.
    if (typeof status !== 'string' || status.length > 100) return;
    await pool.query('UPDATE users SET status=$1 WHERE username=$2', [status, currentUser]);
    const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [currentUser]);
    contacts.forEach(({ contact }: any) => {
      presence.emitToUser(io, contact, 'contact-status', { username: currentUser, status });
    });
  });

  socket.on('disconnect', async () => {
    const username = presence.setOffline(socket.id);
    if (username) {
      await pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [new Date().toISOString(), username]);
      const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [username]);
      contacts.forEach(({ contact }: any) => {
        presence.emitToUser(io, contact, 'contact-offline', username);
      });
    }
  });
});

// ===== START SERVER + VITE MIDDLEWARE =====
async function start(): Promise<void> {
  try {
    await init();
  } catch (e: any) {
    console.warn('⚠️ اخطار در آماده‌سازی اولیه دیتابیس:', e.message);
  }

  // M6: log loudly which engine is active.
  console.log(
    getDbEngine() === 'postgres'
      ? '🗄️ Database engine: PostgreSQL'
      : '⚠️ JSON FALLBACK ACTIVE (ALLOW_JSON_FALLBACK=1) — data is ephemeral'
  );

  const distPath = path.join(process.cwd(), 'dist');
  const publicPath = path.join(process.cwd(), 'public');
  const assetsPath = path.join(distPath, 'assets');
  const isProd = process.env.NODE_ENV === 'production' && fs.existsSync(distPath);
  const validClientRoutes = new Set(['/', '/index.html', '/terms', '/login']);

  const routeMetaMap: Record<string, { title: string; description: string }> = {
    '/': {
      title: 'پیام‌رسان',
      description:
        'پیام‌رسان امن و سریع با رمزنگاری سرتاسری برای گفت‌وگوی خصوصی و بلادرنگ با دوستان و خانواده.',
    },
    '/index.html': {
      title: 'پیام‌رسان',
      description:
        'پیام‌رسان امن و سریع با رمزنگاری سرتاسری برای گفت‌وگوی خصوصی و بلادرنگ با دوستان و خانواده.',
    },
    '/login': {
      title: 'ورود به حساب | پیام‌رسان',
      description:
        'ورود امن به پیام‌رسان با آیدی بله و کد تأیید یک‌بارمصرف؛ گفت‌وگوی خصوصی با رمزنگاری سرتاسری.',
    },
    '/terms': {
      title: 'قوانین پیام‌رسان | پیام‌رسان',
      description:
        'قوانین و مقررات پیام‌رسان را بخوانید؛ شرایط استفاده، حریم خصوصی، حقوق داده و حذف حساب کاربری را بدانید.',
    },
  };

  const applyHtmlMeta = (html: string, reqPath: string): string => {
    const meta = routeMetaMap[reqPath] || routeMetaMap['/'];
    return html
      .replace(/<title>.*?<\/title>/, `<title>${meta.title}</title>`)
      .replace(
        /<meta name="description" content="[^"]*"\/>/,
        `<meta name="description" content="${meta.description}"/>`
      )
      .replace(
        /<meta property="og:title" content="[^"]*"\/>/,
        `<meta property="og:title" content="${meta.title}"/>`
      )
      .replace(
        /<meta property="og:description" content="[^"]*"\/>/,
        `<meta property="og:description" content="${meta.description}"/>`
      );
  };

  const sendNotFound = (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ ok: false, error: 'Not Found' });
    }
    res.status(404).setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(`<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>۴۰۴ - صفحه یافت نشد | پیام‌رسان</title>
  <link rel="stylesheet" href="/css/error.css"/>
</head>
<body>
  <main id="main-content">
    <div class="error-icon" aria-hidden="true">🔍</div>
    <h1>۴۰۴ - صفحه مورد نظر یافت نشد</h1>
    <p>آدرسی که وارد کرده‌اید در پیام‌رسان وجود ندارد یا جابه‌جا شده است.</p>
    <a href="/" class="home-link">بازگشت به صفحه اصلی پیام‌رسان</a>
  </main>
</body>
</html>`);
  };

  if (fs.existsSync(assetsPath)) {
    app.use(
      '/assets',
      express.static(assetsPath, {
        maxAge: '1y',
        immutable: true,
        setHeaders: (res) => {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        },
      })
    );
  }

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    const isExistingFile = (baseDir: string, relPath: string): boolean => {
      try {
        const target = path.resolve(baseDir, '.' + relPath);
        if (!target.startsWith(baseDir + path.sep)) return false;
        return fs.existsSync(target) && fs.statSync(target).isFile();
      } catch {
        return false;
      }
    };

    app.use(async (req, res, next) => {
      const reqPath = req.path;
      const isAppRoute = validClientRoutes.has(reqPath);
      const isViteModule =
        reqPath.startsWith('/@') ||
        reqPath.startsWith('/__vite') ||
        reqPath.startsWith('/src/') ||
        reqPath.startsWith('/node_modules/');
      const isStaticAsset =
        isExistingFile(publicPath, reqPath) || isExistingFile(distPath, reqPath);

      if (!isAppRoute && !isViteModule && !isStaticAsset) {
        return sendNotFound(req, res);
      }
      if (isAppRoute) {
        try {
          const rawHtml = await fs.promises.readFile(path.join(process.cwd(), 'index.html'), 'utf-8');
          const transformed = await vite.transformIndexHtml(req.originalUrl, applyHtmlMeta(rawHtml, reqPath));
          res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8');
          res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
          return res.end(transformed);
        } catch (err) {
          return next(err);
        }
      } else if (isStaticAsset && !reqPath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      }
      next();
    });
    app.use(vite.middlewares);
  } else {
    app.use(
      express.static(distPath, {
        index: false,
        setHeaders: (res, filePath) => {
          if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
          } else {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          }
        },
      })
    );
    app.use(
      express.static(publicPath, {
        index: false,
        setHeaders: (res, filePath) => {
          if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
          } else {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          }
        },
      })
    );
    app.get(['/', '/index.html', '/terms', '/login'], async (req, res) => {
      res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      const rawHtml = await fs.promises.readFile(path.join(distPath, 'index.html'), 'utf-8');
      return res.send(applyHtmlMeta(rawHtml, req.path));
    });
    app.use((req, res) => {
      return sendNotFound(req, res);
    });
  }

  // Global error handler middleware (DP-3)
  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    console.error('Unhandled express route error:', err && err.message ? err.message : String(err));
    if (res.headersSent) return next(err);
    res.status(500).json({ ok: false, msg: 'Internal server error' });
  });

  await restoreSessionsFromDb();
  await purgeExpiredSessions();

  server.listen(config.PORT, '0.0.0.0', () => {
    console.log(`✅ سرور TypeScript + React نسخه ${APP_VERSION} روی پورت ${config.PORT}`);
    console.log(`🌐 http://localhost:${config.PORT}`);
    console.log(`🔐 پنل مدیریت: http://localhost:${config.PORT}${config.ADMIN_PATH}`);
    void bale.checkBaleHealth();
    const healthTimer = setInterval(() => {
      void bale.checkBaleHealth();
    }, 5 * 60 * 1000);
    healthTimer.unref();
    // پاک‌سازی ساعتی سشن‌های منقضی (DP-11)
    const sessionPurgeTimer = setInterval(() => {
      void purgeExpiredSessions();
    }, 60 * 60 * 1000);
    sessionPurgeTimer.unref();
  });
}

process.on('uncaughtException', (err) => {
  console.error('❌ خطای مدیریت‌نشده (Uncaught Exception):', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ ریجکشن مدیریت‌نشده (Unhandled Rejection):', reason);
});

start();
