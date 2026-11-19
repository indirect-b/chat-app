// sync checkpoint — no behavior change (verified)
import 'dotenv/config';
import express, { Request, Response } from 'express';
import helmet from 'helmet';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { config, verifyAdminSecret } from './src/server/config';
import * as bale from './src/server/bale';
import { pool, init } from './src/server/db';
import { presence } from './src/server/presence';
import { getRoomId, resolveMediaAccess, canUploadToRoom } from './src/server/media';
import { checkRoomReadAccess, checkOwnGroupsAccess, checkOwnUsername } from './src/server/roomAccess';
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

// کلید سرور برای پروتکل احراز هویت کور Ristretto255-VOPRF (RFC 9497)
// (رفع F12، بازیابی‌شده از دور اول) بذر اختصاصی VOPRF_SEED (۳۲ بایت Base64) در اولویت است؛ در غیاب
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

const server = http.createServer(app);
const io = new SocketIOServer(server);

app.use(express.json({ limit: '5mb' }));
// Google posts the redirect-mode credential as application/x-www-form-urlencoded
// (credential + g_csrf_token) to /api/google-redirect — JSON parsing alone
// would leave req.body empty for that route.
app.use(express.urlencoded({ extended: false }));

// آپلود فایل با پشتیبانی ترکیبی (Hybrid Cloud-Safe Media Storage + Disk Stream)
// توجه: مسیر عمومی /uploads حذف شده — فایل‌ها فقط از طریق /api/media با
// احراز هویت و بررسی عضویت در چت سرو می‌شوند (به بخش MEDIA در پایین نگاه کن).
const uploadsDir = path.join(process.cwd(), 'public/uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: config.MAX_FILE_SIZE } });

/** Do the first bytes of a file equal `magic`? Used to tell encrypted (PQF1) uploads from raw ones without trusting the client. */
async function fileStartsWithMagic(filePath: string, magic: string): Promise<boolean> {
  let fh: fs.promises.FileHandle | null = null;
  try {
    fh = await fs.promises.open(filePath, 'r');
    const buf = Buffer.alloc(magic.length);
    const { bytesRead } = await fh.read(buf, 0, magic.length, 0);
    return bytesRead === magic.length && buf.toString('latin1') === magic;
  } catch {
    return false;
  } finally {
    if (fh) await fh.close().catch(() => undefined);
  }
}

// متغیرهای درون‌حافظه‌ای توکن‌های موقت
const adminTokens: Record<string, { username: string; expire: number; adminAt: number }> = {};
const userSessions: Record<string, { username: string; expire: number }> = {};

function getSessionUsername(req: Request): string | null {
  const authHeader = req.headers.authorization;
  const raw = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (!raw || typeof raw !== 'string') return null;
  const match = raw.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1].trim();
  if (!token) return null;
  const session = userSessions[token];
  if (!session) return null;
  if (Date.now() > session.expire) {
    delete userSessions[token];
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

function isAdmin(req: Request): boolean {
  const headerToken = req.headers['x-admin-token'];
  const token = Array.isArray(headerToken) ? headerToken[0] : headerToken;
  return verifyAdminSecret(token);
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

function parseMsg(m: any) {
  return {
    ...m,
    reactions: typeof m.reactions === 'string' ? JSON.parse(m.reactions || '{}') : m.reactions || {},
    is_edited: !!m.is_edited,
    is_deleted: !!m.is_deleted,
    is_pinned: !!m.is_pinned,
    is_read: !!m.is_read,
  };
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
  (req: Request, res: Response, next: express.NextFunction) => {
    // Auth runs BEFORE multer parses the body, so an unauthenticated upload
    // never writes a file to disk.
    if (!getSessionUsername(req)) {
      return res.status(401).json({ ok: false, msg: 'unauthorized' });
    }
    next();
  },
  upload.single('file'),
  async (req: Request, res: Response) => {
    const sessionUser = getSessionUsername(req);
    if (!sessionUser) return res.status(401).json({ ok: false, msg: 'unauthorized' });
    if (!req.file) return res.json({ ok: false, msg: 'فایل آپلود نشد' });
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
    const isEncrypted =
      kind === 'avatar' ? 0 : (await fileStartsWithMagic(req.file.path, 'PQF1')) ? 1 : 0;

    const ext = path.extname(req.file.originalname).toLowerCase();
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
          req.file.mimetype || 'application/octet-stream',
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
  const sessionUser = getSessionUsername(req);
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
    res.setHeader('Content-Type', access.blob.mime_type || 'application/octet-stream');
    res.setHeader('X-Media-Encrypted', encryptedHeader);
    res.setHeader('Cache-Control', 'private, max-age=3600, must-revalidate');
    return res.send(buffer);
  }

  const diskFile = path.join(uploadsDir, path.basename(mediaId));
  if (fs.existsSync(diskFile)) {
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
app.get('/api/health', async (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  let dbOk = true;
  try {
    await pool.query('SELECT COUNT(*) as c FROM users');
  } catch {
    dbOk = false;
  }
  const baleStatus = bale.getBaleHealthStatus();
  return res.status(dbOk ? 200 : 503).json({
    ok: dbOk,
    version: APP_VERSION,
    uptimeSec: Math.floor(process.uptime()),
    database: dbOk ? 'ok' : 'degraded',
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
  const isNew = rows.length === 0;
  if (isNew) {
    recoveryCode = generateRecoveryCode();
    const recoveryCodeHash = await hashRecoveryCode(recoveryCode);
    await pool.query(
      'INSERT INTO users (username, bale_chat_id, joined_at, recovery_code_hash, email, display_name, avatar, name_custom, avatar_custom) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
      [email, null, new Date().toISOString(), recoveryCodeHash, email, profile.name, profile.picture, 0, 0]
    );
  } else {
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
  userSessions[sessionToken] = {
    username: email,
    expire: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };

  return { sessionToken, username: email, isNew, recoveryCode };
}

app.post('/api/google-login', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
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

  if (await isUserBlocked(email)) {
    return res.status(403).json({ ok: false, msg: 'این حساب مسدود شده است.' });
  }

  // گوگل خودش مالکیت ایمیل را اثبات کرده است؛ کاربر تازه اتمیک ساخته
  // می‌شود (ثبت‌نام جداگانه‌ای وجود ندارد) و کد بازیابی فقط همین‌بار نمایش داده می‌شود.
  const { sessionToken, username, isNew, recoveryCode } = await completeGoogleSignIn(
    email,
    verified.profile
  );

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

  if (await isUserBlocked(email)) {
    return res.status(403).send('این حساب مسدود شده است.');
  }

  const { sessionToken, isNew, recoveryCode } = await completeGoogleSignIn(
    email,
    verified.profile
  );
  if (isNew && recoveryCode) {
    pendingRecoveryCodes.store(sessionToken, recoveryCode, Date.now());
  }

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

  if (await isUserBlocked(key)) {
    return res.status(403).json({ ok: false, msg: 'این حساب مسدود شده است.' });
  }

  const valid = await verifyRecoveryCode(code, user.recovery_code_hash);
  if (!valid) {
    return res.status(401).json({ ok: false, msg: 'آیدی یا کد بازیابی نامعتبر است.' });
  }

  // مصرف یک‌بارمصرف کد و چرخش فوری به کد بازیابی جدید (فقط هش scrypt جدید ذخیره می‌شود)
  const nextRecoveryCode = generateRecoveryCode();
  const nextHash = await hashRecoveryCode(nextRecoveryCode);
  await pool.query('UPDATE users SET recovery_code_hash=$1 WHERE username=$2', [nextHash, key]);

  const sessionToken = uuidv4();
  userSessions[sessionToken] = {
    username: key,
    expire: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };

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

// ===== RISTRETTO255-VOPRF BLINDED IDENTITY EVALUATION (RFC 9497) =====
app.post('/api/voprf/evaluate', (req: Request, res: Response) => {
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
    // (رفع F12، بازیابی‌شده از دور اول) پیام خطای داخلی به بیرون درز نمی‌کند.
    res.status(400).json({ ok: false });
  }
});

// ===== USER & HYBRID POST-QUANTUM PUBLIC KEY DIRECTORY =====
app.get('/api/user/:username', async (req: Request, res: Response) => {
  const { rows } = await pool.query(
    'SELECT username, display_name, avatar, bio, status, public_key FROM users WHERE username = $1',
    [req.params.username]
  );
  if (!rows.length) return res.json({ ok: false });
  res.json({ ok: true, user: rows[0] });
});

app.post('/api/user/public-key', async (req: Request, res: Response) => {
  const { username, publicKey } = req.body;
  if (!username || !publicKey) return res.json({ ok: false });
  // (رفع F2، بازیابی‌شده از دور اول) فقط خود کاربر با نشست معتبر می‌تواند باندل خودش را منتشر کند؛
  // در غیر این صورت هر کسی می‌توانست باندل هر کاربری را جایگزین کند.
  const sessionUser = getSessionUsername(req);
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

// ===== GROUP EPOCH KEY PACKETS (F3، بازیابی‌شده از دور اول) =====
// بسته کلید اپوک گروه: توزیع‌کننده (سازنده گروه) کلید تصادفی اپوک را با
// ML-KEM-768 به هر عضو کپسوله می‌کند؛ سرور فقط کپسول‌ها را نگه می‌دارد و
// جابه‌جا می‌کند و کلید را نمی‌بیند.
app.post('/api/group/:id/epoch-packet', async (req: Request, res: Response) => {
  const sessionUser = getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false });
  const { epoch, keys } = req.body as { epoch?: unknown; keys?: unknown };
  if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 1) {
    return res.json({ ok: false, msg: 'invalid epoch' });
  }
  if (!keys || typeof keys !== 'object' || Array.isArray(keys)) {
    return res.json({ ok: false, msg: 'invalid keys' });
  }
  for (const [u, ct] of Object.entries(keys as Record<string, unknown>)) {
    if (typeof u !== 'string' || !u || typeof ct !== 'string' || !/^[A-Za-z0-9+/=]+$/.test(ct)) {
      return res.json({ ok: false, msg: 'invalid key entry' });
    }
  }
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.json({ ok: false, msg: 'group not found' });
  const members: string[] = JSON.parse(rows[0].members);
  if (!members.includes(sessionUser)) return res.status(403).json({ ok: false });
  const packet = { epoch, keys, postedBy: sessionUser, postedAt: new Date().toISOString() };
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
  const sessionUser = getSessionUsername(req);
  if (!sessionUser) return res.status(401).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.json({ ok: false });
  const members: string[] = JSON.parse(rows[0].members);
  if (!members.includes(sessionUser)) return res.status(403).json({ ok: false });
  const raw = await getSetting(`group_epoch_packet_${req.params.id}`);
  if (!raw) return res.json({ ok: false });
  try {
    const packet = JSON.parse(raw);
    res.json({ ok: true, epoch: packet.epoch, keys: packet.keys });
  } catch {
    res.json({ ok: false });
  }
});

app.post('/api/user/update', async (req: Request, res: Response) => {
  // A user may only update their OWN profile: without this check anyone
  // could overwrite any user's bio, status and avatar by posting a username.
  // The display name is editable here too; a value that actually differs
  // from the stored one raises the matching custom flag, so later Google
  // logins stop overwriting that field (a save that changes nothing
  // leaves the flags — and future Google sync — untouched).
  const { username, bio, status, avatar, display_name } = req.body || {};
  const access = checkOwnUsername(getSessionUsername(req), String(username ?? ''));
  if (access !== 'ok') {
    return res.status(403).json({ ok: false, msg: 'unauthorized' });
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

app.post('/api/add-contact', async (req: Request, res: Response) => {
  // A user may only add contacts to their OWN list — otherwise anyone could
  // insert contact rows for any account (and harvest public keys in return).
  const { myUsername, contactUsername } = req.body || {};
  const access = checkOwnUsername(getSessionUsername(req), String(myUsername ?? ''));
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
  const access = checkOwnUsername(getSessionUsername(req), String(req.params.username));
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
  const access = await checkRoomReadAccess(getSessionUsername(req), roomId, (sql, params) =>
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
  const access = checkOwnGroupsAccess(getSessionUsername(req), String(req.params.username));
  if (access !== 'ok') {
    return res.status(403).json({ ok: false, msg: 'unauthorized' });
  }
  const { rows } = await pool.query('SELECT * FROM groups');
  const myGroups = rows.filter((g: any) => JSON.parse(g.members).includes(req.params.username));
  res.json({
    ok: true,
    groups: myGroups.map((g: any) => ({
      ...g,
      epoch: Number(g.epoch) || 1,
      members: JSON.parse(g.members),
    })),
  });
});

// ===== REPORT =====
app.post('/api/report', async (req: Request, res: Response) => {
  const { reporter, reportedUser, messageId, messageText, reason } = req.body;
  await pool.query(
    'INSERT INTO reports (id, reporter, reported_user, message_id, message_text, reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [uuidv4(), reporter, reportedUser, messageId || null, messageText || null, reason, new Date().toISOString()]
  );
  res.json({ ok: true });
});

// ===== ACCOUNT DATA EXPORT & ERASURE (DATA RIGHTS) =====
app.get('/api/account/export', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
  const username = getSessionUsername(req);
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
  const username = getSessionUsername(req);
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

  await pool.query('DELETE FROM messages WHERE sender = $1', [username]);
  await pool.query('DELETE FROM contacts WHERE username = $1 OR contact = $1', [username]);
  await pool.query('DELETE FROM users WHERE username = $1', [username]);

  for (const [tok, sess] of Object.entries(userSessions)) {
    if (sess.username === username) {
      delete userSessions[tok];
    }
  }

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

  const rawSessionUser = req.headers['x-session-user'];
  const sessionUser = (Array.isArray(rawSessionUser) ? rawSessionUser[0] : rawSessionUser || '')
    .trim()
    .toLowerCase();

  if (!sessionUser) {
    return res.status(401).end();
  }

  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [sessionUser]);
  if (!rows.length) {
    return res.status(401).end();
  }

  const mode = (await getSetting('server_mode')) || 'normal';
  if (mode === 'maintenance') {
    const msg = await getSetting('maintenance_msg');
    return res.status(503).json({ mode: 'maintenance', msg });
  }

  return res.status(200).json({ mode: 'normal' });
});

// ===== ADMIN =====
app.post('/api/admin/login', (req: Request, res: Response) => {
  res.json({ ok: verifyAdminSecret(req.body.password) });
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
  const { username, reason, blockType, blockUntil } = req.body;
  await pool.query(
    'UPDATE users SET is_blocked=1, block_reason=$1, block_type=$2, block_until=$3 WHERE username=$4',
    [reason || '', blockType || 'permanent', blockUntil || null, username]
  );

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
  const { roomId, msgId } = req.body;
  await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msgId]);
  io.emit('msg-deleted', { roomId, msgId });
  res.json({ ok: true });
});

app.post('/api/create-group', async (req: Request, res: Response) => {
  const { name, members, creator } = req.body;
  if (!name || !name.trim()) return res.json({ ok: false, msg: 'نام گروه را وارد کنید' });
  // (رفع F2، بازیابی‌شده از دور اول) فقط کاربر واردشده می‌تواند گروهی به نام خودش بسازد.
  const sessionUser = getSessionUsername(req);
  if (!sessionUser || sessionUser !== creator) {
    return res.status(401).json({ ok: false });
  }
  const memberList = Array.isArray(members) ? members : [];
  const allMembers = Array.from(new Set([creator, ...memberList].filter(Boolean)));
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
  const { name, members } = req.body;
  const groupId = uuidv4();
  await pool.query('INSERT INTO groups (id, name, members, created_at) VALUES ($1,$2,$3,$4)', [
    groupId,
    name,
    JSON.stringify(members),
    new Date().toISOString(),
  ]);
  (members as string[]).forEach(m => {
    presence.emitToUser(io, m, 'new-group', { id: groupId, name, members, epoch: 1 });
  });
  res.json({ ok: true, groupId });
});

app.post('/api/admin/add-to-group', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { groupId, username } = req.body;
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [groupId]);
  if (!rows.length) return res.json({ ok: false, msg: 'گروه یافت نشد' });
  const group = rows[0];
  const members: string[] = JSON.parse(group.members);
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

app.get('/api/admin/groups', async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM groups');
  res.json({
    ok: true,
    groups: rows.map((g: any) => ({ ...g, epoch: Number(g.epoch) || 1, members: JSON.parse(g.members) })),
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
  const { mode, msg } = req.body;
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
    return res.send(
      `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>لینک منقضی</title><link rel="stylesheet" href="/css/error.css"/></head><body><main><div class="error-icon" aria-hidden="true">⏱️</div><h1>لینک منقضی شده</h1><p>این لینک دیگر معتبر نیست.</p></main></body></html>`
    );
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

app.get('/robots.txt', (req: Request, res: Response) => {
  const proto = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'https';
  const host = req.get('host') || 'localhost:3000';
  const baseUrl = `${proto.split(',')[0].trim()}://${host}`;
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

app.get('/sitemap.xml', (req: Request, res: Response) => {
  const proto = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'https';
  const host = req.get('host') || 'localhost:3000';
  const baseUrl = `${proto.split(',')[0].trim()}://${host}`;
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
    // (رفع F2، بازیابی‌شده از دور اول) احراز هویت سوکت باید با توکن نشست معتبر باشد؛
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
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);

    if (!isGroup) {
      const { rows } = await pool.query('SELECT 1 FROM contacts WHERE username=$1 AND contact=$2', [
        currentUser,
        to,
      ]);
      if (!rows.length) return;
    }

    const disappearAt = disappearAfter ? new Date(Date.now() + disappearAfter * 1000).toISOString() : null;

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
      if (rows.length) {
        JSON.parse(rows[0].members).forEach((m: string) => {
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
        io.emit('msg-deleted', { roomId, msgId: msg.id });
      }, disappearAfter * 1000);
    }
  });

  socket.on('edit-message', async ({ msgId, newText, roomId }: any) => {
    if (!currentUser) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1 AND sender=$2', [msgId, currentUser]);
    if (!rows.length) return;
    await pool.query('UPDATE messages SET text=$1, is_edited=1 WHERE id=$2', [newText, msgId]);
    io.emit('msg-edited', { roomId, msgId, newText });
  });

  socket.on('delete-message', async ({ msgId, roomId }: any) => {
    if (!currentUser) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1 AND sender=$2', [msgId, currentUser]);
    if (!rows.length) return;
    await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msgId]);
    io.emit('msg-deleted', { roomId, msgId });
  });

  socket.on('pin-message', async ({ msgId, roomId }: any) => {
    if (!currentUser) return;
    await pool.query('UPDATE messages SET is_pinned=0 WHERE room_id=$1', [roomId]);
    await pool.query('UPDATE messages SET is_pinned=1 WHERE id=$1', [msgId]);
    io.emit('msg-pinned', { roomId, msgId });
  });

  socket.on('unpin-message', async ({ msgId, roomId }: any) => {
    if (!currentUser) return;
    if (msgId) {
      await pool.query('UPDATE messages SET is_pinned=0 WHERE id=$1', [msgId]);
    }
    if (roomId) {
      await pool.query('UPDATE messages SET is_pinned=0 WHERE room_id=$1', [roomId]);
    }
    io.emit('msg-unpinned', { roomId, msgId });
  });

  socket.on('create-group', async ({ name, members }: any) => {
    if (!currentUser || !name || !name.trim()) return;
    const memberList = Array.isArray(members) ? members : [];
    const allMembers = Array.from(new Set([currentUser, ...memberList].filter(Boolean)));
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
    const { rows } = await pool.query('SELECT reactions FROM messages WHERE id=$1', [msgId]);
    if (!rows.length) return;
    const reactions: Record<string, string[]> = JSON.parse(rows[0].reactions || '{}');
    if (!reactions[emoji]) reactions[emoji] = [];
    const idx = reactions[emoji].indexOf(currentUser);
    if (idx === -1) reactions[emoji].push(currentUser);
    else reactions[emoji].splice(idx, 1);
    if (reactions[emoji].length === 0) delete reactions[emoji];
    await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2', [JSON.stringify(reactions), msgId]);
    io.emit('msg-reaction', { roomId, msgId, reactions });
  });

  socket.on('forward-message', async ({ msgId, toRooms }: any) => {
    if (!currentUser) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1', [msgId]);
    if (!rows.length) return;
    const orig = rows[0];
    for (const roomId of toRooms) {
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
      io.emit('new-message', { roomId, msg: parseMsg(newMsg) });
    }
  });

  socket.on('typing', async ({ to, isGroup, isTyping }: any) => {
    if (!currentUser) return;
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);
    if (isGroup) {
      const { rows } = await pool.query('SELECT members FROM groups WHERE id=$1', [to]);
      if (rows.length) {
        JSON.parse(rows[0].members).forEach((m: string) => {
          if (m !== currentUser) {
            presence.emitToUser(io, m, 'typing', { roomId, username: currentUser, isTyping });
          }
        });
      }
    } else {
      presence.emitToUser(io, to, 'typing', { roomId, username: currentUser, isTyping });
    }
  });

  socket.on('read', async ({ roomId, msgId }: any) => {
    if (!msgId) return;
    await pool.query('UPDATE messages SET is_read=1 WHERE id=$1', [msgId]);
    io.emit('read', { roomId, msgId });
  });

  socket.on('update-status', async (status: string) => {
    if (!currentUser) return;
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

  server.listen(config.PORT, '0.0.0.0', () => {
    console.log(`✅ سرور TypeScript + React نسخه ${APP_VERSION} روی پورت ${config.PORT}`);
    console.log(`🌐 http://localhost:${config.PORT}`);
    console.log(`🔐 پنل مدیریت: http://localhost:${config.PORT}${config.ADMIN_PATH}`);
    void bale.checkBaleHealth();
    const healthTimer = setInterval(() => {
      void bale.checkBaleHealth();
    }, 5 * 60 * 1000);
    healthTimer.unref();
  });
}

process.on('uncaughtException', (err) => {
  console.error('❌ خطای مدیریت‌نشده (Uncaught Exception):', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ ریجکشن مدیریت‌نشده (Unhandled Rejection):', reason);
});

start();
