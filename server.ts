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
import { config, verifyAdminSecret } from './src/server/config';
import * as bale from './src/server/bale';
import { pool, init } from './src/server/db';
import { presence } from './src/server/presence';

// کلید سرور برای پروتکل احراز هویت کور Ristretto255-VOPRF (RFC 9497)
const voprfSeed = sha256(new TextEncoder().encode(config.ADMIN_PASSWORD + '::voprf-ristretto255-seed'));
const serverVoprfKeys = ristretto255_oprf.voprf.deriveKeyPair(
  voprfSeed,
  new TextEncoder().encode('PersianMessenger-Ristretto255-VOPRF-v2')
);

const app = express();
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        mediaSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: [
          "'self'",
          'wss://chatapp-server-1i2a.onrender.com',
          'https://fonts.googleapis.com',
          'https://fonts.gstatic.com',
        ],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: false,
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

// آپلود فایل با پشتیبانی ترکیبی (Hybrid Cloud-Safe Media Storage + Disk Stream)
const uploadsDir = path.join(process.cwd(), 'public/uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: config.MAX_FILE_SIZE } });

// متغیرهای درون‌حافظه‌ای کدهای تایید و توکن‌های موقت
const otps: Record<string, any> = {};
const adminTokens: Record<string, { username: string; expire: number; adminAt: number }> = {};

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

function getRoomId(u1: string, u2: string): string {
  return [u1, u2].sort().join('__');
}

function generateOTP(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
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

// ===== Bale Bot Polling =====
let baleOffset = 0;

async function startBalePolling(): Promise<void> {
  if (!config.BALE_BOT_TOKEN) {
    console.log('⚠️ توکن بله ست نشده - polling غیرفعال است');
    return;
  }
  console.log('🤖 ربات بله در حال اتصال...');
  while (true) {
    try {
      const updates = await bale.getUpdates(baleOffset);
      for (const update of updates) {
        baleOffset = update.update_id + 1;
        await handleBaleUpdate(update);
      }
    } catch (e: any) {
      console.error('❌ خطای polling بله:', e.message);
    }
    await new Promise(r => setTimeout(r, 1000));
  }
}

async function handleBaleUpdate(update: bale.BaleUpdate): Promise<void> {
  const msg = update.message;
  if (!msg || !msg.text) return;
  const chatId = msg.chat.id;
  const baleId = (msg.from.username || String(msg.from.id)).toLowerCase();
  otps[`__chatid__${baleId}`] = chatId;

  if (msg.text === '/start') {
    await bale.sendMessage(chatId, '👋 سلام!\nبرای ورود یا ثبت‌نام، آیدی بله‌ات رو توی سایت وارد کن.');
    return;
  }
  if (otps[baleId]) {
    await bale.sendMessage(
      chatId,
      `🔐 کد تأیید:\n\n${otps[baleId].code}\n\n⏱ ${config.OTP_EXPIRE} ثانیه معتبر است.`
    );
  }
}

// ===== HYBRID PERSISTENT FILE UPLOAD & MEDIA SERVING =====
app.post('/api/upload', upload.single('file'), async (req: Request, res: Response) => {
  if (!req.file) return res.json({ ok: false, msg: 'فایل آپلود نشد' });
  const ext = path.extname(req.file.originalname).toLowerCase();
  let fileType = 'file';
  if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) fileType = 'image';
  else if (['.mp3', '.ogg', '.wav', '.webm', '.m4a'].includes(ext)) fileType = 'voice';
  else if (['.mp4', '.mov', '.avi'].includes(ext)) fileType = 'video';

  let fileUrl = '/uploads/' + req.file.filename;

  // ذخیره‌سازی پایدار ابری برای فایل‌های زیر ۲ مگابایت (ویس‌ها، آواتارها، تصاویر چت)
  // جلوگیری از پاک شدن فایل‌ها در محیط‌های کانتینری Ephemeral (مانند Render و Railway)
  if (config.STORAGE_MODE !== 'disk' && req.file.size <= config.INLINE_MAX_BYTES) {
    try {
      const mediaId = req.file.filename;
      const rawBuffer = await fs.promises.readFile(req.file.path);
      const base64Data = rawBuffer.toString('base64');
      await pool.query(
        'INSERT INTO media_blobs (id, mime_type, data_base64, created_at) VALUES ($1, $2, $3, $4)',
        [mediaId, req.file.mimetype || 'application/octet-stream', base64Data, new Date().toISOString()]
      );
      fileUrl = `/api/media/${mediaId}`;
    } catch {
      // در صورت خطا از همان مسیر دیسک استفاده می‌شود
    }
  }

  res.json({ ok: true, fileUrl, fileType, originalName: req.file.originalname });
});

app.get('/api/media/:id', async (req: Request, res: Response) => {
  const mediaId = String(req.params.id);
  try {
    const { rows } = await pool.query('SELECT * FROM media_blobs WHERE id = $1', [mediaId]);
    if (rows.length) {
      const blob = rows[0];
      const buffer = Buffer.from(blob.data_base64, 'base64');
      res.setHeader('Content-Type', blob.mime_type || 'application/octet-stream');
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      return res.send(buffer);
    }
  } catch {
    // fallback to disk
  }

  const diskFile = path.join(uploadsDir, path.basename(mediaId));
  if (fs.existsSync(diskFile)) {
    return res.sendFile(diskFile);
  }
  return res.status(404).send('Media not found');
});

// ===== AUTH =====
app.post('/api/send-otp', async (req: Request, res: Response) => {
  const { baleId } = req.body;
  if (!baleId) return res.json({ ok: false, msg: 'آیدی بله رو وارد کن' });
  const key = String(baleId).toLowerCase().replace('@', '').trim();
  const code = generateOTP();
  otps[key] = { code, expire: Date.now() + config.OTP_EXPIRE * 1000 };

  const chatId = otps[`__chatid__${key}`];
  if (chatId) {
    await bale.sendMessage(chatId, `🔐 کد تأیید:\n\n${code}\n\n⏱ ${config.OTP_EXPIRE} ثانیه معتبر است.`);
    res.json({ ok: true, msg: '✅ کد به بله‌ات فرستاده شد' });
  } else {
    if (!config.BALE_BOT_TOKEN) {
      console.log(`🔐 [حالت آزمایشی] کد تأیید برای @${key}: ${code}`);
      res.json({ ok: true, msg: `کد تأیید آزمایشی: ${code}` });
    } else {
      res.json({ ok: true, needStart: true, msg: 'ابتدا به ربات بله /start بزن' });
    }
  }
});

app.post('/api/verify-otp', async (req: Request, res: Response) => {
  const { baleId, code } = req.body;
  const key = String(baleId || '').toLowerCase().replace('@', '').trim();
  const otp = otps[key];
  if (!otp) return res.json({ ok: false, msg: 'ابتدا کد درخواست کن' });
  if (Date.now() > otp.expire) {
    delete otps[key];
    return res.json({ ok: false, msg: 'کد منقضی شده' });
  }
  if (otp.code !== code) return res.json({ ok: false, msg: 'کد اشتباه است' });
  delete otps[key];

  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [key]);
  res.json({ ok: true, isNew: rows.length === 0, username: key });
});

app.post('/api/register', async (req: Request, res: Response) => {
  const { baleId } = req.body;
  const key = String(baleId || '').toLowerCase().replace('@', '').trim();
  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [key]);
  if (rows.length) return res.json({ ok: false, msg: 'این حساب قبلاً ثبت‌نام کرده' });

  const chatId = otps[`__chatid__${key}`] || null;
  await pool.query('INSERT INTO users (username, bale_chat_id, joined_at) VALUES ($1, $2, $3)', [
    key,
    chatId,
    new Date().toISOString(),
  ]);
  res.json({ ok: true, username: key });
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
  } catch (e: any) {
    res.status(400).json({ ok: false, msg: e.message });
  }
});

// ===== USER & HYBRID POST-QUANTUM PUBLIC KEY DIRECTORY =====
app.get('/api/user/:username', async (req: Request, res: Response) => {
  const { rows } = await pool.query(
    'SELECT username, avatar, bio, status, public_key FROM users WHERE username = $1',
    [req.params.username]
  );
  if (!rows.length) return res.json({ ok: false });
  res.json({ ok: true, user: rows[0] });
});

app.post('/api/user/public-key', async (req: Request, res: Response) => {
  const { username, publicKey } = req.body;
  if (!username || !publicKey) return res.json({ ok: false });
  await pool.query('UPDATE users SET public_key=$1 WHERE username=$2', [publicKey, username]);

  // اطلاع‌رسانی کلید عمومی جدید به مخاطبان آنلاین برای رمزنگاری خودکار ECDH
  const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [username]);
  contacts.forEach(({ contact }: any) => {
    presence.emitToUser(io, contact, 'peer-key-updated', { username, publicKey });
  });

  res.json({ ok: true });
});

app.post('/api/user/update', async (req: Request, res: Response) => {
  const { username, bio, status, avatar } = req.body;
  await pool.query('UPDATE users SET bio=$1, status=$2, avatar=$3 WHERE username=$4', [
    bio || '',
    status || 'online',
    avatar || null,
    username,
  ]);
  res.json({ ok: true });
});

app.post('/api/add-contact', async (req: Request, res: Response) => {
  const { myUsername, contactUsername } = req.body;
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
  const { rows } = await pool.query(
    'SELECT c.contact, u.avatar, u.status, u.public_key FROM contacts c JOIN users u ON c.contact = u.username WHERE c.username = $1',
    [req.params.username]
  );
  res.json({
    ok: true,
    contacts: rows.map((r: any) => ({
      username: r.contact,
      avatar: r.avatar,
      status: r.status,
      public_key: r.public_key || null,
      online: presence.isOnline(r.contact),
    })),
  });
});

app.get('/api/messages/:roomId', async (req: Request, res: Response) => {
  const { rows } = await pool.query(
    'SELECT * FROM messages WHERE room_id = $1 AND is_deleted = 0 ORDER BY timestamp ASC',
    [req.params.roomId]
  );
  res.json({ ok: true, messages: rows.map(parseMsg) });
});

app.get('/api/groups/:username', async (req: Request, res: Response) => {
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
      `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>لینک منقضی</title></head><body style="font-family:Vazirmatn,sans-serif;direction:rtl;text-align:center;padding:60px"><div style="font-size:60px">⏱️</div><h1>لینک منقضی شده</h1><p>این لینک دیگر معتبر نیست.</p></body></html>`
    );
  }

  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [data.username]);
  delete adminTokens[token];
  if (!rows.length) {
    return res.send(
      `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>کاربر یافت نشد</title></head><body style="font-family:Vazirmatn,sans-serif;direction:rtl;text-align:center;padding:60px"><div style="font-size:60px">❌</div><h1>کاربر یافت نشد</h1><p>کاربر "${data.username}" وجود ندارد.</p></body></html>`
    );
  }

  res.send(
    `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>ورود موقت ادمین</title></head><body style="margin:0"><script>sessionStorage.setItem('adminLoginToken','${data.username}'); location.href='/';</script></body></html>`
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

  socket.on('auth', async (username: string) => {
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
  const validClientRoutes = new Set(['/', '/index.html', '/terms']);

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
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Vazirmatn',system-ui,sans-serif;background:linear-gradient(135deg,#0f0f1a,#16213e,#0f3460);color:#f0f0f0;min-height:100vh;display:flex;align-items:center;justify-content:center;direction:rtl;padding:20px}
    main{max-width:400px;width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:24px;padding:36px 28px;text-align:center}
    h1{font-size:22px;margin:12px 0 8px}
    p{font-size:14px;color:#9ca3af;margin-bottom:24px;line-height:1.7}
    a.home-link{display:inline-block;background:linear-gradient(135deg,#7c3aed,#06b6d4);color:#ffffff;text-decoration:none;padding:12px 24px;border-radius:12px;font-weight:600;font-size:14px}
  </style>
</head>
<body>
  <main id="main-content">
    <div style="font-size:48px" aria-hidden="true">🔍</div>
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

    app.use((req, res, next) => {
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
        res.setHeader('Cache-Control', 'public, max-age=60');
        const origWriteHead = res.writeHead.bind(res);
        res.writeHead = ((statusCode: number, ...args: any[]) => {
          res.setHeader('Cache-Control', 'public, max-age=60');
          return origWriteHead(statusCode, ...args);
        }) as typeof res.writeHead;
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
            res.setHeader('Cache-Control', 'public, max-age=60');
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
            res.setHeader('Cache-Control', 'public, max-age=60');
          } else {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          }
        },
      })
    );
    app.get(['/', '/index.html', '/terms'], (_req, res) => {
      res.setHeader('Cache-Control', 'public, max-age=60');
      res.sendFile(path.join(distPath, 'index.html'));
    });
    app.use((req, res) => {
      return sendNotFound(req, res);
    });
  }

  server.listen(config.PORT, '0.0.0.0', () => {
    console.log(`✅ سرور TypeScript + React روی پورت ${config.PORT}`);
    console.log(`🌐 http://localhost:${config.PORT}`);
    console.log(`🔐 پنل مدیریت: http://localhost:${config.PORT}${config.ADMIN_PATH}`);
    startBalePolling();
  });
}

process.on('uncaughtException', (err) => {
  console.error('❌ خطای مدیریت‌نشده (Uncaught Exception):', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ ریجکشن مدیریت‌نشده (Unhandled Rejection):', reason);
});

start();
