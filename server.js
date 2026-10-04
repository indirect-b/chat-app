// بارگذاری .env برای محیط لوکال (در Render خودکار مدیریت می‌شود)
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const fs = require('fs');
const config = require('./config');
const bale = require('./bale');
const { pool, init } = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ===== آپلود فایل =====
const uploadsDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: config.MAX_FILE_SIZE } });

// ===== متغیرهای درون‌حافظه‌ای =====
let otps = {};                  // baleId -> { code, expire }
let onlineSockets = {};         // socketId -> username
let usernameToSocket = {};      // username -> socketId (سرعت جستجوی O(1))
let adminTokens = {};           // token -> { username, expire } لینک‌های ورود موقت ادمین

// ===== Helper Functions =====
async function getSetting(key) {
  const { rows } = await pool.query('SELECT value FROM settings WHERE key = $1', [key]);
  return rows.length ? rows[0].value : null;
}

async function setSetting(key, value) {
  await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', [key, value]);
}

function isAdmin(req) {
  return req.headers['x-admin-token'] === config.ADMIN_PASSWORD;
}

function getRoomId(u1, u2) {
  return [u1, u2].sort().join('__');
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function isUserBlocked(username) {
  const { rows } = await pool.query('SELECT is_blocked, block_type, block_until FROM users WHERE username = $1', [username]);
  const user = rows[0];
  if (!user || !user.is_blocked) return false;
  if (user.block_type === 'permanent') return true;
  if (user.block_type === 'temporary' && user.block_until) {
    if (new Date(user.block_until) > new Date()) return true;
    // منقضی شده - رفع مسدودیت
    await pool.query('UPDATE users SET is_blocked=0, block_type=NULL, block_until=NULL WHERE username=$1', [username]);
    return false;
  }
  return false;
}

// ثبت ورود/خروج کاربر آنلاین
function setOnline(socketId, username) {
  onlineSockets[socketId] = username;
  usernameToSocket[username] = socketId;
}

function setOffline(socketId) {
  const username = onlineSockets[socketId];
  delete onlineSockets[socketId];
  // فقط اگر این سوکت، سوکت فعلی کاربر بود (جلوگیری از overwrite چندتبی)
  if (username && usernameToSocket[username] === socketId) {
    delete usernameToSocket[username];
  }
  return username;
}

function getSocketIdByUsername(username) {
  return usernameToSocket[username];
}

function parseMsg(m) {
  return {
    ...m,
    reactions: JSON.parse(m.reactions || '{}'),
    is_edited: !!m.is_edited,
    is_deleted: !!m.is_deleted,
    is_pinned: !!m.is_pinned,
    is_read: !!m.is_read,
  };
}

// ===== Bale Bot Polling =====
let baleOffset = 0;

async function startBalePolling() {
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
    } catch (e) {
      console.error('❌ خطای polling بله:', e.message);
    }
    await new Promise(r => setTimeout(r, 1000));
  }
}

async function handleBaleUpdate(update) {
  const msg = update.message;
  if (!msg || !msg.text) return;
  const chatId = msg.chat.id;
  const baleId = msg.from.username || String(msg.from.id);
  otps[`__chatid__${baleId}`] = chatId;

  if (msg.text === '/start') {
    await bale.sendMessage(chatId, '👋 سلام!\nبرای ورود یا ثبت‌نام، آیدی بله‌ات رو توی سایت وارد کن.');
    return;
  }
  if (otps[baleId]) {
    await bale.sendMessage(chatId, `🔐 کد تأیید:\n\n${otps[baleId].code}\n\n⏱ ${config.OTP_EXPIRE} ثانیه معتبر است.`);
  }
}

// ===== FILE UPLOAD =====
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.json({ ok: false, msg: 'فایل آپلود نشد' });
  const fileUrl = '/uploads/' + req.file.filename;
  const ext = path.extname(req.file.originalname).toLowerCase();
  let fileType = 'file';
  if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) fileType = 'image';
  else if (['.mp3', '.ogg', '.wav', '.webm', '.m4a'].includes(ext)) fileType = 'voice';
  else if (['.mp4', '.mov', '.avi'].includes(ext)) fileType = 'video';
  res.json({ ok: true, fileUrl, fileType, originalName: req.file.originalname });
});

// ===== AUTH =====
app.post('/api/send-otp', async (req, res) => {
  const { baleId } = req.body;
  if (!baleId) return res.json({ ok: false, msg: 'آیدی بله رو وارد کن' });
  const key = baleId.toLowerCase().replace('@', '');
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

app.post('/api/verify-otp', async (req, res) => {
  const { baleId, code } = req.body;
  const key = baleId.toLowerCase().replace('@', '');
  const otp = otps[key];
  if (!otp) return res.json({ ok: false, msg: 'ابتدا کد درخواست کن' });
  if (Date.now() > otp.expire) { delete otps[key]; return res.json({ ok: false, msg: 'کد منقضی شده' }); }
  if (otp.code !== code) return res.json({ ok: false, msg: 'کد اشتباه است' });
  delete otps[key];

  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [key]);
  res.json({ ok: true, isNew: rows.length === 0, username: key });
});

app.post('/api/register', async (req, res) => {
  const { baleId } = req.body;
  const key = baleId.toLowerCase().replace('@', '');
  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [key]);
  if (rows.length) return res.json({ ok: false, msg: 'این حساب قبلاً ثبت‌نام کرده' });

  const chatId = otps[`__chatid__${key}`] || null;
  await pool.query('INSERT INTO users (username, bale_chat_id, joined_at) VALUES ($1, $2, $3)', [key, chatId, new Date().toISOString()]);
  res.json({ ok: true, username: key });
});

// ===== USER =====
app.get('/api/user/:username', async (req, res) => {
  const { rows } = await pool.query('SELECT username, avatar, bio, status FROM users WHERE username = $1', [req.params.username]);
  if (!rows.length) return res.json({ ok: false });
  res.json({ ok: true, user: rows[0] });
});

app.post('/api/user/update', async (req, res) => {
  const { username, bio, status, avatar } = req.body;
  await pool.query('UPDATE users SET bio=$1, status=$2, avatar=$3 WHERE username=$4', [bio || '', status || 'online', avatar || null, username]);
  res.json({ ok: true });
});

app.post('/api/add-contact', async (req, res) => {
  const { myUsername, contactUsername } = req.body;
  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [contactUsername]);
  if (!rows.length) return res.json({ ok: false, msg: 'این آیدی وجود ندارد' });
  if (myUsername === contactUsername) return res.json({ ok: false, msg: 'نمیتونی خودت رو اضافه کنی' });
  await pool.query('INSERT INTO contacts (username, contact) VALUES ($1, $2) ON CONFLICT DO NOTHING', [myUsername, contactUsername]);
  res.json({ ok: true });
});

app.get('/api/contacts/:username', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT c.contact, u.avatar, u.status FROM contacts c JOIN users u ON c.contact = u.username WHERE c.username = $1',
    [req.params.username]
  );
  res.json({ ok: true, contacts: rows.map(r => ({ username: r.contact, avatar: r.avatar, status: r.status })) });
});

app.get('/api/messages/:roomId', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM messages WHERE room_id = $1 AND is_deleted = 0 ORDER BY timestamp ASC', [req.params.roomId]);
  res.json({ ok: true, messages: rows.map(parseMsg) });
});

app.get('/api/groups/:username', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM groups');
  const myGroups = rows.filter(g => JSON.parse(g.members).includes(req.params.username));
  res.json({ ok: true, groups: myGroups.map(g => ({ ...g, members: JSON.parse(g.members) })) });
});

// ===== REPORT =====
app.post('/api/report', async (req, res) => {
  const { reporter, reportedUser, messageId, messageText, reason } = req.body;
  await pool.query(
    'INSERT INTO reports (id, reporter, reported_user, message_id, message_text, reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [uuidv4(), reporter, reportedUser, messageId || null, messageText || null, reason, new Date().toISOString()]
  );
  res.json({ ok: true });
});

// ===== SETTINGS =====
app.get('/api/settings/rules', async (req, res) => {
  res.json({ ok: true, rules: await getSetting('rules') });
});

app.get('/api/settings/mode', async (req, res) => {
  res.json({ ok: true, mode: await getSetting('server_mode'), msg: await getSetting('maintenance_msg') });
});

// ===== ADMIN =====
app.post('/api/admin/login', (req, res) => {
  res.json({ ok: req.body.password === config.ADMIN_PASSWORD });
});

app.get('/api/admin/users', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM users ORDER BY joined_at DESC');
  res.json({ ok: true, users: rows });
});

app.get('/api/admin/reports', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM reports ORDER BY created_at DESC');
  res.json({ ok: true, reports: rows });
});

app.post('/api/admin/report-action', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { reportId, status } = req.body;
  await pool.query('UPDATE reports SET status = $1 WHERE id = $2', [status, reportId]);
  res.json({ ok: true });
});

app.post('/api/admin/block', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username, reason, blockType, blockUntil } = req.body;
  await pool.query('UPDATE users SET is_blocked=1, block_reason=$1, block_type=$2, block_until=$3 WHERE username=$4', [reason || '', blockType || 'permanent', blockUntil || null, username]);

  const { rows } = await pool.query('SELECT bale_chat_id FROM users WHERE username = $1', [username]);
  const user = rows[0];
  const sockId = getSocketIdByUsername(username);
  if (sockId) {
    io.to(sockId).emit('blocked', { reason, blockType, blockUntil });
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

app.post('/api/admin/unblock', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username } = req.body;
  await pool.query('UPDATE users SET is_blocked=0, block_reason=NULL, block_type=NULL, block_until=NULL WHERE username=$1', [username]);

  const { rows } = await pool.query('SELECT bale_chat_id FROM users WHERE username = $1', [username]);
  const user = rows[0];
  if (user?.bale_chat_id) {
    await bale.sendMessage(user.bale_chat_id, '✅ مسدودیت حساب شما برداشته شد.');
  }
  res.json({ ok: true });
});

app.post('/api/admin/kick', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username } = req.body;
  const sockId = getSocketIdByUsername(username);
  if (sockId) {
    io.to(sockId).emit('kicked');
    const s = io.sockets.sockets.get(sockId);
    if (s) s.disconnect(true);
  }
  res.json({ ok: true });
});

app.delete('/api/admin/message', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { roomId, msgId } = req.body;
  await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msgId]);
  io.emit('msg-deleted', { roomId, msgId });
  res.json({ ok: true });
});

app.post('/api/admin/create-group', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { name, members } = req.body;
  const groupId = uuidv4();
  await pool.query('INSERT INTO groups (id, name, members, created_at) VALUES ($1,$2,$3,$4)', [groupId, name, JSON.stringify(members), new Date().toISOString()]);
  members.forEach(m => {
    const sockId = getSocketIdByUsername(m);
    if (sockId) io.to(sockId).emit('new-group', { id: groupId, name, members });
  });
  res.json({ ok: true, groupId });
});

app.post('/api/admin/add-to-group', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { groupId, username } = req.body;
  const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [groupId]);
  if (!rows.length) return res.json({ ok: false, msg: 'گروه یافت نشد' });
  const group = rows[0];
  const members = JSON.parse(group.members);
  if (!members.includes(username)) members.push(username);
  await pool.query('UPDATE groups SET members = $1 WHERE id = $2', [JSON.stringify(members), groupId]);
  const sockId = getSocketIdByUsername(username);
  if (sockId) io.to(sockId).emit('new-group', { id: groupId, name: group.name, members });
  res.json({ ok: true });
});

app.get('/api/admin/groups', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM groups');
  res.json({ ok: true, groups: rows.map(g => ({ ...g, members: JSON.parse(g.members) })) });
});

app.get('/api/admin/messages', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { rows } = await pool.query('SELECT * FROM messages WHERE is_deleted=0 ORDER BY timestamp DESC LIMIT 500');
  const grouped = {};
  rows.forEach(m => {
    if (!grouped[m.room_id]) grouped[m.room_id] = [];
    grouped[m.room_id].push(parseMsg(m));
  });
  res.json({ ok: true, messages: grouped });
});

app.get('/api/admin/stats', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const totalUsers = (await pool.query('SELECT COUNT(*) as c FROM users')).rows[0].c;
  const onlineUsers = Object.keys(onlineSockets).length;
  const totalMessages = (await pool.query('SELECT COUNT(*) as c FROM messages WHERE is_deleted=0')).rows[0].c;
  const totalGroups = (await pool.query('SELECT COUNT(*) as c FROM groups')).rows[0].c;
  const pendingReports = (await pool.query("SELECT COUNT(*) as c FROM reports WHERE status='pending'")).rows[0].c;

  // آمار روزانه (۷ روز اخیر)
  const daily = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().split('T')[0];
    const count = (await pool.query("SELECT COUNT(*) as c FROM messages WHERE to_char(to_timestamp(timestamp/1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD') = $1", [dateStr])).rows[0].c;
    daily.push({ date: dateStr, count: parseInt(count) });
  }

  res.json({ ok: true, stats: { totalUsers: parseInt(totalUsers), onlineUsers, totalMessages: parseInt(totalMessages), totalGroups: parseInt(totalGroups), pendingReports: parseInt(pendingReports), daily } });
});

app.post('/api/admin/announce', async (req, res) => {
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

app.post('/api/admin/set-mode', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { mode, msg } = req.body;
  await setSetting('server_mode', mode);
  if (msg) await setSetting('maintenance_msg', msg);
  if (mode === 'maintenance') io.emit('server-maintenance', { msg: msg || await getSetting('maintenance_msg') });
  else if (mode === 'normal') io.emit('server-normal');
  res.json({ ok: true });
});

app.post('/api/admin/set-rules', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  await setSetting('rules', req.body.rules || '');
  res.json({ ok: true });
});

// ===== Admin: ورود به حساب کاربر با لینک موقت =====
app.post('/api/admin/login-as', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username } = req.body;
  if (!username) return res.json({ ok: false, msg: 'آیدی کاربر رو وارد کن' });

  // ساختن توکن تصادفی
  const token = uuidv4();
  adminTokens[token] = {
    username: username,
    expire: Date.now() + 30000, // ۳۰ ثانیه
    adminAt: Date.now()
  };

  res.json({ ok: true, token, url: `/api/admin-login-as/${token}` });
});

// مصرف توکن ورود موقت
app.get('/api/admin-login-as/:token', async (req, res) => {
  const token = req.params.token;
  const data = adminTokens[token];

  if (!data) {
    return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>لینک منقضی</title></head><body style="font-family:Vazirmatn,sans-serif;direction:rtl;text-align:center;padding:60px"><div style="font-size:60px">⏱️</div><h1>لینک منقضی شده</h1><p>این لینک دیگر معتبر نیست.</p></body></html>`);
  }

  // بررسی انقضا
  if (Date.now() > data.expire) {
    delete adminTokens[token];
    return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>لینک منقضی</title></head><body style="font-family:Vazirmatn,sans-serif;direction:rtl;text-align:center;padding:60px"><div style="font-size:60px">⏱️</div><h1>لینک منقضی شده</h1><p>۳۰ ثانیه گذشته و لینک دیگر معتبر نیست.</p></body></html>`);
  }

  // بررسی کاربر
  const { rows } = await pool.query('SELECT username FROM users WHERE username = $1', [data.username]);
  if (!rows.length) {
    delete adminTokens[token];
    return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>کاربر یافت نشد</title></head><body style="font-family:Vazirmatn,sans-serif;direction:rtl;text-align:center;padding:60px"><div style="font-size:60px">❌</div><h1>کاربر یافت نشد</h1><p>کاربر "${data.username}" وجود ندارد.</p></body></html>`);
  }

  // مصرف توکن (یکبار مصرف)
  delete adminTokens[token];

  // ریدایرکت به صفحه اصلی با توکن ورود
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>ورود موقت ادمین</title></head><body style="margin:0"><script>window.opener ? window.close() : (location.href='/'); sessionStorage.setItem('adminLoginToken','${data.username}');</script></body></html>`);
});

app.get(config.ADMIN_PATH, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ===== SOCKET.IO =====
io.on('connection', (socket) => {
  let currentUser = null;

  socket.on('auth', async (username) => {
    if (await isUserBlocked(username)) {
      const { rows } = await pool.query('SELECT block_reason, block_type, block_until FROM users WHERE username=$1', [username]);
      socket.emit('blocked', rows[0] || {});
      return;
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!rows.length) return;
    currentUser = username;
    setOnline(socket.id, username);
    await pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [new Date().toISOString(), username]);

    const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [username]);
    contacts.forEach(({ contact }) => {
      const sockId = getSocketIdByUsername(contact);
      if (sockId) io.to(sockId).emit('contact-online', username);
    });

    socket.emit('auth-ok');
  });

  socket.on('update-location', (loc) => {
    // نگه‌داری لوکیشن غیرفعال شد (geoip حذف شد) - فقط last_seen آپدیت میشه
    if (currentUser) pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [new Date().toISOString(), currentUser]);
  });

  socket.on('send-message', async (data) => {
    if (!currentUser) return;
    const { to, text, fileUrl, fileType, replyToId, replyToText, isGroup, disappearAfter } = data;
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);

    if (!isGroup) {
      const { rows } = await pool.query('SELECT 1 FROM contacts WHERE username=$1 AND contact=$2', [currentUser, to]);
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
      time: new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' }),
      timestamp: Date.now()
    };

    await pool.query(
      'INSERT INTO messages (id,room_id,sender,text,file_url,file_type,reply_to_id,reply_to_text,reactions,is_edited,is_deleted,is_pinned,is_read,disappear_at,time,timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)',
      [msg.id, msg.room_id, msg.sender, msg.text, msg.file_url, msg.file_type, msg.reply_to_id, msg.reply_to_text, msg.reactions, msg.is_edited, msg.is_deleted, msg.is_pinned, msg.is_read, msg.disappear_at, msg.time, msg.timestamp]
    );

    const parsedMsg = parseMsg(msg);

    if (isGroup) {
      const { rows } = await pool.query('SELECT members FROM groups WHERE id=$1', [to]);
      if (rows.length) {
        JSON.parse(rows[0].members).forEach(m => {
          const sockId = getSocketIdByUsername(m);
          if (sockId) io.to(sockId).emit('new-message', { roomId, msg: parsedMsg });
        });
      }
    } else {
      socket.emit('new-message', { roomId, msg: parsedMsg });
      const sockId = getSocketIdByUsername(to);
      if (sockId) io.to(sockId).emit('new-message', { roomId, msg: parsedMsg });
    }

    // ناپدیدشونده
    if (disappearAt) {
      setTimeout(async () => {
        await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msg.id]);
        io.emit('msg-deleted', { roomId, msgId: msg.id });
      }, disappearAfter * 1000);
    }
  });

  socket.on('edit-message', async ({ msgId, newText, roomId }) => {
    if (!currentUser) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1 AND sender=$2', [msgId, currentUser]);
    if (!rows.length) return;
    await pool.query('UPDATE messages SET text=$1, is_edited=1 WHERE id=$2', [newText, msgId]);
    io.emit('msg-edited', { roomId, msgId, newText });
  });

  socket.on('delete-message', async ({ msgId, roomId }) => {
    if (!currentUser) return;
    const { rows } = await pool.query('SELECT * FROM messages WHERE id=$1 AND sender=$2', [msgId, currentUser]);
    if (!rows.length) return;
    await pool.query('UPDATE messages SET is_deleted=1 WHERE id=$1', [msgId]);
    io.emit('msg-deleted', { roomId, msgId });
  });

  // 🐛 رفع باگ پین: حذف پین قبلی قبل از پین جدید
  socket.on('pin-message', async ({ msgId, roomId }) => {
    if (!currentUser) return;
    await pool.query('UPDATE messages SET is_pinned=0 WHERE room_id=$1', [roomId]);
    await pool.query('UPDATE messages SET is_pinned=1 WHERE id=$1', [msgId]);
    io.emit('msg-pinned', { roomId, msgId });
  });

  socket.on('react', async ({ msgId, roomId, emoji }) => {
    if (!currentUser) return;
    const { rows } = await pool.query('SELECT reactions FROM messages WHERE id=$1', [msgId]);
    if (!rows.length) return;
    const reactions = JSON.parse(rows[0].reactions || '{}');
    if (!reactions[emoji]) reactions[emoji] = [];
    const idx = reactions[emoji].indexOf(currentUser);
    if (idx === -1) reactions[emoji].push(currentUser);
    else reactions[emoji].splice(idx, 1);
    if (reactions[emoji].length === 0) delete reactions[emoji];
    await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2', [JSON.stringify(reactions), msgId]);
    io.emit('msg-reaction', { roomId, msgId, reactions });
  });

  // 🐛 رفع باگ فوروارد: فقط متن/فایل کپی میشه، فیلدهای وضعیت نه
  socket.on('forward-message', async ({ msgId, toRooms }) => {
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
        time: new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' }),
        timestamp: Date.now()
      };
      await pool.query(
        'INSERT INTO messages (id,room_id,sender,text,file_url,file_type,reply_to_id,reply_to_text,reactions,is_edited,is_deleted,is_pinned,is_read,disappear_at,time,timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)',
        [newMsg.id, newMsg.room_id, newMsg.sender, newMsg.text, newMsg.file_url, newMsg.file_type, newMsg.reply_to_id, newMsg.reply_to_text, newMsg.reactions, newMsg.is_edited, newMsg.is_deleted, newMsg.is_pinned, newMsg.is_read, newMsg.disappear_at, newMsg.time, newMsg.timestamp]
      );
      io.emit('new-message', { roomId, msg: parseMsg(newMsg) });
    }
  });

  socket.on('typing', async ({ to, isGroup, isTyping }) => {
    if (!currentUser) return;
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);
    if (isGroup) {
      const { rows } = await pool.query('SELECT members FROM groups WHERE id=$1', [to]);
      if (rows.length) JSON.parse(rows[0].members).forEach(m => {
        if (m !== currentUser) {
          const sockId = getSocketIdByUsername(m);
          if (sockId) io.to(sockId).emit('typing', { roomId, username: currentUser, isTyping });
        }
      });
    } else {
      const sockId = getSocketIdByUsername(to);
      if (sockId) io.to(sockId).emit('typing', { roomId, username: currentUser, isTyping });
    }
  });

  // 🐛 رفع باگ read: آپدیت is_read بجای is_deleted
  socket.on('read', async ({ roomId, msgId }) => {
    if (!msgId) return;
    await pool.query('UPDATE messages SET is_read=1 WHERE id=$1', [msgId]);
    io.emit('read', { roomId, msgId });
  });

  socket.on('update-status', async (status) => {
    if (!currentUser) return;
    await pool.query('UPDATE users SET status=$1 WHERE username=$2', [status, currentUser]);
    const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [currentUser]);
    contacts.forEach(({ contact }) => {
      const sockId = getSocketIdByUsername(contact);
      if (sockId) io.to(sockId).emit('contact-status', { username: currentUser, status });
    });
  });

  socket.on('disconnect', async () => {
    const username = setOffline(socket.id);
    if (username) {
      await pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [new Date().toISOString(), username]);
      const { rows: contacts } = await pool.query('SELECT contact FROM contacts WHERE username=$1', [username]);
      contacts.forEach(({ contact }) => {
        const sockId = getSocketIdByUsername(contact);
        if (sockId) io.to(sockId).emit('contact-offline', username);
      });
    }
  });
});

// ===== START SERVER =====
async function start() {
  try {
    await init();
  } catch (e) {
    console.warn('⚠️ اخطار در آماده‌سازی اولیه دیتابیس:', e.message);
  }

  server.listen(config.PORT, '0.0.0.0', () => {
    console.log(`✅ سرور روی پورت ${config.PORT}`);
    console.log(`🌐 http://localhost:${config.PORT}`);
    console.log(`🔐 پنل ادمین: http://localhost:${config.PORT}${config.ADMIN_PATH}`);
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
