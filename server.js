const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const geoip = require('geoip-lite');
const config = require('./config');
const bale = require('./bale');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// File upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'public/uploads')),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: config.MAX_FILE_SIZE } });

// In-memory
let otps = {};
let onlineSockets = {}; // socketId -> username

// ===== HELPERS =====
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, value);
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

function isIranIP(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168') || ip.startsWith('10.')) return true;
  const geo = geoip.lookup(ip);
  return geo && geo.country === 'IR';
}

function isUserBlocked(username) {
  const user = db.prepare('SELECT is_blocked, block_type, block_until FROM users WHERE username = ?').get(username);
  if (!user || !user.is_blocked) return false;
  if (user.block_type === 'permanent') return true;
  if (user.block_type === 'temporary' && user.block_until) {
    if (new Date(user.block_until) > new Date()) return true;
    // expired - unblock
    db.prepare('UPDATE users SET is_blocked=0, block_type=NULL, block_until=NULL WHERE username=?').run(username);
    return false;
  }
  return false;
}

// ===== BALE BOT =====
let baleOffset = 0;

async function startBalePolling() {
  console.log('🤖 ربات بله در حال اتصال...');
  while (true) {
    const updates = await bale.getUpdates(baleOffset);
    for (const update of updates) {
      baleOffset = update.update_id + 1;
      await handleBaleUpdate(update);
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
    res.json({ ok: true, needStart: true, msg: 'ابتدا به ربات بله /start بزن' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const { baleId, code } = req.body;
  const key = baleId.toLowerCase().replace('@', '');
  const otp = otps[key];
  if (!otp) return res.json({ ok: false, msg: 'ابتدا کد درخواست کن' });
  if (Date.now() > otp.expire) { delete otps[key]; return res.json({ ok: false, msg: 'کد منقضی شده' }); }
  if (otp.code !== code) return res.json({ ok: false, msg: 'کد اشتباه است' });
  delete otps[key];

  const existing = db.prepare('SELECT username FROM users WHERE username = ?').get(key);
  res.json({ ok: true, isNew: !existing, username: key });
});

app.post('/api/register', (req, res) => {
  const { baleId } = req.body;
  const key = baleId.toLowerCase().replace('@', '');
  const existing = db.prepare('SELECT username FROM users WHERE username = ?').get(key);
  if (existing) return res.json({ ok: false, msg: 'این حساب قبلاً ثبت‌نام کرده' });

  const chatId = otps[`__chatid__${key}`] || null;
  db.prepare('INSERT INTO users (username, bale_chat_id, joined_at) VALUES (?, ?, ?)').run(key, chatId, new Date().toISOString());
  res.json({ ok: true, username: key });
});

app.get('/api/check-ip', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '';
  res.json({ ok: true, isIran: isIranIP(ip), ip });
});

// ===== USER =====
app.get('/api/user/:username', (req, res) => {
  const user = db.prepare('SELECT username, avatar, bio, status FROM users WHERE username = ?').get(req.params.username);
  if (!user) return res.json({ ok: false });
  res.json({ ok: true, user });
});

app.post('/api/user/update', (req, res) => {
  const { username, bio, status, avatar } = req.body;
  db.prepare('UPDATE users SET bio=?, status=?, avatar=? WHERE username=?').run(bio || '', status || 'online', avatar || null, username);
  res.json({ ok: true });
});

app.post('/api/add-contact', (req, res) => {
  const { myUsername, contactUsername } = req.body;
  const contact = db.prepare('SELECT username FROM users WHERE username = ?').get(contactUsername);
  if (!contact) return res.json({ ok: false, msg: 'این آیدی وجود ندارد' });
  if (myUsername === contactUsername) return res.json({ ok: false, msg: 'نمیتونی خودت رو اضافه کنی' });
  db.prepare('INSERT OR IGNORE INTO contacts (username, contact) VALUES (?, ?)').run(myUsername, contactUsername);
  res.json({ ok: true });
});

app.get('/api/contacts/:username', (req, res) => {
  const rows = db.prepare('SELECT c.contact, u.avatar, u.status FROM contacts c JOIN users u ON c.contact = u.username WHERE c.username = ?').all(req.params.username);
  res.json({ ok: true, contacts: rows.map(r => ({ username: r.contact, avatar: r.avatar, status: r.status })) });
});

app.get('/api/messages/:roomId', (req, res) => {
  const msgs = db.prepare('SELECT * FROM messages WHERE room_id = ? AND is_deleted = 0 ORDER BY timestamp ASC').all(req.params.roomId);
  res.json({ ok: true, messages: msgs.map(parseMsg) });
});

app.get('/api/groups/:username', (req, res) => {
  const groups = db.prepare('SELECT * FROM groups').all();
  const myGroups = groups.filter(g => JSON.parse(g.members).includes(req.params.username));
  res.json({ ok: true, groups: myGroups.map(g => ({ ...g, members: JSON.parse(g.members) })) });
});

// Report
app.post('/api/report', (req, res) => {
  const { reporter, reportedUser, messageId, messageText, reason } = req.body;
  db.prepare('INSERT INTO reports (id, reporter, reported_user, message_id, message_text, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(uuidv4(), reporter, reportedUser, messageId || null, messageText || null, reason, new Date().toISOString());
  res.json({ ok: true });
});

// Settings
app.get('/api/settings/rules', (req, res) => {
  res.json({ ok: true, rules: getSetting('rules') });
});

app.get('/api/settings/mode', (req, res) => {
  res.json({ ok: true, mode: getSetting('server_mode'), msg: getSetting('maintenance_msg') });
});

// ===== ADMIN =====
app.post('/api/admin/login', (req, res) => {
  res.json({ ok: req.body.password === config.ADMIN_PASSWORD });
});

app.get('/api/admin/users', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const users = db.prepare('SELECT * FROM users').all();
  res.json({ ok: true, users });
});

app.get('/api/admin/reports', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const reports = db.prepare('SELECT * FROM reports ORDER BY created_at DESC').all();
  res.json({ ok: true, reports });
});

app.post('/api/admin/report-action', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { reportId, status } = req.body;
  db.prepare('UPDATE reports SET status = ? WHERE id = ?').run(status, reportId);
  res.json({ ok: true });
});

app.post('/api/admin/block', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username, reason, blockType, blockUntil } = req.body;
  db.prepare('UPDATE users SET is_blocked=1, block_reason=?, block_type=?, block_until=? WHERE username=?').run(reason || '', blockType || 'permanent', blockUntil || null, username);

  // kick from server
  const user = db.prepare('SELECT bale_chat_id FROM users WHERE username = ?').get(username);
  const sock = Object.entries(onlineSockets).find(([, u]) => u === username);
  if (sock) {
    io.to(sock[0]).emit('blocked', { reason, blockType, blockUntil });
    const s = io.sockets.sockets.get(sock[0]);
    if (s) s.disconnect(true);
  }

  // notify via bale
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
  db.prepare('UPDATE users SET is_blocked=0, block_reason=NULL, block_type=NULL, block_until=NULL WHERE username=?').run(username);

  const user = db.prepare('SELECT bale_chat_id FROM users WHERE username = ?').get(username);
  if (user?.bale_chat_id) {
    await bale.sendMessage(user.bale_chat_id, '✅ مسدودیت حساب شما برداشته شد.');
  }
  res.json({ ok: true });
});

app.post('/api/admin/kick', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { username } = req.body;
  const sock = Object.entries(onlineSockets).find(([, u]) => u === username);
  if (sock) {
    io.to(sock[0]).emit('kicked');
    const s = io.sockets.sockets.get(sock[0]);
    if (s) s.disconnect(true);
  }
  res.json({ ok: true });
});

app.delete('/api/admin/message', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { roomId, msgId } = req.body;
  db.prepare('UPDATE messages SET is_deleted=1 WHERE id=?').run(msgId);
  io.emit('msg-deleted', { roomId, msgId });
  res.json({ ok: true });
});

app.post('/api/admin/create-group', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { name, members } = req.body;
  const groupId = uuidv4();
  db.prepare('INSERT INTO groups (id, name, members, created_at) VALUES (?, ?, ?, ?)').run(groupId, name, JSON.stringify(members), new Date().toISOString());
  members.forEach(m => {
    const sock = Object.entries(onlineSockets).find(([, u]) => u === m);
    if (sock) io.to(sock[0]).emit('new-group', { id: groupId, name, members });
  });
  res.json({ ok: true, groupId });
});

app.post('/api/admin/add-to-group', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { groupId, username } = req.body;
  const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(groupId);
  if (!group) return res.json({ ok: false, msg: 'گروه یافت نشد' });
  const members = JSON.parse(group.members);
  if (!members.includes(username)) members.push(username);
  db.prepare('UPDATE groups SET members = ? WHERE id = ?').run(JSON.stringify(members), groupId);
  const sock = Object.entries(onlineSockets).find(([, u]) => u === username);
  if (sock) io.to(sock[0]).emit('new-group', { id: groupId, name: group.name, members });
  res.json({ ok: true });
});

app.get('/api/admin/groups', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const groups = db.prepare('SELECT * FROM groups').all().map(g => ({ ...g, members: JSON.parse(g.members) }));
  res.json({ ok: true, groups });
});

app.get('/api/admin/messages', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const msgs = db.prepare('SELECT * FROM messages WHERE is_deleted=0 ORDER BY timestamp DESC LIMIT 500').all();
  const grouped = {};
  msgs.forEach(m => {
    if (!grouped[m.room_id]) grouped[m.room_id] = [];
    grouped[m.room_id].push(parseMsg(m));
  });
  res.json({ ok: true, messages: grouped });
});

app.get('/api/admin/stats', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const onlineUsers = Object.keys(onlineSockets).length;
  const totalMessages = db.prepare('SELECT COUNT(*) as c FROM messages WHERE is_deleted=0').get().c;
  const totalGroups = db.prepare('SELECT COUNT(*) as c FROM groups').get().c;
  const pendingReports = db.prepare('SELECT COUNT(*) as c FROM reports WHERE status="pending"').get().c;

  // daily messages for chart (last 7 days)
  const daily = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().split('T')[0];
    const count = db.prepare("SELECT COUNT(*) as c FROM messages WHERE date(datetime(timestamp/1000,'unixepoch')) = ?").get(dateStr).c;
    daily.push({ date: dateStr, count });
  }

  res.json({ ok: true, stats: { totalUsers, onlineUsers, totalMessages, totalGroups, pendingReports, daily } });
});

app.post('/api/admin/announce', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { text, imageUrl } = req.body;
  if (!text) return res.json({ ok: false, msg: 'متن رو وارد کن' });
  io.emit('announcement', { text, imageUrl });

  const users = db.prepare('SELECT bale_chat_id FROM users WHERE bale_chat_id IS NOT NULL').all();
  for (const u of users) {
    if (imageUrl) await bale.sendPhoto(u.bale_chat_id, imageUrl, text);
    else await bale.sendMessage(u.bale_chat_id, `📢 اطلاع‌رسانی:\n\n${text}`);
  }
  res.json({ ok: true, sent: users.length });
});

app.post('/api/admin/set-mode', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { mode, msg } = req.body;
  setSetting('server_mode', mode);
  if (msg) setSetting('maintenance_msg', msg);
  if (mode === 'maintenance') io.emit('server-maintenance', { msg: msg || getSetting('maintenance_msg') });
  else if (mode === 'normal') io.emit('server-normal');
  res.json({ ok: true });
});

app.post('/api/admin/set-rules', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  setSetting('rules', req.body.rules || '');
  res.json({ ok: true });
});

app.get(config.ADMIN_PATH, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ===== HELPERS =====
function parseMsg(m) {
  return {
    ...m,
    reactions: JSON.parse(m.reactions || '{}'),
    is_edited: !!m.is_edited,
    is_deleted: !!m.is_deleted,
    is_pinned: !!m.is_pinned,
  };
}

// ===== SOCKET.IO =====
io.on('connection', (socket) => {
  let currentUser = null;

  socket.on('auth', (username) => {
    if (isUserBlocked(username)) {
      const u = db.prepare('SELECT block_reason, block_type, block_until FROM users WHERE username=?').get(username);
      socket.emit('blocked', u);
      return;
    }
    const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if (!user) return;
    currentUser = username;
    onlineSockets[socket.id] = username;
    db.prepare('UPDATE users SET last_seen=? WHERE username=?').run(new Date().toISOString(), username);

    const contacts = db.prepare('SELECT contact FROM contacts WHERE username=?').all(username);
    contacts.forEach(({ contact }) => {
      const s = Object.entries(onlineSockets).find(([, u]) => u === contact);
      if (s) io.to(s[0]).emit('contact-online', username);
    });

    socket.emit('auth-ok');
  });

  socket.on('update-location', (loc) => {
    if (currentUser) db.prepare('UPDATE users SET last_seen=? WHERE username=?').run(JSON.stringify(loc), currentUser);
  });

  socket.on('send-message', (data) => {
    if (!currentUser) return;
    const { to, text, fileUrl, fileType, replyToId, replyToText, isGroup, disappearAfter } = data;
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);

    if (!isGroup) {
      const hasContact = db.prepare('SELECT 1 FROM contacts WHERE username=? AND contact=?').get(currentUser, to);
      if (!hasContact) return;
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
      disappear_at: disappearAt,
      time: new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' }),
      timestamp: Date.now()
    };

    db.prepare('INSERT INTO messages (id,room_id,sender,text,file_url,file_type,reply_to_id,reply_to_text,reactions,is_edited,is_deleted,is_pinned,disappear_at,time,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(msg.id, msg.room_id, msg.sender, msg.text, msg.file_url, msg.file_type, msg.reply_to_id, msg.reply_to_text, msg.reactions, msg.is_edited, msg.is_deleted, msg.is_pinned, msg.disappear_at, msg.time, msg.timestamp);

    const parsedMsg = parseMsg(msg);

    if (isGroup) {
      const group = db.prepare('SELECT members FROM groups WHERE id=?').get(to);
      if (group) {
        JSON.parse(group.members).forEach(m => {
          const s = Object.entries(onlineSockets).find(([, u]) => u === m);
          if (s) io.to(s[0]).emit('new-message', { roomId, msg: parsedMsg });
        });
      }
    } else {
      socket.emit('new-message', { roomId, msg: parsedMsg });
      const s = Object.entries(onlineSockets).find(([, u]) => u === to);
      if (s) io.to(s[0]).emit('new-message', { roomId, msg: parsedMsg });
    }

    // disappear
    if (disappearAt) {
      setTimeout(() => {
        db.prepare('UPDATE messages SET is_deleted=1 WHERE id=?').run(msg.id);
        io.emit('msg-deleted', { roomId, msgId: msg.id });
      }, disappearAfter * 1000);
    }
  });

  socket.on('edit-message', ({ msgId, newText, roomId }) => {
    if (!currentUser) return;
    const msg = db.prepare('SELECT * FROM messages WHERE id=? AND sender=?').get(msgId, currentUser);
    if (!msg) return;
    db.prepare('UPDATE messages SET text=?, is_edited=1 WHERE id=?').run(newText, msgId);
    io.emit('msg-edited', { roomId, msgId, newText });
  });

  socket.on('delete-message', ({ msgId, roomId }) => {
    if (!currentUser) return;
    const msg = db.prepare('SELECT * FROM messages WHERE id=? AND sender=?').get(msgId, currentUser);
    if (!msg) return;
    db.prepare('UPDATE messages SET is_deleted=1 WHERE id=?').run(msgId);
    io.emit('msg-deleted', { roomId, msgId });
  });

  socket.on('pin-message', ({ msgId, roomId }) => {
    if (!currentUser) return;
    db.prepare('UPDATE messages SET is_pinned=1 WHERE id=?').run(msgId);
    io.emit('msg-pinned', { roomId, msgId });
  });

  socket.on('react', ({ msgId, roomId, emoji }) => {
    if (!currentUser) return;
    const msg = db.prepare('SELECT reactions FROM messages WHERE id=?').get(msgId);
    if (!msg) return;
    const reactions = JSON.parse(msg.reactions || '{}');
    if (!reactions[emoji]) reactions[emoji] = [];
    const idx = reactions[emoji].indexOf(currentUser);
    if (idx === -1) reactions[emoji].push(currentUser);
    else reactions[emoji].splice(idx, 1);
    if (reactions[emoji].length === 0) delete reactions[emoji];
    db.prepare('UPDATE messages SET reactions=? WHERE id=?').run(JSON.stringify(reactions), msgId);
    io.emit('msg-reaction', { roomId, msgId, reactions });
  });

  socket.on('forward-message', ({ msgId, toRooms }) => {
    if (!currentUser) return;
    const orig = db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
    if (!orig) return;
    toRooms.forEach(roomId => {
      const newMsg = { ...orig, id: uuidv4(), room_id: roomId, sender: currentUser, timestamp: Date.now(), time: new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' }) };
      db.prepare('INSERT INTO messages (id,room_id,sender,text,file_url,file_type,reply_to_id,reply_to_text,reactions,is_edited,is_deleted,is_pinned,disappear_at,time,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(newMsg.id, newMsg.room_id, newMsg.sender, newMsg.text, newMsg.file_url, newMsg.file_type, null, null, '{}', 0, 0, 0, null, newMsg.time, newMsg.timestamp);
      io.emit('new-message', { roomId, msg: parseMsg(newMsg) });
    });
  });

  socket.on('typing', ({ to, isGroup, isTyping }) => {
    if (!currentUser) return;
    const roomId = isGroup ? `group__${to}` : getRoomId(currentUser, to);
    if (isGroup) {
      const group = db.prepare('SELECT members FROM groups WHERE id=?').get(to);
      if (group) JSON.parse(group.members).forEach(m => {
        if (m !== currentUser) {
          const s = Object.entries(onlineSockets).find(([, u]) => u === m);
          if (s) io.to(s[0]).emit('typing', { roomId, username: currentUser, isTyping });
        }
      });
    } else {
      const s = Object.entries(onlineSockets).find(([, u]) => u === to);
      if (s) io.to(s[0]).emit('typing', { roomId, username: currentUser, isTyping });
    }
  });

  socket.on('read', ({ roomId, msgId }) => {
    db.prepare('UPDATE messages SET is_deleted=is_deleted WHERE id=?').run(msgId);
    io.emit('read', { roomId, msgId });
  });

  socket.on('update-status', (status) => {
    if (currentUser) {
      db.prepare('UPDATE users SET status=? WHERE username=?').run(status, currentUser);
      const contacts = db.prepare('SELECT contact FROM contacts WHERE username=?').all(currentUser);
      contacts.forEach(({ contact }) => {
        const s = Object.entries(onlineSockets).find(([, u]) => u === contact);
        if (s) io.to(s[0]).emit('contact-status', { username: currentUser, status });
      });
    }
  });

  socket.on('disconnect', () => {
    if (currentUser) {
      delete onlineSockets[socket.id];
      db.prepare('UPDATE users SET last_seen=? WHERE username=?').run(new Date().toISOString(), currentUser);
      const contacts = db.prepare('SELECT contact FROM contacts WHERE username=?').all(currentUser);
      contacts.forEach(({ contact }) => {
        const s = Object.entries(onlineSockets).find(([, u]) => u === contact);
        if (s) io.to(s[0]).emit('contact-offline', currentUser);
      });
    }
  });
});

server.listen(config.PORT, () => {
  console.log(`✅ سرور روی پورت ${config.PORT}`);
  console.log(`🌐 http://localhost:${config.PORT}`);
  console.log(`🔐 پنل ادمین: http://localhost:${config.PORT}${config.ADMIN_PATH}`);
  startBalePolling();
});
