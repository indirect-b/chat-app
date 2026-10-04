const { Pool } = require('pg');

class MemoryDatabase {
  constructor() {
    this.users = new Map();
    this.contacts = [];
    this.messages = [];
    this.groups = new Map();
    this.reports = [];
    this.settings = new Map([
      ['server_mode', 'normal'],
      ['maintenance_msg', 'سرور در حال به‌روزرسانی است. لطفاً بعداً مراجعه کنید.'],
      ['rules', 'قوانین پیام‌رسان:\n\n۱. احترام به دیگران\n۲. عدم ارسال محتوای نامناسب\n۳. عدم اسپم']
    ]);
  }

  async query(sql, params = []) {
    const s = sql.trim().replace(/\s+/g, ' ');
    const lower = s.toLowerCase();

    // 1. SETTINGS
    if (lower.startsWith('select value from settings where key = $1')) {
      const val = this.settings.get(params[0]) ?? null;
      return { rows: val !== null ? [{ value: val }] : [] };
    }
    if (lower.startsWith('insert into settings (key, value)')) {
      this.settings.set(params[0], params[1]);
      return { rows: [] };
    }

    // 2. USERS
    if (lower.includes('from users where username = $1') || lower.includes('from users where username=$1')) {
      const u = this.users.get(params[0]);
      if (!u) return { rows: [] };
      return { rows: [{ ...u }] };
    }
    if (lower.startsWith('select * from users order by joined_at desc')) {
      const list = Array.from(this.users.values()).sort((a, b) => (b.joined_at || '').localeCompare(a.joined_at || ''));
      return { rows: list };
    }
    if (lower.startsWith('insert into users (username, bale_chat_id, joined_at)')) {
      const [username, bale_chat_id, joined_at] = params;
      const user = {
        username,
        bale_chat_id,
        avatar: null,
        bio: '',
        status: 'online',
        joined_at,
        is_blocked: 0,
        block_reason: null,
        block_type: null,
        block_until: null,
        last_seen: new Date().toISOString()
      };
      this.users.set(username, user);
      return { rows: [] };
    }
    if (lower.includes('update users set bio=$1, status=$2, avatar=$3 where username=$4')) {
      const [bio, status, avatar, username] = params;
      const u = this.users.get(username);
      if (u) {
        u.bio = bio;
        u.status = status;
        u.avatar = avatar;
      }
      return { rows: [] };
    }
    if (lower.includes('update users set is_blocked=0')) {
      const username = params[0];
      const u = this.users.get(username);
      if (u) {
        u.is_blocked = 0;
        u.block_reason = null;
        u.block_type = null;
        u.block_until = null;
      }
      return { rows: [] };
    }
    if (lower.includes('update users set is_blocked=1')) {
      const [reason, blockType, blockUntil, username] = params;
      const u = this.users.get(username);
      if (u) {
        u.is_blocked = 1;
        u.block_reason = reason;
        u.block_type = blockType;
        u.block_until = blockUntil;
      }
      return { rows: [] };
    }
    if (lower.includes('update users set last_seen=$1 where username=$2')) {
      const [last_seen, username] = params;
      const u = this.users.get(username);
      if (u) u.last_seen = last_seen;
      return { rows: [] };
    }
    if (lower.includes('update users set status=$1 where username=$2')) {
      const [status, username] = params;
      const u = this.users.get(username);
      if (u) u.status = status;
      return { rows: [] };
    }
    if (lower.includes('select bale_chat_id from users where bale_chat_id is not null')) {
      const list = Array.from(this.users.values()).filter(u => u.bale_chat_id).map(u => ({ bale_chat_id: u.bale_chat_id }));
      return { rows: list };
    }

    // 3. CONTACTS
    if (lower.startsWith('insert into contacts')) {
      const [username, contact] = params;
      const exists = this.contacts.some(c => c.username === username && c.contact === contact);
      if (!exists) this.contacts.push({ username, contact });
      return { rows: [] };
    }
    if (lower.includes('from contacts c join users u on c.contact = u.username where c.username = $1')) {
      const username = params[0];
      const res = [];
      for (const c of this.contacts) {
        if (c.username === username) {
          const u = this.users.get(c.contact) || { avatar: null, status: 'offline' };
          res.push({ contact: c.contact, avatar: u.avatar, status: u.status });
        }
      }
      return { rows: res };
    }
    if (lower.includes('select contact from contacts where username=$1')) {
      const username = params[0];
      const list = this.contacts.filter(c => c.username === username).map(c => ({ contact: c.contact }));
      return { rows: list };
    }
    if (lower.includes('select 1 from contacts where username=$1 and contact=$2')) {
      const [username, contact] = params;
      const found = this.contacts.some(c => c.username === username && c.contact === contact);
      return { rows: found ? [{ '?column?': 1 }] : [] };
    }

    // 4. MESSAGES
    if (lower.startsWith('insert into messages')) {
      const [id, room_id, sender, text, file_url, file_type, reply_to_id, reply_to_text, reactions, is_edited, is_deleted, is_pinned, is_read, disappear_at, time, timestamp] = params;
      this.messages.push({
        id, room_id, sender, text, file_url, file_type, reply_to_id, reply_to_text,
        reactions: reactions || '{}',
        is_edited: Number(is_edited) || 0,
        is_deleted: Number(is_deleted) || 0,
        is_pinned: Number(is_pinned) || 0,
        is_read: Number(is_read) || 0,
        disappear_at: disappear_at || null,
        time,
        timestamp: Number(timestamp)
      });
      return { rows: [] };
    }
    if (lower.includes('from messages where room_id = $1 and is_deleted = 0 order by timestamp asc')) {
      const roomId = params[0];
      const list = this.messages.filter(m => m.room_id === roomId && !m.is_deleted).sort((a, b) => a.timestamp - b.timestamp);
      return { rows: list.map(m => ({ ...m })) };
    }
    if (lower.includes('from messages where id=$1 and sender=$2')) {
      const [id, sender] = params;
      const m = this.messages.find(msg => msg.id === id && msg.sender === sender);
      return { rows: m ? [{ ...m }] : [] };
    }
    if (lower.includes('select reactions from messages where id=$1')) {
      const id = params[0];
      const m = this.messages.find(msg => msg.id === id);
      return { rows: m ? [{ reactions: m.reactions }] : [] };
    }
    if (lower.includes('update messages set text=$1, is_edited=1 where id=$2')) {
      const [newText, id] = params;
      const m = this.messages.find(msg => msg.id === id);
      if (m) { m.text = newText; m.is_edited = 1; }
      return { rows: [] };
    }
    if (lower.includes('update messages set is_deleted=1 where id=$1')) {
      const id = params[0];
      const m = this.messages.find(msg => msg.id === id);
      if (m) m.is_deleted = 1;
      return { rows: [] };
    }
    if (lower.includes('update messages set is_pinned=0 where room_id=$1')) {
      const roomId = params[0];
      this.messages.forEach(m => { if (m.room_id === roomId) m.is_pinned = 0; });
      return { rows: [] };
    }
    if (lower.includes('update messages set is_pinned=1 where id=$1')) {
      const id = params[0];
      const m = this.messages.find(msg => msg.id === id);
      if (m) m.is_pinned = 1;
      return { rows: [] };
    }
    if (lower.includes('update messages set reactions=$1 where id=$2')) {
      const [reactions, id] = params;
      const m = this.messages.find(msg => msg.id === id);
      if (m) m.reactions = reactions;
      return { rows: [] };
    }
    if (lower.includes('update messages set is_read=1 where id=$1')) {
      const id = params[0];
      const m = this.messages.find(msg => msg.id === id);
      if (m) m.is_read = 1;
      return { rows: [] };
    }
    if (lower.startsWith('select * from messages where is_deleted=0 order by timestamp desc limit 500')) {
      const list = this.messages.filter(m => !m.is_deleted).sort((a, b) => b.timestamp - a.timestamp).slice(0, 500);
      return { rows: list.map(m => ({ ...m })) };
    }

    // 5. GROUPS
    if (lower.startsWith('select * from groups where id = $1')) {
      const g = this.groups.get(params[0]);
      return { rows: g ? [{ ...g }] : [] };
    }
    if (lower.includes('select members from groups where id=$1')) {
      const g = this.groups.get(params[0]);
      return { rows: g ? [{ members: g.members }] : [] };
    }
    if (lower.startsWith('select * from groups')) {
      return { rows: Array.from(this.groups.values()).map(g => ({ ...g })) };
    }
    if (lower.startsWith('insert into groups')) {
      const [id, name, members, created_at] = params;
      this.groups.set(id, { id, name, members, created_at });
      return { rows: [] };
    }
    if (lower.includes('update groups set members = $1 where id = $2')) {
      const [members, id] = params;
      const g = this.groups.get(id);
      if (g) g.members = members;
      return { rows: [] };
    }

    // 6. REPORTS
    if (lower.startsWith('insert into reports')) {
      const [id, reporter, reported_user, message_id, message_text, reason, created_at] = params;
      this.reports.push({ id, reporter, reported_user, message_id, message_text, reason, created_at, status: 'pending' });
      return { rows: [] };
    }
    if (lower.startsWith('select * from reports order by created_at desc')) {
      return { rows: [...this.reports].reverse() };
    }
    if (lower.includes('update reports set status = $1 where id = $2')) {
      const [status, id] = params;
      const r = this.reports.find(rep => rep.id === id);
      if (r) r.status = status;
      return { rows: [] };
    }

    // 7. STATS
    if (lower.includes('select count(*) as c from users')) {
      return { rows: [{ c: this.users.size }] };
    }
    if (lower.includes('select count(*) as c from messages where is_deleted=0')) {
      return { rows: [{ c: this.messages.filter(m => !m.is_deleted).length }] };
    }
    if (lower.includes('select count(*) as c from groups')) {
      return { rows: [{ c: this.groups.size }] };
    }
    if (lower.includes("select count(*) as c from reports where status='pending'")) {
      return { rows: [{ c: this.reports.filter(r => r.status === 'pending').length }] };
    }
    if (lower.includes('select count(*) as c from messages where to_char(')) {
      const dateStr = params[0];
      const count = this.messages.filter(m => {
        const d = new Date(m.timestamp).toISOString().split('T')[0];
        return d === dateStr;
      }).length;
      return { rows: [{ c: count }] };
    }

    return { rows: [] };
  }
}

let pool = null;
let isMock = !process.env.DATABASE_URL;
const memoryDb = new MemoryDatabase();

if (process.env.DATABASE_URL) {
  try {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });
    pool.on('error', (err) => {
      console.error('❌ خطای غیرمنتظره PostgreSQL:', err.message);
    });
  } catch (e) {
    console.warn('⚠️ [AI Studio] اتصال به PostgreSQL ناموفق بود - استفاده از دیتابیس درون‌حافظه‌ای');
    isMock = true;
  }
}

const dbWrapper = {
  query: async (text, params) => {
    if (!isMock && pool) {
      try {
        return await pool.query(text, params);
      } catch (err) {
        console.warn('⚠️ خطای کوئری PostgreSQL، انتقال به حافظه موقت:', err.message);
        isMock = true;
        return await memoryDb.query(text, params);
      }
    }
    return await memoryDb.query(text, params);
  },
  connect: async () => {
    if (!isMock && pool) {
      try {
        return await pool.connect();
      } catch (err) {
        isMock = true;
      }
    }
    return {
      query: (t, p) => dbWrapper.query(t, p),
      release: () => {}
    };
  }
};

// ===== ساخت جداول در صورت عدم وجود =====
async function init() {
  if (!isMock && pool) {
    try {
      const client = await pool.connect();
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            bale_chat_id TEXT,
            avatar TEXT,
            bio TEXT DEFAULT '',
            status TEXT DEFAULT 'online',
            joined_at TEXT,
            is_blocked INTEGER DEFAULT 0,
            block_reason TEXT,
            block_type TEXT,
            block_until TEXT,
            last_seen TEXT
          );

          CREATE TABLE IF NOT EXISTS contacts (
            username TEXT,
            contact TEXT,
            PRIMARY KEY (username, contact)
          );

          CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            room_id TEXT,
            sender TEXT,
            text TEXT,
            file_url TEXT,
            file_type TEXT,
            reply_to_id TEXT,
            reply_to_text TEXT,
            reactions TEXT DEFAULT '{}',
            is_edited INTEGER DEFAULT 0,
            is_deleted INTEGER DEFAULT 0,
            is_pinned INTEGER DEFAULT 0,
            is_read INTEGER DEFAULT 0,
            disappear_at TEXT,
            time TEXT,
            timestamp BIGINT
          );

          CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT,
            members TEXT,
            created_at TEXT
          );

          CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            reporter TEXT,
            reported_user TEXT,
            message_id TEXT,
            message_text TEXT,
            reason TEXT,
            created_at TEXT,
            status TEXT DEFAULT 'pending'
          );

          CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
          );
        `);

        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, timestamp);
          CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp DESC);
          CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
          CREATE INDEX IF NOT EXISTS idx_contacts_username ON contacts(username);
          CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
        `);

        const defaults = [
          ['server_mode', 'normal'],
          ['maintenance_msg', 'سرور در حال به‌روزرسانی است. لطفاً بعداً مراجعه کنید.'],
          ['rules', 'قوانین پیام‌رسان:\n\n۱. احترام به دیگران\n۲. عدم ارسال محتوای نامناسب\n۳. عدم اسپم'],
        ];
        for (const [key, value] of defaults) {
          await client.query(
            'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING',
            [key, value]
          );
        }

        console.log('✅ دیتابیس PostgreSQL آماده است');
        return;
      } finally {
        client.release();
      }
    } catch (e) {
      console.warn('⚠️ [AI Studio] اتصال به PostgreSQL ممکن نشد، استفاده از دیتابیس درون‌حافظه‌ای:', e.message);
      isMock = true;
    }
  }
  console.log('✅ دیتابیس درون‌حافظه‌ای آماده است');
}

module.exports = { pool: dbWrapper, init };
