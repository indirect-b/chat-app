const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'chat.db'));

db.exec(`
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
    disappear_at TEXT,
    time TEXT,
    timestamp INTEGER
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

// Default settings
const defaultSettings = [
  ['server_mode', 'normal'],
  ['maintenance_msg', 'سرور در حال به‌روزرسانی است. لطفاً بعداً مراجعه کنید.'],
  ['rules', 'قوانین پیام‌رسان:\n\n۱. احترام به دیگران\n۲. عدم ارسال محتوای نامناسب\n۳. عدم اسپم'],
];

for (const [key, value] of defaultSettings) {
  db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run(key, value);
}

module.exports = db;
