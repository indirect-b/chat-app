const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // در محیط تولید (Render) SSL لازم است
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// اتصال رو لاگ بگیر
pool.on('error', (err) => {
  console.error('❌ خطای غیرمنتظره PostgreSQL:', err.message);
});

// ===== ساخت جداول در صورت عدم وجود =====
async function init() {
  const client = await pool.connect();
  try {
    // جداول
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

    // ایندکس‌ها برای سرعت بالاتر
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, timestamp);
      CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
      CREATE INDEX IF NOT EXISTS idx_contacts_username ON contacts(username);
      CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
    `);

    // تنظیمات پیش‌فرض
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
  } finally {
    client.release();
  }
}

module.exports = { pool, init };
