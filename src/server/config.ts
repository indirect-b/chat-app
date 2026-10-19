import crypto from 'crypto';

export interface ServerConfig {
  BALE_BOT_TOKEN: string;
  PORT: number;
  ADMIN_PASSWORD: string;
  ADMIN_PATH: string;
  OTP_EXPIRE: number;
  BALE_API: string;
  MAX_FILE_SIZE: number;
  REDIS_URL: string;
  STORAGE_MODE: 'hybrid' | 'disk' | 'cloud';
  INLINE_MAX_BYTES: number;
}

const rawToken = process.env.BALE_BOT_TOKEN || '';

// در صورت عدم تنظیم ADMIN_PASSWORD در محیط عملیاتی، یک کلید تصادفی امن تولید می‌شود
const generatedFallbackAdminKey = crypto.randomBytes(16).toString('hex');
const adminPassword = process.env.ADMIN_PASSWORD || generatedFallbackAdminKey;

if (!process.env.ADMIN_PASSWORD) {
  console.warn(
    `⚠️ [Security] ADMIN_PASSWORD در متغیرهای محیطی تنظیم نشده است. رمز موقت تصادفی تولید شد.`
  );
}

export const config: ServerConfig = {
  BALE_BOT_TOKEN: rawToken && rawToken !== 'your_bale_bot_token_here' ? rawToken : '',
  PORT: process.env.DEFAULT_APP_PORT
    ? parseInt(process.env.DEFAULT_APP_PORT, 10)
    : parseInt(process.env.PORT || '3000', 10) || 3000,
  ADMIN_PASSWORD: adminPassword,
  ADMIN_PATH: process.env.ADMIN_PATH || '/admin-console',
  OTP_EXPIRE: parseInt(process.env.OTP_EXPIRE || '120', 10) || 120,
  BALE_API: process.env.BALE_API || 'https://tapi.bale.ai/bot',
  MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE || String(50 * 1024 * 1024), 10),
  REDIS_URL: process.env.REDIS_URL || '',
  STORAGE_MODE: (process.env.STORAGE_MODE as 'hybrid' | 'disk' | 'cloud') || 'hybrid',
  INLINE_MAX_BYTES: 2 * 1024 * 1024, // فایل‌های زیر ۲ مگابایت (ویس، آواتار، تصاویر) به صورت پایدار ذخیره می‌شوند
};

export function verifyAdminSecret(candidate: string | undefined): boolean {
  if (!candidate || typeof candidate !== 'string') return false;
  const a = Buffer.from(candidate, 'utf-8');
  const b = Buffer.from(config.ADMIN_PASSWORD, 'utf-8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
