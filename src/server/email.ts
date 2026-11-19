import crypto from 'crypto';
import nodemailer, { Transporter, SentMessageInfo } from 'nodemailer';

/**
 * Email auth (alternative to Bale) — Gmail SMTP via nodemailer.
 *
 * Env-gated: EMAIL_USER + EMAIL_APP_PASSWORD must be set, otherwise the
 * email endpoints refuse with a "not enabled" message and the Bale flow
 * is completely untouched. EMAIL_FROM defaults to EMAIL_USER.
 *
 * No real credentials exist yet (Render env vars to be set on deploy).
 */

// OTP codes are valid for 10 minutes; 5 wrong attempts locks (invalidates) a code.
export const EMAIL_OTP_EXPIRE_MS = 10 * 60 * 1000;
export const EMAIL_OTP_MAX_ATTEMPTS = 5;
// OTP request rate limit: 5 requests per hour (per email + per IP).
export const EMAIL_OTP_MAX_REQUESTS_PER_HOUR = 5;
export const EMAIL_OTP_REQUEST_WINDOW_MS = 60 * 60 * 1000;

/**
 * Strict email validation. Returns the normalized (trimmed, lowercased)
 * address, or null when the input is not a plausible deliverable address.
 */
export function validateEmail(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const email = input.trim().toLowerCase();
  if (email.length < 3 || email.length > 254) return null;
  const at = email.indexOf('@');
  if (at <= 0 || at !== email.lastIndexOf('@')) return null;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (!local || !domain) return null;
  if (local.length > 64 || domain.length > 253) return null;
  if (!/^[a-z0-9._%+-]+$/.test(local)) return null;
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return null;
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return null;
  if (domain.startsWith('-') || domain.endsWith('-')) return null;
  const labels = domain.split('.');
  if (labels.length < 2) return null;
  if (labels.some(l => l.length === 0 || l.startsWith('-') || l.endsWith('-'))) return null;
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld)) return null;
  return email;
}

/** 6-digit OTP from a CSPRNG (crypto.randomInt, not Math.random). */
export function generateEmailOtp(): string {
  return crypto.randomInt(100000, 1000000).toString();
}

export function isEmailConfigured(): boolean {
  return Boolean(process.env.EMAIL_USER && process.env.EMAIL_APP_PASSWORD);
}

export function createTransporter(): Transporter {
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER as string,
      pass: process.env.EMAIL_APP_PASSWORD as string,
    },
  });
}

/**
 * Sends a short Persian OTP email. The transporter can be injected (used by
 * the Ethereal smoke test); otherwise a Gmail transporter is created from env.
 */
export async function sendEmailOtp(
  email: string,
  code: string,
  transporter?: Transporter
): Promise<SentMessageInfo> {
  const t = transporter ?? createTransporter();
  const from = process.env.EMAIL_FROM || process.env.EMAIL_USER || '';
  return t.sendMail({
    from,
    to: email,
    subject: 'کد تأیید ورود به پیام‌رسان',
    text:
      `سلام!\n\n` +
      `کد تأیید شما برای ورود به پیام‌رسان:\n\n${code}\n\n` +
      `این کد ۱۰ دقیقه معتبر است. اگر شما این کد را درخواست نکرده‌اید، این ایمیل را نادیده بگیرید.`,
  });
}

export interface EmailOtpRecord {
  code: string;
  expire: number;
  attempts: number;
}

export function createEmailOtpRecord(code: string, now = Date.now()): EmailOtpRecord {
  return { code, expire: now + EMAIL_OTP_EXPIRE_MS, attempts: 0 };
}

export type EmailOtpOutcome = 'ok' | 'missing' | 'expired' | 'wrong' | 'locked';

/**
 * Pure OTP verification helper (also used by the server endpoint, so the
 * tests exercise the real logic). Mutates `attempts` on wrong codes.
 * Fail-closed: a locked or expired record never verifies, even with the
 * correct code — the server deletes such records after this returns.
 */
export function verifyEmailOtpAttempt(
  record: EmailOtpRecord | undefined,
  candidate: string,
  now = Date.now()
): EmailOtpOutcome {
  if (!record) return 'missing';
  if (now > record.expire) return 'expired';
  if (record.attempts >= EMAIL_OTP_MAX_ATTEMPTS) return 'locked';
  if (record.code !== candidate) {
    record.attempts += 1;
    return record.attempts >= EMAIL_OTP_MAX_ATTEMPTS ? 'locked' : 'wrong';
  }
  return 'ok';
}
