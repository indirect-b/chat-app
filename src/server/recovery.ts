import crypto from 'crypto';

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;
const SALT_BYTES = 16;

/**
 * Generates a high-entropy (128-bit) one-time recovery code formatted as
 * 8 groups of 4 uppercase hexadecimal characters: XXXX-XXXX-...-XXXX.
 */
export function generateRecoveryCode(): string {
  const rawHex = crypto.randomBytes(16).toString('hex').toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < rawHex.length; i += 4) {
    groups.push(rawHex.slice(i, i + 4));
  }
  return groups.join('-');
}

export function normalizeRecoveryCode(input: string): string | null {
  if (typeof input !== 'string') return null;
  const cleaned = input.replace(/[\s-]+/g, '').trim().toUpperCase();
  if (!/^[0-9A-F]{32}$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

function scryptAsync(
  password: string,
  salt: Buffer,
  keylen: number,
  options: crypto.ScryptOptions
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/**
 * Hashes a one-time recovery code using memory-hard scrypt (N=16384, r=8, p=1)
 * with a random 128-bit salt. Only this hash is stored server-side.
 */
export async function hashRecoveryCode(rawCode: string): Promise<string> {
  const normalized = normalizeRecoveryCode(rawCode);
  if (!normalized) {
    throw new Error('Invalid recovery code format');
  }
  const salt = crypto.randomBytes(SALT_BYTES);
  const derived = await scryptAsync(normalized, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

/**
 * Constant-time verification of a candidate recovery code against a stored scrypt hash.
 */
export async function verifyRecoveryCode(
  candidateCode: string,
  storedHash: string | null | undefined
): Promise<boolean> {
  if (!storedHash || typeof storedHash !== 'string') return false;
  const normalized = normalizeRecoveryCode(candidateCode);
  if (!normalized) return false;

  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = parseInt(parts[1], 10);
  const r = parseInt(parts[2], 10);
  const p = parseInt(parts[3], 10);
  const saltHex = parts[4];
  const expectedHex = parts[5];

  if (
    !Number.isFinite(N) ||
    !Number.isFinite(r) ||
    !Number.isFinite(p) ||
    N < 1024 ||
    !/^[0-9a-f]+$/i.test(saltHex) ||
    !/^[0-9a-f]+$/i.test(expectedHex)
  ) {
    return false;
  }

  try {
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(expectedHex, 'hex');
    const derived = await scryptAsync(normalized, salt, expected.length, { N, r, p });
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

/**
 * Account-deletion confirmation (Google-only login).
 *
 * Deletion used to be confirmed with a 6-digit OTP sent through the Bale
 * bot; that channel is gone, so the one-time recovery code is the
 * confirmation instead. Returns true only when the candidate matches
 * the stored scrypt hash. Accounts created before recovery codes
 * existed have no hash (NULL) — for them the already-verified session
 * is the only proof available, so deletion proceeds on the session
 * alone. This is a deliberate legacy fallback, not a bypass for
 * code-holding accounts: a hash, once set, must always verify.
 */
export async function canDeleteWithCode(
  storedHash: string | null | undefined,
  candidateCode: string
): Promise<boolean> {
  if (!storedHash) return true;
  return verifyRecoveryCode(candidateCode, storedHash);
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSec: number;
  remaining: number;
}

/**
 * Strict sliding-window rate limiter enforcing limits per IP AND per username
 * for the /api/recover endpoint.
 */
export class RecoveryRateLimiter {
  private readonly maxAttempts: number;
  private readonly windowMs: number;
  private readonly buckets = new Map<string, number[]>();

  constructor(maxAttempts = 5, windowMs = 15 * 60 * 1000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  private prune(key: string, now: number): number[] {
    const list = this.buckets.get(key) || [];
    const cutoff = now - this.windowMs;
    const recent = list.filter(ts => ts > cutoff);
    if (recent.length > 0) {
      this.buckets.set(key, recent);
    } else {
      this.buckets.delete(key);
    }
    return recent;
  }

  public checkAndConsume(ip: string, username: string, now = Date.now()): RateLimitResult {
    const ipKey = `ip:${ip || 'unknown'}`;
    const userKey = `user:${(username || 'unknown').toLowerCase()}`;

    const ipRecent = this.prune(ipKey, now);
    const userRecent = this.prune(userKey, now);

    if (ipRecent.length >= this.maxAttempts || userRecent.length >= this.maxAttempts) {
      const oldestIp = ipRecent[0] ?? now;
      const oldestUser = userRecent[0] ?? now;
      const blockingOldest =
        ipRecent.length >= this.maxAttempts && userRecent.length >= this.maxAttempts
          ? Math.max(oldestIp, oldestUser)
          : ipRecent.length >= this.maxAttempts
          ? oldestIp
          : oldestUser;
      const retryAfterMs = Math.max(1000, blockingOldest + this.windowMs - now);
      return {
        allowed: false,
        retryAfterSec: Math.ceil(retryAfterMs / 1000),
        remaining: 0,
      };
    }

    ipRecent.push(now);
    userRecent.push(now);
    this.buckets.set(ipKey, ipRecent);
    this.buckets.set(userKey, userRecent);

    const remaining = Math.max(
      0,
      this.maxAttempts - Math.max(ipRecent.length, userRecent.length)
    );
    return { allowed: true, retryAfterSec: 0, remaining };
  }

  public reset(): void {
    this.buckets.clear();
  }
}
