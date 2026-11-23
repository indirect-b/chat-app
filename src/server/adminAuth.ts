/**
 * Admin authentication — short-lived session tokens + login lockout (round 5, H4).
 *
 * The admin password is verified ONCE at POST /api/admin/login (timing-safe
 * compare in src/server/config.ts). Success issues a random uuidv4 token
 * stored in-memory with a 30-minute absolute expiry; every other admin call
 * accepts ONLY that token in x-admin-token. The raw password no longer works
 * as a bearer token.
 *
 * Lockout: 5 failed attempts in 15 minutes locks the IP. The lockout
 * duration grows exponentially (15 min × 2^lockoutCount, capped at 2h) and
 * a successful login resets the record. Failed attempts are logged by the
 * route (IP + time, NEVER the password).
 */

import { v4 as uuidv4 } from 'uuid';

export const ADMIN_SESSION_TTL_MS = 30 * 60 * 1000;
export const ADMIN_LOGIN_MAX_FAILURES = 5;
export const ADMIN_LOGIN_WINDOW_MS = 15 * 60 * 1000;
export const ADMIN_LOCKOUT_BASE_MS = 15 * 60 * 1000;
export const ADMIN_LOCKOUT_MAX_MS = 2 * 60 * 60 * 1000;

/** In-memory admin sessions: token → absolute expiry (ms since epoch). */
export class AdminSessionManager {
  private readonly sessions = new Map<string, number>();

  issue(now = Date.now()): { token: string; expiresAt: number } {
    const token = uuidv4();
    const expiresAt = now + ADMIN_SESSION_TTL_MS;
    this.sessions.set(token, expiresAt);
    return { token, expiresAt };
  }

  verify(token: string | undefined | null, now = Date.now()): boolean {
    if (!token || typeof token !== 'string') return false;
    const expiresAt = this.sessions.get(token);
    if (!expiresAt) return false;
    if (now > expiresAt) {
      this.sessions.delete(token);
      return false;
    }
    return true;
  }

  /** Test/support helper: how many live sessions are held. */
  size(now = Date.now()): number {
    for (const [token, exp] of Array.from(this.sessions.entries())) {
      if (now > exp) this.sessions.delete(token);
    }
    return this.sessions.size;
  }
}

export const adminSessionManager = new AdminSessionManager();

export function issueAdminSession(now = Date.now()): { token: string; expiresAt: number } {
  return adminSessionManager.issue(now);
}

export function verifyAdminSession(
  token: string | undefined | null,
  now = Date.now()
): boolean {
  return adminSessionManager.verify(token, now);
}

/** Per-IP failed-login tracking with exponential lockout growth. */
export class AdminLoginLimiter {
  private readonly records = new Map<
    string,
    { failures: number[]; lockoutUntil: number; lockoutCount: number }
  >();

  constructor(
    private readonly maxFailures: number = ADMIN_LOGIN_MAX_FAILURES,
    private readonly windowMs: number = ADMIN_LOGIN_WINDOW_MS,
    private readonly baseLockoutMs: number = ADMIN_LOCKOUT_BASE_MS,
    private readonly maxLockoutMs: number = ADMIN_LOCKOUT_MAX_MS
  ) {}

  check(ip: string, now = Date.now()): { allowed: boolean; retryAfterSec: number } {
    const rec = this.records.get(ip);
    if (rec && now < rec.lockoutUntil) {
      return { allowed: false, retryAfterSec: Math.ceil((rec.lockoutUntil - now) / 1000) };
    }
    return { allowed: true, retryAfterSec: 0 };
  }

  isLocked(ip: string, now = Date.now()): boolean {
    return !this.check(ip, now).allowed;
  }

  recordFailure(ip: string, now = Date.now()): void {
    let rec = this.records.get(ip);
    if (!rec) {
      rec = { failures: [], lockoutUntil: 0, lockoutCount: 0 };
      this.records.set(ip, rec);
    }
    if (now < rec.lockoutUntil) return; // already locked — do not extend
    rec.failures = rec.failures.filter((t) => t > now - this.windowMs);
    rec.failures.push(now);
    if (rec.failures.length >= this.maxFailures) {
      const duration = Math.min(
        this.baseLockoutMs * 2 ** rec.lockoutCount,
        this.maxLockoutMs
      );
      rec.lockoutCount += 1;
      rec.lockoutUntil = now + duration;
      rec.failures = [];
    }
  }

  recordSuccess(ip: string): void {
    this.records.delete(ip);
  }
}

export const adminLoginLimiter = new AdminLoginLimiter();
