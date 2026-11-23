/**
 * Generic in-memory sliding-window rate limiter (round 5, M7).
 *
 * One class for every limiter in the server: the key is whatever the caller
 * chooses (IP, or IP+user / username), so the same code backs the global
 * /api/ limiter, the per-route tight buckets, and the per-user write
 * limiters. `checkAndConsume` records the attempt when allowed and reports
 * the retry delay when the bucket is full.
 */

import type { NextFunction, Request, Response } from 'express';

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSec: number;
  remaining: number;
}

export class SlidingWindowLimiter {
  private readonly buckets = new Map<string, number[]>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number
  ) {}

  checkAndConsume(key: string, now = Date.now()): RateLimitResult {
    const list = (this.buckets.get(key) || []).filter((t) => t > now - this.windowMs);
    if (list.length >= this.max) {
      const retryAfterSec = Math.max(1, Math.ceil((list[0] + this.windowMs - now) / 1000));
      return { allowed: false, retryAfterSec, remaining: 0 };
    }
    list.push(now);
    this.buckets.set(key, list);
    return { allowed: true, retryAfterSec: 0, remaining: this.max - list.length };
  }

  /** Test/support helper: drop all buckets. */
  reset(): void {
    this.buckets.clear();
  }
}

export function getClientIp(req: Request): string {
  return (req.ip || (req.socket && req.socket.remoteAddress) || 'unknown').toString();
}

/**
 * Express middleware factory. `keyFn` may be async (e.g. it may resolve
 * the session username). When the bucket is full the request is rejected
 * with 429 + Retry-After; the handler never runs. A keyFn failure fails
 * open to the client IP (the session lookup itself fails closed elsewhere).
 */
export function rateLimitMiddleware(
  limiter: SlidingWindowLimiter,
  keyFn: (req: Request) => string | Promise<string>
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction): void => {
    void (async () => {
      let key: string;
      try {
        key = await keyFn(req);
      } catch {
        key = getClientIp(req);
      }
      const result = limiter.checkAndConsume(key);
      if (!result.allowed) {
        res.setHeader('Retry-After', String(result.retryAfterSec));
        res.status(429).json({ ok: false, msg: 'Too many requests' });
        return;
      }
      next();
    })();
  };
}
