/**
 * Email signup (alternative to Bale) — pure-function tests.
 *
 * No network, no credentials: validateEmail, OTP generation,
 * OTP expiry/attempt-limit logic, and the sliding-window rate limiter
 * (the same RecoveryRateLimiter class the /api/recover endpoint uses).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateEmail,
  generateEmailOtp,
  createEmailOtpRecord,
  verifyEmailOtpAttempt,
  EMAIL_OTP_EXPIRE_MS,
  EMAIL_OTP_MAX_ATTEMPTS,
} from '../src/server/email';
import { RecoveryRateLimiter } from '../src/server/recovery';

describe('validateEmail', () => {
  it('accepts normal addresses and normalizes case/whitespace', () => {
    assert.equal(validateEmail('User@Example.com'), 'user@example.com');
    assert.equal(
      validateEmail('  name.surname+tag@sub.domain.co  '),
      'name.surname+tag@sub.domain.co'
    );
    assert.equal(validateEmail('a@b.co'), 'a@b.co');
  });

  it('rejects malformed addresses', () => {
    const bad: unknown[] = [
      '',
      '   ',
      'plainaddress',
      '@no-local.com',
      'user@',
      'user@domain',
      'user@domain.',
      'user..dots@example.com',
      '.user@example.com',
      'user.@example.com',
      'user@exam ple.com',
      'user@example.c',
      'user@example.123',
      'user@@example.com',
      'üser@example.com',
      'user@-example.com',
      'user@example-.com',
      'user@.example.com',
      'user@example.com.',
      'a'.repeat(250) + '@example.com',
      null,
      undefined,
      42,
      {},
      ['a@b.co'],
    ];
    for (const input of bad) {
      assert.equal(validateEmail(input), null, JSON.stringify(input));
    }
  });
});

describe('generateEmailOtp', () => {
  it('always returns 6 ASCII digits', () => {
    for (let i = 0; i < 200; i++) {
      assert.match(generateEmailOtp(), /^\d{6}$/);
    }
  });

  it('is not constant across samples', () => {
    const codes = new Set(Array.from({ length: 50 }, () => generateEmailOtp()));
    assert.ok(codes.size > 1);
  });
});

describe('email OTP record expiry / attempt limits', () => {
  it('accepts the correct code within the window', () => {
    const rec = createEmailOtpRecord('123456', 1_000_000);
    assert.equal(rec.expire, 1_000_000 + EMAIL_OTP_EXPIRE_MS);
    assert.equal(rec.attempts, 0);
    assert.equal(verifyEmailOtpAttempt(rec, '123456', 1_000_000 + 1000), 'ok');
  });

  it('reports missing for an unknown record', () => {
    assert.equal(verifyEmailOtpAttempt(undefined, '123456', 1_000_000), 'missing');
  });

  it('rejects expired codes even when correct', () => {
    const rec = createEmailOtpRecord('123456', 1_000_000);
    assert.equal(
      verifyEmailOtpAttempt(rec, '123456', 1_000_000 + EMAIL_OTP_EXPIRE_MS + 1),
      'expired'
    );
  });

  it('counts wrong attempts and locks after the limit', () => {
    const rec = createEmailOtpRecord('123456', 1_000_000);
    for (let i = 1; i < EMAIL_OTP_MAX_ATTEMPTS; i++) {
      assert.equal(verifyEmailOtpAttempt(rec, '000000', 1_000_000), 'wrong');
      assert.equal(rec.attempts, i);
    }
    assert.equal(verifyEmailOtpAttempt(rec, '000000', 1_000_000), 'locked');
    assert.equal(rec.attempts, EMAIL_OTP_MAX_ATTEMPTS);
    // A locked record stays locked even with the correct code (fail-closed).
    assert.equal(verifyEmailOtpAttempt(rec, '123456', 1_000_000), 'locked');
  });

  it('does not consume attempts on a correct code', () => {
    const rec = createEmailOtpRecord('123456', 1_000_000);
    assert.equal(verifyEmailOtpAttempt(rec, '000000', 1_000_000), 'wrong');
    assert.equal(verifyEmailOtpAttempt(rec, '123456', 1_000_000), 'ok');
    assert.equal(rec.attempts, 1);
  });
});

describe('RecoveryRateLimiter (email OTP requests: 5/hour)', () => {
  it('allows 5 requests per hour per email, then blocks', () => {
    const limiter = new RecoveryRateLimiter(5, 60 * 60 * 1000);
    for (let i = 0; i < 5; i++) {
      const r = limiter.checkAndConsume('1.2.3.4', 'email:a@example.com', 1_000_000 + i * 1000);
      assert.equal(r.allowed, true);
    }
    const blocked = limiter.checkAndConsume('1.2.3.4', 'email:a@example.com', 1_000_000 + 6000);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSec > 0);
  });

  it('treats different emails independently (fresh IP)', () => {
    const limiter = new RecoveryRateLimiter(5, 60 * 60 * 1000);
    for (let i = 0; i < 5; i++) {
      assert.equal(
        limiter.checkAndConsume('1.1.1.1', 'email:a@example.com', 1000 + i).allowed,
        true
      );
    }
    assert.equal(limiter.checkAndConsume('2.2.2.2', 'email:b@example.com', 2000).allowed, true);
    assert.equal(limiter.checkAndConsume('2.2.2.2', 'email:a@example.com', 2000).allowed, false);
  });

  it('allows again after the window passes', () => {
    const limiter = new RecoveryRateLimiter(5, 60 * 60 * 1000);
    for (let i = 0; i < 5; i++) {
      limiter.checkAndConsume('1.2.3.4', 'email:a@example.com', 1000);
    }
    assert.equal(
      limiter.checkAndConsume('1.2.3.4', 'email:a@example.com', 1000 + 60 * 60 * 1000 + 1)
        .allowed,
      true
    );
  });
});
