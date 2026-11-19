/**
 * Google Sign-In — pure-function tests.
 *
 * No network, no credentials, no Google calls: the verified-marks
 * store (registration binding fix) and the Google ID-token verification
 * wrapper (with a fake verifier standing in for Google's OAuth2Client).
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  VerifiedMarks,
  VERIFIED_MARK_EXPIRE_MS,
} from '../src/server/verified';
import {
  getGoogleClientId,
  isGoogleConfigured,
  verifyGoogleIdToken,
} from '../src/server/google';

describe('VerifiedMarks (registration requires a live verified mark)', () => {
  it('consume fails when no mark was ever set (register must refuse)', () => {
    const marks = new VerifiedMarks();
    assert.equal(marks.consume('someuser'), false);
    assert.equal(marks.consume('user@example.com'), false);
  });

  it('consume succeeds once after a mark, then the mark is gone (single-use)', () => {
    const marks = new VerifiedMarks();
    marks.mark('someuser', 1_000_000);
    assert.equal(marks.consume('someuser', 1_000_000 + 1000), true);
    // Second consume fails: the mark was consumed by the first one.
    assert.equal(marks.consume('someuser', 1_000_000 + 2000), false);
  });

  it('an expired mark does not verify, even for the right identifier', () => {
    const marks = new VerifiedMarks();
    marks.mark('user@example.com', 1_000_000);
    assert.equal(
      marks.consume('user@example.com', 1_000_000 + VERIFIED_MARK_EXPIRE_MS + 1),
      false
    );
  });

  it('marks are per-identifier: one user’s mark does not verify another', () => {
    const marks = new VerifiedMarks();
    marks.mark('alice@example.com', 1_000_000);
    assert.equal(marks.consume('bob@example.com', 1_000_000 + 1000), false);
    assert.equal(marks.consume('alice@example.com', 1_000_000 + 1000), true);
  });

  it('re-marking refreshes the expiry window', () => {
    const marks = new VerifiedMarks();
    marks.mark('someuser', 1_000_000);
    marks.mark('someuser', 1_000_000 + VERIFIED_MARK_EXPIRE_MS - 1000);
    assert.equal(
      marks.consume('someuser', 1_000_000 + VERIFIED_MARK_EXPIRE_MS + 500),
      true
    );
  });
});

describe('getGoogleClientId / isGoogleConfigured', () => {
  const saved = process.env.GOOGLE_CLIENT_ID;

  afterEach(() => {
    if (saved === undefined) delete process.env.GOOGLE_CLIENT_ID;
    else process.env.GOOGLE_CLIENT_ID = saved;
  });

  it('returns the configured Client ID', () => {
    process.env.GOOGLE_CLIENT_ID = '1234567890-abc.apps.googleusercontent.com';
    assert.equal(
      getGoogleClientId(),
      '1234567890-abc.apps.googleusercontent.com'
    );
    assert.equal(isGoogleConfigured(), true);
  });

  it('returns null when unset (config endpoint must report null)', () => {
    delete process.env.GOOGLE_CLIENT_ID;
    assert.equal(getGoogleClientId(), null);
    assert.equal(isGoogleConfigured(), false);
  });

  it('treats a blank value as unset', () => {
    process.env.GOOGLE_CLIENT_ID = '   ';
    assert.equal(getGoogleClientId(), null);
    assert.equal(isGoogleConfigured(), false);
  });
});

describe('verifyGoogleIdToken (fake verifier — never calls Google)', () => {
  const saved = process.env.GOOGLE_CLIENT_ID;

  beforeEach(() => {
    process.env.GOOGLE_CLIENT_ID = 'test-client-id.apps.googleusercontent.com';
  });

  afterEach(() => {
    if (saved === undefined) delete process.env.GOOGLE_CLIENT_ID;
    else process.env.GOOGLE_CLIENT_ID = saved;
  });

  it('returns the normalized email for a verified token', async () => {
    const email = await verifyGoogleIdToken(
      'fake.valid.token',
      async () => ({ email: 'User@Example.com', emailVerified: true })
    );
    assert.equal(email, 'user@example.com');
  });

  it('rejects when the verifier throws (bad signature / expired token)', async () => {
    await assert.rejects(
      verifyGoogleIdToken('fake.bad.token', async () => {
        throw new Error('invalid signature');
      })
    );
  });

  it('rejects when the email is not verified by Google', async () => {
    await assert.rejects(
      verifyGoogleIdToken('fake.unverified.token', async () => ({
        email: 'user@example.com',
        emailVerified: false,
      }))
    );
  });

  it('rejects when the token carries no email', async () => {
    await assert.rejects(
      verifyGoogleIdToken('fake.noemail.token', async () => ({
        email: '',
        emailVerified: true,
      }))
    );
  });

  it('rejects an empty token without calling the verifier', async () => {
    let called = false;
    await assert.rejects(
      verifyGoogleIdToken('   ', async () => {
        called = true;
        return { email: 'user@example.com', emailVerified: true };
      })
    );
    assert.equal(called, false);
  });

  it('rejects when no Client ID is configured (env-gated)', async () => {
    delete process.env.GOOGLE_CLIENT_ID;
    await assert.rejects(
      verifyGoogleIdToken('fake.valid.token', async () => ({
        email: 'user@example.com',
        emailVerified: true,
      }))
    );
  });
});
