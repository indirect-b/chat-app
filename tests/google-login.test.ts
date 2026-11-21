/**
 * Google Sign-In — pure-function tests.
 *
 * No network, no credentials, no Google calls: the email validation
 * helper (moved here from the deleted email module — Google Sign-In
 * uses it to normalize the verified address) and the Google ID-token
 * verification wrapper (with a fake verifier standing in for Google's
 * OAuth2Client).
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  getGoogleClientId,
  getGoogleRedirectUri,
  isGoogleConfigured,
  validateEmail,
  verifyGoogleIdToken,
} from '../src/server/google';

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

  it('DP-8: reads GOOGLE_REDIRECT_URI from environment variable with fallback', () => {
    assert.equal(getGoogleRedirectUri({}), 'https://chatapp-server-1i2a.onrender.com/api/google-redirect');
    assert.equal(getGoogleRedirectUri({ GOOGLE_REDIRECT_URI: 'https://custom.example.com/oauth/callback' }), 'https://custom.example.com/oauth/callback');
    assert.equal(getGoogleRedirectUri({ GOOGLE_REDIRECT_URI: '   ' }), 'https://chatapp-server-1i2a.onrender.com/api/google-redirect');
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
    const verified = await verifyGoogleIdToken(
      'fake.valid.token',
      async () => ({ email: 'User@Example.com', emailVerified: true })
    );
    assert.equal(verified.email, 'user@example.com');
    assert.equal(verified.profile.name, null);
    assert.equal(verified.profile.picture, null);
  });

  it('returns the Google display name and photo from the token', async () => {
    const verified = await verifyGoogleIdToken(
      'fake.valid.token',
      async () => ({
        email: 'user@example.com',
        emailVerified: true,
        name: '  Mohammad Taha  ',
        picture: 'https://lh3.googleusercontent.com/a-/photo123',
      })
    );
    assert.equal(verified.email, 'user@example.com');
    assert.equal(verified.profile.name, 'Mohammad Taha');
    assert.equal(verified.profile.picture, 'https://lh3.googleusercontent.com/a-/photo123');
  });

  it('tolerates a token without name or picture', async () => {
    const verified = await verifyGoogleIdToken(
      'fake.valid.token',
      async () => ({ email: 'user@example.com', emailVerified: true })
    );
    assert.equal(verified.profile.name, null);
    assert.equal(verified.profile.picture, null);
  });

  it('drops a profile photo from any host other than the Google photo host', async () => {
    const verified = await verifyGoogleIdToken(
      'fake.valid.token',
      async () => ({
        email: 'user@example.com',
        emailVerified: true,
        name: 'User',
        picture: 'https://evil.example.com/photo.jpg',
      })
    );
    assert.equal(verified.profile.name, 'User');
    assert.equal(verified.profile.picture, null);
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
