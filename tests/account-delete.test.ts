/**
 * Account deletion confirmation (Google-only login).
 *
 * No network, no DB: canDeleteWithCode decides whether a deletion
 * request may proceed. Deletion is confirmed with the one-time
 * recovery code, verified against the stored scrypt hash. Accounts
 * created before recovery codes existed have no hash (NULL) — for
 * them the already-verified session is the only proof available, so
 * deletion proceeds on the session alone.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canDeleteWithCode,
  generateRecoveryCode,
  hashRecoveryCode,
} from '../src/server/recovery';

describe('canDeleteWithCode', () => {
  it('accepts the correct recovery code for an account that has a hash', async () => {
    const code = generateRecoveryCode();
    const hash = await hashRecoveryCode(code);
    assert.equal(await canDeleteWithCode(hash, code), true);
  });

  it('rejects a wrong code for an account that has a hash', async () => {
    const hash = await hashRecoveryCode(generateRecoveryCode());
    assert.equal(await canDeleteWithCode(hash, generateRecoveryCode()), false);
  });

  it('rejects a malformed code for an account that has a hash', async () => {
    const hash = await hashRecoveryCode(generateRecoveryCode());
    assert.equal(await canDeleteWithCode(hash, 'not-a-code'), false);
    assert.equal(await canDeleteWithCode(hash, ''), false);
  });

  it('allows deletion on the session alone for legacy accounts with no hash (NULL/undefined)', async () => {
    assert.equal(await canDeleteWithCode(null, ''), true);
    assert.equal(await canDeleteWithCode(undefined, 'anything'), true);
  });
});
