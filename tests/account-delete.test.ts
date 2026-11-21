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
import { pool } from '../src/server/db';
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

describe('sessions table persistence (DP-11)', () => {
  it('persists and deletes sessions in database', async () => {
    const token = 'test-token-' + Date.now();
    const username = 'test-user-' + Date.now();
    const expire = new Date(Date.now() + 3600 * 1000).toISOString();

    await pool.query('INSERT INTO sessions (token, username, expires_at) VALUES ($1, $2, $3)', [
      token,
      username,
      expire,
    ]);

    const { rows } = await pool.query('SELECT * FROM sessions WHERE token = $1', [token]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].token, token);
    assert.equal(rows[0].username, username);

    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    const afterDelete = await pool.query('SELECT * FROM sessions WHERE token = $1', [token]);
    assert.equal(afterDelete.rows.length, 0);
  });
});
