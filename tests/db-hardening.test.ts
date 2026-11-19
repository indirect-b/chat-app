/**
 * Database hardening — pure-function tests.
 *
 * No network, no database: SSL config, RLS SQL builders, and the ops SQL
 * file (supabase/hardening.sql). No secret appears in any assertion.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { Pool } from 'pg';
import {
  getPoolSslConfig,
  buildRlsEnableSql,
  buildAppPolicySql,
  APP_TABLES,
  init,
} from '../src/server/db';

const EXPECTED_TABLES = [
  'users',
  'contacts',
  'messages',
  'groups',
  'reports',
  'settings',
  'media_blobs',
];

const ROLE_PASSWORD_PLACEHOLDER = '__CHATAPP_ROLE_PASSWORD__';

describe('getPoolSslConfig', () => {
  it('verifies the DB certificate in production', () => {
    assert.deepEqual(getPoolSslConfig('production'), {
      rejectUnauthorized: true,
    });
  });

  it('disables SSL outside production', () => {
    assert.equal(getPoolSslConfig('development'), false);
    assert.equal(getPoolSslConfig('test'), false);
    assert.equal(getPoolSslConfig(undefined), false);
    assert.equal(getPoolSslConfig(''), false);
  });
});

describe('RLS SQL builders', () => {
  it('cover all 7 app tables', () => {
    assert.deepEqual([...APP_TABLES], EXPECTED_TABLES);
  });

  it('enable RLS on every table', () => {
    for (const t of APP_TABLES) {
      assert.equal(
        buildRlsEnableSql(t),
        `ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY`
      );
    }
  });

  it('policy SQL references only the chatapp role and the table', () => {
    for (const t of APP_TABLES) {
      const sql = buildAppPolicySql(t);
      assert.ok(sql.includes(`ON ${t} FOR ALL TO chatapp`), sql);
      assert.ok(sql.includes('USING (true) WITH CHECK (true)'), sql);
      // No other role may appear in the policy.
      assert.doesNotMatch(sql, /\bTO\s+(anon|authenticated|postgres|public)\b/);
      assert.doesNotMatch(sql, /\b(anon|authenticated)\b/);
    }
  });
});

describe('supabase/hardening.sql', () => {
  const sql = fs.readFileSync(
    path.join(process.cwd(), 'supabase', 'hardening.sql'),
    'utf-8'
  );

  it('contains the role-password placeholder, not a real password', () => {
    assert.ok(sql.includes(`'${ROLE_PASSWORD_PLACEHOLDER}'`));
    // Every PASSWORD '...' value in the file must be exactly the placeholder.
    const assigned = [...sql.matchAll(/PASSWORD\s+'([^']+)'/g)].map((m) => m[1]);
    assert.ok(assigned.length >= 1, 'expected at least one PASSWORD assignment');
    for (const value of assigned) {
      assert.equal(value, ROLE_PASSWORD_PLACEHOLDER);
    }
    // No connection string with embedded credentials.
    assert.doesNotMatch(sql, /postgres:\/\/[^:]+:[^@]+@/);
  });

  it('enables RLS on all 7 tables', () => {
    for (const t of EXPECTED_TABLES) {
      assert.ok(
        sql.includes(`ALTER TABLE public.${t} ENABLE ROW LEVEL SECURITY`),
        `missing RLS enable for ${t}`
      );
    }
  });

  it('creates one app_all policy per table, for the chatapp role only', () => {
    for (const t of EXPECTED_TABLES) {
      assert.ok(
        sql.includes(
          `CREATE POLICY app_all ON public.${t} FOR ALL TO chatapp USING (true) WITH CHECK (true)`
        ),
        `missing app_all policy for ${t}`
      );
    }
    assert.doesNotMatch(sql, /TO\s+(anon|authenticated|postgres)\b/);
  });

  it('grants only data access on the 7 tables, nothing else', () => {
    for (const t of EXPECTED_TABLES) {
      assert.ok(
        sql.includes(
          `GRANT SELECT, INSERT, UPDATE, DELETE ON public.${t} TO chatapp`
        ),
        `missing grant for ${t}`
      );
    }
    // No DDL grants, no global revokes, no other schemas.
    assert.doesNotMatch(sql, /\b(CREATE|ALTER|DROP|TRUNCATE|REFERENCES|TRIGGER)\b\s+ON\s+public\./);
    assert.doesNotMatch(sql, /\bREVOKE\b/i);
    assert.doesNotMatch(sql, /\bON\s+(auth|storage|realtime)\./);
  });
});

describe('init() DDL tolerance', () => {
  // Fake pool simulating the least-privilege chatapp role: DDL and
  // RLS-enable throw (not the table owner), everything else succeeds.
  function makeFakePool(log: string[], failOn: RegExp[]) {
    const client = {
      query: async (sql: string) => {
        log.push(sql);
        for (const re of failOn) {
          if (re.test(sql)) {
            throw new Error(`simulated failure for: ${sql.slice(0, 40)}`);
          }
        }
        return { rows: [] };
      },
      release: () => {},
    };
    return { connect: async () => client } as unknown as Pool;
  }

  it('does not fall back when DDL throws but the tables are readable', async () => {
    const log: string[] = [];
    const pool = makeFakePool(log, [/CREATE TABLE/, /ENABLE ROW LEVEL SECURITY/]);
    await init(pool);
    // Probe ran and defaults were inserted: startup stayed on Postgres.
    assert.ok(
      log.some((s) => s.includes('SELECT 1 FROM users LIMIT 1')),
      log.join('\n')
    );
    assert.ok(
      log.some((s) => s.includes('INSERT INTO settings')),
      log.join('\n')
    );
  });

  it('falls back when the tables are genuinely unreadable', async () => {
    const log: string[] = [];
    const pool = makeFakePool(log, [/CREATE TABLE/, /SELECT 1 FROM/]);
    await init(pool);
    // Probe failed, so the defaults insert never ran: init fell back.
    assert.ok(
      !log.some((s) => s.includes('INSERT INTO settings')),
      log.join('\n')
    );
  });
});
