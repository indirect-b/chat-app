/**
 * Room-content auth — GET /api/messages/:roomId and /api/groups/:username.
 *
 * No live DB, no network. The decision logic lives in src/server/roomAccess.ts
 * as pure functions taking a `query` function, so the tests run them against
 * a fake in-memory store holding the exact SQL strings the module sends
 * (via isRoomMember). The route wiring itself is verified against server.ts
 * source (the server binds a port on import, so it is never started in tests).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  checkRoomReadAccess,
  checkOwnGroupsAccess,
  type DbQuery,
} from '../src/server/roomAccess';

const USERS = ['alice', 'bob', 'carol'];
const GROUPS = [{ id: 'g1', members: JSON.stringify(['alice', 'bob']) }];

/** Fake query: answers exactly the SQL isRoomMember sends. */
const fakeQuery: DbQuery = async (sql: string, params?: any[]) => {
  if (sql.includes('FROM groups WHERE id')) {
    const g = GROUPS.find(x => x.id === params?.[0]);
    return { rows: g ? [{ members: g.members }] : [] };
  }
  if (sql.includes('FROM users')) {
    return { rows: USERS.map(u => ({ username: u })) };
  }
  throw new Error(`unexpected SQL in fake query: ${sql}`);
};

describe('checkRoomReadAccess — /api/messages/:roomId', () => {
  it('(a) no valid session → unauthenticated (route maps it to 403)', async () => {
    assert.equal(await checkRoomReadAccess(null, 'alice__bob', fakeQuery), 'unauthenticated');
    assert.equal(await checkRoomReadAccess('', 'alice__bob', fakeQuery), 'unauthenticated');
  });

  it('(b) token of a non-member → forbidden', async () => {
    assert.equal(await checkRoomReadAccess('carol', 'alice__bob', fakeQuery), 'forbidden');
    assert.equal(await checkRoomReadAccess('carol', 'group__g1', fakeQuery), 'forbidden');
  });

  it('(c) token of a member → ok (DM, either member; group)', async () => {
    assert.equal(await checkRoomReadAccess('alice', 'alice__bob', fakeQuery), 'ok');
    // DM room ids are always the sorted join (getRoomId), so 'alice__bob'
    // is the canonical id for both members.
    assert.equal(await checkRoomReadAccess('bob', 'alice__bob', fakeQuery), 'ok');
    assert.equal(await checkRoomReadAccess('alice', 'group__g1', fakeQuery), 'ok');
    assert.equal(await checkRoomReadAccess('bob', 'group__g1', fakeQuery), 'ok');
  });

  it('unknown room fails closed with the same status — no existence leak', async () => {
    assert.equal(await checkRoomReadAccess('alice', 'group__nope', fakeQuery), 'forbidden');
    assert.equal(await checkRoomReadAccess('alice', 'alice__mallory', fakeQuery), 'forbidden');
    assert.equal(await checkRoomReadAccess('alice', '', fakeQuery), 'forbidden');
  });
});

describe('checkOwnGroupsAccess — /api/groups/:username', () => {
  it('(d) no valid session → unauthenticated (route maps it to 403)', () => {
    assert.equal(checkOwnGroupsAccess(null, 'alice'), 'unauthenticated');
  });

  it('(e) token username != URL username → forbidden', () => {
    assert.equal(checkOwnGroupsAccess('bob', 'alice'), 'forbidden');
    assert.equal(checkOwnGroupsAccess('alice', 'bob'), 'forbidden');
  });

  it('(f) matching username → ok', () => {
    assert.equal(checkOwnGroupsAccess('alice', 'alice'), 'ok');
    assert.equal(checkOwnGroupsAccess('bob', 'bob'), 'ok');
  });
});

describe('route wiring (server.ts source — server never started in tests)', () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server.ts'), 'utf-8');
  const messagesHandler = serverSrc.slice(
    serverSrc.indexOf("app.get('/api/messages/:roomId'"),
    serverSrc.indexOf("app.get('/api/groups/:username'")
  );
  const groupsHandler = serverSrc.slice(
    serverSrc.indexOf("app.get('/api/groups/:username'"),
    serverSrc.indexOf('// ===== REPORT =====')
  );

  it('/api/messages/:roomId calls checkRoomReadAccess and denies non-ok with 403', () => {
    assert.ok(messagesHandler.includes('checkRoomReadAccess(getSessionUsername(req), roomId'));
    assert.ok(messagesHandler.includes("res.status(403)"));
    assert.ok(!messagesHandler.includes("res.status(401)"));
  });

  it('/api/groups/:username calls checkOwnGroupsAccess and denies non-ok with 403', () => {
    assert.ok(groupsHandler.includes('checkOwnGroupsAccess(getSessionUsername(req)'));
    assert.ok(groupsHandler.includes("res.status(403)"));
  });

  it('no route serves room content without the check (no bare SELECT before the gate)', () => {
    // The SELECT must come after the access gate inside the messages handler.
    const gateAt = messagesHandler.indexOf("if (access !== 'ok')");
    const selectAt = messagesHandler.indexOf('SELECT * FROM messages');
    assert.ok(gateAt !== -1 && selectAt !== -1 && gateAt < selectAt);
  });
});

describe('client sends the session token (ChatApp.tsx source)', () => {
  const chatSrc = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'components', 'ChatApp.tsx'),
    'utf-8'
  );

  it('all three room-content fetches carry a Bearer header', () => {
    const groupsFetches = chatSrc.split(
      "fetch('/api/groups/' + encodeURIComponent(myUsername), {"
    ).length - 1;
    const messagesFetches = chatSrc.split(
      "fetch('/api/messages/' + encodeURIComponent(roomId), {"
    ).length - 1;
    assert.equal(groupsFetches, 1);
    assert.equal(messagesFetches, 2);
    // Each of the three fetches is preceded (within a few lines) by getSessionToken().
    const sites = [...chatSrc.matchAll(/getSessionToken\(\)\s*;\s*\n\s*const res = await fetch\('\/api\/(groups|messages)\//g)];
    assert.equal(sites.length, 3);
  });
});
