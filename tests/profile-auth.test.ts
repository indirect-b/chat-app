/**
 * Profile auth — POST /api/user/update, POST /api/add-contact and
 * GET /api/contacts/:username.
 *
 * No live DB, no network. The decision logic lives in src/server/roomAccess.ts
 * as the pure function checkOwnUsername (the session username must equal the
 * target username), so the tests run it directly; the route wiring itself is
 * verified against server.ts source (the server binds a port on import, so it
 * is never started in tests). Same pattern as tests/room-auth.test.ts.
 *
 * All three endpoints are tested at the HELPER level (checkOwnUsername is
 * shared by all three, so one set of cases covers each route) plus
 * route-wiring source assertions per endpoint. No route is exercised over
 * HTTP — the server is never started in this suite.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { checkOwnUsername, checkOwnGroupsAccess } from '../src/server/roomAccess';

describe('checkOwnUsername — shared by all three profile endpoints', () => {
  it('(a) no valid session → unauthenticated (each route maps it to 403)', () => {
    assert.equal(checkOwnUsername(null, 'alice'), 'unauthenticated');
    assert.equal(checkOwnUsername('', 'alice'), 'unauthenticated');
  });

  it('(b) token of a different user → forbidden', () => {
    assert.equal(checkOwnUsername('bob', 'alice'), 'forbidden');
    assert.equal(checkOwnUsername('alice', 'bob'), 'forbidden');
  });

  it('(c) token of the owner → ok', () => {
    assert.equal(checkOwnUsername('alice', 'alice'), 'ok');
    assert.equal(checkOwnUsername('bob', 'bob'), 'ok');
  });

  it('empty / missing target fails closed — never an open update', () => {
    assert.equal(checkOwnUsername('alice', ''), 'forbidden');
  });
});

describe('checkOwnGroupsAccess still delegates to the same rule', () => {
  it('unchanged behaviour after the refactor (room-auth cases)', () => {
    assert.equal(checkOwnGroupsAccess(null, 'alice'), 'unauthenticated');
    assert.equal(checkOwnGroupsAccess('bob', 'alice'), 'forbidden');
    assert.equal(checkOwnGroupsAccess('alice', 'alice'), 'ok');
  });
});

describe('route wiring (server.ts source — server never started in tests)', () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server.ts'), 'utf-8');
  const userUpdateHandler = serverSrc.slice(
    serverSrc.indexOf("app.post('/api/user/update'"),
    serverSrc.indexOf("app.post('/api/add-contact'")
  );
  const addContactHandler = serverSrc.slice(
    serverSrc.indexOf("app.post('/api/add-contact'"),
    serverSrc.indexOf("app.get('/api/contacts/:username'")
  );
  const contactsHandler = serverSrc.slice(
    serverSrc.indexOf("app.get('/api/contacts/:username'"),
    serverSrc.indexOf('// ===== ROOM MESSAGES')
  );

  it("POST /api/user/update gates on the body's username and denies non-ok with 403", () => {
    assert.ok(userUpdateHandler.includes('checkOwnUsername(getSessionUsername(req)'));
    assert.ok(userUpdateHandler.includes("res.status(403)"));
    // The UPDATE must come after the gate.
    const gateAt = userUpdateHandler.indexOf("if (access !== 'ok')");
    const updateAt = userUpdateHandler.indexOf('UPDATE users SET bio');
    assert.ok(gateAt !== -1 && updateAt !== -1 && gateAt < updateAt);
  });

  it("POST /api/add-contact gates on the body's myUsername and denies non-ok with 403", () => {
    assert.ok(addContactHandler.includes('checkOwnUsername(getSessionUsername(req)'));
    assert.ok(addContactHandler.includes("res.status(403)"));
    // The INSERT must come after the gate.
    const gateAt = addContactHandler.indexOf("if (access !== 'ok')");
    const insertAt = addContactHandler.indexOf('INSERT INTO contacts');
    assert.ok(gateAt !== -1 && insertAt !== -1 && gateAt < insertAt);
  });

  it('GET /api/contacts/:username gates on the URL username and denies non-ok with 403', () => {
    assert.ok(contactsHandler.includes('checkOwnUsername(getSessionUsername(req)'));
    assert.ok(contactsHandler.includes("res.status(403)"));
    // The SELECT must come after the gate.
    const gateAt = contactsHandler.indexOf("if (access !== 'ok')");
    const selectAt = contactsHandler.indexOf('SELECT c.contact, u.display_name, u.avatar');
    assert.ok(gateAt !== -1 && selectAt !== -1 && gateAt < selectAt);
  });
});

describe('client sends the session token (ChatApp.tsx source)', () => {
  const chatSrc = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'components', 'ChatApp.tsx'),
    'utf-8'
  );

  it('the contacts-list fetch carries a Bearer header', () => {
    const at = chatSrc.indexOf("fetch('/api/contacts/' + encodeURIComponent(myUsername)");
    assert.ok(at !== -1);
    const window = chatSrc.slice(Math.max(0, at - 200), at);
    assert.ok(window.includes('getSessionToken()'));
    assert.ok(chatSrc.slice(at, at + 300).includes('Authorization: `Bearer ${sessionToken}`'));
  });

  it('the add-contact fetch carries a Bearer header', () => {
    const at = chatSrc.indexOf("fetch('/api/add-contact'");
    assert.ok(at !== -1);
    const window = chatSrc.slice(Math.max(0, at - 200), at);
    assert.ok(window.includes('getSessionToken()'));
    assert.ok(chatSrc.slice(at, at + 400).includes('Authorization: `Bearer ${sessionToken}`'));
  });

  it('the profile-update fetch carries a Bearer header', () => {
    const at = chatSrc.indexOf("fetch('/api/user/update'");
    assert.ok(at !== -1);
    const window = chatSrc.slice(Math.max(0, at - 200), at);
    assert.ok(window.includes('getSessionToken()'));
    assert.ok(chatSrc.slice(at, at + 400).includes('Authorization: `Bearer ${sessionToken}`'));
  });

  it('no remaining call to the three endpoints lacks a token', () => {
    const sites = [
      ...chatSrc.matchAll(/fetch\('\/api\/(contacts\/|add-contact|user\/update)'/g),
    ];
    assert.equal(sites.length, 3);
  });
});
