/**
 * Fix round 5 — SERVER half.
 *
 * Pure-helper tests (no live DB, no network, server.ts is never imported —
 * it binds a port on import) plus source assertions for the route wiring,
 * following the tests/room-auth.test.ts pattern.
 *
 * Helpers under test:
 * - src/server/uploadPolicy.ts (H1): extension allowlist + magic sniffing,
 *   PQF1 pass-through, server-verified mime.
 * - src/server/adminAuth.ts (H4): admin session tokens + login lockout.
 * - src/server/rateLimit.ts (M7): sliding-window limiter.
 * - src/server/roomAccess.ts canActOnMessage (H2).
 * - src/server/roomEmit.ts emitToRoom (M5).
 * - src/server/profileSync.ts avatar allowlist (L7a).
 * - src/server/messageParse.ts parseMsg / safeParseMembers (L7e).
 * - src/server/media.ts deleteMediaIfUnreferenced (H1d).
 * - src/server/db.ts fallback handlers added for the new SQL shapes.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  validateUploadFile,
  verifyStoredMime,
  sniffMime,
  isPqf1,
  ALLOWED_UPLOAD_EXTENSIONS,
} from '../src/server/uploadPolicy';
import {
  AdminSessionManager,
  AdminLoginLimiter,
  ADMIN_SESSION_TTL_MS,
} from '../src/server/adminAuth';
import { SlidingWindowLimiter } from '../src/server/rateLimit';
import { canActOnMessage, type DbQuery } from '../src/server/roomAccess';
import { emitToRoom, resolveRoomMembers } from '../src/server/roomEmit';
import { presence } from '../src/server/presence';
import { resolveProfileUpdate, isAllowedAvatarUrl } from '../src/server/profileSync';
import { parseMsg, safeParseMembers, safeParseReactions } from '../src/server/messageParse';
import { deleteMediaIfUnreferenced, extractMediaId } from '../src/server/media';
import { PersistentFallbackDatabase } from '../src/server/db';

// ---------------------------------------------------------------------------
// Shared fake store
// ---------------------------------------------------------------------------

const USERS = ['alice', 'bob', 'carol', 'a__b', 'c'];
const GROUPS = [{ id: 'g1', members: JSON.stringify(['alice', 'bob']) }];

interface FakeMsg {
  id: string;
  room_id: string;
  sender: string;
  file_url: string | null;
  is_deleted: number;
  reactions: string;
}

function makeFakeQuery(messages: FakeMsg[]): DbQuery {
  return async (sql: string, params?: any[]) => {
    if (sql.includes('SELECT * FROM messages WHERE id=$1')) {
      const m = messages.find((x) => x.id === params?.[0]);
      return { rows: m ? [{ ...m }] : [] };
    }
    if (sql.includes('SELECT members FROM groups WHERE id=$1')) {
      const g = GROUPS.find((x) => x.id === params?.[0]);
      return { rows: g ? [{ members: g.members }] : [] };
    }
    if (sql.includes('SELECT username FROM users')) {
      return { rows: USERS.map((u) => ({ username: u })) };
    }
    if (sql.includes('FROM messages WHERE file_url = $1 AND is_deleted = 0')) {
      return {
        rows: messages
          .filter((m) => m.file_url === params?.[0] && !m.is_deleted)
          .map((m) => ({ ...m })),
      };
    }
    if (sql.includes('DELETE FROM media_blobs WHERE id = $1')) {
      return { rows: [] };
    }
    throw new Error(`unexpected SQL in fake query: ${sql}`);
  };
}

const PNG_HEAD = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG_HEAD = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
const GIF_HEAD = Buffer.from('GIF89a', 'latin1');
const HTML_HEAD = Buffer.from('<!DOCTYPE html><html>', 'latin1');
const TEXT_HEAD = Buffer.from('#!/bin/sh\necho pwned\n', 'latin1');
const PQF1_HEAD = Buffer.concat([Buffer.from('PQF1', 'latin1'), Buffer.from([0x01, 0x02, 0x03])]);

// ---------------------------------------------------------------------------
// H1 — uploadPolicy
// ---------------------------------------------------------------------------

describe('H1 uploadPolicy — magic bytes + allowlist', () => {
  it('accepts a real PNG/JPEG/GIF whose magic matches its extension', () => {
    const png = validateUploadFile('.png', PNG_HEAD, 'image/png');
    assert.equal(png.ok, true);
    assert.equal(png.verifiedMime, 'image/png');
    assert.equal(png.isEncrypted, false);
    const jpg = validateUploadFile('.jpg', JPEG_HEAD, 'image/jpeg');
    assert.equal(jpg.ok, true);
    assert.equal(jpg.verifiedMime, 'image/jpeg');
    const gif = validateUploadFile('.gif', GIF_HEAD, 'image/gif');
    assert.equal(gif.ok, true);
    assert.equal(gif.verifiedMime, 'image/gif');
  });

  it('rejects HTML / script content regardless of extension (stored XSS)', () => {
    assert.equal(validateUploadFile('.html', HTML_HEAD, 'text/html').ok, false);
    assert.equal(validateUploadFile('.png', HTML_HEAD, 'text/html').ok, false);
    assert.equal(validateUploadFile('.svg', HTML_HEAD, 'image/svg+xml').ok, false);
    assert.equal(validateUploadFile('.txt', TEXT_HEAD, 'text/plain').ok, false);
    // A PNG extension on HTML bytes must not pass (extension alone is not proof).
    assert.equal(validateUploadFile('.jpg', HTML_HEAD, 'image/jpeg').ok, false);
  });

  it('rejects an extension outside the allowlist even with matching magic', () => {
    assert.equal(validateUploadFile('.exe', PNG_HEAD, 'application/octet-stream').ok, false);
    assert.equal(validateUploadFile('.pdf', PNG_HEAD, 'application/pdf').ok, false);
    assert.equal(validateUploadFile('', PNG_HEAD).ok, false);
  });

  it('rejects a magic/extension mismatch (JPEG bytes named .png)', () => {
    assert.equal(validateUploadFile('.png', JPEG_HEAD, 'image/png').ok, false);
    assert.equal(validateUploadFile('.mp3', PNG_HEAD, 'audio/mpeg').ok, false);
  });

  it('PQF1 client-encrypted media passes regardless of inner type', () => {
    const r = validateUploadFile('.png', PQF1_HEAD, 'image/png');
    assert.equal(r.ok, true);
    assert.equal(r.isEncrypted, true);
    // Claimed mime is kept only when it is itself in the allowlist.
    assert.equal(r.verifiedMime, 'image/png');
    const badClaim = validateUploadFile('.mp4', PQF1_HEAD, 'text/html');
    assert.equal(badClaim.ok, true);
    assert.equal(badClaim.isEncrypted, true);
    assert.equal(badClaim.verifiedMime, 'application/octet-stream');
    const noClaim = validateUploadFile('.bin', PQF1_HEAD);
    // .bin is not an allowed extension, so even PQF1 is rejected there.
    assert.equal(noClaim.ok, false);
    const pqf1AllowedExt = validateUploadFile('.jpg', PQF1_HEAD);
    assert.equal(pqf1AllowedExt.ok, true);
    assert.equal(pqf1AllowedExt.verifiedMime, 'application/octet-stream');
  });

  it('sniffMime / isPqf1 spot the magics directly', () => {
    assert.equal(sniffMime(PNG_HEAD), 'image/png');
    assert.equal(sniffMime(JPEG_HEAD), 'image/jpeg');
    assert.equal(sniffMime(GIF_HEAD), 'image/gif');
    assert.equal(sniffMime(HTML_HEAD), null);
    assert.equal(isPqf1(PQF1_HEAD), true);
    assert.equal(isPqf1(PNG_HEAD), false);
  });

  it('verifyStoredMime never serves a stored client claim outside the allowlist', () => {
    assert.equal(verifyStoredMime('text/html'), 'application/octet-stream');
    assert.equal(verifyStoredMime('image/svg+xml'), 'application/octet-stream');
    assert.equal(verifyStoredMime(null), 'application/octet-stream');
    assert.equal(verifyStoredMime(undefined), 'application/octet-stream');
    assert.equal(verifyStoredMime('image/png'), 'image/png');
    assert.equal(verifyStoredMime('video/mp4'), 'video/mp4');
  });

  it('the allowlist mirrors the pre-existing fileType mapping', () => {
    for (const ext of ['.jpg', '.jpeg', '.png', '.gif', '.webp']) {
      assert.ok(ALLOWED_UPLOAD_EXTENSIONS.has(ext), ext);
    }
    for (const ext of ['.mp3', '.ogg', '.wav', '.webm', '.m4a']) {
      assert.ok(ALLOWED_UPLOAD_EXTENSIONS.has(ext), ext);
    }
    for (const ext of ['.mp4', '.mov', '.avi']) {
      assert.ok(ALLOWED_UPLOAD_EXTENSIONS.has(ext), ext);
    }
    assert.ok(!ALLOWED_UPLOAD_EXTENSIONS.has('.html'));
    assert.ok(!ALLOWED_UPLOAD_EXTENSIONS.has('.svg'));
  });
});

// ---------------------------------------------------------------------------
// H1(d) — deleteMediaIfUnreferenced
// ---------------------------------------------------------------------------

describe('H1(d) deleteMediaIfUnreferenced', () => {
  it('deletes the blob + disk file when nothing references it', async () => {
    const deleted: string[] = [];
    const unlinked: string[] = [];
    const query = makeFakeQuery([]);
    const fakeQuery: DbQuery = async (sql, params) => {
      if (sql.includes('DELETE FROM media_blobs')) {
        deleted.push(params?.[0]);
        return { rows: [] };
      }
      return query(sql, params);
    };
    const r = await deleteMediaIfUnreferenced('m1', fakeQuery, async (id) => {
      unlinked.push(id);
    });
    assert.deepEqual(r, { deleted: true, referenced: false });
    assert.deepEqual(deleted, ['m1']);
    assert.deepEqual(unlinked, ['m1']);
  });

  it('keeps the blob when a non-deleted message (either URL form) references it', async () => {
    const query = makeFakeQuery([
      { id: 'x', room_id: 'alice__bob', sender: 'alice', file_url: '/uploads/m2', is_deleted: 0, reactions: '{}' },
    ]);
    let deletes = 0;
    const fakeQuery: DbQuery = async (sql, params) => {
      if (sql.includes('DELETE FROM media_blobs')) {
        deletes += 1;
        return { rows: [] };
      }
      return query(sql, params);
    };
    const r = await deleteMediaIfUnreferenced('m2', fakeQuery, async () => {});
    assert.deepEqual(r, { deleted: false, referenced: true });
    assert.equal(deletes, 0);
  });

  it('deletes when the only referencing message is itself deleted', async () => {
    const query = makeFakeQuery([
      { id: 'x', room_id: 'alice__bob', sender: 'alice', file_url: '/api/media/m3', is_deleted: 1, reactions: '{}' },
    ]);
    let deletes = 0;
    const fakeQuery: DbQuery = async (sql, params) => {
      if (sql.includes('DELETE FROM media_blobs')) {
        deletes += 1;
        return { rows: [] };
      }
      return query(sql, params);
    };
    const r = await deleteMediaIfUnreferenced('m3', fakeQuery, async () => {});
    assert.deepEqual(r, { deleted: true, referenced: false });
    assert.equal(deletes, 1);
  });

  it('extractMediaId parses both URL forms and rejects anything else', () => {
    assert.equal(extractMediaId('/api/media/abc.png'), 'abc.png');
    assert.equal(extractMediaId('/uploads/abc.png'), 'abc.png');
    assert.equal(extractMediaId(null), null);
    assert.equal(extractMediaId('/api/media/'), null);
    assert.equal(extractMediaId('https://evil.example.com/x.png'), null);
  });
});

// ---------------------------------------------------------------------------
// H4 — adminAuth
// ---------------------------------------------------------------------------

describe('H4 adminAuth — session tokens', () => {
  it('issued tokens verify; unknown tokens and the password do not', () => {
    const mgr = new AdminSessionManager();
    const { token, expiresAt } = mgr.issue(1_000_000);
    assert.equal(expiresAt - 1_000_000, ADMIN_SESSION_TTL_MS);
    assert.equal(mgr.verify(token, 1_000_000), true);
    assert.equal(mgr.verify('not-a-token', 1_000_000), false);
    assert.equal(mgr.verify('', 1_000_000), false);
    assert.equal(mgr.verify(undefined, 1_000_000), false);
  });

  it('tokens expire after 30 minutes (absolute expiry)', () => {
    const mgr = new AdminSessionManager();
    const { token } = mgr.issue(1_000_000);
    assert.equal(mgr.verify(token, 1_000_000 + ADMIN_SESSION_TTL_MS), true);
    assert.equal(mgr.verify(token, 1_000_000 + ADMIN_SESSION_TTL_MS + 1), false);
    // Expired tokens are purged, not left valid.
    assert.equal(mgr.size(1_000_000 + ADMIN_SESSION_TTL_MS + 1), 0);
  });
});

describe('H4 adminAuth — login lockout', () => {
  it('allows fewer than 5 failures, then locks the IP for 15 minutes', () => {
    const limiter = new AdminLoginLimiter();
    const t0 = 10_000_000;
    for (let i = 0; i < 4; i++) {
      assert.equal(limiter.check('1.2.3.4', t0 + i * 1000).allowed, true);
      limiter.recordFailure('1.2.3.4', t0 + i * 1000);
    }
    assert.equal(limiter.check('1.2.3.4', t0 + 4000).allowed, true);
    limiter.recordFailure('1.2.3.4', t0 + 4000);
    const locked = limiter.check('1.2.3.4', t0 + 5000);
    assert.equal(locked.allowed, false);
    assert.ok(locked.retryAfterSec > 0 && locked.retryAfterSec <= 15 * 60);
    // Still locked just before expiry, free right after.
    assert.equal(limiter.check('1.2.3.4', t0 + 4000 + 15 * 60 * 1000 - 1000).allowed, false);
    assert.equal(limiter.check('1.2.3.4', t0 + 4000 + 15 * 60 * 1000 + 1000).allowed, true);
    // Other IPs are unaffected.
    assert.equal(limiter.check('5.6.7.8', t0 + 5000).allowed, true);
  });

  it('lockout duration grows exponentially and caps at 2 hours', () => {
    const limiter = new AdminLoginLimiter();
    const t0 = 20_000_000;
    let now = t0;
    const durations: number[] = [];
    for (let round = 0; round < 4; round++) {
      for (let i = 0; i < 5; i++) {
        limiter.recordFailure('9.9.9.9', now);
        now += 1000;
      }
      // Check at the moment of the 5th failure (now - 1s): the full
      // lockout duration must remain.
      const check = limiter.check('9.9.9.9', now - 1000);
      assert.equal(check.allowed, false);
      durations.push(check.retryAfterSec);
      now += check.retryAfterSec * 1000 + 1000; // wait out the lockout
    }
    // 15min, 30min, 60min, then capped at 2h.
    assert.deepEqual(durations, [15 * 60, 30 * 60, 60 * 60, 2 * 60 * 60]);
  });

  it('a successful login resets the failure record', () => {
    const limiter = new AdminLoginLimiter();
    const t0 = 30_000_000;
    for (let i = 0; i < 4; i++) limiter.recordFailure('2.2.2.2', t0 + i * 1000);
    limiter.recordSuccess('2.2.2.2');
    // Four fresh failures after the reset must not lock (needs 5).
    for (let i = 0; i < 4; i++) {
      assert.equal(limiter.check('2.2.2.2', t0 + 10_000 + i * 1000).allowed, true);
      limiter.recordFailure('2.2.2.2', t0 + 10_000 + i * 1000);
    }
    assert.equal(limiter.check('2.2.2.2', t0 + 20_000).allowed, true);
  });
});

// ---------------------------------------------------------------------------
// M7 — rateLimit
// ---------------------------------------------------------------------------

describe('M7 SlidingWindowLimiter', () => {
  it('allows up to max, then rejects with a retry delay, then recovers', () => {
    const limiter = new SlidingWindowLimiter(3, 60_000);
    const t0 = 40_000_000;
    assert.equal(limiter.checkAndConsume('ip', t0).allowed, true);
    assert.equal(limiter.checkAndConsume('ip', t0 + 1000).allowed, true);
    const third = limiter.checkAndConsume('ip', t0 + 2000);
    assert.equal(third.allowed, true);
    assert.equal(third.remaining, 0);
    const fourth = limiter.checkAndConsume('ip', t0 + 3000);
    assert.equal(fourth.allowed, false);
    assert.ok(fourth.retryAfterSec > 0 && fourth.retryAfterSec <= 60);
    // After the window slides past the oldest entry, one slot frees up.
    assert.equal(limiter.checkAndConsume('ip', t0 + 60_001).allowed, true);
  });

  it('buckets are independent per key', () => {
    const limiter = new SlidingWindowLimiter(1, 60_000);
    assert.equal(limiter.checkAndConsume('alice', 50_000_000).allowed, true);
    assert.equal(limiter.checkAndConsume('alice', 50_000_001).allowed, false);
    assert.equal(limiter.checkAndConsume('bob', 50_000_001).allowed, true);
  });
});

// ---------------------------------------------------------------------------
// H2 — canActOnMessage
// ---------------------------------------------------------------------------

describe('H2 canActOnMessage', () => {
  const messages: FakeMsg[] = [
    { id: 'm1', room_id: 'alice__bob', sender: 'alice', file_url: null, is_deleted: 0, reactions: '{}' },
    { id: 'm2', room_id: 'group__g1', sender: 'bob', file_url: null, is_deleted: 0, reactions: '{}' },
  ];

  it('allows a room member acting on a message of that room', async () => {
    const q = makeFakeQuery(messages);
    assert.equal(await canActOnMessage('alice', 'm1', 'alice__bob', q), true);
    assert.equal(await canActOnMessage('bob', 'm1', 'alice__bob', q), true);
    assert.equal(await canActOnMessage('alice', 'm2', 'group__g1', q), true);
  });

  it('denies a non-member even when the message exists', async () => {
    const q = makeFakeQuery(messages);
    assert.equal(await canActOnMessage('carol', 'm1', 'alice__bob', q), false);
    assert.equal(await canActOnMessage('carol', 'm2', 'group__g1', q), false);
  });

  it('denies when the message belongs to a different room (wrong-room pin/react/read)', async () => {
    const q = makeFakeQuery(messages);
    assert.equal(await canActOnMessage('alice', 'm1', 'group__g1', q), false);
    assert.equal(await canActOnMessage('bob', 'm2', 'alice__bob', q), false);
  });

  it('denies unknown messages and missing users', async () => {
    const q = makeFakeQuery(messages);
    assert.equal(await canActOnMessage('alice', 'nope', 'alice__bob', q), false);
    assert.equal(await canActOnMessage(null, 'm1', 'alice__bob', q), false);
    assert.equal(await canActOnMessage('alice', '', 'alice__bob', q), false);
  });
});

// ---------------------------------------------------------------------------
// M5 — emitToRoom
// ---------------------------------------------------------------------------

describe('M5 emitToRoom — room members only', () => {
  function fakeIo(captured: any[]) {
    return {
      to: (sockId: string) => ({
        emit: (event: string, payload: any) => captured.push({ sockId, event, payload }),
      }),
    } as any;
  }

  it('resolves DM members by splitting on __', async () => {
    const q = makeFakeQuery([]);
    assert.deepEqual((await resolveRoomMembers('alice__bob', q)).sort(), ['alice', 'bob']);
  });

  it('resolves group members from the groups row', async () => {
    const q = makeFakeQuery([]);
    assert.deepEqual((await resolveRoomMembers('group__g1', q)).sort(), ['alice', 'bob']);
  });

  it('falls back to a user scan when a username contains __', async () => {
    const q = makeFakeQuery([]);
    // getRoomId('a__b','c') === 'a__b__c' — the naive split yields 3 parts.
    assert.deepEqual((await resolveRoomMembers('a__b__c', q)).sort(), ['a__b', 'c']);
  });

  it('emits only to room members, never to outsiders', async () => {
    const captured: any[] = [];
    presence.setOnline('sock-alice', 'alice');
    presence.setOnline('sock-bob', 'bob');
    presence.setOnline('sock-carol', 'carol');
    try {
      const q = makeFakeQuery([]);
      await emitToRoom(fakeIo(captured), 'alice__bob', 'msg-reaction', { msgId: 'm1' }, q);
      const recipients = captured.map((c) => c.sockId).sort();
      assert.deepEqual(recipients, ['sock-alice', 'sock-bob']);
      assert.equal(captured[0].event, 'msg-reaction');
      await emitToRoom(fakeIo(captured), 'group__g1', 'read', { msgId: 'm2' }, q);
      assert.equal(captured.length, 4); // 2 more, still no carol
      assert.ok(!captured.some((c) => c.sockId === 'sock-carol'));
    } finally {
      presence.setOffline('sock-alice');
      presence.setOffline('sock-bob');
      presence.setOffline('sock-carol');
    }
  });

  it('emits to nobody for an unknown room', async () => {
    const captured: any[] = [];
    presence.setOnline('sock-alice', 'alice');
    try {
      const q = makeFakeQuery([]);
      await emitToRoom(fakeIo(captured), 'group__nope', 'read', { msgId: 'm1' }, q);
      assert.equal(captured.length, 0);
    } finally {
      presence.setOffline('sock-alice');
    }
  });
});

// ---------------------------------------------------------------------------
// L7(a) — avatar allowlist
// ---------------------------------------------------------------------------

describe('L7(a) profileSync avatar allowlist', () => {
  it('accepts Google photos and /api/media/ avatars', () => {
    assert.equal(isAllowedAvatarUrl('https://lh3.googleusercontent.com/a/photo.jpg'), true);
    assert.equal(isAllowedAvatarUrl('/api/media/abc-123.png'), true);
  });

  it('rejects arbitrary hosts, http, and other paths', () => {
    assert.equal(isAllowedAvatarUrl('https://evil.example.com/x.png'), false);
    assert.equal(isAllowedAvatarUrl('http://lh3.googleusercontent.com/x.png'), false);
    assert.equal(isAllowedAvatarUrl('https://lh3.googleusercontent.com.evil.example.com/x.png'), false);
    assert.equal(isAllowedAvatarUrl('/uploads/abc.png'), false);
    assert.equal(isAllowedAvatarUrl(''), false);
    assert.equal(isAllowedAvatarUrl(null), false);
  });

  it('resolveProfileUpdate drops a rejected avatar and keeps the stored one', () => {
    const stored = { display_name: 'Alice', avatar: '/api/media/old.png', name_custom: 0, avatar_custom: 0 };
    const r = resolveProfileUpdate(stored, { avatar: 'https://tracker.example.com/pixel.png' });
    assert.equal(r.avatar, '/api/media/old.png');
    assert.equal(r.avatar_custom, 0); // no flag raised — nothing changed
    const r2 = resolveProfileUpdate(stored, { avatar: 'https://lh3.googleusercontent.com/new.jpg' });
    assert.equal(r2.avatar, 'https://lh3.googleusercontent.com/new.jpg');
    assert.equal(r2.avatar_custom, 1);
  });

  it('resolveProfileUpdate still allows clearing the avatar with an empty value', () => {
    const stored = { display_name: 'Alice', avatar: '/api/media/old.png', name_custom: 0, avatar_custom: 0 };
    const r = resolveProfileUpdate(stored, { avatar: '' });
    assert.equal(r.avatar, null);
  });
});

// ---------------------------------------------------------------------------
// L7(e) — JSON-parse guards
// ---------------------------------------------------------------------------

describe('L7(e) messageParse — corrupt JSON fails closed', () => {
  it('parseMsg with corrupt reactions degrades to {} instead of throwing', () => {
    const m = parseMsg({ id: 'm1', reactions: '{not json', is_edited: 1 });
    assert.deepEqual(m.reactions, {});
    assert.equal(m.is_edited, true);
    const ok = parseMsg({ id: 'm2', reactions: '{"❤️":["alice"]}' });
    assert.deepEqual(ok.reactions, { '❤️': ['alice'] });
    const obj = parseMsg({ id: 'm3', reactions: { '👍': ['bob'] } });
    assert.deepEqual(obj.reactions, { '👍': ['bob'] });
    const missing = parseMsg({ id: 'm4' });
    assert.deepEqual(missing.reactions, {});
  });

  it('safeParseMembers returns null on corrupt JSON, never throws', () => {
    assert.deepEqual(safeParseMembers('["alice","bob"]'), ['alice', 'bob']);
    assert.equal(safeParseMembers('{broken'), null);
    assert.equal(safeParseMembers('{"a":1}'), null);
    assert.equal(safeParseMembers(null), null);
    assert.deepEqual(safeParseMembers(['alice', 1, 'bob']), ['alice', 'bob']);
  });

  it('safeParseReactions returns {} on corrupt JSON, never throws', () => {
    assert.deepEqual(safeParseReactions('{broken'), {});
    assert.deepEqual(safeParseReactions(''), {});
    assert.deepEqual(safeParseReactions(null), {});
  });
});

// ---------------------------------------------------------------------------
// M6 — fallback DB handlers for the new SQL shapes
// ---------------------------------------------------------------------------

describe('M6 fallback DB — new SQL shapes used by round 5', () => {
  it('supports the account-delete / media-cleanup queries', async () => {
    const db = new PersistentFallbackDatabase();
    const stamp = 'r5-' + Date.now();
    const blobId = 'blob-' + stamp;
    const uid = 'user-' + stamp;
    try {
      await db.query(
        'INSERT INTO media_blobs (id, mime_type, data_base64, room_id, is_encrypted, uploaded_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [blobId, 'image/png', null, 'alice__bob', 0, uid, new Date().toISOString()]
      );
      const mine = await db.query('SELECT * FROM media_blobs WHERE uploaded_by = $1', [uid]);
      assert.equal(mine.rows.length, 1);
      assert.equal(mine.rows[0].id, blobId);
      await db.query('DELETE FROM media_blobs WHERE id = $1', [blobId]);
      const gone = await db.query('SELECT * FROM media_blobs WHERE uploaded_by = $1', [uid]);
      assert.equal(gone.rows.length, 0);

      // Reports delete (both directions) + users/messages/contacts deletes.
      await db.query(
        'INSERT INTO reports (id, reporter, reported_user, message_id, message_text, reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        ['rep-' + stamp, uid, 'bob', null, null, 'spam', new Date().toISOString()]
      );
      await db.query('DELETE FROM reports WHERE reporter = $1 OR reported_user = $1', [uid]);
      const reports = await db.query('SELECT * FROM reports ORDER BY created_at DESC');
      assert.ok(!reports.rows.some((r: any) => r.reporter === uid));
      await db.query('DELETE FROM users WHERE username = $1', [uid]);
      await db.query('DELETE FROM messages WHERE sender = $1', [uid]);
      await db.query('DELETE FROM contacts WHERE username = $1 OR contact = $1', [uid]);
    } finally {
      await db.query('DELETE FROM media_blobs WHERE id = $1', [blobId]);
      await db.query('DELETE FROM reports WHERE reporter = $1 OR reported_user = $1', [uid]);
      await db.query('DELETE FROM users WHERE username = $1', [uid]);
      await db.query('DELETE FROM messages WHERE sender = $1', [uid]);
      await db.query('DELETE FROM contacts WHERE username = $1 OR contact = $1', [uid]);
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
  });
});

// ---------------------------------------------------------------------------
// Route wiring (server.ts source — server never started in tests)
// ---------------------------------------------------------------------------

describe('route wiring (server.ts source)', () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server.ts'), 'utf-8');
  const adminJs = fs.readFileSync(
    path.join(__dirname, '..', 'public', 'js', 'admin.js'),
    'utf-8'
  );
  const dbSrc = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'server', 'db.ts'),
    'utf-8'
  );

  const handler = (startMarker: string, endMarker: string) => {
    const start = serverSrc.indexOf(startMarker);
    assert.ok(start !== -1, `marker not found: ${startMarker}`);
    const end = serverSrc.indexOf(endMarker, start);
    assert.ok(end !== -1, `end marker not found: ${endMarker}`);
    return serverSrc.slice(start, end);
  };

  it('H1: uploadsDir is outside public/ and the upload validates magic bytes', () => {
    assert.ok(serverSrc.includes("path.join(process.cwd(), 'data/uploads')"));
    assert.ok(!serverSrc.includes("path.join(process.cwd(), 'public/uploads')"));
    assert.ok(serverSrc.includes('validateUploadFile('));
    assert.ok(serverSrc.includes('readFileHead(req.file.path)'));
    assert.ok(serverSrc.includes('fileFilter'));
    assert.ok(serverSrc.includes('ALLOWED_UPLOAD_EXTENSIONS'));
  });

  it('H1: /api/media serves the verified mime as an attachment, never text/html', () => {
    const media = handler("app.get('/api/media/:id'", '// ===== PUBLIC CLIENT CONFIG');
    assert.ok(media.includes('verifyStoredMime('));
    assert.ok(media.includes("Content-Disposition', 'attachment'"));
    // Content-Type is set ONLY from the verified mime — never from a
    // stored claim, and never literally to text/html.
    assert.ok(media.includes("res.setHeader('Content-Type', verifyStoredMime("));
    assert.ok(!media.includes("Content-Type', 'text/html"));
    // No stored mime is ever served verbatim.
    assert.ok(!media.includes('access.blob.mime_type ||'));
  });

  it('H3: getSessionUsername is async and checks the block list (fail closed)', () => {
    assert.ok(serverSrc.includes('async function getSessionUsername(req: Request): Promise<string | null>'));
    assert.ok(serverSrc.includes('await isUserBlocked(session.username)'));
    assert.ok(serverSrc.includes('fail-closed') || serverSrc.includes('fail closed'));
    // Every call site awaits it — no bare getSessionUsername(req) remains.
    const bare = serverSrc.match(/(?<!await )getSessionUsername\(req\)/g) || [];
    assert.deepEqual(bare, []);
    // The old sync pre-middleware shape is gone.
    assert.ok(!serverSrc.includes('if (!getSessionUsername(req))'));
  });

  it('H3: POST /api/admin/block revokes all sessions of the blocked user', () => {
    const block = handler("app.post('/api/admin/block'", "app.post('/api/admin/unblock'");
    assert.ok(block.includes('removeAllUserSessions(username)'));
  });

  it('H4: admin login issues a session token; isAdmin rejects the raw password', () => {
    const login = handler("app.post('/api/admin/login'", "app.get('/api/admin/users'");
    assert.ok(login.includes('issueAdminSession('));
    assert.ok(login.includes('adminToken'));
    assert.ok(login.includes('429'));
    assert.ok(login.includes('adminLoginLimiter'));
    assert.ok(!login.includes('res.json({ ok: verifyAdminSecret'));
    assert.ok(serverSrc.includes('verifyAdminSession(token)'));
    // isAdmin must not call verifyAdminSecret anymore.
    const isAdminFn = serverSrc.slice(
      serverSrc.indexOf('function isAdmin(req: Request)'),
      serverSrc.indexOf('async function isUserBlocked')
    );
    assert.ok(!isAdminFn.includes('verifyAdminSecret'));
    assert.ok(isAdminFn.includes('verifyAdminSession'));
    // admin.js stores the returned token, never the password.
    assert.ok(adminJs.includes('d.adminToken'));
    assert.ok(!/token = p;/.test(adminJs));
    assert.ok(adminJs.includes('تلاش‌های ناموفق زیاد است؛ چند دقیقه دیگر تلاش کنید'));
  });

  it('M2: logout exists; recover revokes sessions; reissue keeps the current one', () => {
    assert.ok(serverSrc.includes("app.post('/api/logout'"));
    assert.ok(serverSrc.includes('removeUserSession(token)'));
    assert.ok(serverSrc.includes("res.clearCookie('session_token'"));
    const recover = handler("app.post('/api/recover'", "app.post('/api/quick-login'");
    assert.ok(recover.includes('removeAllUserSessions(key)'));
    assert.ok(recover.includes("res.status(401).json({ ok: false, msg: 'آیدی یا کد بازیابی نامعتبر است.' })"));
    assert.ok(!recover.includes('این حساب مسدود شده است'));
    const reissue = handler("app.post(['/api/auth/reissue-recovery-code'", '// ===== GROUP EPOCH');
    assert.ok(reissue.includes('removeAllUserSessionsExcept(sessionUser, currentToken)'));
    // Cookie security: secure follows the request (true on Render HTTPS),
    // never NODE_ENV.
    assert.ok(!serverSrc.includes("secure: process.env.NODE_ENV === 'production'"));
    assert.ok(serverSrc.includes('secure: req.secure,'));
  });

  it('M3: /api/settings/mode uses the session, never the X-Session-User header', () => {
    const mode = handler("app.get('/api/settings/mode'", '// ===== ADMIN =====');
    assert.ok(!mode.includes('x-session-user'));
    assert.ok(mode.includes('await getSessionUsername(req)'));
    assert.ok(mode.includes("error: 'unauthorized'"));
    // No distinct blocked message leaks from login paths either.
    assert.ok(!serverSrc.includes("msg: 'این حساب مسدود شده است.'"));
  });

  it('M3: epoch-packet not-found and not-member return the identical shape', () => {
    const epochPost = handler("app.post('/api/group/:id/epoch-packet'", "app.get('/api/group/:id/epoch-packet'");
    const epochGet = handler("app.get('/api/group/:id/epoch-packet'", "app.post('/api/user/update'");
    // No 'group not found' message and no distinct 403 in EITHER epoch handler.
    assert.ok(!epochPost.includes("msg: 'group not found'"));
    assert.ok(!epochGet.includes("msg: 'group not found'"));
    assert.ok(epochPost.includes('if (!rows.length) return res.json({ ok: false });'));
    assert.ok(epochPost.includes('if (!members.includes(sessionUser)) return res.json({ ok: false });'));
    assert.ok(epochGet.includes('if (!members.includes(sessionUser)) return res.json({ ok: false });'));
  });

  it('M4: /api/report requires a session and forces reporter = session user', () => {
    const report = handler("app.post(\n  '/api/report'", '// ===== ACCOUNT DATA EXPORT');
    assert.ok(report.includes("res.status(401).json({ ok: false, msg: 'unauthorized' })"));
    assert.ok(report.includes('[uuidv4(), sessionUser, reported'));
    assert.ok(!report.includes('reporter, reportedUser'));
    assert.ok(report.includes('slice(0, 2000)')); // messageText cap
    assert.ok(report.includes('slice(0, 500)')); // reason cap
    assert.ok(report.includes('reportLimiter'));
  });

  it('M5: message events use emitToRoom; only announce/mode stay global', () => {
    const globalEmits = [...serverSrc.matchAll(/io\.emit\('([^']+)'/g)].map((m) => m[1]);
    assert.deepEqual(globalEmits.sort(), ['announcement', 'server-maintenance', 'server-normal']);
    for (const event of ['msg-edited', 'msg-deleted', 'msg-pinned', 'msg-unpinned', 'msg-reaction', 'read', 'new-message']) {
      assert.ok(serverSrc.includes(`emitToRoom(io,`) && serverSrc.includes(`'${event}'`), event);
    }
    assert.ok(serverSrc.includes("if (orig.is_deleted) return;")); // no resurrecting deleted forwards
  });

  it('M6: JSON fallback is opt-in only and the engine is logged at startup', () => {
    assert.ok(dbSrc.includes("process.env.ALLOW_JSON_FALLBACK === '1'"));
    assert.ok(dbSrc.includes('export function getDbEngine()'));
    assert.ok(dbSrc.includes('throw err;'));
    assert.ok(serverSrc.includes('getDbEngine()'));
    assert.ok(serverSrc.includes('Database engine: PostgreSQL'));
    assert.ok(serverSrc.includes('JSON FALLBACK ACTIVE'));
  });

  it('M7: global + tight limiters, socket throttle, and length caps are wired', () => {
    assert.ok(serverSrc.includes("app.use('/api/', rateLimitMiddleware(apiGlobalLimiter"));
    assert.ok(serverSrc.includes('userLookupLimiter'));
    assert.ok(serverSrc.includes('healthLimiter'));
    assert.ok(serverSrc.includes('uploadLimiter'));
    assert.ok(serverSrc.includes('socketEventCount > 30'));
    assert.ok(serverSrc.includes('text.length > 50000'));
    assert.ok(serverSrc.includes('emoji.length > 16'));
    assert.ok(serverSrc.includes('604800'));
    assert.ok(serverSrc.includes('bio.length > 1000'));
    assert.ok(serverSrc.includes('allMembers.length > 100'));
    assert.ok(serverSrc.includes('SELECT username FROM users'));
  });

  it('L1: Permissions-Policy header is set (helmet 8 has no such option)', () => {
    assert.ok(
      serverSrc.includes("Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'")
    );
  });

  it('L2: /api/health trims the response for non-admin callers', () => {
    const health = handler("app.get('/api/health'", '// ===== GOOGLE SIGN-IN');
    assert.ok(health.includes('if (!isAdmin(req))'));
    assert.ok(health.includes('return res.status(dbOk ? 200 : 503).json({ ok: dbOk });'));
    assert.ok(health.includes('SELECT COUNT(*) as c FROM users'));
  });

  it('L7: avatar allowlist enforced via resolveProfileUpdate; VOPRF warns loudly; fixed host; validated mode/block', () => {
    assert.ok(serverSrc.includes('VOPRF_SEED is not set'));
    assert.ok(serverSrc.includes("const CANONICAL_HOST = 'https://chatapp-server-1i2a.onrender.com'"));
    assert.ok(!serverSrc.includes("req.get('host')"));
    assert.ok(serverSrc.includes("mode !== 'normal' && mode !== 'maintenance'"));
    assert.ok(serverSrc.includes("blockType !== 'permanent' && blockType !== 'temporary'"));
    assert.ok(serverSrc.includes("msg: 'invalid blockUntil'"));
  });

  it('Info: favicon 204, admin-login-as bogus token 404 JSON', () => {
    assert.ok(serverSrc.includes("app.get('/favicon.ico'"));
    assert.ok(serverSrc.includes('res.status(204).end()'));
    const loginAs = handler("app.get('/api/admin-login-as/:token'", '// مسیر پنل مدیریت');
    assert.ok(loginAs.includes("res.status(404).json({ ok: false, error: 'Not Found' })"));
  });

  it('H2: socket handlers gate on membership (canActOnMessage / isRoomMember)', () => {
    const socket = serverSrc.slice(serverSrc.indexOf("io.on('connection'"));
    assert.ok(socket.includes('canActOnMessage(currentUser, msgId, roomId'));
    assert.ok(socket.includes('if (!currentUser || !msgId) return;')); // read requires auth
    assert.ok(socket.includes("SELECT 1 FROM contacts WHERE username=$1 AND contact=$2"));
    // Group send requires membership before insert.
    assert.ok(socket.includes('isRoomMember(currentUser, roomId'));
  });
});
