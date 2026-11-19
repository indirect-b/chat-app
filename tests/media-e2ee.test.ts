/**
 * Media E2EE + members-only media links — no live DB, no network.
 *
 * The route logic lives in src/server/media.ts as pure functions taking a
 * `query` function, so the tests run them against a fake in-memory store
 * holding the exact SQL strings the module sends. The crypto round-trips use
 * the real file-key helpers (same key setup as the pq-mprba tests). The
 * /api/upload auth-before-multer and the removed /uploads static route are
 * verified against server.ts source (the server itself is never started in
 * tests — it binds a port on import).
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  getRoomId,
  isRoomMember,
  resolveMediaAccess,
  canUploadToRoom,
  type DbQuery,
} from '../src/server/media';
import {
  encryptFileBytes,
  decryptFileBytes,
  isEncryptedFileBytes,
  encryptMessageText,
  ensureUserHybridKeyPair,
  parsePeerKeyBundle,
  createGroupEpochPacket,
  rotateGroupEpoch,
  resetAllCryptoStateForTests,
  E2EEError,
} from '../src/utils/crypto';

// Same in-memory localStorage shim as the pq-mprba tests.
class MemoryStorage {
  private map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  key(index: number): string | null {
    return Array.from(this.map.keys())[index] ?? null;
  }
  getItem(key: string): string | null {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.map.set(key, String(value));
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  clear(): void {
    this.map.clear();
  }
}
const mockLocalStorage = new MemoryStorage();
Object.defineProperty(globalThis, 'localStorage', {
  value: mockLocalStorage,
  configurable: true,
  writable: true,
});

interface FakeBlob {
  id: string;
  mime_type: string;
  data_base64: string | null;
  room_id: string | null;
  is_encrypted: number;
  uploaded_by: string | null;
  created_at: string;
}

function makeFakeStore() {
  const store = {
    users: [
      { username: 'alice', avatar: '/api/media/avatar1.png' },
      { username: 'bob', avatar: null },
      { username: 'carol', avatar: null },
      { username: 'mallory', avatar: null },
    ],
    groups: [{ id: 'g1', members: JSON.stringify(['alice', 'bob', 'carol']) }],
    messages: [
      { room_id: 'alice__bob', file_url: '/api/media/old1.jpg', is_deleted: 0 },
      { room_id: 'alice__bob', file_url: '/api/media/old2.jpg', is_deleted: 1 },
      { room_id: 'group__g1', file_url: '/uploads/old3.png', is_deleted: 0 },
    ],
    blobs: [
      {
        id: 'new1.jpg',
        mime_type: 'image/jpeg',
        data_base64: 'AAAA',
        room_id: 'alice__bob',
        is_encrypted: 1,
        uploaded_by: 'alice',
        created_at: '2026-11-19T00:00:00Z',
      },
      {
        id: 'new2.png',
        mime_type: 'image/png',
        data_base64: 'BBBB',
        room_id: 'group__g1',
        is_encrypted: 1,
        uploaded_by: 'bob',
        created_at: '2026-11-19T00:00:00Z',
      },
      {
        id: 'old1.jpg',
        mime_type: 'image/jpeg',
        data_base64: 'CCCC',
        room_id: null,
        is_encrypted: 0,
        uploaded_by: null,
        created_at: '2026-11-01T00:00:00Z',
      },
      {
        id: 'orphan1.jpg',
        mime_type: 'image/jpeg',
        data_base64: 'DDDD',
        room_id: null,
        is_encrypted: 0,
        uploaded_by: null,
        created_at: '2026-11-01T00:00:00Z',
      },
      {
        id: 'avatar1.png',
        mime_type: 'image/png',
        data_base64: 'EEEE',
        room_id: null,
        is_encrypted: 0,
        uploaded_by: 'alice',
        created_at: '2026-11-01T00:00:00Z',
      },
      {
        id: 'preview1.png',
        mime_type: 'image/png',
        data_base64: 'FFFF',
        room_id: null,
        is_encrypted: 0,
        uploaded_by: 'alice',
        created_at: '2026-11-19T00:00:00Z',
      },
    ] as FakeBlob[],
  };

  const query: DbQuery = async (sql: string, params: any[] = []) => {
    const lower = sql.trim().replace(/\s+/g, ' ').toLowerCase();
    if (lower === 'select username from users') {
      return { rows: store.users.map(u => ({ username: u.username })) };
    }
    if (lower === 'select members from groups where id=$1') {
      const g = store.groups.find(x => x.id === params[0]);
      return { rows: g ? [{ members: g.members }] : [] };
    }
    if (lower === 'select * from media_blobs where id = $1') {
      const b = store.blobs.find(x => x.id === params[0]);
      return { rows: b ? [{ ...b }] : [] };
    }
    if (lower === 'select room_id, is_deleted from messages where file_url = $1') {
      const m = store.messages.find(x => x.file_url === params[0]);
      return { rows: m ? [{ room_id: m.room_id, is_deleted: m.is_deleted }] : [] };
    }
    if (lower === 'select username from users where avatar = $1 or avatar = $2') {
      const u = store.users.find(x => x.avatar === params[0] || x.avatar === params[1]);
      return { rows: u ? [{ username: u.username }] : [] };
    }
    throw new Error(`fake query cannot handle: ${sql}`);
  };

  return { store, query };
}

describe('isRoomMember', () => {
  it('admits both DM members and denies outsiders (exact room-id match)', async () => {
    const { query } = makeFakeStore();
    assert.equal(await isRoomMember('alice', 'alice__bob', query), true);
    assert.equal(await isRoomMember('bob', 'alice__bob', query), true);
    assert.equal(await isRoomMember('mallory', 'alice__bob', query), false);
    assert.equal(await isRoomMember('carol', 'alice__bob', query), false);
  });

  it('admits group members from the members list and denies outsiders', async () => {
    const { query } = makeFakeStore();
    assert.equal(await isRoomMember('carol', 'group__g1', query), true);
    assert.equal(await isRoomMember('mallory', 'group__g1', query), false);
    assert.equal(await isRoomMember('alice', 'group__missing', query), false);
  });

  it('does not let a username with "__" impersonate membership (prefix trap)', async () => {
    // Room 'x__y__z' belongs to users 'x__y' and 'z' — user 'x' is NOT a member.
    const { query } = makeFakeStore();
    assert.equal(getRoomId('x__y', 'z'), 'x__y__z');
    assert.equal(await isRoomMember('x', 'x__y__z', query), false);
  });
});

describe('canUploadToRoom (upload authorization)', () => {
  it('allows members and refuses non-members', async () => {
    const { query } = makeFakeStore();
    assert.equal(await canUploadToRoom('alice', 'alice__bob', query), true);
    assert.equal(await canUploadToRoom('mallory', 'alice__bob', query), false);
    assert.equal(await canUploadToRoom('carol', 'group__g1', query), true);
    assert.equal(await canUploadToRoom('mallory', 'group__g1', query), false);
    assert.equal(await canUploadToRoom('alice', '', query), false);
  });
});

describe('resolveMediaAccess (media fetch authorization)', () => {
  it('(c) a non-member with a valid session gets 403 on new encrypted media', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('new1.jpg', 'mallory', query);
    assert.equal(res.status, 'forbidden');
  });

  it('(c) a non-member gets 403 on pre-change media linked from a message', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('old1.jpg', 'mallory', query);
    assert.equal(res.status, 'forbidden');
  });

  it('(d) a member gets 200 on new encrypted media, with the encrypted flag', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('new1.jpg', 'bob', query);
    assert.equal(res.status, 'ok');
    assert.equal(res.roomId, 'alice__bob');
    assert.equal(res.isEncrypted, true);
    assert.equal(res.blob.id, 'new1.jpg');
  });

  it('(d) a member gets 200 on pre-change media (access-controlled, NOT encrypted)', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('old1.jpg', 'bob', query);
    assert.equal(res.status, 'ok');
    assert.equal(res.roomId, 'alice__bob');
    assert.equal(res.isEncrypted, false);
  });

  it('(d) a disk-only pre-change file resolves through its /uploads/ message link', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('old3.png', 'carol', query);
    assert.equal(res.status, 'ok');
    assert.equal(res.roomId, 'group__g1');
    assert.equal(res.blob, null);
  });

  it('a deleted message denies access to its media', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('old2.jpg', 'alice', query);
    assert.equal(res.status, 'forbidden');
  });

  it('(e) orphan media (no room, no message, not an avatar) is 403', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('orphan1.jpg', 'alice', query);
    assert.equal(res.status, 'forbidden');
  });

  it('unknown media id is 404', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('nope.jpg', 'alice', query);
    assert.equal(res.status, 'not-found');
  });

  it('no username at all is forbidden (unauthenticated fetch)', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('new1.jpg', '', query);
    assert.equal(res.status, 'forbidden');
  });

  it('a current avatar is fetchable by any authenticated user', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('avatar1.png', 'mallory', query);
    assert.equal(res.status, 'ok');
    assert.equal(res.roomId, null);
    assert.equal(res.isEncrypted, false);
  });

  it('the uploader can fetch their own just-uploaded avatar before it is saved', async () => {
    const { query } = makeFakeStore();
    const res = await resolveMediaAccess('preview1.png', 'alice', query);
    assert.equal(res.status, 'ok');
    const other = await resolveMediaAccess('preview1.png', 'bob', query);
    assert.equal(other.status, 'forbidden');
  });
});

describe('server routes (source checks — the server is never started in tests)', () => {
  const serverSrc = fs.readFileSync(path.join(process.cwd(), 'server.ts'), 'utf-8');

  it('(a) /api/upload requires a valid session BEFORE multer parses the body', () => {
    const start = serverSrc.indexOf("app.post(\n  '/api/upload'");
    assert.ok(start >= 0, 'upload route not found');
    const end = serverSrc.indexOf("upload.single('file')", start);
    assert.ok(end > start, 'multer middleware not found after the upload route');
    const guard = serverSrc.slice(start, end);
    assert.ok(guard.includes('getSessionUsername(req)'), 'no session check before multer');
    assert.ok(guard.includes('401'), 'no 401 before multer');
  });

  it('(f) the public /uploads static route is gone; media is served only through authenticated /api/media', () => {
    assert.doesNotMatch(serverSrc, /app\.use\('\/uploads',\s*express\.static/);
    assert.doesNotMatch(serverSrc, /express\.static\(uploadsDir\)/);
    const mediaStart = serverSrc.indexOf("app.get('/api/media/:id'");
    assert.ok(mediaStart >= 0, 'media route not found');
    const nextRoute = serverSrc.indexOf('\napp.', mediaStart + 10);
    const mediaBlock = serverSrc.slice(mediaStart, nextRoute >= 0 ? nextRoute : undefined);
    assert.ok(mediaBlock.includes('getSessionUsername(req)'), 'media route has no session check');
    assert.ok(mediaBlock.includes('401'), 'media route has no 401');
    assert.ok(mediaBlock.includes('resolveMediaAccess'), 'media route does not use resolveMediaAccess');
    assert.ok(mediaBlock.includes('X-Media-Encrypted'), 'media route does not report the encryption flag');
  });

  it('the upload route records room_id and the uploader, and never returns a /uploads URL', () => {
    const start = serverSrc.indexOf("app.post(\n  '/api/upload'");
    const end = serverSrc.indexOf("app.get('/api/media/:id'", start);
    const block = serverSrc.slice(start, end);
    assert.ok(block.includes('room_id'), 'upload does not record room_id');
    assert.ok(block.includes('uploaded_by'), 'upload does not record the uploader');
    assert.ok(block.includes("`/api/media/${mediaId}`"), 'upload does not return an /api/media URL');
    assert.doesNotMatch(block, /'\/uploads\/'/);
  });
});

describe('file encryption round-trips (real crypto, same key setup as the pq-mprba tests)', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('(g) DM: alice encrypts, bob decrypts → identical bytes; ciphertext is opaque', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const plain = new TextEncoder().encode('a fake JPEG body — \u{1F4F7} bytes go here');
    const cipher = await encryptFileBytes(plain, 'alice__bob', {
      myUsername: 'alice',
      peerPublicKey: bobBundle,
      peerUsername: 'bob',
    });
    assert.equal(isEncryptedFileBytes(cipher), true);
    assert.equal(isEncryptedFileBytes(plain), false);
    assert.notDeepEqual(Array.from(cipher), Array.from(plain));
    const back = await decryptFileBytes(cipher, 'alice__bob', {
      myUsername: 'bob',
      peerPublicKey: aliceBundle,
      peerUsername: 'alice',
    });
    assert.deepEqual(Array.from(back), Array.from(plain));
  });

  it('(g) DM: tampering with the ciphertext fails closed', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const cipher = await encryptFileBytes(new TextEncoder().encode('secret'), 'alice__bob', {
      myUsername: 'alice',
      peerPublicKey: bobBundle,
      peerUsername: 'bob',
    });
    const tampered = new Uint8Array(cipher);
    tampered[tampered.length - 1] ^= 0xff;
    await assert.rejects(
      decryptFileBytes(tampered, 'alice__bob', {
        myUsername: 'bob',
        peerPublicKey: aliceBundle,
        peerUsername: 'alice',
      }),
      (err: unknown) => err instanceof E2EEError
    );
  });

  it('(g) group: encrypt/decrypt with the epoch key; old-epoch files still open inside the grace buffer', async () => {
    const members = ['alice', 'bob', 'carol'];
    const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
    for (const m of members) {
      bundles[m] = parsePeerKeyBundle((await ensureUserHybridKeyPair(m))!, m);
    }
    const rotateWithPacket = async (epoch: number) => {
      const packet = await createGroupEpochPacket(bundles);
      await rotateGroupEpoch('media-team', epoch, members, packet.epochKeyB64);
    };
    await rotateWithPacket(1);
    const plain = new TextEncoder().encode('group photo bytes');
    const cipher = await encryptFileBytes(plain, 'group__media-team', {
      groupMembers: members,
    });
    // Kind byte 2 = group epoch; epoch 1 embedded in the header.
    assert.equal(cipher[4], 2);
    await rotateWithPacket(2);
    const back = await decryptFileBytes(cipher, 'group__media-team', {
      groupMembers: members,
    });
    assert.deepEqual(Array.from(back), Array.from(plain));
  });

  it('(g) manual passphrase rooms round-trip with a purpose-separated key', async () => {
    const plain = new TextEncoder().encode('manual-secret file');
    const cipher = await encryptFileBytes(plain, 'alice__bob', {
      customSecret: 'correct horse battery staple',
    });
    assert.equal(cipher[4], 3);
    const back = await decryptFileBytes(cipher, 'alice__bob', {
      customSecret: 'correct horse battery staple',
    });
    assert.deepEqual(Array.from(back), Array.from(plain));
    await assert.rejects(
      decryptFileBytes(cipher, 'alice__bob', { customSecret: 'wrong passphrase' }),
      (err: unknown) => err instanceof E2EEError
    );
  });

  it('(h) no room key available fails closed — nothing is uploaded', async () => {
    await assert.rejects(
      encryptFileBytes(new TextEncoder().encode('x'), 'alice__bob', {}),
      (err: unknown) => err instanceof E2EEError && err.code === 'MISSING_KEYS'
    );
    await assert.rejects(
      encryptFileBytes(new TextEncoder().encode('x'), 'group__no-epoch-team', {
        groupMembers: ['alice', 'bob'],
      }),
      (err: unknown) => err instanceof E2EEError && err.code === 'MISSING_KEYS'
    );
    await assert.rejects(
      decryptFileBytes(new TextEncoder().encode('garbage'), 'alice__bob', {}),
      (err: unknown) => err instanceof E2EEError
    );
  });

  it('file encryption does not consume a message-ratchet step', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';
    const opts = { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle };
    const m1 = await encryptMessageText('first', roomId, opts);
    assert.ok(m1.startsWith('e2ee:pq:v2:0:'), m1.slice(0, 20));
    await encryptFileBytes(new TextEncoder().encode('photo'), roomId, opts);
    const m2 = await encryptMessageText('second', roomId, opts);
    // The second message is still step 1 — the file upload did not advance the ratchet.
    assert.ok(m2.startsWith('e2ee:pq:v2:1:'), m2.slice(0, 20));
  });
});
