import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  E2EEError,
  computePayloadHashKey,
  decryptMessageText,
  decryptMessageTextWithHistoryCache,
  encryptMessageText,
  ensureUserHybridKeyPair,
  resetAllCryptoStateForTests,
  simulateRefreshForTests,
} from '../src/utils/crypto';
import {
  DECRYPTED_HISTORY_MAX_ENTRIES,
  DECRYPTED_HISTORY_TTL_MS,
  IDB_HISTORY_STORE,
  deleteDecryptedHistoryForUser,
  deleteIdentityRecordV4,
  disablePasswordProtection,
  enablePasswordProtection,
  getDecryptedHistoryEntry,
  loadIdentityRecordV4,
  lockIdentity,
  pruneDecryptedHistory,
  storeDecryptedHistoryEntry,
  unlockIdentityWithPassphrase,
} from '../src/utils/keystore';

/**
 * Minimal in-memory fake IndexedDB implementing exactly the surface
 * src/utils/keystore.ts uses: open (+onupgradeneeded), objectStoreNames,
 * createObjectStore, transaction, get/put/delete/getAll, onsuccess/onerror,
 * tx.oncomplete/onerror, close.
 *
 * Why a fake instead of the Node fallbacks: the bug only reproduces on the
 * browser path — ratchetDecryptWithSkippedKeys consults the durable replay
 * store only when hasBrowserIndexedDB() is true. With the fake installed,
 * the tests exercise the real browser code paths (durable replay store +
 * encrypted history cache) end to end.
 */

type FakeStoreEntry = { keyPath: string; records: Map<unknown, any> };
type FakeDbEntry = { version: number; stores: Map<string, FakeStoreEntry> };

const fakeDatabases = new Map<string, FakeDbEntry>();

function resetFakeIndexedDB(): void {
  fakeDatabases.clear();
}

class FakeIDBRequest {
  result: any = undefined;
  error: any = null;
  onsuccess: ((ev: { target: FakeIDBRequest }) => void) | null = null;
  onerror: ((ev: { target: FakeIDBRequest }) => void) | null = null;
}

class FakeIDBObjectStore {
  constructor(
    private readonly records: Map<unknown, any>,
    private readonly keyPath: string
  ) {}

  private fire(req: FakeIDBRequest): void {
    // Callbacks are assigned synchronously right after the call in
    // keystore.ts, so a microtask fires after the handler is in place.
    queueMicrotask(() => {
      if (req.onsuccess) req.onsuccess({ target: req });
    });
  }

  get(key: unknown): FakeIDBRequest {
    const req = new FakeIDBRequest();
    req.result = this.records.get(key);
    this.fire(req);
    return req;
  }

  put(value: any): FakeIDBRequest {
    const req = new FakeIDBRequest();
    const key = value?.[this.keyPath];
    this.records.set(key, value);
    req.result = key;
    this.fire(req);
    return req;
  }

  delete(key: unknown): FakeIDBRequest {
    const req = new FakeIDBRequest();
    this.records.delete(key);
    req.result = undefined;
    this.fire(req);
    return req;
  }

  getAll(): FakeIDBRequest {
    const req = new FakeIDBRequest();
    req.result = Array.from(this.records.values());
    this.fire(req);
    return req;
  }
}

class FakeIDBTransaction {
  private _oncomplete: (() => void) | null = null;
  private _onerror: (() => void) | null = null;

  constructor(private readonly stores: Map<string, FakeStoreEntry>) {}

  set oncomplete(fn: (() => void) | null) {
    this._oncomplete = fn;
    if (fn) {
      // keystore.ts assigns oncomplete after issuing the requests, so this
      // microtask runs after the requests' onsuccess callbacks (FIFO).
      queueMicrotask(() => {
        this._oncomplete?.();
      });
    }
  }
  get oncomplete(): (() => void) | null {
    return this._oncomplete;
  }
  set onerror(fn: (() => void) | null) {
    this._onerror = fn;
  }
  get onerror(): (() => void) | null {
    return this._onerror;
  }

  objectStore(name: string): FakeIDBObjectStore {
    const store = this.stores.get(name);
    if (!store) throw new Error(`FakeIDB: object store '${name}' does not exist`);
    return new FakeIDBObjectStore(store.records, store.keyPath);
  }
}

class FakeIDBDatabase {
  constructor(private readonly entry: FakeDbEntry) {}

  get objectStoreNames(): { contains(name: string): boolean } {
    return { contains: (name: string) => this.entry.stores.has(name) };
  }

  createObjectStore(name: string, options: { keyPath: string }): FakeIDBObjectStore {
    if (!this.entry.stores.has(name)) {
      this.entry.stores.set(name, { keyPath: options.keyPath, records: new Map() });
    }
    const store = this.entry.stores.get(name)!;
    return new FakeIDBObjectStore(store.records, store.keyPath);
  }

  transaction(_storeNames: string | string[], _mode: string): FakeIDBTransaction {
    return new FakeIDBTransaction(this.entry.stores);
  }

  close(): void {
    // no-op
  }
}

class FakeIDBOpenRequest extends FakeIDBRequest {
  onupgradeneeded: ((ev: { target: FakeIDBOpenRequest }) => void) | null = null;
}

const fakeIndexedDB = {
  open(name: string, version: number): FakeIDBOpenRequest {
    const req = new FakeIDBOpenRequest();
    queueMicrotask(() => {
      let entry = fakeDatabases.get(name);
      let needsUpgrade = false;
      if (!entry) {
        entry = { version, stores: new Map() };
        fakeDatabases.set(name, entry);
        needsUpgrade = true;
      } else if (version > entry.version) {
        entry.version = version;
        needsUpgrade = true;
      }
      const db = new FakeIDBDatabase(entry);
      req.result = db;
      if (needsUpgrade) req.onupgradeneeded?.({ target: req });
      req.onsuccess?.({ target: req });
    });
    return req;
  },
};

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  clear(): void {
    this.map.clear();
  }
  getItem(key: string): string | null {
    return this.map.has(key) ? this.map.get(key)! : null;
  }
  key(index: number): string | null {
    return Array.from(this.map.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.map.set(key, String(value));
  }
}

const mockLocalStorage = new MemoryStorage();
const mockSessionStorage = new MemoryStorage();

const originalIndexedDB = (globalThis as any).indexedDB;

function fakeHistoryRecords(): Array<Record<string, any>> {
  const entry = fakeDatabases.get('pq_mprba_keystore_v4');
  const store = entry?.stores.get(IDB_HISTORY_STORE);
  return store ? Array.from(store.records.values()) : [];
}

function fakeHistoryRecordCount(): number {
  return fakeHistoryRecords().length;
}

function seedFakeHistoryRecords(username: string, count: number, timestamp: number): void {
  let entry = fakeDatabases.get('pq_mprba_keystore_v4');
  if (!entry) {
    entry = { version: 5, stores: new Map() };
    fakeDatabases.set('pq_mprba_keystore_v4', entry);
  }
  let store = entry.stores.get(IDB_HISTORY_STORE);
  if (!store) {
    store = { keyPath: 'key', records: new Map() };
    entry.stores.set(IDB_HISTORY_STORE, store);
  }
  for (let i = 0; i < count; i++) {
    const key = `${username}::room${i}::hash${String(i).padStart(6, '0')}`;
    store.records.set(key, {
      key,
      username,
      roomId: `room${i}`,
      payloadHash: `hash${String(i).padStart(6, '0')}`,
      iv: new Uint8Array(12),
      ciphertext: new Uint8Array(16),
      timestamp,
    });
  }
}

const ROOM_ALICE_BOB = 'alice__bob';
const PASSPHRASE = 'correct-horse-battery-staple';

async function makePair(): Promise<{ aliceBundle: string; bobBundle: string }> {
  const aliceBundle = await ensureUserHybridKeyPair('alice');
  const bobBundle = await ensureUserHybridKeyPair('bob');
  return { aliceBundle, bobBundle };
}

function assertE2EECode(err: unknown, code: string): void {
  assert.ok(err instanceof E2EEError, `expected E2EEError, got ${String(err)}`);
  assert.equal((err as E2EEError).code, code);
}

describe('Decrypted history cache — fix for messages locking after refresh', () => {
  before(() => {
    (globalThis as any).indexedDB = fakeIndexedDB;
    Object.defineProperty(globalThis, 'localStorage', {
      value: mockLocalStorage,
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, 'sessionStorage', {
      value: mockSessionStorage,
      configurable: true,
      writable: true,
    });
  });

  after(() => {
    (globalThis as any).indexedDB = originalIndexedDB;
  });

  beforeEach(() => {
    resetFakeIndexedDB();
    mockLocalStorage.clear();
    mockSessionStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('round-trips a decrypted entry through the AES-GCM history cache, and the stored bytes never contain the plaintext', async () => {
    await ensureUserHybridKeyPair('alice');
    const hash = 'hash01234567890123456789';
    const stored = await storeDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, hash, {
      text: 'سلام طاها، این پیام باید بعد از رفرش هم خوانا بماند',
      mode: 'PQ-MLKEM-RATCHET',
      ratchetStep: 3,
      mldsaVerified: true,
    });
    assert.equal(stored, true, 'store must succeed while the wrapping key is available');

    const read = await getDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, hash);
    assert.ok(read, 'cache must return the entry');
    assert.equal(read.text, 'سلام طاها، این پیام باید بعد از رفرش هم خوانا بماند');
    assert.equal(read.mode, 'PQ-MLKEM-RATCHET');
    assert.equal(read.ratchetStep, 3);
    assert.equal(read.mldsaVerified, true);

    const raw = fakeHistoryRecords();
    assert.equal(raw.length, 1);
    assert.ok(raw[0].iv instanceof Uint8Array);
    assert.ok(raw[0].ciphertext instanceof Uint8Array);
    assert.equal(
      Buffer.from(raw[0].ciphertext).toString('utf8').includes('سلام'),
      false,
      'ciphertext must not contain the plaintext'
    );
    assert.equal(
      JSON.stringify(raw[0]).includes('سلام طاها'),
      false,
      'no stored field may contain the plaintext'
    );
  });

  it('REGRESSION: a received message decrypts again after a refresh instead of failing with REPLAY_DETECTED', async () => {
    const { aliceBundle, bobBundle } = await makePair();
    const plain = 'پیام آزمایشی پس از رفرش';
    const payload = await encryptMessageText(plain, ROOM_ALICE_BOB, {
      myUsername: 'alice',
      peerPublicKey: bobBundle,
      peerUsername: 'bob',
    });
    const opts = {
      myUsername: 'bob',
      peerPublicKey: aliceBundle,
      peerUsername: 'alice',
      sender: 'alice',
    };

    // Live decrypt (as the socket path does) — succeeds and populates the cache.
    const live = await decryptMessageTextWithHistoryCache(payload, ROOM_ALICE_BOB, opts);
    assert.equal(live.text, plain);
    assert.equal(live.failed, false);

    // Simulate a browser refresh: volatile ratchet state is gone, durable
    // stores (identity, replay store, history cache) survive.
    simulateRefreshForTests();

    // Negative control — the original bug: re-decrypting the same payload
    // without the cache is rejected by the durable replay store.
    await assert.rejects(
      decryptMessageText(payload, ROOM_ALICE_BOB, opts),
      (err: unknown) => {
        assertE2EECode(err, 'REPLAY_DETECTED');
        return true;
      }
    );

    // The fix: the history path returns the original plaintext from cache.
    const again = await decryptMessageTextWithHistoryCache(payload, ROOM_ALICE_BOB, opts);
    assert.equal(again.text, plain);
    assert.equal(again.failed, false);

    // And again after a second refresh — the cache is durable.
    simulateRefreshForTests();
    const third = await decryptMessageTextWithHistoryCache(payload, ROOM_ALICE_BOB, opts);
    assert.equal(third.text, plain);
  });

  it('own sent message: readable from history after a refresh (was zeroized before)', async () => {
    const { aliceBundle, bobBundle } = await makePair();
    const plain = 'پیام ارسالی خودم';
    const payload = await encryptMessageText(plain, ROOM_ALICE_BOB, {
      myUsername: 'alice',
      peerPublicKey: bobBundle,
      peerUsername: 'bob',
    });
    const opts = {
      myUsername: 'alice',
      peerPublicKey: bobBundle,
      peerUsername: 'bob',
      sender: 'alice',
    };

    // The socket echo of our own message: in-session sent cache hit, and the
    // wrapper stores it durably in the history cache.
    const echo = await decryptMessageTextWithHistoryCache(payload, ROOM_ALICE_BOB, opts);
    assert.equal(echo.text, plain);

    simulateRefreshForTests();

    // Negative control: without the cache the sent key is gone.
    await assert.rejects(
      decryptMessageText(payload, ROOM_ALICE_BOB, opts),
      (err: unknown) => {
        assertE2EECode(err, 'DECRYPTION_FAILED');
        return true;
      }
    );

    const again = await decryptMessageTextWithHistoryCache(payload, ROOM_ALICE_BOB, opts);
    assert.equal(again.text, plain);
    assert.equal(again.failed, false);
  });

  it('L8: cache is unreadable while the identity is locked and readable again after unlock', async () => {
    await ensureUserHybridKeyPair('carol');
    const hash = 'hashcarol000000000000001';
    const stored = await storeDecryptedHistoryEntry('carol', 'carol__dave', hash, {
      text: 'پیام محافظت‌شده با رمز عبور',
      mode: 'PQ-MLKEM-RATCHET',
      ratchetStep: 0,
      mldsaVerified: true,
    });
    assert.equal(stored, true);

    // Enabling password protection rotates the wrapping key; the cache
    // entries are re-wrapped under the new key so history stays readable.
    await enablePasswordProtection('carol', PASSPHRASE);
    const afterEnable = await getDecryptedHistoryEntry('carol', 'carol__dave', hash);
    assert.ok(afterEnable, 'history must stay readable after enabling protection');
    assert.equal(afterEnable.text, 'پیام محافظت‌شده با رمز عبور');

    lockIdentity('carol');
    assert.equal(
      await getDecryptedHistoryEntry('carol', 'carol__dave', hash),
      null,
      'locked identity must not read the cache'
    );
    assert.equal(
      await storeDecryptedHistoryEntry('carol', 'carol__dave', 'hashcarol000000000000002', {
        text: 'نباید ذخیره شود',
        mldsaVerified: false,
      }),
      false,
      'locked identity must not write the cache'
    );

    await unlockIdentityWithPassphrase('carol', PASSPHRASE);
    const afterUnlock = await getDecryptedHistoryEntry('carol', 'carol__dave', hash);
    assert.ok(afterUnlock, 'history must be readable again after unlock');
    assert.equal(afterUnlock.text, 'پیام محافظت‌شده با رمز عبور');

    await disablePasswordProtection('carol', PASSPHRASE);
    const afterDisable = await getDecryptedHistoryEntry('carol', 'carol__dave', hash);
    assert.ok(afterDisable, 'history must stay readable after disabling protection');
    assert.equal(afterDisable.text, 'پیام محافظت‌شده با رمز عبور');
  });

  it('cache is namespaced per user and room (no cross-talk) and refuses unknown identities', async () => {
    await ensureUserHybridKeyPair('alice');
    await ensureUserHybridKeyPair('bob');
    const hash = 'hash01234567890123456789';
    await storeDecryptedHistoryEntry('alice', 'alice__bob', hash, {
      text: 'A1',
      mldsaVerified: true,
    });
    await storeDecryptedHistoryEntry('alice', 'alice__carol', hash, {
      text: 'A2',
      mldsaVerified: true,
    });
    await storeDecryptedHistoryEntry('bob', 'alice__bob', hash, {
      text: 'B1',
      mldsaVerified: true,
    });

    assert.equal((await getDecryptedHistoryEntry('alice', 'alice__bob', hash))?.text, 'A1');
    assert.equal((await getDecryptedHistoryEntry('alice', 'alice__carol', hash))?.text, 'A2');
    assert.equal((await getDecryptedHistoryEntry('bob', 'alice__bob', hash))?.text, 'B1');
    assert.equal(await getDecryptedHistoryEntry('alice', 'alice__bob', 'hash00000000000000000000'), null);
    assert.equal(await getDecryptedHistoryEntry('alice', 'alice__dave', hash), null);
    assert.equal(await getDecryptedHistoryEntry('mallory', 'alice__bob', hash), null);
    assert.equal(
      await storeDecryptedHistoryEntry('ghost', 'alice__bob', hash, { text: 'x', mldsaVerified: false }),
      false,
      'no identity means no wrapping key means no write'
    );
  });

  it('deleting the identity wipes that user’s history cache', async () => {
    await ensureUserHybridKeyPair('alice');
    await ensureUserHybridKeyPair('bob');
    await storeDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, 'hash01234567890123456789', {
      text: 'A1',
      mldsaVerified: true,
    });
    await storeDecryptedHistoryEntry('bob', ROOM_ALICE_BOB, 'hash01234567890123456789', {
      text: 'B1',
      mldsaVerified: true,
    });
    assert.equal(fakeHistoryRecordCount(), 2);

    await deleteIdentityRecordV4('alice');
    assert.equal(await loadIdentityRecordV4('alice'), null);
    assert.equal(await getDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, 'hash01234567890123456789'), null);
    assert.equal(fakeHistoryRecordCount(), 1, 'only the deleted user’s entries are removed');
    assert.equal(
      (await getDecryptedHistoryEntry('bob', ROOM_ALICE_BOB, 'hash01234567890123456789'))?.text,
      'B1',
      'the other user’s cache is untouched'
    );
  });

  it('prune removes entries older than the 30-day TTL and trims each user to the 10,000-entry cap', async () => {
    assert.equal(DECRYPTED_HISTORY_TTL_MS, 30 * 24 * 60 * 60 * 1000);
    assert.equal(DECRYPTED_HISTORY_MAX_ENTRIES, 10_000);

    await ensureUserHybridKeyPair('alice');
    await storeDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, 'hash01234567890123456789', {
      text: 'fresh',
      mldsaVerified: true,
    });
    await pruneDecryptedHistory();
    assert.equal(
      (await getDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, 'hash01234567890123456789'))?.text,
      'fresh',
      'fresh entries survive pruning'
    );
    await pruneDecryptedHistory(Date.now() + DECRYPTED_HISTORY_TTL_MS + 1000);
    assert.equal(
      await getDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, 'hash01234567890123456789'),
      null,
      'entries older than the TTL are pruned'
    );

    const now = Date.now();
    seedFakeHistoryRecords('capuser', DECRYPTED_HISTORY_MAX_ENTRIES + 5, now);
    assert.equal(fakeHistoryRecordCount(), DECRYPTED_HISTORY_MAX_ENTRIES + 5);
    await pruneDecryptedHistory(now);
    assert.equal(fakeHistoryRecordCount(), DECRYPTED_HISTORY_MAX_ENTRIES);
    const keys = fakeHistoryRecords().map(r => r.key as string);
    assert.equal(keys.includes('capuser::room0::hash000000'), false, 'oldest entries are trimmed first');
    assert.equal(keys.includes(`capuser::room${DECRYPTED_HISTORY_MAX_ENTRIES + 4}::hash010004`), true);
  });

  it('payload hash key is stable and shared between the send cache and the history cache', () => {
    const payload = 'e2ee:pq:v2:0:AAAA:BBBB:CCCC:DDDD';
    assert.equal(computePayloadHashKey(payload), computePayloadHashKey(payload));
    assert.equal(computePayloadHashKey(payload).length, 24);
    assert.notEqual(computePayloadHashKey(payload), computePayloadHashKey(payload + 'x'));
  });

  it('deleting a single user’s cache via the public API leaves other users alone', async () => {
    await ensureUserHybridKeyPair('alice');
    await ensureUserHybridKeyPair('bob');
    await storeDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, 'hash01234567890123456789', {
      text: 'A1',
      mldsaVerified: true,
    });
    await storeDecryptedHistoryEntry('bob', ROOM_ALICE_BOB, 'hash01234567890123456789', {
      text: 'B1',
      mldsaVerified: true,
    });
    await deleteDecryptedHistoryForUser('alice');
    assert.equal(await getDecryptedHistoryEntry('alice', ROOM_ALICE_BOB, 'hash01234567890123456789'), null);
    assert.equal(
      (await getDecryptedHistoryEntry('bob', ROOM_ALICE_BOB, 'hash01234567890123456789'))?.text,
      'B1'
    );
  });
});
