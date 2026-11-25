import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  clearRatchetSession,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  resetAllCryptoStateForTests,
  simulateRefreshForTests,
} from '../src/utils/crypto';
import {
  IDB_RATCHET_STORE,
  deleteDurableRatchetState,
  enablePasswordProtection,
  loadDurableRatchetState,
  lockIdentity,
  persistDurableRatchetState,
  unlockIdentityWithPassphrase,
  type DurableRatchetStateV1,
} from '../src/utils/keystore';

/**
 * Minimal in-memory fake IndexedDB implementing exactly the surface
 * src/utils/keystore.ts uses: open (+onupgradeneeded), objectStoreNames,
 * createObjectStore, transaction, get/put/delete/getAll, onsuccess/onerror,
 * tx.oncomplete/onerror, close. (Copied from
 * tests/decrypted-history-cache.test.ts — same surface, same fake.)
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

function fakeRatchetRecords(): Array<Record<string, any>> {
  const entry = fakeDatabases.get('pq_mprba_keystore_v4');
  const store = entry?.stores.get(IDB_RATCHET_STORE);
  return store ? Array.from(store.records.values()) : [];
}

const ROOM_ALICE_BOB = 'alice__bob';
const PASSPHRASE = 'correct-horse-battery-staple';

async function makePair(): Promise<{ aliceBundle: string; bobBundle: string }> {
  const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
  const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
  return { aliceBundle, bobBundle };
}

async function encryptAsAlice(text: string, bobBundle: string): Promise<string> {
  return encryptMessageText(text, ROOM_ALICE_BOB, {
    myUsername: 'alice',
    peerUsername: 'bob',
    peerPublicKey: bobBundle,
  });
}

async function decryptAsBob(payload: string, aliceBundle: string) {
  return decryptMessageText(payload, ROOM_ALICE_BOB, {
    myUsername: 'bob',
    peerUsername: 'alice',
    peerPublicKey: aliceBundle,
    sender: 'alice',
  });
}

function craftedState(skipped: Array<{ step: number; timestamp: number }>): DurableRatchetStateV1 {
  return {
    sendChainKey: Array.from({ length: 32 }, (_, i) => i),
    recvChainKey: Array.from({ length: 32 }, (_, i) => 255 - i),
    sendStep: 3,
    recvStep: 7,
    sentSinceRekey: 3,
    seenRecvSteps: [0, 1, 2, 5],
    kemCipherTextB64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    peerKemFingerprint: 'deadbeefdeadbeef',
    skippedKeys: skipped.map(({ step, timestamp }) => ({
      step,
      mk: Array.from({ length: 32 }, () => 7),
      timestamp,
    })),
    sessionEpoch: 2,
    hkdfSaltVersion: 'v2',
  };
}

describe('Durable ratchet state — fix for skipped-keys vault lost on refresh (#2)', () => {
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

  it('out-of-order messages survive a refresh via the durable vault, and the session continues', async () => {
    const { aliceBundle, bobBundle } = await makePair();

    // Alice encrypts 7 messages upfront (steps 0..6).
    const payloads: string[] = [];
    for (let i = 0; i <= 6; i++) {
      payloads.push(await encryptAsAlice(`پیام ${i}`, bobBundle));
    }

    // Bob decrypts 0,1,2 in order, then 5 (skips 3,4 into the vault).
    for (let i = 0; i <= 2; i++) {
      const d = await decryptAsBob(payloads[i], aliceBundle);
      assert.equal(d.text, `پیام ${i}`);
      assert.equal(d.ratchetStep, i);
    }
    const d5 = await decryptAsBob(payloads[5], aliceBundle);
    assert.equal(d5.text, 'پیام 5');
    assert.equal(d5.ratchetStep, 5);

    // The durable vault holds steps 3 and 4, recvStep has advanced past them.
    const stored = await loadDurableRatchetState('bob', ROOM_ALICE_BOB);
    assert.ok(stored, 'ratchet state must be persisted after decrypt');
    assert.deepEqual(stored.skippedKeys.map(e => e.step), [3, 4]);
    assert.equal(stored.recvStep, 6);

    // Full page refresh: all RAM state is gone (ratchet, sent cache, FSM).
    simulateRefreshForTests();

    // Steps 3 and 4 must still decrypt — from the durable vault, not RAM.
    const d3 = await decryptAsBob(payloads[3], aliceBundle);
    assert.equal(d3.text, 'پیام 3');
    const d4 = await decryptAsBob(payloads[4], aliceBundle);
    assert.equal(d4.text, 'پیام 4');

    // The consumed skipped keys are gone from the durable store.
    const after = await loadDurableRatchetState('bob', ROOM_ALICE_BOB);
    assert.ok(after);
    assert.deepEqual(after.skippedKeys.map(e => e.step), []);

    // And the session continues: step 6 (next chain step) still decrypts.
    const d6 = await decryptAsBob(payloads[6], aliceBundle);
    assert.equal(d6.text, 'پیام 6');
    assert.equal(d6.ratchetStep, 6);
  });

  it('round-trips a ratchet state through the encrypted store, and the stored bytes never contain plaintext', async () => {
    await ensureUserHybridKeyPair('alice');
    const state = craftedState([{ step: 3, timestamp: Date.now() }]);

    const stored = await persistDurableRatchetState('alice', ROOM_ALICE_BOB, state);
    assert.equal(stored, true, 'persist must succeed while the wrapping key is available');

    const loaded = await loadDurableRatchetState('alice', ROOM_ALICE_BOB);
    assert.ok(loaded, 'load must return the state');
    assert.deepEqual(loaded, state);

    const raw = fakeRatchetRecords();
    assert.equal(raw.length, 1);
    assert.ok(raw[0].iv instanceof Uint8Array);
    assert.ok(raw[0].ciphertext instanceof Uint8Array);
    assert.ok(raw[0].ciphertext.length > 100, 'ciphertext must hold the whole encrypted state');
    assert.equal(
      Buffer.from(raw[0].ciphertext).toString('utf8').includes('deadbeefdeadbeef'),
      false,
      'ciphertext must not contain the peer fingerprint plaintext'
    );
    assert.equal(
      JSON.stringify(raw[0]).includes('deadbeefdeadbeef'),
      false,
      'no stored field may contain plaintext state'
    );

    await deleteDurableRatchetState('alice', ROOM_ALICE_BOB);
    assert.equal(await loadDurableRatchetState('alice', ROOM_ALICE_BOB), null);
  });

  it('prunes expired skipped keys on load (10-minute TTL)', async () => {
    await ensureUserHybridKeyPair('alice');
    const now = Date.now();
    const state = craftedState([
      { step: 3, timestamp: now - 11 * 60 * 1000 }, // expired
      { step: 4, timestamp: now }, // fresh
    ]);
    assert.equal(await persistDurableRatchetState('alice', ROOM_ALICE_BOB, state), true);

    const loaded = await loadDurableRatchetState('alice', ROOM_ALICE_BOB);
    assert.ok(loaded);
    assert.deepEqual(loaded.skippedKeys.map(e => e.step), [4]);
  });

  it('a tampered record fails closed and is deleted', async () => {
    await ensureUserHybridKeyPair('alice');
    const state = craftedState([{ step: 3, timestamp: Date.now() }]);
    assert.equal(await persistDurableRatchetState('alice', ROOM_ALICE_BOB, state), true);

    const recs = fakeRatchetRecords();
    assert.equal(recs.length, 1);
    recs[0].ciphertext[0] ^= 0xff; // flip one byte — AES-GCM auth must fail

    assert.equal(await loadDurableRatchetState('alice', ROOM_ALICE_BOB), null);
    assert.equal(fakeRatchetRecords().length, 0, 'corrupt record must be removed');
  });

  it('locked identity (L8) cannot read or write the durable store, and unlock restores it', async () => {
    const { aliceBundle, bobBundle } = await makePair();
    const c1 = await encryptAsAlice('سلام', bobBundle);
    await decryptAsBob(c1, aliceBundle);
    assert.ok(await loadDurableRatchetState('bob', ROOM_ALICE_BOB));

    await enablePasswordProtection('bob', PASSPHRASE);
    await lockIdentity('bob');

    assert.equal(await loadDurableRatchetState('bob', ROOM_ALICE_BOB), null);
    assert.equal(
      await persistDurableRatchetState('bob', ROOM_ALICE_BOB, craftedState([])),
      false,
      'persist must no-op while the identity is locked'
    );

    // Unlock: the rewrap done at enable-time migrated the old record, so it reads again.
    await unlockIdentityWithPassphrase('bob', PASSPHRASE);
    const loaded = await loadDurableRatchetState('bob', ROOM_ALICE_BOB);
    assert.ok(loaded, 'record must survive the L8 rewrap and read after unlock');
    assert.equal(loaded.recvStep, 1);
  });

  it('clearRatchetSession also deletes the durable copy', async () => {
    const { aliceBundle, bobBundle } = await makePair();
    const c1 = await encryptAsAlice('سلام', bobBundle);
    await decryptAsBob(c1, aliceBundle);
    assert.ok(await loadDurableRatchetState('bob', ROOM_ALICE_BOB));

    clearRatchetSession('bob', ROOM_ALICE_BOB);
    // clearRatchetSession deletes the durable copy fire-and-forget.
    await new Promise(r => setTimeout(r, 50));
    assert.equal(await loadDurableRatchetState('bob', ROOM_ALICE_BOB), null);
  });
});
