import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  E2EEError,
  E2EE_GROUP_EPOCH_V3_PREFIX,
  clearRatchetSession,
  createGroupEpochPacket,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  parsePeerKeyBundle,
  resetAllCryptoStateForTests,
  rotateGroupEpoch,
  setRoomSecret,
} from '../src/utils/crypto';
import { isDurableReplaySeen } from '../src/utils/keystore';

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

/** Rotate epoch 1 for a fresh group and return the members' bundles. */
async function setupGroup(groupId: string, members: string[]) {
  const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
  const bundleStrs: Record<string, string> = {};
  for (const m of members) {
    bundleStrs[m] = (await ensureUserHybridKeyPair(m))!;
    bundles[m] = parsePeerKeyBundle(bundleStrs[m], m);
  }
  const packet = await createGroupEpochPacket(bundles, members[0], 1);
  await rotateGroupEpoch(groupId, 1, members, packet.epochKeyB64);
  return { bundles, bundleStrs };
}

describe('Fix round 5 — crypto (M1, L3, L4, L5, L6 + M4 report auth)', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    mockSessionStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('M1: DM replay is rejected after ratchet-state loss (refresh) via the durable store', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';
    const payload = await encryptMessageText('m1 secret', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });
    assert.ok(payload.startsWith('e2ee:pq:v2:0:'));

    const opts = {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    };
    assert.equal((await decryptMessageText(payload, roomId, opts)).text, 'm1 secret');

    // Same-session replay is already blocked by RAM state.
    await assert.rejects(
      () => decryptMessageText(payload, roomId, opts),
      (err: unknown) => err instanceof E2EEError && err.code === 'REPLAY_DETECTED'
    );

    // Simulate a refresh: RAM ratchet state is lost, identities + durable
    // store survive. Before the fix this returned the full plaintext.
    clearRatchetSession('bob', roomId);
    await assert.rejects(
      () => decryptMessageText(payload, roomId, opts),
      (err: unknown) => err instanceof E2EEError && err.code === 'REPLAY_DETECTED'
    );
  });

  it('M1: a durable-store error fails closed (REPLAY_CHECK_FAILED), never "not seen"', async () => {
    const originalIndexedDB = (globalThis as any).indexedDB;
    (globalThis as any).indexedDB = {
      open: () => {
        throw new Error('IDB unavailable');
      },
    };
    try {
      await assert.rejects(
        () => isDurableReplaySeen('alice__bob', 'some-token'),
        (err: unknown) => err instanceof Error && err.message.startsWith('DURABLE_REPLAY_CHECK_FAILED')
      );
    } finally {
      if (originalIndexedDB === undefined) delete (globalThis as any).indexedDB;
      else (globalThis as any).indexedDB = originalIndexedDB;
    }
  });

  it('L3: v3 group decrypt without sender/bundle fails closed (pentest case 8c)', async () => {
    const { bundleStrs } = await setupGroup('l3-team', ['alice', 'bob']);
    const roomId = 'group__l3-team';
    const payload = await encryptMessageText('l3 group secret', roomId, {
      myUsername: 'alice',
      groupMembers: ['alice', 'bob'],
    });
    assert.ok(payload.startsWith(E2EE_GROUP_EPOCH_V3_PREFIX));

    // No sender, no peer key — used to return plaintext with mldsaVerified:false.
    await assert.rejects(
      () => decryptMessageText(payload, roomId, { myUsername: 'bob', groupMembers: ['alice', 'bob'] }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_BUNDLE'
    );
    // Sender named but no key anywhere (own key is never in the peer
    // store) — also fails closed.
    await assert.rejects(
      () =>
        decryptMessageText(payload, roomId, {
          myUsername: 'bob',
          sender: 'alice',
          groupMembers: ['alice', 'bob'],
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_BUNDLE'
    );

    // With sender + verified bundle it still decrypts and verifies
    // (existing M3 behavior, must keep passing).
    const dec = await decryptMessageText(payload, roomId, {
      myUsername: 'bob',
      sender: 'alice',
      peerPublicKey: bundleStrs['alice'],
      groupMembers: ['alice', 'bob'],
    });
    assert.equal(dec.text, 'l3 group secret');
    assert.equal(dec.mldsaVerified, true);
  });

  it('L3: self-sent v3 group messages still decrypt (sender-is-me exemption)', async () => {
    await setupGroup('l3-self', ['alice', 'bob']);
    const roomId = 'group__l3-self';
    const payload = await encryptMessageText('my own group note', roomId, {
      myUsername: 'alice',
      groupMembers: ['alice', 'bob'],
    });
    assert.ok(payload.startsWith(E2EE_GROUP_EPOCH_V3_PREFIX));

    // No peer key for myself exists anywhere — the exemption (not a
    // fail-open) is what keeps this readable.
    const dec = await decryptMessageText(payload, roomId, {
      myUsername: 'alice',
      sender: 'alice',
      groupMembers: ['alice', 'bob'],
    });
    assert.equal(dec.text, 'my own group note');
  });

  it('L5: a manual room secret no longer downgrades PQ encryption to PBKDF2 (DM)', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    setRoomSecret('alice__bob', 'correct-horse-battery');

    const payload = await encryptMessageText('pq despite secret', 'alice__bob', {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });
    assert.ok(payload.startsWith('e2ee:pq:'), `expected a PQ payload, got ${payload.slice(0, 20)}`);

    // Decrypt is format-driven, so bob still opens it as PQ.
    const dec = await decryptMessageText(payload, 'alice__bob', {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    });
    assert.equal(dec.text, 'pq despite secret');
    assert.equal(dec.mode, 'PQ-MLKEM-RATCHET');
  });

  it('L5: a manual room secret no longer downgrades PQ group encryption', async () => {
    await setupGroup('l5-team', ['alice', 'bob']);
    setRoomSecret('group__l5-team', 'correct-horse-battery');

    const payload = await encryptMessageText('pq group despite secret', 'group__l5-team', {
      myUsername: 'alice',
      groupMembers: ['alice', 'bob'],
    });
    assert.ok(payload.startsWith('e2ee:gep:v3:'), `expected a signed v3 payload, got ${payload.slice(0, 20)}`);
  });

  it('L5: manual secret + no PQ bundle still uses PBKDF2; classical-only peer keeps the old fallback', async () => {
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    await ensureUserHybridKeyPair('alice');
    setRoomSecret('alice__bob', 'correct-horse-battery');

    // No peer bundle at all → PBKDF2, unchanged.
    const v1 = await encryptMessageText('legacy secret msg', 'alice__bob', { myUsername: 'alice' });
    assert.ok(v1.startsWith('e2ee:v1:'));

    // Classical-only peer (bare ECDH JWK, no ML-KEM/ML-DSA) + manual
    // secret → PBKDF2 as before.
    const classicalOnly = JSON.stringify(JSON.parse(bobBundle).ecdhJwk);
    const v1b = await encryptMessageText('classical peer msg', 'alice__bob', {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: classicalOnly,
    });
    assert.ok(v1b.startsWith('e2ee:v1:'));

    // ...but without a manual secret a classical-only peer is still
    // rejected fail-closed (DP-15).
    setRoomSecret('alice__bob', '');
    await assert.rejects(
      () =>
        encryptMessageText('no secret, classical peer', 'alice__bob', {
          myUsername: 'alice',
          peerUsername: 'bob',
          peerPublicKey: classicalOnly,
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_BUNDLE'
    );
  });

  it('L6: DM decrypt binds the envelope sender to the verified bundle (pentest case 7a)', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';
    const payload = await encryptMessageText('signed by alice', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });

    // Spoofed envelope sender: Alice's bundle + sender='carol' must throw.
    await assert.rejects(
      () =>
        decryptMessageText(payload, roomId, {
          myUsername: 'bob',
          peerUsername: 'alice',
          peerPublicKey: aliceBundle,
          sender: 'carol',
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_SIGNATURE'
    );

    // Correct sender still decrypts.
    const dec = await decryptMessageText(payload, roomId, {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    });
    assert.equal(dec.text, 'signed by alice');
    assert.equal(dec.mldsaVerified, true);
  });

  it('L6 (group): a v3 message whose bundle username mismatches the sender is rejected', async () => {
    const { bundleStrs } = await setupGroup('l6-team', ['alice', 'bob']);
    const roomId = 'group__l6-team';
    const payload = await encryptMessageText('group secret', roomId, {
      myUsername: 'alice',
      groupMembers: ['alice', 'bob'],
    });

    // Alice's bundle presented with sender='carol': parsePeerKeyBundle
    // flags the username mismatch as isMldsaSignatureInvalid, and the
    // L3 fail-closed check turns that into INVALID_SIGNATURE.
    await assert.rejects(
      () =>
        decryptMessageText(payload, roomId, {
          myUsername: 'bob',
          sender: 'carol',
          peerPublicKey: bundleStrs['alice'],
          groupMembers: ['alice', 'bob'],
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_SIGNATURE'
    );
  });

  it('L4: ChatApp warns visibly on unverified group messages (GROUP-EPOCH-FSM + mldsaVerified===false)', () => {
    const chatSrc = fs.readFileSync(
      path.join(__dirname, '..', 'src', 'components', 'ChatApp.tsx'),
      'utf-8'
    );
    const warnAt = chatSrc.indexOf('⚠️ امضا تأیید نشد');
    assert.ok(warnAt !== -1, 'ChatApp must render an unverified-signature warning');
    const condition = chatSrc.slice(Math.max(0, warnAt - 500), warnAt);
    assert.match(condition, /GROUP-EPOCH-FSM/, 'warning must be conditioned on GROUP-EPOCH-FSM');
    assert.match(condition, /mldsaVerified === false/, 'warning must be conditioned on mldsaVerified===false');
  });

  it('M4: ChatApp sends the session token on POST /api/report', () => {
    const chatSrc = fs.readFileSync(
      path.join(__dirname, '..', 'src', 'components', 'ChatApp.tsx'),
      'utf-8'
    );
    const reportAt = chatSrc.indexOf("fetch('/api/report'");
    assert.ok(reportAt !== -1, 'handleSubmitReport must call /api/report');
    const call = chatSrc.slice(reportAt, reportAt + 400);
    assert.match(call, /Authorization: `Bearer \$\{getSessionToken\(\)\}`/);
  });
});
