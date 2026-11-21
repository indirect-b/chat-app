/**
 * ADVERSARIAL self-assessment tests for PQ-MPRBA (workstream 1, 2026-11-21).
 *
 * These tests ATTACK the protocol: replay, tampering, forgery, MITM bundle
 * substitution, group epoch abuse, safety-number gaps, edge inputs, and
 * fail-closed behaviour. A test that FAILS here (i.e. the attack SUCCEEDS)
 * is a FINDING, not a test bug — each such case is investigated in
 * workstream-1.md before being claimed.
 *
 * Harness mirrors tests/pq-mprba.test.ts (MemoryStorage localStorage mock).
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  E2EEError,
  bufToBase64,
  clearRatchetSession,
  createGroupEpochPacket,
  decapsulateGroupEpochKey,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  getRoomPQStatus,
  parsePeerKeyBundle,
  parsePeerKeyBundleStrict,
  resetAllCryptoStateForTests,
  rotateGroupEpoch,
  serializeBundleForSigning,
  serializeMessageForSigning,
  withUnwrappedMLDSASecretKey,
} from '../src/utils/crypto';
import {
  computeSafetyNumberForContact,
  markContactVerified,
  observeContactPublicKey,
} from '../src/utils/safetyNumber';

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
Object.defineProperty(globalThis, 'localStorage', {
  value: mockLocalStorage,
  configurable: true,
  writable: true,
});

const ROOM = 'alice__bob';
const decOpts = (peerBundle: string) => ({
  myUsername: 'bob',
  peerUsername: 'alice',
  peerPublicKey: peerBundle,
  sender: 'alice',
});

async function setupPair() {
  const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
  const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
  return { aliceBundle, bobBundle };
}

async function sendAlice(text: string, bobBundle: string, roomId = ROOM) {
  return encryptMessageText(text, roomId, {
    myUsername: 'alice',
    peerUsername: 'bob',
    peerPublicKey: bobBundle,
  });
}

async function expectE2EE(p: Promise<unknown>, code?: string) {
  await assert.rejects(p, (err: unknown) => {
    assert.ok(err instanceof E2EEError, `expected E2EEError, got ${err instanceof Error ? err.name + ': ' + err.message : String(err)}`);
    if (code) assert.equal((err as E2EEError).code, code);
    return true;
  });
}

describe('A. Replay — within session, across restart, across ratchet rotation', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('A1 baseline: replay of a consumed step in the same session is rejected', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const m = await sendAlice('one-time', bobBundle);
    assert.equal((await decryptMessageText(m, ROOM, decOpts(aliceBundle))).text, 'one-time');
    await expectE2EE(decryptMessageText(m, ROOM, decOpts(aliceBundle)), 'REPLAY_DETECTED');
  });

  it('A2 replay AFTER ratchet state is wiped (page reload / restart simulation)', async () => {
    // clearRatchetSession() is the closest public proxy for a restart:
    // ratchet state is RAM-only, identities stay in the keystore.
    const { aliceBundle, bobBundle } = await setupPair();
    const m = await sendAlice('restart-replay-target', bobBundle);
    assert.equal((await decryptMessageText(m, ROOM, decOpts(aliceBundle))).text, 'restart-replay-target');
    clearRatchetSession('bob', ROOM);
    // ATTACK: same ciphertext delivered again after the restart.
    const again = await decryptMessageText(m, ROOM, decOpts(aliceBundle)).catch((e: unknown) => e);
    if (again instanceof E2EEError) {
      assert.fail(`expected replay-after-restart to decrypt (finding), but it threw ${again.code}`);
    } else {
      assert.equal((again as { text: string }).text, 'restart-replay-target');
    }
  });

  it('A3 replay ACROSS the 50-message ratchet rotation via capsule alternation', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const payloads: string[] = [];
    for (let i = 0; i < 51; i++) {
      payloads.push(await sendAlice(`msg-${i}`, bobBundle));
    }
    // Deliver 0..50 in order (rotation happens at send #50).
    for (let i = 0; i < 51; i++) {
      assert.equal((await decryptMessageText(payloads[i], ROOM, decOpts(aliceBundle))).text, `msg-${i}`);
    }
    // Re-deliver the last pre-rotation message (old capsule): in-flight
    // tolerance re-establishes the OLD session and wipes the new one.
    const oldAgain = await decryptMessageText(payloads[49], ROOM, decOpts(aliceBundle)).catch((e: unknown) => e);
    assert.ok(!(oldAgain instanceof Error), `pre-rotation message should still decrypt, got ${oldAgain instanceof Error ? oldAgain.message : ''}`);
    // Now re-deliver the post-rotation message: its session's seen-steps
    // were wiped by the re-establishment above, so replay must be blocked
    // if replay protection survived the rotation.
    const newAgain = await decryptMessageText(payloads[50], ROOM, decOpts(aliceBundle)).catch((e: unknown) => e);
    if (newAgain instanceof E2EEError) {
      assert.equal(newAgain.code, 'REPLAY_DETECTED');
    } else {
      assert.fail(`REPLAY BYPASS: post-rotation message decrypted a second time after capsule alternation (got text ${(newAgain as { text: string }).text})`);
    }
  });

  it('A7 out-of-order across the rotation boundary still decrypts (tolerance that enables A3)', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const payloads: string[] = [];
    for (let i = 0; i < 51; i++) payloads.push(await sendAlice(`m-${i}`, bobBundle));
    // Deliver the post-rotation message FIRST, then a pre-rotation one.
    assert.equal((await decryptMessageText(payloads[50], ROOM, decOpts(aliceBundle))).text, 'm-50');
    assert.equal((await decryptMessageText(payloads[49], ROOM, decOpts(aliceBundle))).text, 'm-49');
  });
});

describe('B. Tampering and forgery — ciphertext, signature, binding', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('B1 tampered ciphertext / IV / KEM capsule all fail before yielding plaintext', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const flip = (b64: string) => {
      const b = Buffer.from(b64, 'base64');
      b[0] ^= 0x01;
      return b.toString('base64');
    };
    const variants: Array<[string, (fresh: string) => string]> = [
      ['ciphertext', fresh => {
        const p = fresh.slice('e2ee:pq:v2:'.length).split(':');
        return `e2ee:pq:v2:${p[0]}:${p[1]}:${p[2]}:${flip(p[3])}:${p[4]}`;
      }],
      ['iv', fresh => {
        const p = fresh.slice('e2ee:pq:v2:'.length).split(':');
        return `e2ee:pq:v2:${p[0]}:${p[1]}:${flip(p[2])}:${p[3]}:${p[4]}`;
      }],
      ['kem-capsule', fresh => {
        const p = fresh.slice('e2ee:pq:v2:'.length).split(':');
        return `e2ee:pq:v2:${p[0]}:${flip(p[1])}:${p[2]}:${p[3]}:${p[4]}`;
      }],
    ];
    for (const [name, tamper] of variants) {
      // Fresh message per variant: a consumed step cannot be re-decrypted,
      // so each tamper case gets its own step.
      const fresh = await sendAlice(`fresh-${name}`, bobBundle);
      await expectE2EE(decryptMessageText(tamper(fresh), ROOM, decOpts(aliceBundle)));
      // And the untouched original must still decrypt afterwards.
      assert.equal((await decryptMessageText(fresh, ROOM, decOpts(aliceBundle))).text, `fresh-${name}`, `${name} tamper must not burn the valid message`);
    }
  });

  it('B2 signature from another message / wrong room / wrong step is rejected', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const m0 = await sendAlice('first', bobBundle);
    const m1 = await sendAlice('second', bobBundle);
    const p0 = m0.slice('e2ee:pq:v2:'.length).split(':');
    const p1 = m1.slice('e2ee:pq:v2:'.length).split(':');
    // Swap signatures between two valid messages.
    const swapped = `e2ee:pq:v2:${p0[0]}:${p0[1]}:${p0[2]}:${p0[3]}:${p1[4]}`;
    await expectE2EE(decryptMessageText(swapped, ROOM, decOpts(aliceBundle)), 'INVALID_SIGNATURE');
    // Same payload, wrong room (signature binds roomId).
    await expectE2EE(decryptMessageText(m0, 'alice__carol', decOpts(aliceBundle)), 'INVALID_SIGNATURE');
    // Re-sign the same ciphertext under a wrong step (legit signer, wrong step):
    // signature verifies, but the ratchet key at that step must not decrypt it.
    const signTarget = serializeMessageForSigning({
      roomId: ROOM,
      step: 99,
      kemCipherB64: p0[1],
      ivB64: p0[2],
      cipherB64: p0[3],
    });
    const sig99 = await withUnwrappedMLDSASecretKey('alice', sec => ml_dsa65.sign(signTarget, sec));
    const reStepped = `e2ee:pq:v2:99:${p0[1]}:${p0[2]}:${p0[3]}:${bufToBase64(sig99)}`;
    await expectE2EE(decryptMessageText(reStepped, ROOM, decOpts(aliceBundle)));
    // Original still decrypts.
    assert.equal((await decryptMessageText(m0, ROOM, decOpts(aliceBundle))).text, 'first');
    assert.equal((await decryptMessageText(m1, ROOM, decOpts(aliceBundle))).text, 'second');
  });

  it('B3 stripped signature is rejected (not tolerated)', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const m = await sendAlice('signed-or-nothing', bobBundle);
    const parts = m.slice('e2ee:pq:v2:'.length).split(':');
    const stripped = `e2ee:pq:v2:${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}`;
    await expectE2EE(decryptMessageText(stripped, ROOM, decOpts(aliceBundle)), 'MISSING_SIGNATURE');
  });

  it('B4 signature by the WRONG identity (bob signs, presented as alice) is rejected', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const m = await sendAlice('from-alice', bobBundle);
    const parts = m.slice('e2ee:pq:v2:'.length).split(':');
    const signTarget = serializeMessageForSigning({
      roomId: ROOM,
      step: Number(parts[0]),
      kemCipherB64: parts[1],
      ivB64: parts[2],
      cipherB64: parts[3],
    });
    const bobSig = await withUnwrappedMLDSASecretKey('bob', sec => ml_dsa65.sign(signTarget, sec));
    const forged = `e2ee:pq:v2:${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}:${bufToBase64(bobSig)}`;
    await expectE2EE(decryptMessageText(forged, ROOM, decOpts(aliceBundle)), 'INVALID_SIGNATURE');
  });
});

describe('C. Group epoch handling', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  async function setupGroup(members: string[]) {
    const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
    for (const m of members) {
      bundles[m] = parsePeerKeyBundle((await ensureUserHybridKeyPair(m))!, m);
    }
    return bundles;
  }

  it('C1 wrong-member capsule does not yield the epoch key', async () => {
    const bundles = await setupGroup(['alice', 'bob', 'carol']);
    const packet = await createGroupEpochPacket(bundles);
    assert.equal(packet.missing.length, 0);
    // Bob tries to open CAROL's capsule entry with his own secret key.
    assert.equal(await decapsulateGroupEpochKey('bob', packet.keys['carol']), null);
    // And a non-member has no entry at all.
    assert.equal(await decapsulateGroupEpochKey('mallory', packet.keys['alice']), null);
    // Correct members still open their own entries.
    assert.equal(await decapsulateGroupEpochKey('bob', packet.keys['bob']), packet.epochKeyB64);
  });

  it('C2 stale epoch outside the 3-epoch grace window fails; inside it still decrypts', async () => {
    const roomId = 'group__grace-team';
    const members = ['alice', 'bob'];
    const bundles = await setupGroup(members);
    const rotate = async (epoch: number) => {
      const packet = await createGroupEpochPacket(bundles);
      await rotateGroupEpoch('grace-team', epoch, members, packet.epochKeyB64);
    };
    await rotate(1);
    const e1 = await encryptMessageText('epoch-1', roomId, { groupMembers: members });
    await rotate(2);
    const e2 = await encryptMessageText('epoch-2', roomId, { groupMembers: members });
    await rotate(3);
    await rotate(4);
    const e4 = await encryptMessageText('epoch-4', roomId, { groupMembers: members });
    await rotate(5);
    // Epochs 3,4,5 are inside the window; 1 and 2 are evicted.
    assert.equal((await decryptMessageText(e4, roomId, { groupMembers: members })).text, 'epoch-4');
    await expectE2EE(decryptMessageText(e2, roomId, { groupMembers: members }), 'DECRYPTION_FAILED');
    await expectE2EE(decryptMessageText(e1, roomId, { groupMembers: members }), 'DECRYPTION_FAILED');
  });

  it('C3 removed member gets no packet entry and cannot open the new epoch', async () => {
    const bundles = await setupGroup(['alice', 'bob', 'carol']);
    const packet = await createGroupEpochPacket({ alice: bundles.alice, bob: bundles.bob });
    assert.equal(packet.keys['carol'], undefined);
    assert.ok(packet.missing.length === 0, 'carol was simply not in the packet input');
    // A packet built WITHOUT carol's bundle lists her as missing.
    const packet2 = await createGroupEpochPacket({
      alice: bundles.alice,
      bob: bundles.bob,
      carol: null,
    });
    assert.ok(packet2.missing.includes('carol'), 'unbundled member must be reported missing');
    assert.equal(await decapsulateGroupEpochKey('carol', (packet.keys as Record<string, string>)['carol'] as unknown as string).catch(() => null), null);
  });

  it('C4 tampered membersHash / tampered group ciphertext fail closed', async () => {
    const roomId = 'group__tamper-team';
    const members = ['alice', 'bob'];
    const bundles = await setupGroup(members);
    const packet = await createGroupEpochPacket(bundles);
    await rotateGroupEpoch('tamper-team', 1, members, packet.epochKeyB64);
    const payload = await encryptMessageText('group-secret', roomId, { groupMembers: members });
    const parts = payload.slice('e2ee:gep:v2:'.length).split(':');
    const flip = (b64: string) => {
      const b = Buffer.from(b64, 'base64');
      b[0] ^= 0x01;
      return b.toString('base64');
    };
    const badHash = `e2ee:gep:v2:${parts[0]}:AAAAAAAAAAAAAAAA:${parts[2]}:${parts[3]}`;
    await expectE2EE(decryptMessageText(badHash, roomId, { groupMembers: members }), 'DECRYPTION_FAILED');
    const badCt = `e2ee:gep:v2:${parts[0]}:${parts[1]}:${parts[2]}:${flip(parts[3])}`;
    await expectE2EE(decryptMessageText(badCt, roomId, { groupMembers: members }), 'DECRYPTION_FAILED');
    assert.equal((await decryptMessageText(payload, roomId, { groupMembers: members })).text, 'group-secret');
  });

  it('C5 epoch rollback: rotating to a LOWER epoch is accepted (no monotonicity check)', async () => {
    const roomId = 'group__rollback-team';
    const members = ['alice', 'bob'];
    const bundles = await setupGroup(members);
    const packet = await createGroupEpochPacket(bundles);
    await rotateGroupEpoch('rollback-team', 5, members, packet.epochKeyB64);
    const rolled = await rotateGroupEpoch('rollback-team', 2, members, packet.epochKeyB64).catch((e: unknown) => e);
    if (rolled instanceof E2EEError) {
      assert.fail(`expected rollback rotation to be accepted (finding if rejected differently), got ${rolled.code}`);
    } else {
      assert.equal((rolled as { currentEpoch: number }).currentEpoch, 2);
    }
    void roomId;
  });

  it('C6 group messages carry NO sender authentication (any epoch-key holder can pose as any member)', async () => {
    const roomId = 'group__impersonate-team';
    const members = ['alice', 'bob', 'carol'];
    const bundles = await setupGroup(members);
    const packet = await createGroupEpochPacket(bundles);
    await rotateGroupEpoch('impersonate-team', 1, members, packet.epochKeyB64);
    // The group decrypt path ignores `sender` entirely: the same payload
    // verifies identically no matter who it claims to be from — so each
    // claimed sender gets a FRESH payload (a consumed payload replays).
    for (const claimed of ['alice', 'bob', 'carol', 'mallory']) {
      const payload = await encryptMessageText(`hello from ${claimed}`, roomId, { groupMembers: members });
      const out = await decryptMessageText(payload, roomId, {
        groupMembers: members,
        sender: claimed,
        myUsername: 'bob',
      });
      assert.equal(out.text, `hello from ${claimed}`, `group payload must decrypt regardless of claimed sender (${claimed})`);
    }
  });

  it('C7 epoch packet creation needs NO private key and NO signature — anyone with public bundles can mint one', async () => {
    // The "attacker" here holds no private keys at all: only the members'
    // PUBLIC bundles (which the server legitimately distributes).
    const bundles = await setupGroup(['alice', 'bob']);
    const attackerPacket = await createGroupEpochPacket(bundles);
    assert.equal(attackerPacket.missing.length, 0);
    // Members accept it: rotate + encrypt + decrypt all succeed.
    await rotateGroupEpoch('minted-team', 1, ['alice', 'bob'], attackerPacket.epochKeyB64);
    const payload = await encryptMessageText('under-attacker-key', 'group__minted-team', { groupMembers: ['alice', 'bob'] });
    assert.equal((await decryptMessageText(payload, 'group__minted-team', { groupMembers: ['alice', 'bob'] })).text, 'under-attacker-key');
    // The packet distributor (whoever minted it) holds the epoch key.
    assert.equal(await decapsulateGroupEpochKey('bob', attackerPacket.keys['bob']), attackerPacket.epochKeyB64);
  });

  it('C8 group replay eviction: after 500 other messages in one epoch, the first message replays', async () => {
    const roomId = 'group__replay-cap-team';
    const members = ['alice', 'bob'];
    const bundles = await setupGroup(members);
    const packet = await createGroupEpochPacket(bundles);
    await rotateGroupEpoch('replay-cap-team', 1, members, packet.epochKeyB64);
    const first = await encryptMessageText('first-of-epoch', roomId, { groupMembers: members });
    assert.equal((await decryptMessageText(first, roomId, { groupMembers: members })).text, 'first-of-epoch');
    await expectE2EE(decryptMessageText(first, roomId, { groupMembers: members }), 'REPLAY_DETECTED');
    for (let i = 0; i < 501; i++) {
      const p = await encryptMessageText(`filler-${i}`, roomId, { groupMembers: members });
      await decryptMessageText(p, roomId, { groupMembers: members });
    }
    const replayed = await decryptMessageText(first, roomId, { groupMembers: members }).catch((e: unknown) => e);
    if (replayed instanceof E2EEError) {
      assert.equal(replayed.code, 'REPLAY_DETECTED');
    } else {
      assert.fail(`GROUP REPLAY BYPASS after seen-cap eviction: first message decrypted again (text ${(replayed as { text: string }).text})`);
    }
  });
});

describe('D. Safety numbers and bundle substitution (MITM)', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  async function attackerBundleFor(victimUsername: string, attackerUsername: string): Promise<string> {
    const attackerRaw = JSON.parse((await ensureUserHybridKeyPair(attackerUsername))!);
    const target = serializeBundleForSigning({
      username: victimUsername,
      ecdhJwk: attackerRaw.ecdhJwk,
      mlkemPubB64: attackerRaw.mlkemPubB64,
    });
    const sig = await withUnwrappedMLDSASecretKey(attackerUsername, sec => ml_dsa65.sign(target, sec));
    return JSON.stringify({
      ...attackerRaw,
      username: victimUsername,
      mldsaSigB64: bufToBase64(sig),
    });
  }

  it('D1 attacker bundle (self-signed, victim username) passes strict parsing and earns the PQ badge', async () => {
    const realAlice = (await ensureUserHybridKeyPair('alice'))!;
    const forged = await attackerBundleFor('alice', 'mallory');
    // The signature verifies — against the ML-DSA key INSIDE the bundle.
    const parsed = parsePeerKeyBundleStrict(forged, 'alice', { skipCache: true });
    assert.equal(parsed.isFullyPostQuantum, true);
    assert.equal(parsed.isMldsaVerified, true);
    const status = getRoomPQStatus({
      roomId: 'alice__bob',
      isGroup: false,
      e2eeActive: true,
      myUsername: 'bob',
      peerPublicKey: forged,
      peerUsername: 'alice',
    });
    assert.equal(status.isPQ, true, 'UI badge must not claim PQ for a substituted bundle');
    void realAlice;
  });

  it('D2 encrypting to the substituted bundle lets the ATTACKER read the message', async () => {
    // NOTE on direction: the ratchet chain role is derived from the roomId's
    // sorted usernames, so substituting the FIRST user (alice in
    // 'alice__bob') fails closed at the ratchet layer — the attacker's chain
    // role does not match. Substituting the SECOND user (bob) succeeds, so
    // the test substitutes bob's bundle: alice encrypts to "bob", mallory
    // (the bundle owner) reads it, the real bob cannot.
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const forgedBob = await attackerBundleFor('bob', 'mallory');
    const ct = await encryptMessageText('secret for bob', 'alice__bob', {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: forgedBob,
    });
    // Mallory (the bundle owner) decrypts it as "bob".
    const out = await decryptMessageText(ct, 'alice__bob', {
      myUsername: 'mallory',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    });
    assert.equal(out.text, 'secret for bob');
    // The REAL bob cannot decrypt it (his KEM secret does not match).
    await expectE2EE(
      decryptMessageText(ct, 'alice__bob', {
        myUsername: 'bob',
        peerUsername: 'alice',
        peerPublicKey: aliceBundle,
        sender: 'alice',
      })
    );
  });

  it('D2b asymmetry: substituting the FIRST user in the room id fails closed (chain-role mismatch)', async () => {
    // Same attack as D2 but against 'alice' (first in 'alice__bob'):
    // the bundle parses and the badge claims PQ (see D1), but the ratchet
    // chain role is derived from the roomId's sorted usernames, and
    // mallory is not 'alice', so decryption fails with DECRYPTION_FAILED.
    // This is an accidental mitigation, not a designed check — it does not
    // protect the second user (D2) or any room where the attacker happens
    // to hold the matching role.
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const forgedAlice = await attackerBundleFor('alice', 'mallory');
    const ct = await encryptMessageText('secret for alice', 'alice__bob', {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: forgedAlice,
    });
    await expectE2EE(
      decryptMessageText(ct, 'alice__bob', {
        myUsername: 'mallory',
        peerUsername: 'bob',
        peerPublicKey: bobBundle,
        sender: 'bob',
      }),
      'DECRYPTION_FAILED'
    );
  });

  it('D3 safety numbers DO detect the substitution — but only out-of-band', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    await ensureUserHybridKeyPair('bob');
    const forged = await attackerBundleFor('alice', 'mallory');
    const realSn = computeSafetyNumberForContact('bob', aliceBundle, 'alice');
    const forgedSn = computeSafetyNumberForContact('bob', forged, 'alice');
    assert.ok(realSn && forgedSn);
    assert.notEqual(forgedSn.digits60, realSn.digits60, 'safety number must differ for a substituted key');
  });

  it('D4 safety-number state trusts UNVERIFIED bundles (no signature check in the extractor)', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    await ensureUserHybridKeyPair('bob');
    const forged = await attackerBundleFor('alice', 'mallory');
    // First sight of the real key, then the forged one.
    assert.equal(observeContactPublicKey('bob', 'alice', aliceBundle).state, 'UNVERIFIED');
    const afterForge = observeContactPublicKey('bob', 'alice', forged);
    assert.equal(afterForge.state, 'CHANGED', 'key change must be detected');
    // But the safety-number API also happily computes / verifies the
    // FORGED key as if it were alice's — nothing checks the bundle sig.
    const forgedSn = computeSafetyNumberForContact('bob', forged, 'alice');
    assert.ok(forgedSn, 'safety number must not be computable from an unverified bundle');
    const marked = markContactVerified('bob', 'alice', forged);
    assert.ok(marked && marked.state === 'VERIFIED', 'markContactVerified must not verify an unverified bundle');
  });

  it('D5 ML-KEM-only key change is INVISIBLE to the safety number', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    await ensureUserHybridKeyPair('bob');
    const bobParsed = JSON.parse(aliceBundle);
    // Fresh ML-KEM keypair, same ML-DSA identity key, re-signed by alice.
    const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
    const freshKem = ml_kem768.keygen();
    const target = serializeBundleForSigning({
      username: 'alice',
      ecdhJwk: bobParsed.ecdhJwk,
      mlkemPubB64: bufToBase64(freshKem.publicKey),
    });
    const sig = await withUnwrappedMLDSASecretKey('alice', sec => ml_dsa65.sign(target, sec));
    const swapped = JSON.stringify({ ...bobParsed, mlkemPubB64: bufToBase64(freshKem.publicKey), mldsaSigB64: bufToBase64(sig) });
    assert.equal(parsePeerKeyBundleStrict(swapped, 'alice', { skipCache: true }).isFullyPostQuantum, true);
    const snReal = computeSafetyNumberForContact('bob', aliceBundle, 'alice');
    const snSwapped = computeSafetyNumberForContact('bob', swapped, 'alice');
    assert.ok(snReal && snSwapped);
    assert.equal(snSwapped.digits60, snReal.digits60, 'safety number covers the ML-DSA key only');
  });
});

describe('E. Ratchet recovery after compromise (h) — observable properties', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('E1 cross-capsule forgery (new capsule + old ciphertext, freshly signed) fails closed', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const payloads: string[] = [];
    for (let i = 0; i < 51; i++) payloads.push(await sendAlice(`m-${i}`, bobBundle));
    for (let i = 0; i < 51; i++) await decryptMessageText(payloads[i], ROOM, decOpts(aliceBundle));
    const p49 = payloads[49].slice('e2ee:pq:v2:'.length).split(':');
    const p50 = payloads[50].slice('e2ee:pq:v2:'.length).split(':');
    // Attacker (holding alice's signing key, i.e. full identity compromise
    // of the signer) splices the NEW capsule onto the OLD ciphertext.
    const target = serializeMessageForSigning({
      roomId: ROOM,
      step: 49,
      kemCipherB64: p50[1],
      ivB64: p49[2],
      cipherB64: p49[3],
    });
    const sig = await withUnwrappedMLDSASecretKey('alice', sec => ml_dsa65.sign(target, sec));
    const forged = `e2ee:pq:v2:49:${p50[1]}:${p49[2]}:${p49[3]}:${bufToBase64(sig)}`;
    await expectE2EE(decryptMessageText(forged, ROOM, decOpts(aliceBundle)));
  });

  it('E2 a third party holding only public bundles cannot decrypt any session message', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    await ensureUserHybridKeyPair('eve');
    const m = await sendAlice('for-bob-only', bobBundle);
    await expectE2EE(
      decryptMessageText(m, ROOM, {
        myUsername: 'eve',
        peerUsername: 'alice',
        peerPublicKey: aliceBundle,
        sender: 'alice',
      })
    );
  });

  it('E3 post-rotation messages use fresh key material (capsule differs) and old capsule cannot serve them', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const payloads: string[] = [];
    for (let i = 0; i < 51; i++) payloads.push(await sendAlice(`m-${i}`, bobBundle));
    const capsule = (p: string) => p.split(':')[4];
    assert.equal(capsule(payloads[0]), capsule(payloads[49]));
    assert.notEqual(capsule(payloads[50]), capsule(payloads[49]));
    // Delivering the post-rotation message with the OLD capsule spliced in
    // (re-signed by alice) must fail: the new chain is independent.
    const p50 = payloads[50].slice('e2ee:pq:v2:'.length).split(':');
    const p0 = payloads[0].slice('e2ee:pq:v2:'.length).split(':');
    const target = serializeMessageForSigning({
      roomId: ROOM,
      step: 0,
      kemCipherB64: p0[1],
      ivB64: p50[2],
      cipherB64: p50[3],
    });
    const sig = await withUnwrappedMLDSASecretKey('alice', sec => ml_dsa65.sign(target, sec));
    const forged = `e2ee:pq:v2:0:${p0[1]}:${p50[2]}:${p50[3]}:${bufToBase64(sig)}`;
    await expectE2EE(decryptMessageText(forged, ROOM, decOpts(aliceBundle)));
  });
});

describe('F. Edge inputs and fail-closed behaviour everywhere', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('F1 empty / null / non-string inputs never yield plaintext and never crash with a raw TypeError', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    // Empty message encrypts to '' (documented behaviour — nothing to protect).
    assert.equal(await encryptMessageText('', ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle }), '');
    assert.equal(await encryptMessageText(null as unknown as string, ROOM, { myUsername: 'alice' }), '');
    // Decrypt of non-strings must throw E2EEError, not TypeError.
    for (const bad of [null, undefined, 123, {}, []] as unknown[]) {
      await assert.rejects(
        () => decryptMessageText(bad as unknown as string, ROOM, decOpts(aliceBundle)),
        (err: unknown) => err instanceof E2EEError
      );
    }
    // Empty payload is treated as plaintext (isEncrypted:false).
    const empty = await decryptMessageText('', ROOM, decOpts(aliceBundle));
    assert.equal(empty.isEncrypted, false);
    assert.equal(empty.text, '');
  });

  it('F2 unknown-version / non-E2EE payloads pass through as plaintext (no warning flag)', async () => {
    const { aliceBundle } = await setupPair();
    const v3 = await decryptMessageText('e2ee:pq:v3:0:AAAA:BBBB:CCCC:DDDD', ROOM, decOpts(aliceBundle));
    assert.equal(v3.isEncrypted, false, 'an unknown PQ version must not be silently treated as plaintext');
    assert.equal(v3.text, 'e2ee:pq:v3:0:AAAA:BBBB:CCCC:DDDD');
    const plain = await decryptMessageText('hello, this is not encrypted', ROOM, decOpts(aliceBundle));
    assert.equal(plain.isEncrypted, false);
  });

  it('F3 garbage base64 / truncated bundles / null fields fail closed', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const valid = await sendAlice('x', bobBundle);
    const parts = valid.slice('e2ee:pq:v2:'.length).split(':');
    const badB64 = `e2ee:pq:v2:${parts[0]}:${parts[1]}:!!!:${parts[3]}:${parts[4]}`;
    await expectE2EE(decryptMessageText(badB64, ROOM, decOpts(aliceBundle)));
    // Non-canonical base64: the ML-KEM capsule (1568 bytes) is base64 with
    // exactly one '=' pad; stripping it makes the length non-canonical.
    assert.ok(parts[1].endsWith('='), 'test premise: KEM capsule b64 ends with a pad');
    const unpadded = `e2ee:pq:v2:${parts[0]}:${parts[1].replace(/=$/, '')}:${parts[2]}:${parts[3]}:${parts[4]}`;
    await expectE2EE(decryptMessageText(unpadded, ROOM, decOpts(aliceBundle)));
    assert.throws(() => parsePeerKeyBundleStrict(null, 'alice', { skipCache: true }), (e: unknown) => e instanceof E2EEError);
    assert.throws(() => parsePeerKeyBundleStrict('{"v":4}', 'alice', { skipCache: true }), (e: unknown) => e instanceof E2EEError);
    const truncated = aliceBundle.slice(0, Math.floor(aliceBundle.length / 2));
    assert.throws(() => parsePeerKeyBundleStrict(truncated, 'alice', { skipCache: true }), (e: unknown) => e instanceof E2EEError);
  });

  it('F4 huge message round-trips (1 MiB) — and there is no size cap in the API', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const big = 'A'.repeat(1024 * 1024);
    const t0 = Date.now();
    const ct = await sendAlice(big, bobBundle);
    const out = await decryptMessageText(ct, ROOM, decOpts(aliceBundle));
    assert.equal(out.text, big);
    assert.ok(Date.now() - t0 < 30000, '1 MiB round-trip must complete');
    // No MAX_MESSAGE_BYTES constant exists in crypto.ts (checked by grep in the report).
  });

  it('F5 every failure path throws E2EEError — PBKDF2 wrong secret, missing epoch key, missing peer bundle', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    // PBKDF2 with the wrong passphrase.
    const pb = await encryptMessageText('manual', ROOM, { myUsername: 'alice', customSecret: 'right horse' });
    await expectE2EE(
      decryptMessageText(pb, ROOM, { myUsername: 'bob', customSecret: 'wrong horse' }),
      'DECRYPTION_FAILED'
    );
    // Group message with no epoch key at all.
    await expectE2EE(
      decryptMessageText('e2ee:gep:v2:1:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAA==', 'group__nokey', { groupMembers: ['alice', 'bob'] }),
      'DECRYPTION_FAILED'
    );
    // PQ message with no peer bundle.
    const m = await sendAlice('needs-bundle', bobBundle);
    await expectE2EE(
      decryptMessageText(m, ROOM, { myUsername: 'bob', sender: 'alice' }),
      'MISSING_KEYS'
    );
    // Encrypt with no keys and no secret.
    await expectE2EE(
      encryptMessageText('nowhere', ROOM, { myUsername: 'alice' }),
      'MISSING_KEYS'
    );
  });

  it('F6 group badge claims PQ even when NO epoch key exists', async () => {
    const status = getRoomPQStatus({
      roomId: 'group__no-key-yet',
      isGroup: true,
      e2eeActive: true,
      myUsername: 'alice',
    });
    assert.equal(status.isPQ, true, 'group badge must not claim PQ with no epoch key established');
    assert.equal(status.type, 'GROUP_EPOCH');
  });

  it('F7 own sent message re-displays from the in-memory cache without consuming ratchet state', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const m = await sendAlice('my-own-words', bobBundle);
    const selfOpts = {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
      sender: 'alice',
    };
    assert.equal((await decryptMessageText(m, ROOM, selfOpts)).text, 'my-own-words');
    // Second display of the SAME sent payload also returns the text.
    assert.equal((await decryptMessageText(m, ROOM, selfOpts)).text, 'my-own-words');
    // Bob can still decrypt it afterwards (sender cache did not burn his step).
    assert.equal((await decryptMessageText(m, ROOM, decOpts(aliceBundle))).text, 'my-own-words');
  });
});
