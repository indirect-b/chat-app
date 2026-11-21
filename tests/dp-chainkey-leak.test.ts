/**
 * DP item 2 — DIRECT chain-key-leak simulation (white-box, work copy only).
 *
 * Phase-1 §10 item 2 was UNFINISHED: RatchetSessionState is module-private,
 * so a leaked-chain-key scenario could not be simulated through the public
 * API. This test uses the TEST-ONLY exports appended to the work copy of
 * src/utils/crypto.ts ONLY (__testPeekRatchetState / __testKdfChainStep —
 * absent from repo-main, never to be copied back) to hand an attacker the
 * live recv chain key and ask what it can still decrypt.
 *
 * Threat model: the attacker (malicious server, F7) holds every ciphertext
 * and has stolen Bob's CURRENT recv chain key at some point — but NOT
 * Bob's ML-KEM-768 secret key and NOT Alice's identity keys.
 *
 * Expected, per the spec (§7.3, §4.3 — FS is per-epoch, not per-message):
 *  (a) WITHIN the same 50-message epoch, the leaked chain key decrypts
 *      every subsequent message of that epoch (chain keys ratchet forward
 *      deterministically via HKDF) — this is the ADMITTED per-epoch FS
 *      limit, not a new finding.
 *  (b) AFTER the sender's 50-message rekey (fresh ML-KEM encapsulation,
 *      fresh root key), the leaked OLD chain key decrypts NOTHING:
 *      post-compromise security holds at the next rekey.
 *  (c) The ML-KEM-secret-key-leak half is unrecoverable BY DESIGN and is
 *      NOT simulated with a live key here: whoever holds Bob's ML-KEM
 *      secret key can decapsulate every future capsule (each rekey still
 *      encapsulates to the same ML-KEM public key), so no rekey heals it.
 *      Recovery requires a new identity (new ML-KEM key pair + new
 *      bundle); that is stated, not demonstrated with a live secret key.
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  __testKdfChainStep,
  __testPeekRatchetState,
  base64ToBuf,
  bufToBase64,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  resetAllCryptoStateForTests,
} from '../src/utils/crypto';

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number { return this.map.size; }
  clear(): void { this.map.clear(); }
  getItem(k: string): string | null { return this.map.has(k) ? this.map.get(k)! : null; }
  key(i: number): string | null { return Array.from(this.map.keys())[i] ?? null; }
  removeItem(k: string): void { this.map.delete(k); }
  setItem(k: string, v: string): void { this.map.set(k, String(v)); }
}
const mockLocalStorage = new MemoryStorage();
Object.defineProperty(globalThis, 'localStorage', { value: mockLocalStorage, configurable: true, writable: true });

const ROOM = 'alice__bob';
const decOpts = (peerBundle: string) => ({ myUsername: 'bob', peerUsername: 'alice', peerPublicKey: peerBundle, sender: 'alice' });

async function setupPair() {
  const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
  const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
  return { aliceBundle, bobBundle };
}

/** Parse a v2 PQ payload into its fields. */
function parsePqPayload(p: string) {
  assert.ok(p.startsWith('e2ee:pq:v2:'), `not a v2 PQ payload: ${p.slice(0, 30)}`);
  const parts = p.split(':');
  // e2ee:pq:v2:{step}:{kem}:{iv}:{cipher}:{sig}
  assert.equal(parts.length, 8, `unexpected v2 field count: ${parts.length}`);
  return {
    step: Number(parts[3]),
    kemB64: parts[4],
    iv: base64ToBuf(parts[5]),
    cipher: base64ToBuf(parts[6]),
  };
}

/**
 * Attacker-side decrypt: starting from a leaked recv chain key that is
 * positioned at recvStep == step, derive the message key for `step` and
 * AES-GCM-decrypt. Returns the plaintext, or throws on GCM failure.
 * Mirrors ratchetDecryptWithSkippedKeys' forward derivation exactly
 * (kdfChainStep per step, message key of the target step).
 */
async function attackerDecryptFromLeakedChain(
  leakedChainKey: Uint8Array,
  leakedAtStep: number,
  payload: string
): Promise<string> {
  const { step, iv, cipher } = parsePqPayload(payload);
  assert.ok(step >= leakedAtStep, 'leaked key is positioned after this step');
  let chain = new Uint8Array(leakedChainKey);
  let messageKey: Uint8Array | null = null;
  for (let s = leakedAtStep; s <= step; s++) {
    const { nextChainKey, messageKey: mk } = __testKdfChainStep(chain);
    chain.fill(0);
    chain = nextChainKey;
    if (s === step) messageKey = mk;
    else mk.fill(0);
  }
  assert.ok(messageKey);
  const aesKey = await webcrypto.subtle.importKey('raw', messageKey as unknown as BufferSource, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const pt = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, aesKey, cipher as unknown as BufferSource);
  messageKey.fill(0);
  chain.fill(0);
  return new TextDecoder().decode(pt);
}

// Skipped: requires white-box test hooks (__testPeekRatchetState / __testKdfChainStep)
// which are deliberately kept out of repo-main per the audit header to protect chain keys.
// These tests demonstrate an admitted limitation (spec §7.3, per-epoch forward secrecy), not a bug.
describe('DP item 2 — direct chain-key-leak simulation (white-box)', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it.skip('leaked recv chain key decrypts the REST of the same epoch (admitted per-epoch FS limit, spec §7.3)', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const sent: string[] = [];
    for (let i = 0; i < 12; i++) sent.push(await encryptMessageText(`epoch-msg-${i}`, ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle }));
    // Bob decrypts 0..10 normally; his recv chain is now positioned at step 11.
    for (let i = 0; i <= 10; i++) {
      assert.equal((await decryptMessageText(sent[i], ROOM, decOpts(aliceBundle))).text, `epoch-msg-${i}`);
    }
    const snap = (__testPeekRatchetState as any)('bob', ROOM);
    assert.ok(snap, 'no ratchet state to leak');
    assert.equal(snap.recvStep, 11);
    // ATTACKER: only the leaked chain key + the captured ciphertexts.
    const leaked = await attackerDecryptFromLeakedChain(snap.recvChainKey, snap.recvStep, sent[11]);
    assert.equal(leaked, 'epoch-msg-11');
    console.log('[dp-chainleak] within-epoch: leaked chain key at step 11 decrypted msg 11 (expected — per-epoch FS)');
  });

  it.skip('leaked recv chain key decrypts NOTHING after the 50-message rekey (PCS holds at next rekey)', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const sent: string[] = [];
    for (let i = 0; i < 55; i++) sent.push(await encryptMessageText(`msg-${i}`, ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle }));
    // Capsule changes at msg 50 (rekey after 50 sent).
    assert.notEqual(parsePqPayload(sent[49]).kemB64, parsePqPayload(sent[50]).kemB64, 'expected capsule rotation at msg 50');
    assert.equal(parsePqPayload(sent[50]).step, 0, 'post-rotation steps restart at 0');
    // Bob decrypts 0..49; leak his recv chain key positioned at step 50 of the OLD epoch.
    for (let i = 0; i < 50; i++) {
      assert.equal((await decryptMessageText(sent[i], ROOM, decOpts(aliceBundle))).text, `msg-${i}`);
    }
    const snap = (__testPeekRatchetState as any)('bob', ROOM);
    assert.ok(snap);
    assert.equal(snap.recvStep, 50);
    const oldKem = snap.kemCipherTextB64;
    // Bob decrypts the post-rotation messages normally (new session).
    for (let i = 50; i < 55; i++) {
      assert.equal((await decryptMessageText(sent[i], ROOM, decOpts(aliceBundle))).text, `msg-${i}`);
    }
    // ATTACKER with ONLY the old chain key vs post-rotation ciphertexts:
    // step numbering restarts at 0 under a new capsule, so the attacker
    // tries the leaked key at step 0 of the new epoch — GCM must fail.
    let failures = 0;
    for (let i = 50; i < 55; i++) {
      const { step } = parsePqPayload(sent[i]);
      assert.equal(step, i - 50);
      assert.notEqual(parsePqPayload(sent[i]).kemB64, oldKem, 'post-rotation capsule must differ');
      await assert.rejects(
        attackerDecryptFromLeakedChain(snap.recvChainKey, 0, sent[i]),
        'leaked OLD chain key must NOT decrypt post-rotation message'
      );
      failures++;
    }
    assert.equal(failures, 5);
    console.log('[dp-chainleak] post-rekey: leaked old chain key failed to decrypt all 5 post-rotation messages (PCS holds)');
  });

  it.skip('sanity: the white-box peek matches the live session (same capsule, same steps)', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const m = await encryptMessageText('hello', ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle });
    await decryptMessageText(m, ROOM, decOpts(aliceBundle));
    const snap = (__testPeekRatchetState as any)('bob', ROOM);
    assert.ok(snap);
    assert.equal(snap.recvStep, 1);
    assert.equal(snap.kemCipherTextB64, parsePqPayload(m).kemB64);
    assert.equal(bufToBase64(snap.recvChainKey).length > 0, true);
  });
});
