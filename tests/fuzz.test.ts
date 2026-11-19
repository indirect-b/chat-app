/**
 * Deterministic Fuzz Test Suite for Message Parsing, Key Bundles, Group Epochs, and Safety QR Payloads.
 *
 * Security Invariant:
 *   Every malformed, truncated, bit-flipped, oversized, or random input MUST fail closed:
 *   - Throw E2EEError (or return PARSE_ERROR / MISMATCH for non-throwing QR parser)
 *   - Never crash with uncaught RangeError/TypeError/DOMException
 *   - Never produce plaintext
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  E2EEError,
  createGroupEpochPacket,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  parsePeerKeyBundle,
  parsePeerKeyBundleStrict,
  resetAllCryptoStateForTests,
  rotateGroupEpoch,
} from '../src/utils/crypto';
import { parseAndCompareQrPayload } from '../src/utils/safetyNumber';

// Deterministic xorshift32 PRNG for reproducible fuzzing runs
function createPrng(seed: number) {
  let state = seed >>> 0;
  return {
    nextUint32(): number {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return state >>> 0;
    },
    nextInt(maxExclusive: number): number {
      return this.nextUint32() % maxExclusive;
    },
    nextBytes(len: number): Uint8Array {
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        out[i] = this.nextUint32() & 0xff;
      }
      return out;
    },
    nextAscii(len: number): string {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=:-_{}[]"!@#$%^&*() \n\t\0';
      let out = '';
      for (let i = 0; i < len; i++) {
        out += alphabet[this.nextInt(alphabet.length)];
      }
      return out;
    },
  };
}

describe('Fuzz Tests — Fail-Closed Parsing & Decryption', () => {
  beforeEach(() => {
    resetAllCryptoStateForTests();
  });

  it('fails closed (throws E2EEError) on 150 malformed, truncated, bit-flipped, and random PQ ciphertexts', async () => {
    const rng = createPrng(0x20261119);
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';

    const validPq = await encryptMessageText('top-secret-plaintext-marker', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });

    const malformedCases: string[] = [
      'e2ee:pq:v2:',
      'e2ee:pq:v2:0',
      'e2ee:pq:v2:0:AAAA:BBBB:CCCC', // missing signature (4 fields instead of 5)
      'e2ee:pq:v2:0:AAAA:BBBB:CCCC:', // empty signature
      'e2ee:pq:v2:-1:AAAA:BBBB:CCCC:DDDD', // negative step
      'e2ee:pq:v2:9999999999999999999999:AAAA:BBBB:CCCC:DDDD', // overflow step
      'e2ee:pq:v2:NaN:AAAA:BBBB:CCCC:DDDD',
      'e2ee:pq:v2:0:!!!not_base64!!!:BBBB:CCCC:DDDD',
      'e2ee:pq:v2:0:AAAA:BBBB:CCCC:DDDD:EEEE', // extra field
    ];

    // 40 prefix truncations of a real valid PQ packet
    for (let i = 1; i <= 40; i++) {
      const cut = Math.max('e2ee:pq:v2:'.length, Math.floor((validPq.length * i) / 41));
      malformedCases.push(validPq.slice(0, cut));
    }

    // 40 random single-character mutations across a real valid PQ packet
    for (let i = 0; i < 40; i++) {
      const idx = 'e2ee:pq:v2:'.length + rng.nextInt(validPq.length - 'e2ee:pq:v2:'.length);
      const orig = validPq[idx];
      const replacement = orig === 'A' ? 'B' : 'A';
      malformedCases.push(validPq.slice(0, idx) + replacement + validPq.slice(idx + 1));
    }

    // 61 completely random payloads with the PQ prefix
    for (let i = 0; i < 61; i++) {
      const fieldCount = 1 + rng.nextInt(6);
      const fields: string[] = [];
      for (let f = 0; f < fieldCount; f++) {
        if (f === 0 && rng.nextInt(2) === 0) {
          fields.push(String(rng.nextInt(250)));
        } else if (rng.nextInt(2) === 0) {
          fields.push(Buffer.from(rng.nextBytes(1 + rng.nextInt(64))).toString('base64'));
        } else {
          fields.push(rng.nextAscii(1 + rng.nextInt(48)));
        }
      }
      malformedCases.push(`e2ee:pq:v2:${fields.join(':')}`);
    }

    assert.ok(malformedCases.length >= 150);

    for (const payload of malformedCases) {
      let threwE2EE = false;
      try {
        await decryptMessageText(payload, roomId, {
          myUsername: 'bob',
          peerUsername: 'alice',
          peerPublicKey: aliceBundle,
          sender: 'alice',
        });
      } catch (err) {
        assert.ok(
          err instanceof E2EEError,
          `Expected E2EEError for fuzzed PQ payload, got ${err instanceof Error ? err.name + ': ' + err.message : String(err)}`
        );
        threwE2EE = true;
      }
      assert.equal(threwE2EE, true, 'Fuzzed PQ payload must never decrypt to plaintext');
    }
  });

  it('fails closed (throws E2EEError) on 120 malformed Group Epoch, ECDH, and PBKDF2 packets', async () => {
    const rng = createPrng(0xabcdef01);
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;

    const groupRoom = 'group__fuzz-room';
    const groupMembers = ['alice', 'bob'];
    // (رفع F3) رمزگذاری گروهی بدون بسته کلید اپوک خطا می‌دهد؛ نخست بسته را بساز و بچرخان.
    const groupBundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
    for (const m of groupMembers) {
      groupBundles[m] = parsePeerKeyBundle(m === 'alice' ? aliceBundle : bobBundle, m);
    }
    const groupPacket = await createGroupEpochPacket(groupBundles);
    await rotateGroupEpoch('fuzz-room', 1, groupMembers, groupPacket.epochKeyB64);
    const validGroup = await encryptMessageText('group secret', groupRoom, {
      groupMembers,
    });
    const validPbkdf2 = await encryptMessageText('manual secret', 'alice__bob', {
      customSecret: 'strong-passphrase',
    });

    const cases: Array<{ payload: string; roomId: string; customSecret?: string }> = [
      { payload: 'e2ee:gep:v2:', roomId: groupRoom },
      { payload: 'e2ee:gep:v2:0:abc:AAAA:BBBB', roomId: groupRoom },
      { payload: 'e2ee:gep:v2:-5:abc:AAAA:BBBB', roomId: groupRoom },
      { payload: 'e2ee:gep:v2:999:abc:AAAA:BBBB', roomId: groupRoom },
      { payload: 'e2ee:ecdh:', roomId: 'alice__bob' },
      { payload: 'e2ee:ecdh:onlyonepart', roomId: 'alice__bob' },
      { payload: 'e2ee:v1:', roomId: 'alice__bob', customSecret: 'strong-passphrase' },
      { payload: 'e2ee:v1:AAAA:BBBB', roomId: 'alice__bob', customSecret: 'strong-passphrase' },
    ];

    // Mutate valid group packets
    for (let i = 0; i < 40; i++) {
      const idx = 'e2ee:gep:v2:'.length + rng.nextInt(validGroup.length - 'e2ee:gep:v2:'.length);
      const mutated = validGroup.slice(0, idx) + (validGroup[idx] === 'X' ? 'Y' : 'X') + validGroup.slice(idx + 1);
      cases.push({ payload: mutated, roomId: groupRoom });
    }

    // Mutate valid PBKDF2 packets
    for (let i = 0; i < 32; i++) {
      const idx = 'e2ee:v1:'.length + rng.nextInt(validPbkdf2.length - 'e2ee:v1:'.length);
      const mutated = validPbkdf2.slice(0, idx) + (validPbkdf2[idx] === 'Q' ? 'R' : 'Q') + validPbkdf2.slice(idx + 1);
      cases.push({ payload: mutated, roomId: 'alice__bob', customSecret: 'strong-passphrase' });
    }

    // Random garbage with e2ee:gep:v2:, e2ee:ecdh:, e2ee:v1: prefixes
    const prefixes = ['e2ee:gep:v2:', 'e2ee:ecdh:', 'e2ee:v1:'];
    for (let i = 0; i < 40; i++) {
      const pref = prefixes[i % prefixes.length];
      cases.push({
        payload: pref + rng.nextAscii(1 + rng.nextInt(80)),
        roomId: pref === 'e2ee:gep:v2:' ? groupRoom : 'alice__bob',
        customSecret: pref === 'e2ee:v1:' ? 'strong-passphrase' : undefined,
      });
    }

    for (const tc of cases) {
      let threwE2EE = false;
      try {
        await decryptMessageText(tc.payload, tc.roomId, {
          myUsername: 'bob',
          peerUsername: 'alice',
          peerPublicKey: tc.roomId === groupRoom ? bobBundle : aliceBundle,
          customSecret: tc.customSecret,
          groupMembers: ['alice', 'bob'],
        });
      } catch (err) {
        assert.ok(
          err instanceof E2EEError,
          `Expected E2EEError for ${tc.payload.slice(0, 24)}, got ${err instanceof Error ? err.name : String(err)}`
        );
        threwE2EE = true;
      }
      assert.equal(threwE2EE, true);
    }

    // Invalid epoch rotations must also fail closed with E2EEError
    for (const badEpoch of [0, -1, Number.NaN, 1.5, Number.POSITIVE_INFINITY]) {
      await assert.rejects(
        () => rotateGroupEpoch('fuzz-room', badEpoch, ['alice', 'bob']),
        (err: unknown) => err instanceof E2EEError
      );
    }
  });

  it('fails closed (throws E2EEError) on 120 malformed, truncated, and forged key bundles', async () => {
    const rng = createPrng(0x13579bdf);
    const validBundleStr = (await ensureUserHybridKeyPair('alice'))!;
    const validObj = JSON.parse(validBundleStr);

    const badBundles: Array<string | null | undefined> = [
      null,
      undefined,
      '',
      '{}',
      '[]',
      'null',
      'not-json',
      JSON.stringify({ v: 1, ecdhJwk: {} }),
      JSON.stringify({ v: 4, ecdhJwk: null }),
      JSON.stringify({ ...validObj, mldsaSigB64: '' }),
      JSON.stringify({ ...validObj, mldsaPubB64: Buffer.from(rng.nextBytes(32)).toString('base64') }),
      JSON.stringify({ ...validObj, mlkemPubB64: Buffer.from(rng.nextBytes(32)).toString('base64') }),
      JSON.stringify({ ...validObj, mldsaSigB64: Buffer.from(rng.nextBytes(64)).toString('base64') }),
      JSON.stringify({ ...validObj, username: 'impostor' }),
    ];

    // 40 truncated versions of the valid bundle
    for (let i = 1; i <= 40; i++) {
      badBundles.push(validBundleStr.slice(0, Math.floor((validBundleStr.length * i) / 41)));
    }

    // 40 bit-flipped versions of fields inside the valid bundle
    for (let i = 0; i < 40; i++) {
      const clone = JSON.parse(validBundleStr);
      const targetField = ['mlkemPubB64', 'mldsaPubB64', 'mldsaSigB64'][i % 3];
      const raw = Buffer.from(clone[targetField], 'base64');
      raw[rng.nextInt(raw.length)] ^= 1 << rng.nextInt(8);
      clone[targetField] = raw.toString('base64');
      badBundles.push(JSON.stringify(clone));
    }

    // 26 completely random strings
    for (let i = 0; i < 26; i++) {
      badBundles.push(rng.nextAscii(1 + rng.nextInt(256)));
    }

    assert.ok(badBundles.length >= 120);

    for (const bundle of badBundles) {
      assert.throws(
        () => parsePeerKeyBundleStrict(bundle, 'alice', { skipCache: true }),
        (err: unknown) => err instanceof E2EEError,
        'Malformed or forged bundle must throw E2EEError'
      );
    }
  });

  it('never crashes or returns MATCH on 100 fuzzed Safety Number QR payloads', () => {
    const rng = createPrng(0xfeedface);
    const expectedHex = '0123456789abcdef'.repeat(4);

    for (let i = 0; i < 100; i++) {
      const raw = i % 2 === 0
        ? `PQ-MPRBA-SAFETY-v1:${rng.nextAscii(rng.nextInt(96))}`
        : rng.nextAscii(rng.nextInt(128));
      const res = parseAndCompareQrPayload(raw, expectedHex);
      assert.notEqual(res.status, 'MATCH');
      assert.ok(res.status === 'PARSE_ERROR' || res.status === 'MISMATCH');
    }
  });
});
