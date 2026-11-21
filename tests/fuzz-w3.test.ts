/**
 * Workstream 3 (audit 2026-11-21) — EXTENDED adversarial fuzzing.
 *
 * Extends tests/fuzz.test.ts (round 2) with malformed inputs aimed at the
 * raw crypto parsers: truncated/corrupted ML-KEM ciphertexts and public keys,
 * truncated/corrupted ML-DSA signatures, garbage base64/hex, empty and
 * oversized buffers, wrong-length keys, tampered AES-GCM ciphertext+tag
 * combos, malformed bundles/epoch packets, and malformed PQF1 file payloads.
 *
 * Pass criterion (same as round 2): every malformed input must fail closed —
 * throw E2EEError (or return null/false where the API is non-throwing),
 * never crash the process in an unhandled way, and NEVER output plaintext.
 *
 * One documented exception is FIPS 203 implicit rejection: decapsulating a
 * VALID-LENGTH but corrupt ML-KEM ciphertext returns a pseudorandom shared
 * secret instead of throwing. That is correct FIPS 203 behaviour, not a
 * failure — the test asserts the returned secret differs from the true one.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  E2EEError,
  base64ToBuf,
  bufToBase64,
  createGroupEpochPacket,
  decapsulateGroupEpochKey,
  decryptFileBytes,
  decryptMessageText,
  encryptFileBytes,
  encryptMessageText,
  ensureUserHybridKeyPair,
  parsePeerKeyBundle,
  parsePeerKeyBundleStrict,
  resetAllCryptoStateForTests,
  rotateGroupEpoch,
} from '../src/utils/crypto';
import { parseAndCompareQrPayload } from '../src/utils/safetyNumber';

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number { return this.map.size; }
  clear(): void { this.map.clear(); }
  getItem(key: string): string | null { return this.map.has(key) ? this.map.get(key)! : null; }
  key(index: number): string | null { return Array.from(this.map.keys())[index] ?? null; }
  removeItem(key: string): void { this.map.delete(key); }
  setItem(key: string, value: string): void { this.map.set(key, String(value)); }
}
const mockLocalStorage = new MemoryStorage();
Object.defineProperty(globalThis, 'localStorage', {
  value: mockLocalStorage, configurable: true, writable: true,
});

function xorshift(seed: number) {
  let s = seed >>> 0;
  return {
    bytes(len: number): Uint8Array {
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        s ^= s << 13; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
        out[i] = s & 0xff;
      }
      return out;
    },
  };
}

describe('W3 extended fuzz — raw noble primitives (ML-KEM-768 / ML-DSA-65)', () => {
  it('decapsulate: wrong-length ciphertexts and secret keys throw; corrupt valid-length ct yields a DIFFERENT secret (FIPS 203 implicit rejection)', () => {
    const rng = xorshift(0x1a2b3c4d);
    const { publicKey, secretKey } = ml_kem768.keygen();
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);

    // Wrong-length ciphertexts must throw, never return a secret.
    for (const len of [0, 1, 100, 1079, 1087, 1089, 2000, 100000]) {
      assert.throws(
        () => ml_kem768.decapsulate(rng.bytes(len), secretKey),
        `decapsulate must throw for ct length ${len}`
      );
    }
    // Wrong-length secret keys must throw.
    for (const len of [0, 1, 100, 2399, 2401, 5000]) {
      assert.throws(
        () => ml_kem768.decapsulate(cipherText, rng.bytes(len)),
        `decapsulate must throw for sk length ${len}`
      );
    }
    // Corrupt but valid-length ciphertext: FIPS 203 implicit rejection —
    // returns a pseudorandom 32-byte secret, NOT the true one, never throws.
    for (let i = 0; i < 20; i++) {
      const bad = new Uint8Array(cipherText);
      bad[Math.floor(rng.bytes(2)[0] * cipherText.length / 256)] ^= 0xff;
      const out = ml_kem768.decapsulate(bad, secretKey);
      assert.equal(out.length, 32, 'implicit-rejection output must be 32 bytes');
      assert.notDeepEqual(Array.from(out), Array.from(sharedSecret), 'corrupt ct must NOT yield the true shared secret');
    }
    // encapsulate with wrong-length public keys must throw.
    for (const len of [0, 1, 100, 1183, 1185, 2000]) {
      assert.throws(
        () => ml_kem768.encapsulate(rng.bytes(len)),
        `encapsulate must throw for pk length ${len}`
      );
    }
    // keygen with wrong-length seed must throw.
    for (const len of [0, 1, 63, 65, 128]) {
      assert.throws(() => ml_kem768.keygen(rng.bytes(len)), `keygen must throw for seed length ${len}`);
    }
  });

  it('ML-DSA-65 verify: wrong-length signatures/keys return false or throw — never true; tampered sig never verifies', () => {
    const rng = xorshift(0x5e6f7a8b);
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('verify-me');
    const sig = ml_dsa65.sign(msg, secretKey);
    assert.equal(sig.length, 3309, 'ML-DSA-65 signature is 3309 bytes');
    assert.equal(ml_dsa65.verify(sig, msg, publicKey), true);

    for (const len of [0, 1, 100, 3291, 3308, 3310, 5000]) {
      const badSig = rng.bytes(len);
      let ok: boolean | 'threw' = 'threw';
      try { ok = ml_dsa65.verify(badSig, msg, publicKey); } catch { ok = 'threw'; }
      assert.ok(ok === false || ok === 'threw', `verify with sig length ${len} must be false or throw, got ${ok}`);
    }
    for (const len of [0, 1, 100, 1951, 1953, 4000]) {
      const badPk = rng.bytes(len);
      let ok: boolean | 'threw' = 'threw';
      try { ok = ml_dsa65.verify(sig, msg, badPk); } catch { ok = 'threw'; }
      assert.ok(ok === false || ok === 'threw', `verify with pk length ${len} must be false or throw, got ${ok}`);
    }
    // Single-bit flips anywhere in a valid signature must fail verification.
    for (let i = 0; i < 30; i++) {
      const bad = new Uint8Array(sig);
      bad[Math.floor(rng.bytes(2)[0] * sig.length / 256) + (i % 7)] ^= 1 << (i % 8);
      assert.equal(ml_dsa65.verify(bad, msg, publicKey), false, `bit-flipped sig #${i} must not verify`);
    }
    // Wrong message / wrong key must fail.
    assert.equal(ml_dsa65.verify(sig, new TextEncoder().encode('verify-me!'), publicKey), false);
    const other = ml_dsa65.keygen();
    assert.equal(ml_dsa65.verify(sig, msg, other.publicKey), false);
    // Empty message signs/verifies (valid API use) but a truncated sig does not.
    const emptySig = ml_dsa65.sign(new Uint8Array(0), secretKey);
    assert.equal(ml_dsa65.verify(emptySig, new Uint8Array(0), publicKey), true);
    assert.equal(ml_dsa65.verify(emptySig.slice(0, 100), new Uint8Array(0), publicKey), false);
    // sign with wrong-length secret key throws.
    for (const len of [0, 1, 100, 4031, 4033]) {
      assert.throws(() => ml_dsa65.sign(msg, rng.bytes(len)), `sign must throw for sk length ${len}`);
    }
  });
});

describe('W3 extended fuzz — base64 / bundle / epoch packet parsers', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('base64ToBuf rejects garbage, non-canonical, wrong-length and non-string input', () => {
    const bad: unknown[] = [
      '', 'A', 'AB', 'ABC', '====', 'A===', 'AB=C', 'AQ== ', ' AQ==', 'AQ==\n',
      'éé==', 'AQ==AQ', 'AQ', 'AQ==AQ==', null, undefined, 12345, {}, [],
      'AR==', // non-canonical: decodes to 0x01 which re-encodes as 'AQ=='
      'AB==', // non-canonical
      '//==', // decodes then re-encodes differently? (0xff -> '/w==')
    ];
    for (const input of bad) {
      assert.throws(
        () => base64ToBuf(input as string),
        (err: unknown) => err instanceof E2EEError,
        `base64ToBuf must throw E2EEError for ${JSON.stringify(input)}`
      );
    }
    // Valid canonical inputs still decode.
    assert.deepEqual(Array.from(base64ToBuf('AQ==')), [1]);
    assert.deepEqual(Array.from(base64ToBuf('AAECAwQFBgc=')), [0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it('parsePeerKeyBundleStrict rejects off-by-one key lengths and malformed ECDH JWKs', async () => {
    const rng = xorshift(0xdeadbeef);
    const validStr = (await ensureUserHybridKeyPair('alice'))!;
    const validObj = JSON.parse(validStr);

    const b64 = (len: number) => Buffer.from(rng.bytes(len)).toString('base64');
    const variants: Array<[string, Record<string, unknown>]> = [
      ['ML-KEM pub 1183 bytes (off by -1)', { ...validObj, mlkemPubB64: b64(1183) }],
      ['ML-KEM pub 1185 bytes (off by +1)', { ...validObj, mlkemPubB64: b64(1185) }],
      ['ML-DSA pub 1951 bytes (off by -1)', { ...validObj, mldsaPubB64: b64(1951) }],
      ['ML-DSA pub 1953 bytes (off by +1)', { ...validObj, mldsaPubB64: b64(1953) }],
      ['ML-DSA sig 3308 bytes (off by -1)', { ...validObj, mldsaSigB64: b64(3308) }],
      ['ML-DSA sig 3310 bytes (off by +1)', { ...validObj, mldsaSigB64: b64(3310) }],
      ['ML-KEM pub empty', { ...validObj, mlkemPubB64: '' }],
      ['ML-DSA pub empty', { ...validObj, mldsaPubB64: '' }],
      ['ML-KEM pub garbage base64', { ...validObj, mlkemPubB64: '!!!not-base64!!!' }],
      ['ML-DSA sig garbage base64', { ...validObj, mldsaSigB64: '!!!not-base64!!!' }],
      ['ECDH JWK crv P-384', { ...validObj, ecdhJwk: { ...validObj.ecdhJwk, crv: 'P-384' } }],
      // NOTE: 'ECDH JWK crv missing' is intentionally NOT in this list: the
      // parser defaults a missing crv to 'P-256' in the signed serialization
      // (crypto.ts serializeBundleForSigning), so a crv-stripped bundle still
      // verifies. That leniency is covered by its own test below, where ECDH
      // use of such a bundle fails closed at WebCrypto import.
      ['ECDH JWK x too short', { ...validObj, ecdhJwk: { ...validObj.ecdhJwk, x: 'AAAA' } }],
      ['ECDH JWK y non-base64url', { ...validObj, ecdhJwk: { ...validObj.ecdhJwk, y: '!!!' } }],
      ['ECDH JWK y missing', { ...validObj, ecdhJwk: { kty: 'EC', crv: 'P-256', x: validObj.ecdhJwk.x } }],
      ['ECDH JWK as string', { ...validObj, ecdhJwk: 'not-an-object' }],
      // NOTE: 'ECDH JWK kty RSA' and 'ECDH JWK crv missing' are NOT in this
      // list: serializeBundleForSigning() signs only crv:x:y, so kty is not
      // bound by the signature and a missing crv defaults to 'P-256'. Both
      // still verify; both fail closed at ECDH use (see leniency test).
      ['version 5', { ...validObj, v: 5 }],
      ["version '4' (string)", { ...validObj, v: '4' }],
      ['username wrong user', { ...validObj, username: 'mallory' }],
      // NOTE: 'username empty' / 'username missing' are NOT in this list:
      // when an expected username is supplied, verification uses the EXPECTED
      // name (the signature binds it), so the bundle's own empty field is
      // ignored; without an expected name the same bundles fail closed
      // (INVALID_SIGNATURE). See the leniency test below.
      // NOTE: an 'extra unknown field' is also NOT in this list: unknown JSON
      // fields are ignored by design (only signed fields are read), so a
      // 100 KB extra field parses fine. That is asserted, not rejected, below.
    ];
    for (const [label, obj] of variants) {
      assert.throws(
        () => parsePeerKeyBundleStrict(JSON.stringify(obj), 'alice', { skipCache: true }),
        (err: unknown) => err instanceof E2EEError,
        `bundle variant must throw E2EEError: ${label}`
      );
    }
    // The untouched valid bundle still parses.
    const parsed = parsePeerKeyBundleStrict(validStr, 'alice', { skipCache: true });
    assert.equal(parsed.username, 'alice');
    assert.equal(parsed.isFullyPostQuantum, true);
    // Unknown extra fields are ignored (not signed, not read).
    const withExtra = parsePeerKeyBundleStrict(
      JSON.stringify({ ...validObj, evil: 'x'.repeat(100000) }), 'alice', { skipCache: true }
    );
    assert.equal(withExtra.isFullyPostQuantum, true);
  });

  it('OBSERVED LENIENCY: bundle with ECDH JWK crv stripped still verifies (defaults to P-256), but ECDH use fails closed', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const mkVariant = (mut: (o: Record<string, any>) => void) => {
      const o = JSON.parse(bobBundle);
      mut(o);
      return JSON.stringify(o);
    };
    for (const [label, stripped] of [
      ['crv missing', mkVariant(o => { delete o.ecdhJwk.crv; })],
      ['kty RSA', mkVariant(o => { o.ecdhJwk.kty = 'RSA'; })],
    ] as Array<[string, string]>) {
      // Parser accepts it as fully post-quantum (signature covers crv||'P-256' + x + y only).
      const parsed = parsePeerKeyBundleStrict(stripped, 'bob', { skipCache: true });
      assert.equal(parsed.isFullyPostQuantum, true, `leniency case: ${label}`);
      // ...but any attempt to actually derive the ECDH shared secret throws
      // E2EEError (WebCrypto rejects the JWK). No session is created.
      await assert.rejects(
        () => encryptMessageText('probe', 'alice__bob', {
          myUsername: 'alice', peerUsername: 'bob', peerPublicKey: stripped,
        }),
        (err: unknown) => err instanceof E2EEError,
        `ECDH use must fail closed: ${label}`
      );
    }
  });

  it('OBSERVED LENIENCY: empty/missing bundle username is ignored when an expected username is supplied (signature binds the expected name); fails closed without one', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const obj = JSON.parse(aliceBundle);
    for (const [label, s] of [
      ['empty username', JSON.stringify({ ...obj, username: '' })],
      ['missing username', JSON.stringify({ ...obj, username: undefined })],
    ] as Array<[string, string]>) {
      const parsed = parsePeerKeyBundleStrict(s, 'alice', { skipCache: true });
      assert.equal(parsed.isFullyPostQuantum, true, `leniency case: ${label}`);
      assert.throws(
        () => parsePeerKeyBundleStrict(s, undefined, { skipCache: true }),
        (err: unknown) => err instanceof E2EEError,
        `no-expected-username parse must fail closed: ${label}`
      );
      // And a wrong expected username still fails (signature binds the name).
      assert.throws(
        () => parsePeerKeyBundleStrict(s, 'mallory', { skipCache: true }),
        (err: unknown) => err instanceof E2EEError,
        `wrong expected username must fail: ${label}`
      );
    }
  });

  it('decapsulateGroupEpochKey returns null (never a key, never throws) on malformed packets', async () => {
    await ensureUserHybridKeyPair('alice');
    const rng = xorshift(0x11223344);
    const b64 = (len: number) => Buffer.from(rng.bytes(len)).toString('base64');
    const badPackets = [
      '', 'a', 'a:b', 'a:b:c:d', '::', ':::',
      `${b64(100)}:${b64(12)}:${b64(48)}`, // wrong-length KEM ct (100, not 1088)
      `${b64(1088)}:${b64(11)}:${b64(48)}`, // wrong-length IV
      `${b64(1088)}:${b64(12)}:${b64(15)}`, // wrapped key too short for GCM tag
      `${b64(1088)}:${b64(12)}:${b64(100000)}`, // oversized wrapped key
      '!!!:!!!:!!!',
      `${b64(1088)}:${b64(12)}:${b64(48)}:extra`,
    ];
    for (const pkt of badPackets) {
      const out = await decapsulateGroupEpochKey('alice', pkt);
      assert.equal(out, null, `malformed epoch packet must decapsulate to null: ${pkt.slice(0, 40)}`);
    }
    // A well-formed packet round-trips.
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const bundles = {
      alice: parsePeerKeyBundle((await ensureUserHybridKeyPair('alice'))!, 'alice'),
      bob: parsePeerKeyBundle(bobBundle, 'bob'),
    };
    const packet = await createGroupEpochPacket(bundles);
    const mine = await decapsulateGroupEpochKey('alice', packet.keys['alice']);
    assert.equal(mine, packet.epochKeyB64);
  });

  it('rotateGroupEpoch: wrong-length epoch keys are ACCEPTED (no length validation) — recorded as a finding, not a crash', async () => {
    const rng = xorshift(0x55667788);
    const b64 = (len: number) => Buffer.from(rng.bytes(len)).toString('base64');
    // These MUST throw (invalid epoch number / missing key / garbage base64).
    for (const badEpoch of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      await assert.rejects(
        () => rotateGroupEpoch('w3-room', badEpoch, ['alice', 'bob'], b64(32)),
        (err: unknown) => err instanceof E2EEError,
        `epoch ${badEpoch} must throw`
      );
    }
    await assert.rejects(
      () => rotateGroupEpoch('w3-room', 1, ['alice', 'bob']),
      (err: unknown) => err instanceof E2EEError,
      'missing epoch key must throw'
    );
    await assert.rejects(
      () => rotateGroupEpoch('w3-room', 1, ['alice', 'bob'], '!!!not-base64!!!'),
      (err: unknown) => err instanceof E2EEError,
      'garbage base64 epoch key must throw'
    );
    // Wrong-length keys: OBSERVED BEHAVIOUR — accepted without validation.
    // (If this assertion fails, the length check was added and the finding is fixed.)
    for (const len of [1, 16, 31, 33, 64]) {
      const state = await rotateGroupEpoch('w3-room', 1, ['alice', 'bob'], b64(len));
      assert.equal(state.epochs[1].rootKey.length, len, `epoch key of ${len} bytes is stored as-is`);
    }
  });
});

describe('W3 extended fuzz — decryptMessageText tampering, oversize, edge steps', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('tampered AES-GCM tag / IV / truncated ciphertext never decrypts, never leaks plaintext', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';
    const opts = { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, sender: 'alice' };
    const valid = await encryptMessageText('w3-secret-marker-0123456789', roomId, {
      myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle,
    });
    assert.ok(valid.startsWith('e2ee:pq:v2:'));
    const parts = valid.slice('e2ee:pq:v2:'.length).split(':');
    assert.equal(parts.length, 5);
    const [step, kem, iv, cipher, sig] = parts;

    const flipB64Char = (s: string, pos: number) => {
      const ch = s[pos];
      const rep = ch === 'A' ? 'B' : 'A';
      return s.slice(0, pos) + rep + s.slice(pos + 1);
    };
    const cases: Array<[string, string]> = [
      ['last char of ciphertext (GCM tag) flipped', `e2ee:pq:v2:${step}:${kem}:${iv}:${flipB64Char(cipher, cipher.length - 1)}:${sig}`],
      ['first char of ciphertext flipped', `e2ee:pq:v2:${step}:${kem}:${iv}:${flipB64Char(cipher, 0)}:${sig}`],
      ['IV flipped', `e2ee:pq:v2:${step}:${kem}:${flipB64Char(iv, 0)}:${cipher}:${sig}`],
      ['ciphertext truncated to tag-only (16 zero bytes)', `e2ee:pq:v2:${step}:${kem}:${iv}:${bufToBase64(new Uint8Array(16))}:${sig}`],
      ['ciphertext truncated to 15 bytes (no full tag)', `e2ee:pq:v2:${step}:${kem}:${iv}:${bufToBase64(new Uint8Array(15))}:${sig}`],
      ['ciphertext empty', `e2ee:pq:v2:${step}:${kem}:${iv}::${sig}`],
      ['IV empty', `e2ee:pq:v2:${step}:${kem}::${cipher}:${sig}`],
      ['KEM ct empty', `e2ee:pq:v2:${step}::${iv}:${cipher}:${sig}`],
      ['signature empty', `e2ee:pq:v2:${step}:${kem}:${iv}:${cipher}:`],
      ['step huge (2^53+1, unsafe integer)', `e2ee:pq:v2:9007199254740993:${kem}:${iv}:${cipher}:${sig}`],
      ['step 1000 digits', `e2ee:pq:v2:${'9'.repeat(1000)}:${kem}:${iv}:${cipher}:${sig}`],
      ['step leading zeros', `e2ee:pq:v2:0007:${kem}:${iv}:${cipher}:${sig}`],
      ['step empty', `e2ee:pq:v2::${kem}:${iv}:${cipher}:${sig}`],
      ['all fields empty', 'e2ee:pq:v2::::'],
      ['payload is only the prefix', 'e2ee:pq:v2:'],
    ];
    for (const [label, payload] of cases) {
      let threw = false;
      try {
        const res = await decryptMessageText(payload, roomId, opts);
        assert.ok(!String(res.text).includes('w3-secret-marker'), `plaintext leaked for: ${label}`);
      } catch (err) {
        assert.ok(err instanceof E2EEError, `expected E2EEError for ${label}, got ${err}`);
        threw = true;
      }
      assert.equal(threw, true, `must throw E2EEError: ${label}`);
    }

    // Non-string / null payloads throw. The empty string '' is NOT an error
    // by design: isE2EEPayload('') is false, so it returns as an empty
    // plaintext message (no secret material involved).
    for (const bad of [null, undefined, 12345, {}, []] as unknown[]) {
      await assert.rejects(
        () => decryptMessageText(bad as string, roomId, opts),
        (err: unknown) => err instanceof E2EEError,
        `non-string payload must throw E2EEError: ${JSON.stringify(bad)}`
      );
    }
    const emptyRes = await decryptMessageText('', roomId, opts);
    assert.equal(emptyRes.isEncrypted, false);
    assert.equal(emptyRes.text, '');
    // Plaintext (non-E2EE) input is returned as-is by design — assert it is
    // NOT treated as decrypted secret material.
    const plain = await decryptMessageText('hello, not encrypted', roomId, opts);
    assert.equal(plain.isEncrypted, false);
    assert.equal(plain.text, 'hello, not encrypted');
  });

  it('oversized ciphertext fields fail closed without crashing (1 MB and 10 MB)', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';
    const opts = { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, sender: 'alice' };
    const valid = await encryptMessageText('w3-oversize-probe', roomId, {
      myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle,
    });
    const parts = valid.slice('e2ee:pq:v2:'.length).split(':');
    const [step, kem, iv, , sig] = parts;
    const rng = xorshift(0x99aabbcc);
    for (const mb of [1, 10]) {
      const bigB64 = Buffer.from(rng.bytes(mb * 1024 * 1024)).toString('base64');
      const t0 = Date.now();
      await assert.rejects(
        () => decryptMessageText(`e2ee:pq:v2:${step}:${kem}:${iv}:${bigB64}:${sig}`, roomId, opts),
        (err: unknown) => err instanceof E2EEError,
        `${mb} MB ciphertext must throw E2EEError`
      );
      const dt = Date.now() - t0;
      console.log(`    [w3] ${mb} MB ciphertext rejected in ${dt} ms`);
      assert.ok(dt < 30000, `${mb} MB input must not hang the process`);
    }
    // Oversized base64 field that is not valid base64 at all.
    await assert.rejects(
      () => decryptMessageText(`e2ee:pq:v2:${step}:${kem}:${iv}:${'!'.repeat(1024 * 1024)}:${sig}`, roomId, opts),
      (err: unknown) => err instanceof E2EEError
    );
  });

  it('group epoch packets: bad epoch numbers, bad membersHash, wrong secret never decrypt', async () => {
    const members = ['alice', 'bob'];
    const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
    for (const m of members) bundles[m] = parsePeerKeyBundle((await ensureUserHybridKeyPair(m))!, m);
    const packet = await createGroupEpochPacket(bundles);
    await rotateGroupEpoch('w3-group', 1, members, packet.epochKeyB64);
    const valid = await encryptMessageText('w3-group-secret', 'group__w3-group', { groupMembers: members });
    assert.ok(valid.startsWith('e2ee:gep:v2:'));
    const parts = valid.slice('e2ee:gep:v2:'.length).split(':');
    const [epoch, membersHash, iv, cipher] = parts;
    const opts = { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: bundles['alice'] as unknown as string, groupMembers: members };
    const cases: Array<[string, string]> = [
      ['epoch 0', `e2ee:gep:v2:0:${membersHash}:${iv}:${cipher}`],
      ['epoch 99999999999999999999', `e2ee:gep:v2:99999999999999999999:${membersHash}:${iv}:${cipher}`],
      ['epoch 1.5', `e2ee:gep:v2:1.5:${membersHash}:${iv}:${cipher}`],
      ['membersHash 65 chars', `e2ee:gep:v2:${epoch}:${'A'.repeat(65)}:${iv}:${cipher}`],
      ['membersHash empty', `e2ee:gep:v2:${epoch}::${iv}:${cipher}`],
      ['membersHash wrong value', `e2ee:gep:v2:${epoch}:AAAAAAAAAAAA:${iv}:${cipher}`],
      ['ciphertext tag flipped', `e2ee:gep:v2:${epoch}:${membersHash}:${iv}:${cipher.slice(0, -1)}${cipher.slice(-1) === 'A' ? 'B' : 'A'}`],
      ['ciphertext 15 bytes', `e2ee:gep:v2:${epoch}:${membersHash}:${iv}:${bufToBase64(new Uint8Array(15))}`],
    ];
    for (const [label, payload] of cases) {
      await assert.rejects(
        () => decryptMessageText(payload, 'group__w3-group', opts),
        (err: unknown) => err instanceof E2EEError,
        `group packet must throw E2EEError: ${label}`
      );
    }
    // PBKDF2 with the wrong passphrase fails closed (and legacy-iteration
    // fallback must not accept it either).
    const manual = await encryptMessageText('w3-manual-secret', 'alice__bob', { customSecret: 'correct horse battery staple' });
    await assert.rejects(
      () => decryptMessageText(manual, 'alice__bob', { customSecret: 'wrong passphrase' }),
      (err: unknown) => err instanceof E2EEError
    );
  });
});

describe('W3 extended fuzz — PQF1 file payloads and safety QR edge cases', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('malformed PQF1 file payloads fail closed; header fields are range-checked by lookup', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const opts = { myUsername: 'bob', peerPublicKey: aliceBundle, peerUsername: 'alice' };
    const plain = new TextEncoder().encode('w3-file-secret-bytes');
    const valid = await encryptFileBytes(plain, 'alice__bob', {
      myUsername: 'alice', peerPublicKey: bobBundle, peerUsername: 'bob',
    });
    assert.equal(valid[4], 1, 'DM file kind byte is 1');
    const headerLen = 21; // 4 magic + 1 kind + 4 epoch + 12 IV
    assert.equal(valid.length, headerLen + plain.length + 16);

    const mutate = (fn: (b: Uint8Array) => void) => {
      const c = new Uint8Array(valid);
      fn(c);
      return c;
    };
    const cases: Array<[string, Uint8Array]> = [
      ['bad magic (first byte)', mutate(b => { b[0] = 0x58; })],
      ['bad magic (all four)', mutate(b => { b.set([0, 0, 0, 0], 0); })],
      ['kind 0', mutate(b => { b[4] = 0; })],
      ['kind 4 (unknown)', mutate(b => { b[4] = 4; })],
      ['kind 255', mutate(b => { b[4] = 255; })],
      // NOTE: for DM files (kind 1) the epoch header bytes are ignored by
      // design — the DM key does not depend on any epoch. Epoch tampering is
      // only meaningful for group files and is tested in the group case below.
      ['IV byte flipped', mutate(b => { b[9] ^= 0xff; })],
      ['last ciphertext byte flipped (tag)', mutate(b => { b[b.length - 1] ^= 0xff; })],
      ['truncated to 20 bytes (short header)', valid.slice(0, 20)],
      ['header only (21 bytes, no ciphertext)', valid.slice(0, 21)],
      ['header + 15 bytes (no full tag)', valid.slice(0, 21 + 15)],
      ['header + 16 bytes (tag only, empty plaintext)', valid.slice(0, 21 + 16)],
      ['empty', new Uint8Array(0)],
      ['3 bytes', new Uint8Array([0x50, 0x51, 0x46])],
    ];
    for (const [label, data] of cases) {
      await assert.rejects(
        () => decryptFileBytes(data, 'alice__bob', opts),
        (err: unknown) => err instanceof E2EEError,
        `PQF1 case must throw E2EEError: ${label}`
      );
    }
    // null / undefined input.
    for (const bad of [null, undefined] as unknown[]) {
      await assert.rejects(
        () => decryptFileBytes(bad as Uint8Array, 'alice__bob', opts),
        (err: unknown) => err instanceof E2EEError
      );
    }
    // Untampered file still decrypts.
    const back = await decryptFileBytes(valid, 'alice__bob', opts);
    assert.deepEqual(Array.from(back), Array.from(plain));
  });

  it('group PQF1 files: tampered epoch header fails closed (no epoch key for that epoch)', async () => {
    const members = ['alice', 'bob'];
    const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
    for (const m of members) bundles[m] = parsePeerKeyBundle((await ensureUserHybridKeyPair(m))!, m);
    const packet = await createGroupEpochPacket(bundles);
    await rotateGroupEpoch('w3-files', 1, members, packet.epochKeyB64);
    const plain = new TextEncoder().encode('w3-group-file-bytes');
    const valid = await encryptFileBytes(plain, 'group__w3-files', { groupMembers: members });
    assert.equal(valid[4], 2, 'group file kind byte is 2');
    const gOpts = { groupMembers: members };
    const mutate = (fn: (b: Uint8Array) => void) => {
      const c = new Uint8Array(valid);
      fn(c);
      return c;
    };
    for (const [label, data] of [
      ['epoch 0xFFFFFFFF', mutate(b => { b.set([0xff, 0xff, 0xff, 0xff], 5); })],
      ['epoch 0', mutate(b => { b.set([0, 0, 0, 0], 5); })],
      ['epoch 2 (not yet rotated)', mutate(b => { b.set([0, 0, 0, 2], 5); })],
      ['kind byte changed to DM (1)', mutate(b => { b[4] = 1; })],
      ['last byte flipped (tag)', mutate(b => { b[b.length - 1] ^= 0xff; })],
    ] as Array<[string, Uint8Array]>) {
      await assert.rejects(
        () => decryptFileBytes(data, 'group__w3-files', gOpts),
        (err: unknown) => err instanceof E2EEError,
        `group PQF1 case must throw E2EEError: ${label}`
      );
    }
    const back = await decryptFileBytes(valid, 'group__w3-files', gOpts);
    assert.deepEqual(Array.from(back), Array.from(plain));
  });

  it('safety QR parser rejects null/undefined/uppercase-hex/odd-length payloads without MATCH', () => {
    const expectedHex = '0123456789abcdef'.repeat(4);
    for (const bad of [null, undefined, '', '   ', 'PQ-MPRBA-SAFETY-v1:', 'PQ-MPRBA-SAFETY-v1:0123456789ABCDEF'.repeat(4), 'PQ-MPRBA-SAFETY-v1:' + 'ab'.repeat(31), 'PQ-MPRBA-SAFETY-v1:' + 'ab'.repeat(33), 'pq-mprba-safety-v1:' + expectedHex] as unknown[]) {
      const res = parseAndCompareQrPayload(bad as string, expectedHex);
      assert.notEqual(res.status, 'MATCH', `QR payload must never MATCH: ${JSON.stringify(bad)?.slice(0, 60)}`);
      assert.ok(res.status === 'PARSE_ERROR' || res.status === 'MISMATCH');
    }
    const good = parseAndCompareQrPayload(`PQ-MPRBA-SAFETY-v1:${expectedHex}`, expectedHex);
    assert.equal(good.status, 'MATCH');
  });
});
