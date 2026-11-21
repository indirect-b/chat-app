/**
 * DP prehash reconstruction — deepening workstream 3, item 5 (§10).
 *
 * Phase 1 left 30 ML-DSA-65 prehash KAT cases as SKIPPED-POLICY because
 * noble's PUBLIC prehash() wrapper refuses them (20 of 30 sigGen prehash
 * cases and 10 of 15 sigVer prehash cases; the other 15 prehash cases use
 * strong hashes and already passed through the public API). The 30
 * skipped split as:
 *   - weak hashes (< 192-bit security for ML-DSA-65): SHA2-224, SHA3-224,
 *     SHA2-256, SHA3-256, SHA2-512/224, SHA2-512/256
 *     ("Pre-hash security strength too low") — 20 cases
 *   - SHAKE XOFs whose default output length does not match the FIPS 204
 *     OID length ("Pre-hash XOF output length must be 32/64 bytes")
 *     — 10 cases (SHAKE-128/SHAKE-256)
 *
 * This test runs ALL 45 prehash cases (30 sigGen + 15 sigVer, i.e. the
 * 30 skipped-policy ones plus the 15 that already passed) WITHOUT the
 * public wrapper, using noble's own documented lower-level pieces, all
 * already installed:
 *   - getMessagePrehash(hash, msg, ctx) from @noble/post-quantum/utils.js
 *     (exported, documented: "Builds the domain-separated prehash payload
 *     for the prehash sign/verify paths"; its checkHash() call uses
 *     requiredStrength=0, i.e. no strength gate — the gate lives only in
 *     the ml_dsa65.prehash() wrapper)
 *   - ml_dsa65.internal.sign/verify with externalMu:false, which derives
 *     mu = SHAKE-256(tr || M', 64) from M' exactly as FIPS 204 HashML-DSA
 *     specifies
 *   - the FIPS 204 XOF pairings from @noble/hashes/sha3.js:
 *     shake128_32 (SHAKE128, 32-byte output, id-shake128) and
 *     shake256_64 (SHAKE256, 64-byte output, id-shake256)
 *
 * What this proves: the pre-hash digest, the OID embedding, the
 * context binding, the mu derivation and noble's core sign/verify all
 * agree with NIST's expected signatures bit-for-bit for these 30 cases.
 * What it does NOT prove: nothing here is a second, independent
 * ML-DSA implementation — the core signing/verification is still noble.
 * The independent-implementation route (fetching another ML-DSA
 * implementation as a tarball, e.g. mldsa-wasm) was NOT executed: the
 * environment's execution-risk check blocks downloading/extracting/
 * running that foreign package content in this session. So item 5 is
 * PARTIALLY CLOSED (vectors now execute and pass), not closed by an
 * independent cross-check. The app never uses HashML-DSA prehash, so
 * no app code path is affected either way.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { getMessagePrehash } from '@noble/post-quantum/utils.js';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128_32, shake256_64 } from '@noble/hashes/sha3.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'official-acvp-2026-11-21.json'), 'utf-8')
) as {
  mlDsa65: Record<string, Array<Record<string, unknown>>>;
};

const PREHASH_HASHES: Record<string, unknown> = {
  'SHA2-224': sha224,
  'SHA2-256': sha256,
  'SHA2-384': sha384,
  'SHA2-512': sha512,
  'SHA2-512/224': sha512_224,
  'SHA2-512/256': sha512_256,
  'SHA3-224': sha3_224,
  'SHA3-256': sha3_256,
  'SHA3-384': sha3_384,
  'SHA3-512': sha3_512,
  // FIPS 204 §5.4.1 / RFC 8702 pairings: id-shake128 = SHAKE128(M,256),
  // id-shake256 = SHAKE256(M,512). Bare shake128/shake256 default to
  // 16/32 bytes and are rejected by checkHash; the _32/_64 variants
  // carry the right outputLen for their OID.
  'SHAKE-128': shake128_32,
  'SHAKE-256': shake256_64,
};

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
function bytesToUpperHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex').toUpperCase();
}
const asStr = (v: unknown): string => String(v ?? '');

describe('DP item 5 — ML-DSA-65 prehash KAT cases reconstructed via getMessagePrehash + internal sign/verify', () => {
  it('sigGen prehash: every prehash case (tgId 4 det + tgId 16 rand) matches NIST expected signature bit-for-bit', () => {
    const cases = vectors.mlDsa65.sigGen.filter((tc) => tc.preHash === 'preHash');
    assert.equal(cases.length, 30);
    let weakHash = 0;
    let shake = 0;
    for (const tc of cases) {
      const hash = PREHASH_HASHES[asStr(tc.hashAlg)];
      assert.ok(hash, `no hash mapped for ${tc.hashAlg}`);
      if (String(tc.hashAlg).startsWith('SHAKE')) shake++;
      else if (!['SHA2-384', 'SHA2-512', 'SHA3-384', 'SHA3-512'].includes(String(tc.hashAlg))) weakHash++;
      const ctx = hexToBytes(asStr(tc.context ?? ''));
      const msg = hexToBytes(asStr(tc.message));
      const sk = hexToBytes(asStr(tc.sk));
      // M' = 0x01 || len(ctx) || ctx || OID(hash) || PH(msg)  (FIPS 204 HashML-DSA)
      const prehashed = (getMessagePrehash as (h: unknown, m: Uint8Array, c: Uint8Array) => Uint8Array)(hash, msg, ctx);
      const extraEntropy =
        tc.deterministic === false ? hexToBytes(asStr(tc.rnd)) : (false as const);
      const sig = ml_dsa65.internal.sign(prehashed, sk, { extraEntropy });
      assert.equal(
        bytesToUpperHex(sig),
        asStr(tc.signature),
        `sigGen prehash tgId=${tc.tgId} tcId=${tc.tcId} hashAlg=${tc.hashAlg}`
      );
    }
    console.log(`[dp-prehash] sigGen prehash: 30/30 match (weak-hash ${weakHash}, SHAKE ${shake}, strong-hash ${30 - weakHash - shake})`);
  });

  it('sigVer prehash: every prehash case (tgId 4) agrees with NIST testPassed, incl. negative cases', () => {
    const cases = vectors.mlDsa65.sigVer.filter((tc) => tc.preHash === 'preHash');
    assert.equal(cases.length, 15);
    let passed = 0;
    let failed = 0;
    for (const tc of cases) {
      const hash = PREHASH_HASHES[asStr(tc.hashAlg)];
      assert.ok(hash, `no hash mapped for ${tc.hashAlg}`);
      const ctx = hexToBytes(asStr(tc.context ?? ''));
      const prehashed = (getMessagePrehash as (h: unknown, m: Uint8Array, c: Uint8Array) => Uint8Array)(
        hash,
        hexToBytes(asStr(tc.message)),
        ctx
      );
      const verified = ml_dsa65.internal.verify(
        hexToBytes(asStr(tc.signature)),
        prehashed,
        hexToBytes(asStr(tc.pk))
      );
      assert.equal(verified, tc.testPassed, `sigVer prehash tgId=${tc.tgId} tcId=${tc.tcId} hashAlg=${tc.hashAlg}`);
      if (tc.testPassed) passed++;
      else failed++;
    }
    console.log(`[dp-prehash] sigVer prehash: 15/15 agree (expected-pass ${passed}, expected-fail ${failed})`);
  });

  it('control: the public prehash() wrapper still refuses the weak/SHAKE cases (policy gate intact, not bypassed in the app path)', () => {
    // The public wrapper must keep refusing: this test does NOT patch it,
    // it only uses the lower-level getMessagePrehash + internal.* path.
    assert.throws(
      () => (ml_dsa65.prehash as (h: unknown) => unknown)(sha256),
      /Pre-hash security strength too low/
    );
    assert.throws(
      () => (ml_dsa65.prehash as (h: unknown) => unknown)(shake128_32),
      /Pre-hash/
    );
  });
});
