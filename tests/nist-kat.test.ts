/**
 * Official NIST Known-Answer Tests (KAT) for FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).
 *
 * Vector Source:
 *   NIST ACVP-Server official test vectors:
 *   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
 *   - ML-KEM-keyGen-FIPS203 (ML-KEM-768, tgId 2, tcId 26 & 27)
 *   - ML-KEM-encapDecap-FIPS203 (ML-KEM-768 encapsulation tgId 2 tcId 26 & 27; decapsulation tgId 5 tcId 86 & 87)
 *   - ML-DSA-keyGen-FIPS204 (ML-DSA-65, tgId 2, tcId 26 & 27)
 *   - ML-DSA-sigGen-FIPS204 (ML-DSA-65 deterministic external pure, tgId 3, tcId 31 & 32)
 *   - ML-DSA-sigVer-FIPS204 (ML-DSA-65 external pure positive & negative, tgId 3, tcId 31, 33 & 34)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

interface KatVectors {
  source: string;
  mlKem768: {
    keyGen: Array<{ tgId: number; tcId: number; d: string; z: string; ek: string; dk: string }>;
    encapsulation: Array<{ tgId: number; tcId: number; ek: string; m: string; c: string; k: string }>;
    decapsulation: Array<{ tgId: number; tcId: number; dk: string; c: string; k: string }>;
  };
  mlDsa65: {
    keyGen: Array<{ tgId: number; tcId: number; seed: string; pk: string; sk: string }>;
    sigGenDeterministicExternalPure: Array<{
      tgId: number;
      tcId: number;
      sk: string;
      message: string;
      context: string;
      signature: string;
    }>;
    sigVerExternalPure: Array<{
      tgId: number;
      tcId: number;
      pk: string;
      message: string;
      context: string;
      signature: string;
      testPassed: boolean;
    }>;
  };
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToUpperHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex').toUpperCase();
}

const fixturePath = path.resolve(process.cwd(), 'tests/fixtures/nist-pqc-kat-vectors.json');
const vectors: KatVectors = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

describe('NIST FIPS 203 (ML-KEM-768) Known-Answer Tests (ACVP-Server)', () => {
  it('matches official FIPS 203 ML-KEM-768 KeyGen vectors bit-for-bit', () => {
    assert.ok(vectors.mlKem768.keyGen.length >= 2);
    for (const tc of vectors.mlKem768.keyGen) {
      const seed = new Uint8Array(64);
      seed.set(hexToBytes(tc.d), 0);
      seed.set(hexToBytes(tc.z), 32);

      const { publicKey, secretKey } = ml_kem768.keygen(seed);
      assert.equal(bytesToUpperHex(publicKey), tc.ek, `ML-KEM-768 KeyGen ek mismatch on tcId=${tc.tcId}`);
      assert.equal(bytesToUpperHex(secretKey), tc.dk, `ML-KEM-768 KeyGen dk mismatch on tcId=${tc.tcId}`);
    }
  });

  it('matches official FIPS 203 ML-KEM-768 Encapsulation vectors bit-for-bit', () => {
    assert.ok(vectors.mlKem768.encapsulation.length >= 2);
    for (const tc of vectors.mlKem768.encapsulation) {
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(
        hexToBytes(tc.ek),
        hexToBytes(tc.m)
      );
      assert.equal(bytesToUpperHex(cipherText), tc.c, `ML-KEM-768 Encap c mismatch on tcId=${tc.tcId}`);
      assert.equal(bytesToUpperHex(sharedSecret), tc.k, `ML-KEM-768 Encap k mismatch on tcId=${tc.tcId}`);
    }
  });

  it('matches official FIPS 203 ML-KEM-768 Decapsulation vectors bit-for-bit', () => {
    assert.ok(vectors.mlKem768.decapsulation.length >= 2);
    for (const tc of vectors.mlKem768.decapsulation) {
      const sharedSecret = ml_kem768.decapsulate(hexToBytes(tc.c), hexToBytes(tc.dk));
      assert.equal(bytesToUpperHex(sharedSecret), tc.k, `ML-KEM-768 Decap k mismatch on tcId=${tc.tcId}`);
    }
  });
});

describe('NIST FIPS 204 (ML-DSA-65) Known-Answer Tests (ACVP-Server)', () => {
  it('matches official FIPS 204 ML-DSA-65 KeyGen vectors bit-for-bit', () => {
    assert.ok(vectors.mlDsa65.keyGen.length >= 2);
    for (const tc of vectors.mlDsa65.keyGen) {
      const { publicKey, secretKey } = ml_dsa65.keygen(hexToBytes(tc.seed));
      assert.equal(bytesToUpperHex(publicKey), tc.pk, `ML-DSA-65 KeyGen pk mismatch on tcId=${tc.tcId}`);
      assert.equal(bytesToUpperHex(secretKey), tc.sk, `ML-DSA-65 KeyGen sk mismatch on tcId=${tc.tcId}`);
    }
  });

  it('matches official FIPS 204 ML-DSA-65 deterministic external pure SigGen vectors bit-for-bit', () => {
    assert.ok(vectors.mlDsa65.sigGenDeterministicExternalPure.length >= 2);
    for (const tc of vectors.mlDsa65.sigGenDeterministicExternalPure) {
      const sig = ml_dsa65.sign(hexToBytes(tc.message), hexToBytes(tc.sk), {
        context: hexToBytes(tc.context),
        extraEntropy: false,
      });
      assert.equal(bytesToUpperHex(sig), tc.signature, `ML-DSA-65 SigGen mismatch on tcId=${tc.tcId}`);
    }
  });

  it('matches official FIPS 204 ML-DSA-65 external pure SigVer positive and negative vectors', () => {
    assert.ok(vectors.mlDsa65.sigVerExternalPure.length >= 3);
    for (const tc of vectors.mlDsa65.sigVerExternalPure) {
      const verified = ml_dsa65.verify(
        hexToBytes(tc.signature),
        hexToBytes(tc.message),
        hexToBytes(tc.pk),
        { context: hexToBytes(tc.context) }
      );
      assert.equal(verified, tc.testPassed, `ML-DSA-65 SigVer mismatch on tcId=${tc.tcId}`);
    }
  });
});
