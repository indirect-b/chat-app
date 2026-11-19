/**
 * Post-Quantum Cryptographic Performance Benchmark Suite (Item 4.1)
 *
 * Measures baseline execution time for:
 *  - ML-KEM-768 encapsulate / decapsulate
 *  - ML-DSA-65 sign / verify (typical message size)
 *  - Full PQ-MPRBA v2 message encrypt / decrypt round-trip
 *  - Verified-bundle read-only UI cache vs fresh signature verification
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  clearVerifiedBundleCache,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  getVerifiedBundleCacheStats,
  parsePeerKeyBundle,
  resetAllCryptoStateForTests,
} from '../src/utils/crypto';

function summarizeMs(samples: number[]): { avgMs: number; p95Ms: number; minMs: number; maxMs: number } {
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const p95Idx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
  return {
    avgMs: Number((sum / sorted.length).toFixed(3)),
    p95Ms: Number(sorted[p95Idx].toFixed(3)),
    minMs: Number(sorted[0].toFixed(3)),
    maxMs: Number(sorted[sorted.length - 1].toFixed(3)),
  };
}

describe('PQ-MPRBA Performance Benchmarks', () => {
  it('measures ML-KEM-768 encap/decap and ML-DSA-65 sign/verify baseline latency', () => {
    const iterations = 25;
    const kemKeys = ml_kem768.keygen();
    const dsaKeys = ml_dsa65.keygen();
    const typicalMsg = new TextEncoder().encode(
      'MLDSA-MSG-v2:alice__bob:42:TypicalChatMessagePayloadLengthAround256BytesForRealWorldBenchmarks'
    );

    const encapSamples: number[] = [];
    const decapSamples: number[] = [];
    const signSamples: number[] = [];
    const verifySamples: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(kemKeys.publicKey);
      const t1 = performance.now();
      const recovered = ml_kem768.decapsulate(cipherText, kemKeys.secretKey);
      const t2 = performance.now();

      assert.deepEqual(recovered, sharedSecret);
      encapSamples.push(t1 - t0);
      decapSamples.push(t2 - t1);

      const t3 = performance.now();
      const sig = ml_dsa65.sign(typicalMsg, dsaKeys.secretKey);
      const t4 = performance.now();
      const valid = ml_dsa65.verify(sig, typicalMsg, dsaKeys.publicKey);
      const t5 = performance.now();

      assert.equal(valid, true);
      signSamples.push(t4 - t3);
      verifySamples.push(t5 - t4);
    }

    const encapStats = summarizeMs(encapSamples);
    const decapStats = summarizeMs(decapSamples);
    const signStats = summarizeMs(signSamples);
    const verifyStats = summarizeMs(verifySamples);

    console.log('[BENCHMARK] ML-KEM-768 encapsulate:', JSON.stringify(encapStats));
    console.log('[BENCHMARK] ML-KEM-768 decapsulate:', JSON.stringify(decapStats));
    console.log('[BENCHMARK] ML-DSA-65 sign (typical msg):', JSON.stringify(signStats));
    console.log('[BENCHMARK] ML-DSA-65 verify (typical msg):', JSON.stringify(verifyStats));

    // Sanity bounds (generous for CI / software JS implementations)
    assert.ok(encapStats.avgMs < 500, `ML-KEM-768 encap unexpectedly slow: ${encapStats.avgMs}ms`);
    assert.ok(decapStats.avgMs < 500, `ML-KEM-768 decap unexpectedly slow: ${decapStats.avgMs}ms`);
    assert.ok(signStats.avgMs < 1000, `ML-DSA-65 sign unexpectedly slow: ${signStats.avgMs}ms`);
    assert.ok(verifyStats.avgMs < 500, `ML-DSA-65 verify unexpectedly slow: ${verifyStats.avgMs}ms`);
  });

  it('measures end-to-end PQ-MPRBA encrypt/decrypt round-trip and verified-bundle UI cache speedup', async () => {
    resetAllCryptoStateForTests();
    clearVerifiedBundleCache();

    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';

    const encSamples: number[] = [];
    const decSamples: number[] = [];

    for (let i = 0; i < 15; i++) {
      const t0 = performance.now();
      const ct = await encryptMessageText(`Benchmark message #${i} — سلام دنیا`, roomId, {
        myUsername: 'alice',
        peerUsername: 'bob',
        peerPublicKey: bobBundle,
      });
      const t1 = performance.now();
      const pt = await decryptMessageText(ct, roomId, {
        myUsername: 'bob',
        peerUsername: 'alice',
        peerPublicKey: aliceBundle,
        sender: 'alice',
      });
      const t2 = performance.now();

      assert.equal(pt.text, `Benchmark message #${i} — سلام دنیا`);
      encSamples.push(t1 - t0);
      decSamples.push(t2 - t1);
    }

    // Compare uncached vs cached read-only bundle verification
    clearVerifiedBundleCache();
    const uncachedStart = performance.now();
    for (let i = 0; i < 20; i++) {
      const res = parsePeerKeyBundle(aliceBundle, 'alice', { skipCache: true });
      assert.equal(res.isMldsaVerified, true);
    }
    const uncachedTotalMs = Number((performance.now() - uncachedStart).toFixed(3));

    clearVerifiedBundleCache();
    parsePeerKeyBundle(aliceBundle, 'alice'); // warm cache once
    const cachedStart = performance.now();
    for (let i = 0; i < 20; i++) {
      const res = parsePeerKeyBundle(aliceBundle, 'alice');
      assert.equal(res.isMldsaVerified, true);
    }
    const cachedTotalMs = Number((performance.now() - cachedStart).toFixed(3));

    console.log('[BENCHMARK] E2EE PQ encryptMessageText:', JSON.stringify(summarizeMs(encSamples)));
    console.log('[BENCHMARK] E2EE PQ decryptMessageText:', JSON.stringify(summarizeMs(decSamples)));
    console.log(
      '[BENCHMARK] UI parsePeerKeyBundle (20x):',
      JSON.stringify({
        uncachedTotalMs,
        cachedTotalMs,
        cacheHits: getVerifiedBundleCacheStats().hits,
      })
    );

    assert.equal(getVerifiedBundleCacheStats().hits, 20);
    assert.ok(cachedTotalMs <= uncachedTotalMs + 5);
  });
});
