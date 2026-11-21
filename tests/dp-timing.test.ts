/**
 * DP item 7 — LOCAL statistical timing harness (Node only).
 *
 * Phase-1 §10 item 7 was UNFINISHED: no live timing measurement was ever
 * performed; side-channel conclusions were static-analysis judgements.
 * This harness measures, in this Node v24 VM, the wall-clock time of the
 * crypto operations an attacker could in principle time, across input
 * classes that differ ONLY in validity:
 *   - ML-KEM-768 decapsulate: valid ct / corrupt valid-length ct
 *     (FIPS 203 implicit rejection) / wrong-length ct (throws)
 *   - ML-DSA-65 verify: valid sig / 1-bit-flipped sig / wrong-length sig
 *     / valid sig over a wrong message
 *   - ML-DSA-65 sign: baseline
 *   - AES-256-GCM (WebCrypto) decrypt: valid / flipped tag (auth failure)
 *
 * Method: warmup, then N timed iterations per class with
 * performance.now(); report mean / median / p5 / p95 / min / max and the
 * mean difference between classes in units of the pooled standard
 * deviation (a rough "how many sigmas apart" — NOT a formal test).
 * No timing assertion is made: a single Node process on a shared VM
 * cannot support a pass/fail timing claim, and JIT/GC noise dominates
 * sub-microsecond effects. The numbers below are distributions to read,
 * not a verdict.
 *
 * EXPLICITLY UNCLOSEABLE here: microarchitectural / cache-timing leakage
 * of the noble JS implementations (rejection loops, early-exit norm
 * checks, bigint arithmetic — see the library's own disclaimer, M13).
 * Measuring that needs a controlled lab harness (fixed CPU, cache
 * flushing, statistical tests such as dudect/TVLA) and is specialist /
 * accredited-lab work, not something a Node timing loop can do.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { webcrypto } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

function stats(samples: number[]) {
  const s = [...samples].sort((a, b) => a - b);
  const n = s.length;
  const mean = s.reduce((a, b) => a + b, 0) / n;
  const sd = Math.sqrt(s.reduce((a, b) => a + (b - mean) ** 2, 0) / n);
  const q = (p: number) => s[Math.min(n - 1, Math.floor(p * n))];
  return { n, mean, median: q(0.5), p5: q(0.05), p95: q(0.95), min: s[0], max: s[n - 1], sd };
}

function fmt(r: ReturnType<typeof stats>): string {
  const u = (v: number) => `${v.toFixed(1)}µs`;
  return `n=${r.n} mean=${u(r.mean)} median=${u(r.median)} p5=${u(r.p5)} p95=${u(r.p95)} min=${u(r.min)} max=${u(r.max)} sd=${u(r.sd)}`;
}

function compare(a: ReturnType<typeof stats>, b: ReturnType<typeof stats>): string {
  const pooled = Math.sqrt((a.sd ** 2 + b.sd ** 2) / 2);
  const d = pooled === 0 ? 0 : (a.mean - b.mean) / pooled;
  return `Δmean=${(a.mean - b.mean).toFixed(1)}µs (${d.toFixed(2)} pooled sd)`;
}

async function timeIt(fn: () => void | Promise<void>, n: number): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    await fn();
    out.push((performance.now() - t0) * 1000);
  }
  return out;
}

describe('DP item 7 — local timing distributions (informational, no pass/fail on timing)', () => {
  it('measures decap / verify / sign / GCM timing across valid vs invalid input classes', async () => {
    const N = 300;
    const WARM = 50;

    // ---- fixtures ----
    const { publicKey: kemPub, secretKey: kemSec } = ml_kem768.keygen();
    const { cipherText: validCt, sharedSecret } = ml_kem768.encapsulate(kemPub);
    const corruptCt = new Uint8Array(validCt);
    corruptCt[0] ^= 0x01;
    const shortCt = validCt.slice(0, 100);

    const { publicKey: dsaPub, secretKey: dsaSec } = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('timing probe message');
    const otherMsg = new TextEncoder().encode('timing probe messagf');
    const validSig = ml_dsa65.sign(msg, dsaSec);
    const flippedSig = new Uint8Array(validSig);
    flippedSig[100] ^= 0x01;
    const shortSig = validSig.slice(0, 100);

    const gcmKey = await webcrypto.subtle.importKey('raw', new Uint8Array(32), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = new Uint8Array(12);
    const gcmCt = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, gcmKey, msg));
    const gcmBadTag = new Uint8Array(gcmCt);
    gcmBadTag[gcmBadTag.length - 1] ^= 0x01;

    // ---- warmup (JIT + caches) ----
    for (let i = 0; i < WARM; i++) {
      ml_kem768.decapsulate(validCt, kemSec);
      ml_dsa65.verify(validSig, msg, dsaPub);
      ml_dsa65.sign(msg, dsaSec);
    }

    const decapValid = stats(await timeIt(() => { ml_kem768.decapsulate(validCt, kemSec); }, N));
    const decapCorrupt = stats(await timeIt(() => { ml_kem768.decapsulate(corruptCt, kemSec); }, N));
    const decapShort = stats(await timeIt(() => { try { ml_kem768.decapsulate(shortCt, kemSec); } catch { /* expected */ } }, N));
    // Implicit-rejection check (correctness, not timing): corrupt ct must
    // yield a DIFFERENT secret, never the true one.
    assert.notDeepEqual(ml_kem768.decapsulate(corruptCt, kemSec), sharedSecret);

    const verifyValid = stats(await timeIt(() => { ml_dsa65.verify(validSig, msg, dsaPub); }, N));
    const verifyFlipped = stats(await timeIt(() => { ml_dsa65.verify(flippedSig, msg, dsaPub); }, N));
    const verifyWrongMsg = stats(await timeIt(() => { ml_dsa65.verify(validSig, otherMsg, dsaPub); }, N));
    const verifyShort = stats(await timeIt(() => { try { ml_dsa65.verify(shortSig, msg, dsaPub); } catch { /* expected */ } }, N));
    assert.equal(ml_dsa65.verify(flippedSig, msg, dsaPub), false);
    assert.equal(ml_dsa65.verify(validSig, otherMsg, dsaPub), false);

    const sign = stats(await timeIt(() => { ml_dsa65.sign(msg, dsaSec); }, N));

    const gcmValid = stats(await timeIt(async () => { await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, gcmKey, gcmCt as unknown as BufferSource); }, N));
    const gcmBad = stats(await timeIt(async () => { try { await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, gcmKey, gcmBadTag as unknown as BufferSource); } catch { /* expected */ } }, N));

    console.log('[dp-timing] Node ' + process.version + ', N=' + N + ' per class, µs:');
    console.log('[dp-timing] ML-KEM decap valid       : ' + fmt(decapValid));
    console.log('[dp-timing] ML-KEM decap corrupt     : ' + fmt(decapCorrupt) + '  vs valid: ' + compare(decapCorrupt, decapValid));
    console.log('[dp-timing] ML-KEM decap short(throw): ' + fmt(decapShort) + '  vs valid: ' + compare(decapShort, decapValid));
    console.log('[dp-timing] ML-DSA verify valid      : ' + fmt(verifyValid));
    console.log('[dp-timing] ML-DSA verify flipped    : ' + fmt(verifyFlipped) + '  vs valid: ' + compare(verifyFlipped, verifyValid));
    console.log('[dp-timing] ML-DSA verify wrong-msg  : ' + fmt(verifyWrongMsg) + '  vs valid: ' + compare(verifyWrongMsg, verifyValid));
    console.log('[dp-timing] ML-DSA verify short      : ' + fmt(verifyShort) + '  vs valid: ' + compare(verifyShort, verifyValid));
    console.log('[dp-timing] ML-DSA sign              : ' + fmt(sign));
    console.log('[dp-timing] AES-GCM decrypt valid    : ' + fmt(gcmValid));
    console.log('[dp-timing] AES-GCM decrypt bad-tag  : ' + fmt(gcmBad) + '  vs valid: ' + compare(gcmBad, gcmValid));
    console.log('[dp-timing] NOTE: single shared-VM Node process; JIT/GC noise dominates. No timing verdict is asserted. Cache-timing/microarchitectural analysis remains UNCLOSEABLE here.');
  });
});
