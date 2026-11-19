# Cryptographic & Security Audit Status

**Status: NO INDEPENDENT THIRD-PARTY AUDIT HAS BEEN PERFORMED.**

As of version `6.1.0` (`2026-11-19`), `chat-app` has **not** been audited by any external or independent cryptography firm, penetration testing team, or formal verification specialist. All testing and hardening to date are **internal / self-reviewed** only.

---

## 1. Self-Reviewed & Automated-Test-Covered Components

The following components have been reviewed internally and are exercised by automated tests (`npm test`):

| Component | Files | Verification Evidence |
| --- | --- | --- |
| **FIPS 203 ML-KEM-768 Primitive Conformance** | `@noble/post-quantum` `0.7.1`, `tests/nist-kat.test.ts`, `tests/fixtures/nist-pqc-kat-vectors.json` | Official NIST ACVP-Server KAT vectors (KeyGen tcId 26/27, Encap tcId 26/27, Decap tcId 86/87) verified bit-for-bit. |
| **FIPS 204 ML-DSA-65 Primitive Conformance** | `@noble/post-quantum` `0.7.1`, `tests/nist-kat.test.ts`, `tests/fixtures/nist-pqc-kat-vectors.json` | Official NIST ACVP-Server KAT vectors (KeyGen tcId 26/27, deterministic external pure SigGen tcId 31/32, positive & negative SigVer tcId 31/33/34) verified bit-for-bit. |
| **IndexedDB `v: 4` Keystore & Legacy Key Discard** | `src/utils/keystore.ts`, `src/utils/crypto.ts`, `tests/pq-mprba.test.ts` | Verified non-extractable ECDH P-256 + AES-GCM wrapping `CryptoKey`s (`extractable: false`, `exportKey` rejects), automatic deletion of `v: 2`/`v: 3` `localStorage` private keys and ratchets, and CSPRNG key generation. |
| **Fail-Closed Encrypt/Decrypt, Signature-Before-Decrypt, Replay & `MAX_SKIP`** | `src/utils/crypto.ts`, `tests/pq-mprba.test.ts`, `tests/fuzz.test.ts` | Verified `E2EEError` on all invalid/forged/replayed/out-of-bounds inputs; 390+ deterministic fuzz cases (PQ ciphertexts, group epochs, ECDH/PBKDF2 packets, key bundles, QR payloads) all fail closed without crashing or leaking plaintext. |
| **Safety Numbers (`PQ-MPRBA-SAFETY-v1`)** | `src/utils/safetyNumber.ts`, `tests/pq-mprba.test.ts` | Verified symmetry, `VERIFIED` preservation across session rekey, and permanent `VERIFIED` revocation + `CHANGED` state on peer ML-DSA-65 key change. |
| **Strict Helmet CSP & Externalized Assets** | `server.ts`, `public/admin.html`, `public/js/admin.js`, `public/js/admin-login-redirect.js`, `public/css/admin.css`, `public/css/error.css`, `tests/pq-mprba.test.ts` | Verified `default-src 'self'`, zero `'unsafe-inline'`, zero `'unsafe-eval'`, and zero unpinned third-party CDN script/style links. |
| **Bale Fallback Recovery Codes & Rate Limiting** | `src/server/recovery.ts`, `server.ts`, `src/components/AuthScreen.tsx`, `tests/pq-mprba.test.ts` | Verified 128-bit CSPRNG code format, salted `scrypt` (`N=16384, r=8, p=1`), `crypto.timingSafeEqual`, one-time rotation, and sliding-window rate limiter (5 attempts / 15 min per IP and per username). |
| **PQ Baseline Performance** | `tests/benchmark.test.ts` | Baseline latency measured for ML-KEM-768 encap/decap, ML-DSA-65 sign/verify, full PQ encrypt/decrypt, and bounded verified-bundle UI cache. |

---

## 2. Unaudited Components & Open Gaps

The following areas have **not** received independent security review or formal verification:

1. **Custom Protocol Design (`PQ-MPRBA` / `e2ee:pq:v2:`):** No formal proof (e.g., Tamarin, ProVerif, CryptoVerif) of the hybrid ML-KEM-768 + ECDH P-256 + ML-DSA-65 + symmetric-ratchet composition.
2. **Side-Channel & Timing Resistance in JS/V8:** JavaScript engines (V8, SpiderMonkey, JavaScriptCore) do not guarantee constant-time execution or deterministic garbage collection / zeroization of copied memory buffers (`Uint8Array.fill(0)` is best-effort in JS).
3. **Browser Origin & XSS Surface:** React components, DOM rendering, file upload/download handling, and service-worker/caching behavior have not undergone third-party web penetration testing.
4. **Server-Side Auth, Sessions, Socket.IO & Admin Panel:** `server.ts`, `src/server/db.ts`, `src/server/bale.ts`, and `public/js/admin.js` have not been independently penetration-tested.
5. **Group Chat Key Distribution (`e2ee:gep:v2:`):** Not a full MLS/PQ-MLS protocol; lacks independent review of membership-change security.
6. **Ristretto255-VOPRF Integration:** Server-side blinding/evaluation endpoints have not been independently audited for linkability or abuse resistance.
7. **Deployment & Operational Security:** Render hosting configuration, PostgreSQL TLS/backup encryption, and secret rotation depend on the operator's environment.

---

## 3. Path Toward an Independent Audit

Before positioning this software for high-assurance or hostile-environment use, an independent audit should prioritize:
1. Formal specification and protocol review of `src/utils/crypto.ts` and `src/utils/keystore.ts`.
2. Full-stack web security & XSS/CSP penetration test of `server.ts`, Socket.IO handlers, and React UI.
3. Replacement of symmetric group epoch derivation with an audited group key agreement (e.g., MLS / PQ-MLS).
