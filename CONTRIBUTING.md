# Contributing to `chat-app`

Thank you for your interest in contributing to `chat-app`. Because this is an end-to-end encrypted messaging application, every change to cryptography, authentication, storage, or CSP headers is held to strict fail-closed engineering standards.

---

## 1. Local Setup

- **Node.js:** `>= 20` (developed and tested on Node `22.x`).
- **Install dependencies:**
  ```bash
  npm install
  ```
- **Run development server:**
  ```bash
  npm run dev
  ```
  The app runs on `http://localhost:3000` (using `data/database.json` when `DATABASE_URL` is not set).

---

## 2. Running Tests, Type-Checking & Build

Before submitting any pull request, all three checks below must pass cleanly with zero errors:

```bash
# 1. Run the full automated test suite (protocol, keystore, NIST KATs, fuzzing, benchmarks)
npm test

# 2. TypeScript strict type-checking (tsc --noEmit)
npm run lint

# 3. Production Vite bundle build
npm run build
```

### Test Suite Layout (`tests/`)
- `tests/pq-mprba.test.ts` — Core PQ-MPRBA v4 protocol, non-extractable WebCrypto/IndexedDB keystore, legacy key discard, signature-before-decrypt, replay & `MAX_SKIP`, Group Epoch FSM, Safety Numbers, recovery codes & rate limiter, and Helmet CSP verification.
- `tests/nist-kat.test.ts` — Official NIST ACVP-Server Known-Answer Tests for FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).
- `tests/fuzz.test.ts` — Deterministic fuzz tests ensuring malformed/truncated/random ciphertexts, key bundles, epoch packets, and Safety Number QR codes always fail closed (`E2EEError`).
- `tests/benchmark.test.ts` — Baseline latency measurements for ML-KEM-768, ML-DSA-65, E2EE round-trip, and verified-bundle UI caching.

---

## 3. Code Style & Security Engineering Rules

1. **TypeScript Everywhere:** Write strict TypeScript (`src/`, `server.ts`, `tests/`). Keep imports at top level and avoid `any` where concrete types exist.
2. **Fail-Closed Cryptography:**
   - Never fall back to plaintext on encryption or decryption failure — throw `E2EEError` with an explicit error code.
   - Always verify ML-DSA-65 signatures **before** advancing ratchet state or attempting AES-GCM decryption.
   - Never skip signature verification on session establishment (`skipCache: true` is mandatory).
   - Zeroize temporary secret `Uint8Array` buffers in `finally` blocks.
3. **Key Storage Discipline (`v: 4`):**
   - Never store private keys, ratchet keys, or plaintext message caches in `localStorage`.
   - Use non-extractable WebCrypto `CryptoKey`s (`extractable: false`) in IndexedDB via `src/utils/keystore.ts`.
4. **Strict CSP Compliance:**
   - Never introduce `'unsafe-inline'`, `'unsafe-eval'`, inline `<script>`/`<style>` blocks, `onclick` attributes, or unpinned third-party CDN scripts/styles.
5. **Minimal Dependencies:** Avoid adding new runtime npm dependencies unless strictly necessary and well-audited.
6. **Honest Documentation:** Never claim an independent audit exists, and update `docs/THREAT_MODEL.md` / `docs/AUDIT_STATUS.md` whenever changing security boundaries.

---

## 4. Private Security Vulnerability Disclosure

If you discover a security vulnerability, **do NOT open a public issue or pull request** containing exploit details.

Follow the private disclosure process in [`SECURITY.md`](SECURITY.md):
- Report privately via GitHub's **Private Vulnerability Reporting** under the repository's **Security** tab (or contact the maintainer privately).
- Provide reproduction steps, affected files/versions, and estimated impact.
- Allow reasonable time for triage and a coordinated fix before public disclosure.
