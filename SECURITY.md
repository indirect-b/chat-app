# Security Policy & Web Trust Model

**Version:** `6.1.0`

This document states the security properties, structural limitations, and vulnerability disclosure process of `chat-app` plainly and honestly.

---

## 1. Honest Web Platform Trust Model

`chat-app` is a **web application** (React + TypeScript served over HTTPS by a centralized Node.js/Express server). Even with client-side post-quantum end-to-end encryption (ML-KEM-768 + ECDH P-256 + ML-DSA-65 + AES-256-GCM), **browser-delivered E2EE has fundamental trust boundaries** that users must understand:

1. **A compromised server can serve compromised code.**
   Every time a browser loads or reloads the web app, it executes JavaScript delivered by the server. An attacker with full control of the server, hosting account (Render), TLS certificate, or deployment pipeline could serve modified JavaScript that exfiltrates plaintext before encryption or replaces peer public keys.
2. **PWA / browser caching does not provide permanent code pinning.**
   Even when cached locally (HTTP cache or PWA), cached web assets are only pinned until the next cache expiration or application update served by the origin. It is **not** equivalent to signed, reproducibly built native binaries installed from an out-of-band distribution channel.
3. **Key storage hardening (`v: 4`) and its honest WebCrypto boundary.**
   - As of `v6.1.0` (storage schema `v: 4`), private identity keys and session ratchets are **never** stored in `localStorage`.
   - The ECDH P-256 private key is stored directly in IndexedDB as a WebCrypto `CryptoKey` with `extractable: false`.
   - Because the W3C WebCrypto API does not yet support native ML-KEM-768 or ML-DSA-65 `CryptoKey` objects, raw ML-KEM-768 and ML-DSA-65 private keys are encrypted at rest in IndexedDB using a per-user 256-bit AES-GCM wrapping `CryptoKey` created with `extractable: false` (unique 96-bit IV + AAD per key). Unwrapped secret bytes exist in JavaScript memory only during a single decapsulation/signing call and are zeroized in a `finally` block.
   - **Limitation:** `extractable: false` prevents extracting raw wrapping/ECDH key bytes via `crypto.subtle.exportKey`, and isolates keys from `localStorage` leaks. However, an active same-origin XSS attacker executing arbitrary JavaScript in the page origin could still invoke the IndexedDB wrapping key's `decrypt()` method at runtime. Strict Content Security Policy (`default-src 'self'`, no `'unsafe-inline'`, no `'unsafe-eval'`, no unpinned third-party CDN scripts/styles) is therefore mandatory and enforced by Helmet.
   - Symmetric ratchet chain keys, skipped message keys, and group epoch keys are held strictly in RAM (never persisted to `localStorage` or IndexedDB) and zeroized immediately upon consumption, rotation, or session reset.
4. **Safety Number verification is the user's primary defense against MITM and key substitution.**
   - Out-of-band verification of the 60-digit / QR Safety Number (`PQ-MPRBA-SAFETY-v1`, SHA-256 over lexicographically sorted length-prefixed ML-DSA-65 identity verification keys) detects silent identity key replacement by a malicious server or active network attacker.
   - Whenever a contact's ML-DSA-65 identity key changes (whether due to reinstall, second-device login, or MITM), the client automatically marks the contact `CHANGED`, clears any prior `VERIFIED` status permanently, shows a persistent in-chat warning, and requires explicit user confirmation before sending outgoing messages.
   - Users **must** re-verify Safety Numbers out-of-band (in person, or over an independent trusted voice/video channel) after any key-change alert before sharing sensitive information.

---

## 2. Independent Audit Status

**`chat-app` has NOT undergone an independent third-party cryptographic or security audit.**
See [`docs/AUDIT_STATUS.md`](docs/AUDIT_STATUS.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the exact scope of self-reviewed items versus unaudited components. Do not rely on this application for life-critical or high-risk threat models without an independent audit.

---

## 3. Supported Versions

Only the latest release on the `main` branch is actively maintained for security fixes:

| Version | Supported |
| ------- | --------- |
| `6.1.x` | Yes       |
| `< 6.1` | No (legacy `v: 2`/`v: 3` localStorage keys are automatically discarded on upgrade) |

---

## 4. Reporting a Vulnerability

**Do NOT open public GitHub issues for suspected security vulnerabilities.**

Please report security issues privately to the repository maintainer:

1. Use GitHub's **Private Vulnerability Reporting** ("Report a vulnerability" under the repository's **Security** tab), or contact the repository owner privately if Security Advisories are not enabled.
2. Include:
   - Affected version/commit and component (`src/utils/crypto.ts`, `src/utils/keystore.ts`, `server.ts`, etc.)
   - Clear reproduction steps or proof-of-concept
   - Impact assessment (e.g., plaintext recovery, key substitution, auth bypass, XSS/CSP bypass)
3. You should receive an acknowledgment within **72 hours**, followed by a remediation plan or coordinated disclosure timeline once verified.
