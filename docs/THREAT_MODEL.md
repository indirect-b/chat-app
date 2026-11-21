# Threat Model — `chat-app` (`v6.5.0`)

This document describes the security goals, adversary assumptions, mitigations, and explicit non-goals/limitations of `chat-app`.

---

## 1. System Overview & Assets

`chat-app` is a Persian-language end-to-end encrypted web messenger:

- **Client:** React 19 + TypeScript + Vite SPA executing in a standard web browser.
- **Cryptography:** Hybrid post-quantum E2EE (`PQ-MPRBA` / `e2ee:pq:v2:`):
  - Key encapsulation: **ML-KEM-768** (FIPS 203 via `@noble/post-quantum`) combined with **ECDH P-256** (WebCrypto `extractable: false`) via HKDF-SHA-256.
  - Identity & message authentication: **ML-DSA-65** (FIPS 204 via `@noble/post-quantum`) signing both the public key bundle (`MLDSA-BUNDLE-v2:...`) and every PQ message (`MLDSA-MSG-v2:...`).
  - Symmetric message encryption: **AES-256-GCM** with 96-bit random IVs and an in-memory symmetric KDF ratchet (HKDF-SHA-256, `MAX_SKIP = 100`, replay set `seenRecvSteps`, session rotation at 50 messages with `previousSession` slot, zeroization after use).
  - Safety Numbers: `PQ-MPRBA-SAFETY-v1` (SHA-256 over lexicographically sorted, 4-byte big-endian length-prefixed ML-DSA-65 public keys).
- **Server:** Centralized Node.js + Express + Socket.IO server backed by PostgreSQL (with atomic JSON file fallback), hosted on Render.
- **Authentication:** Google Sign-In with server-side one-time fallback recovery codes (128-bit random codes stored server-side only as salted `scrypt` hashes, distributed via Bale fallback) + server-issued opaque session tokens (`x-session-token` / `Authorization: Bearer`).

### Protected Assets
1. Message plaintext (1:1 PQ chats and group chats).
2. Client long-term identity private keys (ML-DSA-65, ML-KEM-768, ECDH P-256) and ephemeral ratchet chain/message keys.
3. User session tokens, recovery codes, and account export/delete endpoints.
4. Peer identity verification state (Safety Number `VERIFIED` / `CHANGED` records).

---

## 2. Adversary Model & Controls

| Adversary | Capabilities | Mitigations in `chat-app` | Residual Risk / Honest Limitation |
| --- | --- | --- | --- |
| **Passive Network / Harvest-Now-Decrypt-Later (HNDL)** | Records all TLS + application ciphertexts for future quantum decryption | Hybrid ML-KEM-768 + ECDH P-256 key establishment; AES-256-GCM; per-message symmetric ratchet with zeroization | Metadata (who talks to whom, message timestamps, message sizes, IP addresses) is visible to the server and partially to network observers. |
| **Active Network MITM / Honest-but-Curious Server** | Reads stored DB ciphertexts, attempts key substitution, replays/reorders/modifies ciphertexts | Fail-closed encryption (`E2EEError`, never falls back to plaintext); mandatory ML-DSA-65 verification on both key bundles and every message *before* decryption or ratchet mutation; strict replay rejection (`REPLAY_DETECTED`); Safety Numbers with automatic `CHANGED` alert | A malicious server that **modifies served JS/HTML** can bypass client-side E2EE entirely (see Web Trust Model in [`SECURITY.md`](../SECURITY.md)). Group chat epoch keys use ML-KEM-768 encapsulated epoch packets (`createGroupEpochPacket`), signed by the distributor and verified by members. |
| **Same-Origin XSS** | Attempts to steal keys or read DOM | Strict Helmet CSP (`default-src 'self'`, no `unsafe-inline`, no `unsafe-eval`, no unpinned CDN scripts/styles); private keys moved out of `localStorage` into IndexedDB wrapped with non-extractable WebCrypto keys; ratchet keys RAM-only | WebCrypto does not natively support ML-KEM/ML-DSA `CryptoKey`s; an active XSS payload running in-origin can still call the IndexedDB wrapping key's `decrypt()` method or read decrypted DOM text. |
| **Unauthenticated / Credential-Stuffing Attacker** | Brute-forces `/api/recover`, `/api/google-login`, or calls account endpoints directly | Server-verified opaque session tokens required for `/api/account/export` and `/api/account/delete`; `/api/recover` enforces salted `scrypt` (`N=16384, r=8, p=1`), constant-time compare, one-time code rotation, and strict sliding-window rate limit (5 attempts / 15 min per IP AND per username) | Rate limiter state is in-memory per server process; multi-instance horizontal scaling would require a shared store (e.g., Redis/PostgreSQL). |
| **Bale Outage / Platform Censorship** | Blocks or disrupts Bale fallback delivery | One-time recovery codes issued on registration and rotated on recovery login (`/api/recover`), backed by Google Sign-In as primary authentication | Users who lose their recovery code while primary login is unreachable cannot log in without operator intervention. |
| **Compromised Endpoint / Malicious Browser Extension** | Full OS or browser-profile access | Out of scope for any client-side E2EE web app | An attacker controlling the user's OS or browser extensions can read screens, keystrokes, memory, and IndexedDB directly. |

---

## 3. Multi-Device Behavior (Explicit Non-Goal — Verified from Code)

**Multi-device key sync is OUT OF SCOPE for `chat-app` `v6.5.0`.**

The following behavior was verified directly against `src/utils/keystore.ts`, `src/utils/crypto.ts`, `src/utils/safetyNumber.ts`, `src/components/ChatApp.tsx`, and `server.ts`:

1. **Keys are strictly device-local (IndexedDB `pq_mprba_keystore_v4`).**
   Identity private keys (non-extractable ECDH P-256 + non-extractable AES-GCM wrapping key + wrapped ML-KEM-768 and ML-DSA-65 private keys) are stored only in the local browser's IndexedDB and are **never** uploaded, exported, or synchronized across devices.
2. **Logging in on a second device generates a brand-new identity keypair.**
   When a user logs into an existing account on Device 2 (via Google Sign-In or `/api/recover`), `ChatApp.tsx` calls `ensureUserHybridKeyPair(username)`. Because Device 2 has no `v: 4` record in its IndexedDB, it generates fresh CSPRNG ML-KEM-768, ML-DSA-65, and ECDH P-256 keys.
3. **The server stores only one public key bundle per user and overwrites it.**
   Device 2 posts its new bundle to `POST /api/user/public-key`. In `server.ts`, `db.updateUserPublicKey(username, publicKey)` overwrites `users.public_key` for that account and broadcasts `peer-key-updated` to online contacts.
4. **Consequences for contacts (Safety Numbers):**
   Every contact's client calls `observeContactPublicKey(myUsername, contactUsername, newBundle)`. Because the ML-DSA-65 public key changed, each contact's local verification state immediately transitions to `CHANGED`, any previous `VERIFIED` state is permanently cleared, a persistent in-chat key-change alert is displayed, and outgoing sends require explicit confirmation (`verifyFirst` / `sendAnyway`).
5. **Consequences for message history & Device 1:**
   - **History:** Because ratchet session keys are RAM-only and Device 2 has a different ML-KEM-768/ECDH private key, previously encrypted 1:1 PQ messages stored on the server **cannot** be decrypted on Device 2 (they fail closed with `E2EEError` and display the locked-message notice).
   - **Device 1 desynchronization:** Once Device 2 overwrites `users.public_key` on the server, peers encapsulate new sessions to Device 2's public key, so Device 1 can no longer decrypt new messages addressed to Device 2 (and Device 1's own signatures will fail verification on peers who fetched Device 2's bundle).
   - **Recommendation:** Use `chat-app` on a single primary browser/device per account, and re-verify Safety Numbers out-of-band whenever switching devices or reinstalling.

---

## 4. Known Cryptographic & Architectural Gaps

1. **No independent third-party audit** — see [`docs/AUDIT_STATUS.md`](AUDIT_STATUS.md).
2. **Centralized infrastructure** — a single Express/Socket.IO server relays messages and serves the web client; federation and P2P are future work (see [`docs/DEPLOYMENT.md`](DEPLOYMENT.md)).
3. **Symmetric-only ratchet (no per-turn DH/KEM ratchet yet)** — forward secrecy is provided per message via HKDF chain stepping + zeroization, while post-compromise security (PCS) currently requires explicit session rekey (`rotateSessionRatchetOnly`) or new KEM encapsulation rather than continuous per-turn ML-KEM ratcheting.
4. **Group E2EE (`e2ee:gep:v2:`)** — uses an epoch state machine (`Group Epoch FSM`) with a 3-epoch grace buffer and zeroization, but without an authenticated asymmetric group key agreement (such as MLS / PQ-MLS), the server could theoretically observe deterministic fallback epoch derivations unless a custom out-of-band group secret or encapsulated epoch key is supplied.
5. **Metadata protection** — message routing, room membership, and contact graphs are visible to the server.
