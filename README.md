<div align="center">

# 💬 chat-app — Post-Quantum Encrypted Web Messenger

**A real-time Persian web messenger with end-to-end encryption built for the post-quantum era.**

Every message is protected by **PQ-MPRBA** — an original browser-native protocol combining a hybrid
**ML-KEM-768 (FIPS 203) + ECDH P-256** ratchet with **Ristretto255-VOPRF** blinded authentication (RFC 9497)
and **ML-DSA-65 (FIPS 204)** identity signatures.
The server never sees plaintext, and never learns who is talking to whom.

[![Version](https://img.shields.io/badge/version-6.5.0-blue)](CHANGELOG.md)
[![React](https://img.shields.io/badge/React-19-61dafb?logo=react&logoColor=white)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Node.js](https://img.shields.io/badge/Node.js-Express-339933?logo=nodedotjs&logoColor=white)](https://expressjs.com)
[![Socket.IO](https://img.shields.io/badge/Socket.IO-4-010101?logo=socketdotio&logoColor=white)](https://socket.io)
[![Crypto](https://img.shields.io/badge/crypto-ML--KEM--768%20%2B%20AES--256--GCM-purple)](#-the-pq-mprba-protocol)
[![Stars](https://img.shields.io/github/stars/indirect-b/chat-app?style=social)](https://github.com/indirect-b/chat-app/stargazers)

**🚀 Live demo:** https://chatapp-server-1i2a.onrender.com &nbsp;·&nbsp; Google sign-in only
<br/><sub>(free-tier hosting: the first load may take ~30s while the server wakes up)</sub>

</div>

| Login — Bale ID + OTP, E2EE notice | Chat — PQ-KEM badge, AES-256-GCM thread |
| :---: | :---: |
| ![Login screen](docs/screenshots/screenshot-login.png) | ![Chat thread](docs/screenshots/screenshot-chat.png) |

---

## Why this exists

Most web messengers either skip end-to-end encryption entirely or bolt on a classical ECDH scheme
that a future quantum computer will retroactively break (*"store now, decrypt later"*).
chat-app was designed from the start for hostile networks and a post-quantum future:

- 🔐 **Post-quantum by design** — hybrid key exchange, so recorded traffic stays safe even against Shor's algorithm.
- 🙈 **Metadata-resistant** — blinded authentication means the server routes messages without linking identities.
- ⚡ **Built for unstable networks** — out-of-order message recovery, group key rotation that doesn't corrupt in-flight messages.
- 🧩 **Zero-knowledge server** — the backend is a forwarder of ciphertext, nothing more.

## ✨ Features

- Real-time direct & group messaging (Socket.IO, WebSocket + long-polling fallback)
- End-to-end encryption: **AES-256-GCM**, keys derived per message via a hybrid post-quantum ratchet
- Login with **Bale ID**: OTP codes delivered by a Bale bot (`src/server/bale.ts`), plus a 1-click quick test login
- Blinded identity authentication via **Ristretto255-VOPRF** with DLEQ zero-knowledge proofs
- **ML-DSA-65 identity signatures (FIPS 204)** — key bundles and session handshakes are signed and verified; the PQ-KEM badge appears only for verified hybrid post-quantum sessions, a classical fallback shows a warning banner, and a forged signature triggers a man-in-the-middle warning
- **Group Epoch FSM** — membership changes rotate group keys without losing in-flight messages
- Typing indicators, presence, reactions, message edit/delete/pin/forward, read receipts
- Voice notes & file attachments up to **50 MB**, processed off the main thread in Web Workers
- PBKDF2 room passphrases (600,000 iterations; pre-hardening rooms used 50,000 and stay readable)
- Stealth admin dashboard at an obfuscated, server-side-only path (timing-safe auth)
- Dual-mode persistence: **PostgreSQL** when configured, otherwise an atomic, mutex-guarded JSON store
- Hybrid media storage so uploads survive container redeploys on Render / Railway / Docker

## 🔐 The PQ-MPRBA protocol

**PQ-MPRBA** *(Post-Quantum Multi-Party Ratchet with Blinded Authentication)* runs entirely in the
browser (`src/utils/crypto.ts`, Web Crypto API + `@noble/post-quantum` / `@noble/curves`).

PQ-MPRBA was designed by Mohammad Taha Azizi Ahad.

**Layer 1 — Hybrid post-quantum ratchet.**
Each session combines **ML-KEM-768** (NIST FIPS 203, lattice-based) with classical **ECDH P-256**;
both shared secrets feed **HKDF-SHA256** into a symmetric ratchet chain. Every message gets a fresh
one-time **AES-256-GCM** key, giving forward secrecy and post-compromise recovery. Breaking a session
requires breaking *both* the lattice problem and the elliptic-curve problem.

**Out-of-order recovery.** If message #3 arrives before #2, the ratchet fast-forwards and caches the
skipped one-time keys in a bounded in-memory vault (`MAX_SKIP = 100` per room, 10-minute TTL).
Consumed keys and ML-KEM secrets are **zeroized in RAM** (`Uint8Array.fill(0)`) immediately after use.

**Layer 2 — Blinded authentication (Ristretto255-VOPRF, RFC 9497).**
The client blinds its identity scalar locally, the server evaluates it with its secret key and returns
a **DLEQ proof** (`POST /api/voprf/evaluate`), the client verifies the proof and unblinds the result to
derive an unlinkable routing token. The server can authenticate users without ever seeing — or linking —
their identities, replacing heavy RSA blind signatures with compact 32-byte group elements.

**Layer 3 — Post-quantum identity (ML-DSA-65, FIPS 204).**
Each user holds an ML-DSA-65 keypair alongside the ML-KEM/ECDH bundle. Key bundles and session
handshakes are signed with ML-DSA and verified on receipt, so a session's post-quantum claim is
authenticated, not just asserted. The UI enforces this: the 🛡️ PQ-KEM badge appears only when
ML-KEM-768 is present *and* the ML-DSA-65 signature verifies; a classical ECDH fallback shows a
⚠️ classical warning banner instead of the badge, and a forged signature raises a
⛔ man-in-the-middle warning.

**Group epochs.** Group keys rotate through a deterministic finite state machine
(`STABLE → ROTATING → STABLE`, synced via the `group-epoch-rotated` socket event). Outgoing messages
queue during rotation, and a 3-epoch grace buffer (`MAX_EPOCH_HISTORY = 3`) keeps messages sent
milliseconds before a membership change decryptable.

> ⚠️ **Honest status:** PQ-MPRBA is an original, experimental protocol written for this project.
> It has **not** been independently audited. Treat it as research-grade cryptography, not a
> replacement for audited messengers in high-risk situations.

## 🧪 Security self-assessment — 21 November 2026

**This is a self-assessment, not an independent audit, not a FIPS 140-3 validation, and not a formal proof.** On the night of 20–21 November 2026 the protocol and implementation were tested the way audit firms test a protocol: the existing suite was re-run independently, new adversarial tests were written and run, official NIST CAVP/ACVP vectors were fetched fresh and run, the whitepaper was checked claim-by-claim against the code, and dependencies were checked against the GitHub Advisory Database. Every result below was produced by running code — nothing is taken on trust from earlier reports. Code reviewed: `main` (v6.5.0-era behaviour; `package.json` still says 6.1.0). Existing suite re-run independently three times: **142/142 pass**. Full method, evidence and the Persian report: `docs/AUDIT_STATUS.md`.

### Results at a glance

| Suite | Tests | Passed | Failed | Notes |
| --- | ---: | ---: | ---: | --- |
| Existing suite (`npm test`, re-run independently 3×) | 142 | 142 | 0 | `tsc --noEmit` clean. Two tests only pass in-process / in-order — see caveats below. |
| New adversarial tests (`tests/adversarial.test.ts`) | 32 | 30 | 2 | The 2 failures (A3, C8) are confirmed findings, reproduced twice. |
| Official NIST ACVP KAT (`tests/kat-official.test.ts`) | 8 tests / 285 cases | 255 cases | 0 cases | 30 cases policy-skipped (ML-DSA-65 prehash — noble's public API refuses them); never counted as passes. |
| Extended fuzz (`tests/fuzz-w3.test.ts`) | 14 | 14 | 0 | ~200 additional cases. |
| **Total** | **196 test functions** | **194** | **2** | |

### Findings — 43 distinct (0 Critical)

| ID | Finding | Location |
| --- | --- | --- |
| **H1** | Replay bypass across the 50-message ratchet rotation (capsule alternation wipes the consumed-step set) | `crypto.ts:891` |
| **H2** | Group epoch packets are unauthenticated — anyone with public bundles can mint one; a malicious server can rotate a group onto a key it chose | `crypto.ts:1188,1301; server.ts:694-726` |
| **H3** | Replay protection is session-lifetime-only; history locks after reload / room re-open (§7.5 design no longer exists in code) | `crypto.ts:1606` |
| **H4** | The promised previous-session slot does not exist; late pre-rotation messages are undecryptable | `crypto.ts:124-135` |
| **H5** | multer 1.4.5-lts.2 hit by 9 published advisories (8 High DoS + 1 Low); the 1.x line is unmaintained | `package.json:17` |
| **H6** | body-parser 1.20.8 is one patch behind CVE-2026-111181 (High DoS, unauthenticated) | `server.ts:120` |

| ID | Finding | Location |
| --- | --- | --- |
| **M1** | Replay protection is RAM-only: after a ratchet-state wipe any captured message decrypts again | `crypto.ts:157` |
| **M2** | Group replay protection evicts after 500 messages in one epoch | `crypto.ts:1836` |
| **M3** | Group messages carry no sender authentication — any epoch-key holder can pose as any member | `crypto.ts:1770-1850` |
| **M4** | Bundle substitution succeeds end-to-end for the second user in a room | `crypto.ts:451+` |
| **M5** | Safety-number functions trust unverified bundles | `safetyNumber.ts:183-200` |
| **M6** | Group epoch rotation on membership change is signalled but the new key is not distributed atomically; no remove-member path exists at all | `server.ts:1112-1140` |
| **M7** | Group badge claims PQ unconditionally, even with no epoch key established | `crypto.ts:608-616` |
| **M8** | No logout / device-wipe path for keystore v4; identity keys stay in IndexedDB forever | `keystore.ts:300+` |
| **M9** | Manual room passphrases stored as plaintext in localStorage | `crypto.ts:2145-2175` |
| **M10** | 1:1 file/media keys are classical, static ECDH-derived keys with no forward secrecy — and file encryption is not described in the whitepaper | `crypto.ts:1990-2025` |
| **M11** | Socket `forward-message` handler has no membership or ownership check | `server.ts:1521-1560` |
| **M12** | follow-redirects 1.16.1 hit by CVE-2026-116689 (limited exposure here — axios is only used for Bale) | `axios 1.20.0` |
| **M13** | @noble/post-quantum 0.7.1 has never been independently audited and disclaims constant-time execution | `package.json` |
| **M14** | google-auth-library is in package.json but missing from bun.lock — installs do not reproduce it from the lockfile | `package.json:19` |
| **M15** | No FIPS 140-3-style runtime self-tests and no error state | `src/, server.ts` |

| ID | Finding | Location |
| --- | --- | --- |
| **L1** | Group epoch rollback is accepted (no monotonicity check) | `crypto.ts:1301-1345` |
| **L2** | ML-KEM-only key change is invisible to the safety number | `safetyNumber.ts:253-300` |
| **L3** | E2EE payloads with an unknown version pass through as plaintext, no warning | `crypto.ts:1627-1630` |
| **L4** | Empty / null plaintext silently "encrypts" to '' | `crypto.ts:1418` |
| **L5** | Bundle parser leniency: signature does not bind ECDH `kty`; missing `crv` defaults to P-256; empty username tolerated | `crypto.ts:219-230,437-560` |
| **L6** | Legacy ECDH decrypt path skips the bundle username check | `crypto.ts:1880-1905` |
| **L7** | POST /api/voprf/evaluate is unauthenticated and unthrottled | `server.ts:638-660` |
| **L8** | Wrapping key lives in the same IndexedDB as the wrapped secrets and is not password-derived | `keystore.ts:300-340` |
| **L9** | Session tokens in localStorage (7-day expiry); server session store is in-memory | `ChatApp.tsx:75; server.ts:455` |
| **L10** | ensureUserHybridKeyPair swallows all errors and returns null (silent identity-less state) | `crypto.ts:390-391` |
| **L11** | User can switch E2EE off; plaintext sends and raw file uploads then occur | `ChatApp.tsx:1565-1574` |
| **L12** | Documentation drift (stale Bale-OTP login, stale F3/F7/F9 descriptions, version labels disagree) | `docs/THREAT_MODEL.md; SECURITY_REVIEW.md` |
| **L13** | uuid 9.0.1 is in the range of CVE-2026-41907, but the vulnerable code path is never used | `server.ts:9` |
| **L14** | rotateGroupEpoch accepts epoch keys of any length (no 32-byte validation) | `crypto.ts:1301-1330` |
| **L15** | No upper bound on decrypt input size; a 10 MB ciphertext costs ~3.3 s CPU | `crypto.ts:173-192` |
| **L16** | Decryption distinguishes failure reasons with six different error codes (local-only oracle today) | `crypto.ts:1646-1649` |

| ID | Finding | Location |
| --- | --- | --- |
| **I1** | "Fully post-quantum" labelling remains in code comments and the UI tooltip | `crypto.ts:1,665-668` |
| **I2** | Hand-rolled QR generator has no test-vector validation | `safetyNumber.ts:692+` |
| **I3** | kdfChainStep uses HKDF with an all-zero salt | `crypto.ts:210-215` |
| **I4** | Early-exit comparisons only on public values; admin password length leaks via timing | `config.ts:47-48` |
| **I5** | package.json still says 6.1.0 while CHANGELOG says v6.5.0 | `package.json:3` |
| **I6** | Outdated but vulnerability-free dependencies (axios, express, dotenv, ws, qs, vite) | `package.json` |

<details>
<summary><strong>Full test inventory — every test, with its result (click to expand)</strong></summary>

#### Existing suite — 142 tests, all ✅ PASS

**`tests/account-delete.test.ts`** — 4 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| accepts the correct recovery code for an account that has a hash | ✅ PASS |
| rejects a wrong code for an account that has a hash | ✅ PASS |
| rejects a malformed code for an account that has a hash | ✅ PASS |
| allows deletion on the session alone for legacy accounts with no hash (NULL/undefined) | ✅ PASS |

**`tests/benchmark.test.ts`** — 2 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| measures ML-KEM-768 encap/decap and ML-DSA-65 sign/verify baseline latency | ✅ PASS |
| measures end-to-end PQ-MPRBA encrypt/decrypt round-trip and verified-bundle UI cache speedup | ✅ PASS |

**`tests/db-hardening.test.ts`** — 11 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| verifies the DB certificate in production | ✅ PASS |
| disables SSL outside production | ✅ PASS |
| cover all 7 app tables | ✅ PASS |
| enable RLS on every table | ✅ PASS |
| policy SQL references only the chatapp role and the table | ✅ PASS |
| contains the role-password placeholder, not a real password | ✅ PASS |
| enables RLS on all 7 tables | ✅ PASS |
| creates one app_all policy per table, for the chatapp role only | ✅ PASS |
| grants only data access on the 7 tables, nothing else | ✅ PASS |
| does not fall back when DDL throws but the tables are readable | ✅ PASS |
| falls back when the tables are genuinely unreadable | ✅ PASS |

**`tests/fuzz.test.ts`** — 4 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| fails closed (throws E2EEError) on 150 malformed, truncated, bit-flipped, and random PQ ciphertexts | ✅ PASS |
| fails closed (throws E2EEError) on 120 malformed Group Epoch, ECDH, and PBKDF2 packets | ✅ PASS |
| fails closed (throws E2EEError) on 120 malformed, truncated, and forged key bundles | ✅ PASS |
| never crashes or returns MATCH on 100 fuzzed Safety Number QR payloads | ✅ PASS |

**`tests/google-login.test.ts`** — 14 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| accepts normal addresses and normalizes case/whitespace | ✅ PASS |
| rejects malformed addresses | ✅ PASS |
| returns the configured Client ID | ✅ PASS |
| returns null when unset (config endpoint must report null) | ✅ PASS |
| treats a blank value as unset | ✅ PASS |
| returns the normalized email for a verified token | ✅ PASS |
| returns the Google display name and photo from the token | ✅ PASS |
| tolerates a token without name or picture | ✅ PASS |
| drops a profile photo from any host other than the Google photo host | ✅ PASS |
| rejects when the verifier throws (bad signature / expired token) | ✅ PASS |
| rejects when the email is not verified by Google | ✅ PASS |
| rejects when the token carries no email | ✅ PASS |
| rejects an empty token without calling the verifier | ✅ PASS |
| rejects when no Client ID is configured (env-gated) | ✅ PASS |

**`tests/google-profile.test.ts`** — 27 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| trims and keeps a normal name | ✅ PASS |
| strips control characters (no header/line injection via the name) | ✅ PASS |
| caps at 100 characters | ✅ PASS |
| returns null for empty / blank / non-string names | ✅ PASS |
| keeps a Google photo URL | ✅ PASS |
| rejects any other host (tracking / spoofed photo URLs) | ✅ PASS |
| rejects http and unparsable values | ✅ PASS |
| pins exactly one photo host | ✅ PASS |
| applies name + photo for a user with no custom flags | ✅ PASS |
| keeps a manually-set name but still updates the photo | ✅ PASS |
| keeps a manually-set avatar but still updates the name | ✅ PASS |
| returns null when both fields are manually set (nothing to sync) | ✅ PASS |
| never clears a stored value when the token carries none | ✅ PASS |
| refreshes a non-custom field when Google changed it | ✅ PASS |
| returns null when the Google values already match the stored ones | ✅ PASS |
| treats rows created before the profile columns existed as empty | ✅ PASS |
| raises the name flag only when the submitted name differs | ✅ PASS |
| leaves both flags at 0 on a save that changes nothing | ✅ PASS |
| leaves unsubmitted fields untouched (older clients) | ✅ PASS |
| clearing the name (empty string) is a manual choice and raises the flag | ✅ PASS |
| raises the avatar flag when a new photo is uploaded | ✅ PASS |
| both Google login flows share completeGoogleSignIn with the verified profile | ✅ PASS |
| POST /api/user/update resolves the edit through resolveProfileUpdate and stores the flags | ✅ PASS |
| the contacts endpoint returns the display name | ✅ PASS |
| CSP allows the Google photo host in img-src and nothing else new | ✅ PASS |
| the client shows the display name with a username fallback | ✅ PASS |
| Google photos render directly; other external avatar URLs render nothing (no token leak) | ✅ PASS |

**`tests/media-e2ee.test.ts`** — 24 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| admits both DM members and denies outsiders (exact room-id match) | ✅ PASS |
| admits group members from the members list and denies outsiders | ✅ PASS |
| does not let a username with "__" impersonate membership (prefix trap) | ✅ PASS |
| allows members and refuses non-members | ✅ PASS |
| (c) a non-member with a valid session gets 403 on new encrypted media | ✅ PASS |
| (c) a non-member gets 403 on pre-change media linked from a message | ✅ PASS |
| (d) a member gets 200 on new encrypted media, with the encrypted flag | ✅ PASS |
| (d) a member gets 200 on pre-change media (access-controlled, NOT encrypted) | ✅ PASS |
| (d) a disk-only pre-change file resolves through its /uploads/ message link | ✅ PASS |
| a deleted message denies access to its media | ✅ PASS |
| (e) orphan media (no room, no message, not an avatar) is 403 | ✅ PASS |
| unknown media id is 404 | ✅ PASS |
| no username at all is forbidden (unauthenticated fetch) | ✅ PASS |
| a current avatar is fetchable by any authenticated user | ✅ PASS |
| the uploader can fetch their own just-uploaded avatar before it is saved | ✅ PASS |
| (a) /api/upload requires a valid session BEFORE multer parses the body | ✅ PASS |
| (f) the public /uploads static route is gone; media is served only through authenticated /api/media | ✅ PASS |
| the upload route records room_id and the uploader, and never returns a /uploads URL | ✅ PASS |
| (g) DM: alice encrypts, bob decrypts → identical bytes; ciphertext is opaque | ✅ PASS |
| (g) DM: tampering with the ciphertext fails closed | ✅ PASS |
| (g) group: encrypt/decrypt with the epoch key; old-epoch files still open inside the grace buffer | ✅ PASS |
| (g) manual passphrase rooms round-trip with a purpose-separated key | ✅ PASS |
| (h) no room key available fails closed — nothing is uploaded | ✅ PASS |
| file encryption does not consume a message-ratchet step | ✅ PASS |

**`tests/nist-kat.test.ts`** — 6 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| matches official FIPS 203 ML-KEM-768 KeyGen vectors bit-for-bit | ✅ PASS |
| matches official FIPS 203 ML-KEM-768 Encapsulation vectors bit-for-bit | ✅ PASS |
| matches official FIPS 203 ML-KEM-768 Decapsulation vectors bit-for-bit | ✅ PASS |
| matches official FIPS 204 ML-DSA-65 KeyGen vectors bit-for-bit | ✅ PASS |
| matches official FIPS 204 ML-DSA-65 deterministic external pure SigGen vectors bit-for-bit | ✅ PASS |
| matches official FIPS 204 ML-DSA-65 external pure SigVer positive and negative vectors | ✅ PASS |

**`tests/pq-mprba.test.ts`** — 19 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| stores v4 identity & wrapping keys as non-extractable WebCrypto CryptoKeys and never writes private keys to localStorage | ✅ PASS |
| discards legacy v2/v3 plaintext localStorage keys and bumps storage marker to v4 | ✅ PASS |
| generates fresh CSPRNG identity keys rather than deterministic username-derived keys | ✅ PASS |
| binds ML-KEM-768 and ECDH P-256 public keys under a verified ML-DSA-65 bundle signature | ✅ PASS |
| encryptMessageText fails closed (throws E2EEError, never returns plaintext) | ✅ PASS |
| completes bidirectional PQ-MPRBA v2 round-trip with RAM-only ratchet state | ✅ PASS |
| verifies ML-DSA-65 signature BEFORE decrypting or advancing ratchet state | ✅ PASS |
| rejects replayed PQ messages with E2EEError(REPLAY_DETECTED) | ✅ PASS — Passes within one process only; does not cover replay after reload (finding H3). |
| handles out-of-order messages via skipped keys and burns each skipped key after single use | ✅ PASS |
| enforces MAX_SKIP bound (100) to prevent ratchet DoS | ✅ PASS |
| supports Group Epoch FSM rotation with ML-KEM-768 epoch packets, 3-epoch grace buffer, and expires older epochs | ✅ PASS |
| refuses to encrypt a group message without an epoch key, refuses keyless rotation (F3), and rejects replayed group messages (F7) | ✅ PASS |
| rotates the PQ ratchet session after 50 sent messages (F9) | ✅ PASS — Passes in-order only; late pre-rotation messages not covered (finding H4). |
| requires an explicit manual passphrase for PBKDF2 and never uses a public default (F4) | ✅ PASS |
| caches verified bundles for UI reads while forcing fresh verification when skipCache is true | ✅ PASS |
| computes symmetric Safety Numbers, preserves VERIFIED on session rekey, and marks CHANGED on identity key rotation | ✅ PASS |
| zeroizes sensitive Uint8Array buffers in place | ✅ PASS |
| hashes Bale fallback recovery codes with salted scrypt and enforces strict RecoveryRateLimiter bounds | ✅ PASS |
| enforces strict Helmet CSP without unsafe-inline, unsafe-eval, or unpinned CDN assets | ✅ PASS |

**`tests/privacy-policy.test.ts`** — 8 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| is a complete HTML document with the required title | ✅ PASS |
| states the sign-in identifiers collected (Bale ID / email) | ✅ PASS |
| states messages are stored encrypted and unreadable by the server | ✅ PASS |
| states only the salted hash of the recovery code is stored | ✅ PASS |
| states Google Sign-In shares only email and name | ✅ PASS |
| states data is stored on Render and deletion is available in-app | ✅ PASS |
| gives the privacy contact email | ✅ PASS |
| contains no scripts and no external resources (CSP-safe); presentation is one inline <style> block only | ✅ PASS |

**`tests/profile-auth.test.ts`** — 12 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| (a) no valid session → unauthenticated (each route maps it to 403) | ✅ PASS |
| (b) token of a different user → forbidden | ✅ PASS |
| (c) token of the owner → ok | ✅ PASS |
| empty / missing target fails closed — never an open update | ✅ PASS |
| unchanged behaviour after the refactor (room-auth cases) | ✅ PASS |
| POST /api/user/update gates on the body's username and denies non-ok with 403 | ✅ PASS |
| POST /api/add-contact gates on the body's myUsername and denies non-ok with 403 | ✅ PASS |
| GET /api/contacts/:username gates on the URL username and denies non-ok with 403 | ✅ PASS |
| the contacts-list fetch carries a Bearer header | ✅ PASS |
| the add-contact fetch carries a Bearer header | ✅ PASS |
| the profile-update fetch carries a Bearer header | ✅ PASS |
| no remaining call to the three endpoints lacks a token | ✅ PASS |

**`tests/room-auth.test.ts`** — 11 tests, all ✅ PASS

| Test | Result |
| --- | --- |
| (a) no valid session → unauthenticated (route maps it to 403) | ✅ PASS |
| (b) token of a non-member → forbidden | ✅ PASS |
| (c) token of a member → ok (DM, either member; group) | ✅ PASS |
| unknown room fails closed with the same status — no existence leak | ✅ PASS |
| (d) no valid session → unauthenticated (route maps it to 403) | ✅ PASS |
| (e) token username != URL username → forbidden | ✅ PASS |
| (f) matching username → ok | ✅ PASS |
| /api/messages/:roomId calls checkRoomReadAccess and denies non-ok with 403 | ✅ PASS |
| /api/groups/:username calls checkOwnGroupsAccess and denies non-ok with 403 | ✅ PASS |
| no route serves room content without the check (no bare SELECT before the gate) | ✅ PASS |
| all three room-content fetches carry a Bearer header | ✅ PASS |

#### New adversarial tests — 32 tests: 30 ✅ PASS, 2 ❌ FAIL

"PASS — behaviour confirmed (finding …)" means the test asserts the *actual* behaviour (including a weakness) and passes; "FAIL — attack succeeds" means the test asserts the *secure* behaviour and the attack defeated it. A3 and C8 are written the second way deliberately, so they stay red until fixed.

| Test | Result |
| --- | --- |
| A1 baseline: replay of a consumed step in the same session is rejected | ✅ PASS — attack blocked |
| A2 replay AFTER ratchet state is wiped (page reload / restart simulation) | ✅ PASS — behaviour confirmed (finding M1) |
| A3 replay ACROSS the 50-message ratchet rotation via capsule alternation | ❌ FAIL — attack succeeds (finding H1) |
| A7 out-of-order across the rotation boundary still decrypts (tolerance that enables A3) | ✅ PASS — attack blocked |
| B1 tampered ciphertext / IV / KEM capsule all fail before yielding plaintext | ✅ PASS — attack blocked |
| B2 signature from another message / wrong room / wrong step is rejected | ✅ PASS — attack blocked |
| B3 stripped signature is rejected (not tolerated) | ✅ PASS — attack blocked |
| B4 signature by the WRONG identity (bob signs, presented as alice) is rejected | ✅ PASS — attack blocked |
| C1 wrong-member capsule does not yield the epoch key | ✅ PASS — attack blocked |
| C2 stale epoch outside the 3-epoch grace window fails; inside it still decrypts | ✅ PASS — attack blocked |
| C3 removed member gets no packet entry and cannot open the new epoch | ✅ PASS — attack blocked |
| C4 tampered membersHash / tampered group ciphertext fail closed | ✅ PASS — attack blocked |
| C5 epoch rollback: rotating to a LOWER epoch is accepted (no monotonicity check) | ✅ PASS — behaviour confirmed (finding L1) |
| C6 group messages carry NO sender authentication (any epoch-key holder can pose as any member) | ✅ PASS — behaviour confirmed (finding M3) |
| C7 epoch packet creation needs NO private key and NO signature — anyone with public bundles can mint one | ✅ PASS — behaviour confirmed (finding H2) |
| C8 group replay eviction: after 500 other messages in one epoch, the first message replays | ❌ FAIL — attack succeeds (finding M2) |
| D1 attacker bundle (self-signed, victim username) passes strict parsing and earns the PQ badge | ✅ PASS — behaviour confirmed (finding M4) |
| D2 encrypting to the substituted bundle lets the ATTACKER read the message | ✅ PASS — behaviour confirmed (finding M4) |
| D2b asymmetry: substituting the FIRST user in the room id fails closed (chain-role mismatch) | ✅ PASS — attack blocked |
| D3 safety numbers DO detect the substitution — but only out-of-band | ✅ PASS — attack blocked |
| D4 safety-number state trusts UNVERIFIED bundles (no signature check in the extractor) | ✅ PASS — behaviour confirmed (finding M5) |
| D5 ML-KEM-only key change is INVISIBLE to the safety number | ✅ PASS — behaviour confirmed (finding L2) |
| E1 cross-capsule forgery (new capsule + old ciphertext, freshly signed) fails closed | ✅ PASS — attack blocked |
| E2 a third party holding only public bundles cannot decrypt any session message | ✅ PASS — attack blocked |
| E3 post-rotation messages use fresh key material (capsule differs) and old capsule cannot serve them | ✅ PASS — attack blocked |
| F1 empty / null / non-string inputs never yield plaintext and never crash with a raw TypeError | ✅ PASS — behaviour confirmed (finding L4) |
| F2 unknown-version / non-E2EE payloads pass through as plaintext (no warning flag) | ✅ PASS — behaviour confirmed (finding L3) |
| F3 garbage base64 / truncated bundles / null fields fail closed | ✅ PASS — attack blocked |
| F4 huge message round-trips (1 MiB) — and there is no size cap in the API | ✅ PASS — behaviour confirmed (finding L15) |
| F5 every failure path throws E2EEError — PBKDF2 wrong secret, missing epoch key, missing peer bundle | ✅ PASS — attack blocked |
| F6 group badge claims PQ even when NO epoch key exists | ✅ PASS — behaviour confirmed (finding M7) |
| F7 own sent message re-displays from the in-memory cache without consuming ratchet state | ✅ PASS — by design |
#### Official NIST ACVP KAT — 8 tests, 285 cases: 255 ✅ PASS, 30 policy-skipped, 0 ❌ FAIL

Vectors fetched fresh on 2026-11-21 from `usnistgov/ACVP-Server` (vsId 42, FIPS 203/204). The repo's bundled 13-vector fixture was verified byte-for-byte authentic against the fresh official files (13/13).

| Test | Result |
| --- | --- |
| keyGen: all 25 official ML-KEM-768 cases (tgId 2) match bit-for-bit | ✅ PASS |
| encapsulation: all 25 official ML-KEM-768 cases (tgId 2) match bit-for-bit | ✅ PASS |
| decapsulation: all 10 official ML-KEM-768 cases (tgId 5) match bit-for-bit | ✅ PASS |
| key validity checks: all 20 official ML-KEM-768 keyCheck cases (tgId 9 decap, tgId 10 encap) | ✅ PASS |
| keyGen: all 25 official ML-DSA-65 cases (tgId 2) match bit-for-bit | ✅ PASS |
| sigGen: all 120 official ML-DSA-65 cases (tgId 3,4,9,10,15,16,21,22) match bit-for-bit | ✅ PASS |
| sigVer: all 60 official ML-DSA-65 cases (tgId 3,4,9,10) agree, incl. negative cases | ✅ PASS |
| reports KAT coverage summary (285 official cases) | ✅ PASS |
#### Extended fuzz — 14 tests, all ✅ PASS (~200 cases)

| Test | Result |
| --- | --- |
| decapsulate: wrong-length ciphertexts and secret keys throw; corrupt valid-length ct yields a DIFFERENT secret (FIPS 203 implicit rejection) | ✅ PASS — fail-closed |
| ML-DSA-65 verify: wrong-length signatures/keys return false or throw — never true; tampered sig never verifies | ✅ PASS — fail-closed |
| base64ToBuf rejects garbage, non-canonical, wrong-length and non-string input | ✅ PASS — fail-closed |
| parsePeerKeyBundleStrict rejects off-by-one key lengths and malformed ECDH JWKs | ✅ PASS — fail-closed |
| OBSERVED LENIENCY: bundle with ECDH JWK crv stripped still verifies (defaults to P-256), but ECDH use fails closed | ✅ PASS — behaviour confirmed (finding L5) |
| OBSERVED LENIENCY: empty/missing bundle username is ignored when an expected username is supplied (signature binds the expected name); fails closed without one | ✅ PASS — behaviour confirmed (finding L5) |
| decapsulateGroupEpochKey returns null (never a key, never throws) on malformed packets | ✅ PASS — fail-closed |
| rotateGroupEpoch: wrong-length epoch keys are ACCEPTED (no length validation) — recorded as a finding, not a crash | ✅ PASS — behaviour confirmed (finding L14) |
| tampered AES-GCM tag / IV / truncated ciphertext never decrypts, never leaks plaintext | ✅ PASS — fail-closed |
| oversized ciphertext fields fail closed without crashing (1 MB and 10 MB) | ✅ PASS — fail-closed (note: 10 MB costs ~3.3 s CPU, finding L15) |
| group epoch packets: bad epoch numbers, bad membersHash, wrong secret never decrypt | ✅ PASS — fail-closed |
| malformed PQF1 file payloads fail closed; header fields are range-checked by lookup | ✅ PASS — fail-closed |
| group PQF1 files: tampered epoch header fails closed (no epoch key for that epoch) | ✅ PASS — fail-closed |
| safety QR parser rejects null/undefined/uppercase-hex/odd-length payloads without MATCH | ✅ PASS — fail-closed |

</details>


## 🌐 Live verification — 21 November 2026

**Separate from the self-assessment above.** The section above ran the test suites against the code; this section checked what is actually deployed and running at https://chatapp-server-1i2a.onrender.com on 2026-11-21 06:48–07:12 (UTC 03:18–03:42). Method: unauthenticated HTTP probes from the auditor's machine, plus a signed-in browser session as the author's own account (indirectnebula6@gmail.com) in a brand-new test room only — the account had no prior chats or groups, no existing room, chat or file was touched, nothing was deleted, and no destructive test (account deletion, load/flood) was run.

### What the deployed code is

The production bundle was downloaded from the live server and compared byte-for-byte with a fresh local production build (`vite build`) of the same audited checkout:

| Chunk | Served | Local build | Verdict |
| --- | ---: | ---: | --- |
| `ChatApp` (all protocol + UI code) | 140,733 B | 140,733 B | **Identical** — the only differing bytes are the 8-character hash in the `vendor-crypto` import specifier. |
| `vendor-crypto` (noble primitives) | 69,490 B | 69,487 B | Same logic; 3 bytes differ in a minifier-equivalent Keccak emission. Markers present: Keccak, Kyber modulus `3329`. |
| `vendor-react-dom` | 207,018 B | 207,006 B | Same logic; 12 bytes differ in a minifier-equivalent (De Morgan) emission. |
| `esm` | 41,189 B | 41,209 B | One expression differs in a query-string parser (`r[1]` vs `r.slice(1).join('=')`) — a dependency-version difference, not protocol code. |
| Entry `index` | 11,131 B | 11,227 B | Chunk-filename references + bootstrap; no app logic. |
| `AuthScreen`, `TermsScreen`, `rolldown-runtime`, `vendor-react`, CSS | — | — | Identical filenames (content hashes match). |

Protocol markers found in the served bundle: `e2ee:pq:v2:`, `REPLAY_DETECTED`, `MAX_SKIP`, `e2ee:gep:v2:`, `mlkem768`, `mldsa65`. **Conclusion: the code running live is the code that was audited.** Differences are build-tooling noise (minifier, one dependency version), not different logic.

### What was checked live

| Check | Method | Result |
| --- | --- | --- |
| Deployed version | `GET /api/health` | ✅ `6.5.0`, `database: ok` — matches the audited code. |
| Served security headers | `GET /` | ✅ Strict CSP (`default-src 'self'`, no `unsafe-inline`/`unsafe-eval`), HSTS `max-age=31536000; includeSubDomains; preload`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, COOP/CORP `same-origin`. |
| Public uploads removed | `GET /uploads/test.jpg` | ✅ 404. |
| Media gating, no session | `GET /api/media/…` | ✅ 401. |
| Profile endpoint, no session | `GET /api/user/me` | ⚠️ 200 with `{"ok":false}` — leaks nothing, but answers 200 instead of 401. |
| Unknown API paths | `GET /api/groups`, `/api/auth/me` | `{"ok":false,"error":"Not Found"}`. |
| Login screen | Signed-in browser session | ✅ Google-only (`ورود با گوگل` + recovery-code login). **No "Quick Test Login" button exists** — the "Live demo" line in this README used to claim it; corrected with this update. |
| Google profile sync | Signed-in browser session | ✅ Display name "Indirect Nebula" from Google. A photo avatar is shown; its source URL is not exposed, so it is not proven to be the Google photo. |
| Send + deliver | Test room `live-test-2026-11-21`, message "live test 1" 06:51 | ✅ Delivered ✓✓, Epoch #1. |
| **History after reload (finding H3)** | Reloaded the test room | ❌ **Confirmed live:** every message became undecryptable — text reads "🔒 [پیام رمزنگاری‌شده - کلید این نشست در دسترس نیست یا بازنشانی شده است]", media reads "🔒 رسانه در دسترس نیست". Cause per the app's own Session Key dialog: RAM-only ratchet key, zeroized on reload, no PBKDF2 override set. |
| Media upload | Uploaded `live-test-file.txt` (15 B) | ⚠️ Uploaded, but the UI gave no feedback at all — no preview, message or error — so it was repeated 4× (07:07–07:09), creating 4 duplicate media messages. All 4 locked after the reload (H3). Left as-is, not deleted. |
| Media link, logged out | UI inspection | Not possible — the app exposes no media link anywhere (no download, no copy-link); the blob id sits inside the encrypted payload. API-level gating (401) was verified instead. |
| Cold start | First request after idle | ~28 s to first byte (free tier sleeps); warm requests ~1–2 s. |
| Transient login notice | First load | A notice briefly said Google login was unavailable and to try later; it disappeared and sign-in then worked. |

### Not tested live

- **Socket-level adversarial tests** (live equivalents of A1–A3, B1–B4, C1–C8, D1–D5, E1–E3, F1–F7): need a captured outgoing Socket.IO frame. No frame was captured in this pass and no live replay/tamper test was run. They need a frame captured with F12 (Network → WS → socket.io → Messages).
- Two-client decryption (a second account was not signed in).
- Account deletion (destructive by design — deliberately not run against production).
- Rate limiting / behaviour under load (not probed).


## 🏗️ Architecture

```mermaid
flowchart LR
    subgraph Browser["Browser (all crypto happens here)"]
        UI["React 19 + TypeScript SPA"]
        CR["crypto.ts — PQ-MPRBA engine<br/>ML-KEM-768 + ECDH P-256 · ML-DSA-65 · AES-256-GCM · VOPRF"]
        WK["Web Workers — media up to 50 MB"]
        UI --> CR
        UI --> WK
    end
    subgraph Server["Node.js server (zero-knowledge forwarder)"]
        EX["Express + Socket.IO (server.ts)"]
        PR["PresenceManager"]
        DB["Dual-mode DB<br/>PostgreSQL · atomic JSON fallback"]
        BL["Bale bot — OTP delivery"]
        EX --> PR
        EX --> DB
        EX --> BL
    end
    UI <-->|"ciphertext + blinded tokens only"| EX
```

| Layer | Technology |
| :--- | :--- |
| Frontend | React 19, TypeScript, Vite, modular RTL CSS (Vazirmatn) |
| Crypto | Web Crypto API, `@noble/post-quantum`, `@noble/curves`, Web Workers |
| Backend | Node.js, Express, Socket.IO, Helmet, CORS, express-rate-limit |
| Auth | Bale OTP bot + Ristretto255-VOPRF blinded tokens |
| Storage | PostgreSQL (`pg`) or atomic JSON fallback; hybrid `media_blobs` + disk |

Key engineering details:

- **Atomic disk fallback** (`src/server/db.ts`) — mutations are coalesced through a 250 ms debounced
  write mutex and persisted via write-to-`.tmp` + atomic rename; history is auto-pruned at 5,000 messages.
- **Hybrid media persistence** — files ≤ 2 MB are stored as database blobs and served from
  `GET /api/media/:id` with immutable caching; larger files (up to 50 MB) stream from disk, so media
  survives ephemeral-container redeploys.
- **Cluster-ready presence** (`src/server/presence.ts`) — O(1) bidirectional `socketId ↔ username`
  lookup, with `REDIS_URL` hooks for horizontal scaling.
- **No hardcoded secrets** (`src/server/config.ts`) — if `ADMIN_PASSWORD` is unset, a random
  32-char hex secret is generated at boot; admin checks use `crypto.timingSafeEqual`, and the admin
  path never appears in frontend bundles.

## 🚀 Quick start

**Prerequisites:** Node.js 18+ or 22+, npm 9+. PostgreSQL is optional.

```bash
git clone https://github.com/indirect-b/chat-app.git
cd chat-app
npm install
cp .env.example .env   # then fill in your secrets
npm run dev            # full-stack dev server (Express + Vite + Socket.IO)
```

Open http://localhost:3000 and sign in with Google.
Production: `npm run build` then `npm start`.

### Environment variables

| Variable | Description |
| :--- | :--- |
| `PORT` | Server port (default `3000`) |
| `ADMIN_PASSWORD` | Admin secret (auto-generated at boot if empty) |
| `ADMIN_PATH` | Obfuscated admin dashboard path |
| `BALE_API` | Bale Bot API base URL |
| `BALE_BOT_TOKEN` | Bale bot token used to deliver OTP codes |
| `DATABASE_URL` | PostgreSQL connection string (empty = JSON fallback) |
| `REDIS_URL` | Redis URL for clustered presence (optional) |
| `STORAGE_MODE` | Media storage mode (`hybrid` recommended) |
| `MAX_FILE_SIZE` | Max upload size in bytes (default 50 MB) |
| `OTP_EXPIRE` | OTP validity window in seconds |

## 📂 Project structure

```text
server.ts                 # Express + Socket.IO server, media endpoints, Vite integration
src/
├── App.tsx               # Session, maintenance/blocked states, toasts
├── components/
│   ├── AuthScreen.tsx    # 3-step Bale OTP login + quick test login
│   └── ChatApp.tsx       # Messenger UI, key sync, voice recorder, modals
├── utils/crypto.ts       # PQ-MPRBA engine: hybrid ratchet, VOPRF, group epochs
└── server/
    ├── config.ts         # Hardened config, timing-safe admin verification
    ├── db.ts             # PostgreSQL pool + atomic JSON fallback
    ├── presence.ts       # Cluster-ready presence manager
    └── bale.ts           # Bale Bot API client (OTP delivery)
public/                   # Static assets, admin dashboard, modular CSS
data/database.json        # Auto-generated fallback database snapshot
```

## 🔌 API & realtime events

<details>
<summary><b>REST API</b></summary>

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/send-otp` | Generate a 6-digit OTP and send it via the Bale bot |
| `POST` | `/api/verify-otp` | Validate an OTP |
| `POST` | `/api/register` | Register a verified user |
| `POST` | `/api/quick-login` | Instant test login (auto-creates demo contacts) |
| `POST` | `/api/voprf/evaluate` | Evaluate a blinded Ristretto255 point, return a DLEQ proof (RFC 9497) |
| `GET` | `/api/user/:username` | Public profile + hybrid (ML-KEM-768 + P-256) public key |
| `POST` | `/api/user/public-key` | Publish a hybrid key bundle |
| `POST` | `/api/user/update` | Update bio, status, avatar |
| `GET` | `/api/contacts/:username` | Contacts with presence + public keys |
| `POST` | `/api/add-contact` | Add a contact by username |
| `GET` | `/api/messages/:roomId` | Messages of a direct/group room |
| `GET` | `/api/groups/:username` | Groups + current cryptographic epoch |
| `POST` | `/api/upload` | Hybrid upload (≤ 2 MB → DB blob, > 2 MB → disk) |
| `GET` | `/api/media/:id` | Serve a stored media blob |
| `POST` | `/api/report` | Report a message or user |
| `GET` | `/api/settings/mode` | Server mode (`normal` / `maintenance`) |
| `GET` | `/api/settings/rules` | Platform rules text |

</details>

<details>
<summary><b>Socket.IO events</b></summary>

- **Client → Server:** `auth`, `send-message`, `edit-message`, `delete-message`, `pin-message`, `react`, `forward-message`, `typing`, `read`, `update-status`, `update-location`
- **Server → Client:** `auth-ok`, `new-message`, `msg-edited`, `msg-deleted`, `msg-pinned`, `msg-reaction`, `typing`, `read`, `contact-online`, `contact-offline`, `contact-status`, `peer-key-updated`, `new-group`, `group-epoch-rotated`, `blocked`, `kicked`, `server-maintenance`, `server-normal`, `announcement`

</details>

## 📋 Version history

Full details in [CHANGELOG.md](CHANGELOG.md).

- **v6.5.0** — Google profile sync: display name + photo come from the Google profile, manual edits win

- **v6.4.0** — Google-only login: Bale and email login removed; Google Sign-In in redirect mode is the only way in; styled privacy page

- **v6.3.0** — Media end-to-end encryption: files are encrypted with the room key before upload, media links open only for chat members; room and profile endpoints now require a session and ownership

- **v6.2.0** — Login without Bale: email signup (OTP), Google Sign-In (server-verified), public privacy page, database hardening (verified SSL, RLS on all tables, least-privilege role)

- **v6.1.0** — IndexedDB keystore (keys out of localStorage), strict CSP (no inline scripts, no CDN), NIST KAT + fuzz tests, Bale fallback recovery codes, SECURITY.md + threat model

- **Latest (Oct 2026)** — ML-DSA-65 identity signatures (FIPS 204), anti-silent-downgrade indicators (verified-PQ badge gating, classical-fallback warning, forged-signature alert)
- **v6.0** — PQ-MPRBA: hybrid ML-KEM-768 + ECDH P-256 ratchet, Ristretto255-VOPRF blinded auth, Group Epoch FSM
- **v5.0** — Automatic ECDH P-256 key exchange & public-key directory
- **v4.0** — Non-blocking atomic disk fallback (debounced mutex, `.tmp` rename)
- **v3.0** — Hybrid cloud-safe media storage (`media_blobs`)
- **v2.0** — Cluster-ready presence service
- **v1.0** — Admin & environment security hardening

## 🔄 Development & Release Workflow

Development on `chat-app` follows an **offline milestone & staging model**:
- Feature development, protocol refactoring, cryptanalysis, and benchmark testing are conducted locally in intensive iterative cycles (often over several weeks to a full month of offline R&D).
- Once a release milestone is fully stabilized, fuzz-tested, and verified against NIST KAT vectors, the accumulated work is organized into structured, staged commits and uploaded to GitHub in managed, sequenced intervals.
- Consequently, the Git commit history reflects concentrated milestone deployments rather than fragmented continuous commits.

---

## 🇮🇷 درباره پروژه (فارسی)

**پیام‌رسان** یک پیام‌رسان تحت وب فارسی و بلادرنگ است که تمام پیام‌هایش با رمزنگاری سرتاسری
**پساکوانتومی** محافظت می‌شود. پروتکل اختصاصی پروژه، **PQ-MPRBA**، ترکیبی از تبادل کلید هیبریدی
**ML-KEM-768 + ECDH P-256** و احراز هویت کور **Ristretto255-VOPRF** است و هویت‌ها با امضای **ML-DSA-65** تأیید می‌شوند؛ یعنی سرور نه متن پیام‌ها
را می‌بیند و نه می‌تواند هویت کاربران را به هم گره بزند. ورود با آیدی بله (کد تأیید از طریق ربات بله)
انجام می‌شود و برای تست، ورود سریع بدون کد هم وجود دارد.

### 🔄 چرخه توسعه و انتشار
فرآیند توسعه این پروژه مبتنی بر **توسعه متمرکز محلی و انتشار تجمیعی (Milestone-based Staging)** است:
کدنویسی، بازطراحی پروتکل‌ها، بهینه‌سازی‌های امنیتی و تست‌ها در دوره‌های زمانی فشرده (گاهاً در طول یک ماه کار مداوم آفلاین) روی سیستم محلی پیاده‌سازی و آزمایش می‌شوند. پس از دستیابی به نسخه پایدار و عبور موفق از تمامی تست‌های امنیتی و بنچمارک‌ها، تغییرات در قالب کامیت‌ها و شاخه‌های مشخص در فواصل زمانی مدیریت‌شده روی مخزن گیت‌هاب آپلود و ثبت می‌گردند.

**اجرای سریع:** `npm install` ← ساخت فایل `.env` از روی `.env.example` ← `npm run dev`

---

<div align="center">

Built by [Mohammad Taha Azizi Ahad](https://github.com/indirect-b) — feedback, issues and stars are welcome ⭐

</div>
