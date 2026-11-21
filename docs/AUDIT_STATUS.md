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

---

## 4. Overnight self-assessment — 2026-11-21

**Self-assessment — NOT an independent audit, NOT a FIPS 140-3 validation, NOT a formal proof.** Run overnight 20–21 November 2026 (29–30 Aban 1405) by the project author and his agent, in three parallel workstreams, each re-running the suite independently in its own clean checkout of `main` (v6.5.0-era behaviour; `package.json` still says 6.1.0). Benchmarks: official NIST CAVP/ACVP vectors (FIPS 203/204), FIPS 140-3/CMVP criteria, the IETF/IRTF CFRG review lens, and the published methodologies of Trail of Bits / NCC Group / Cure53 / Kudelski Security as a coverage map. Real FIPS 140-3 validation requires an accredited CMVP lab and cannot be substituted by self-testing. The full Persian report (448 lines, with file:line evidence for every claim) is kept with the project workspace as `audit-overnight-2026-11-21.md`.

**Headline:** the cryptographic core is sound — primitives, KATs and fail-closed behaviour all hold (existing suite re-run independently three times: **142/142 pass**), and no plaintext leak, signature forgery or KAT failure was found. The two protocol Highs share one root cause (round 2 moved ratchet state to RAM-only and deleted the persistent decrypted cache without updating the spec, the tests, or the display path); the two dependency Highs close with a version upgrade. The whitepaper text is additionally one major version stale (v6.0.0 text vs v6.5.0-era code).

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

