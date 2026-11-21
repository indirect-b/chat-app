/**
 * DP item 15 — test-suite adequacy: masking proofs + coverage holes.
 *
 * Phase-1 §10 item 15: "test quality only spot-checked". This file does
 * the systematic part for the crypto core and proves, by execution, the
 * two masking cases named in §10:
 *
 *  (M1) The in-process replay test hides H3. The existing suite's only
 *       "history re-displays" evidence is F7: an OWN sent message
 *       re-displays from the in-memory sentPlaintextMemoryCache. No
 *       existing test re-decrypts an INCOMING message a second time
 *       (room re-open). This test does exactly that: the second decrypt
 *       of an incoming message throws REPLAY_DETECTED — i.e. in the
 *       same process, with no reload at all, re-opening a room locks
 *       incoming history. The suite's green replay test and its green
 *       own-message-cache test together create the false impression
 *       that "replay protection + history" both work.
 *  (M2) The in-order rotation test hides what cross-boundary delivery
 *       really does — and the finding here CORRECTS phase 1. Phase 1
 *       (H4) claimed a late pre-rotation message across the rotation
 *       boundary is "now undecryptable". Executing the exact scenario
 *       shows the opposite: message 49, delivered AFTER message 50,
 *       DECRYPTS — because ensurePQRatchetSession re-establishes the
 *       old session from the old capsule. What is actually lost is
 *       the POST-ROTATION session's consumed-step set: after the late
 *       delivery, message 50 replays successfully. So the in-order
 *       rotation test does not mask a lost message; it masks that
 *       cross-boundary delivery silently destroys the new session's
 *       replay state — i.e. H4's root cause is real (no previous-session
 *       slot) but its stated effect was wrong, and the live effect is
 *       H1's replay bypass, not message loss. The test below asserts
 *       the OBSERVED behaviour (49 decrypts; 50 then replays) and the
 *       report records this as a correction to H4, not as a new High.
 *
 *  (M3) Coverage hole, closed here (new PASSING tests): the Google
 *       redirect-mode functions — checkGoogleRedirectRequest,
 *       parseGoogleCsrfCookie, buildGoogleRedirectUrl,
 *       PendingRecoveryCodes — had ZERO tests anywhere in the repo
 *       (grep, 2026-11-21). The redirect login flow is a production
 *       auth path with no test coverage at all. These tests pin the
 *       gate behaviour (400 vs 403 vs ok), the cookie parsing, the
 *       one-hop session-in-URL construction, and the take-once
 *       semantics of the pending recovery codes.
 *
 * Tests M1/M2 assert the ACTUAL (weak) behaviour, so they PASS — like
 * W1's "PASS (behaviour confirmed — finding …)" tests. They are red
 * flags in green clothing: read the test names, not just the count.
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  E2EEError,
  clearRatchetSession,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  resetAllCryptoStateForTests,
} from '../src/utils/crypto';
import {
  PendingRecoveryCodes,
  buildGoogleRedirectUrl,
  checkGoogleRedirectRequest,
  parseGoogleCsrfCookie,
} from '../src/server/google';

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number { return this.map.size; }
  clear(): void { this.map.clear(); }
  getItem(k: string): string | null { return this.map.has(k) ? this.map.get(k)! : null; }
  key(i: number): string | null { return Array.from(this.map.keys())[i] ?? null; }
  removeItem(k: string): void { this.map.delete(k); }
  setItem(k: string, v: string): void { this.map.set(k, String(v)); }
}
const mockLocalStorage = new MemoryStorage();
Object.defineProperty(globalThis, 'localStorage', { value: mockLocalStorage, configurable: true, writable: true });

const ROOM = 'alice__bob';
const decOpts = (peerBundle: string) => ({ myUsername: 'bob', peerUsername: 'alice', peerPublicKey: peerBundle, sender: 'alice' });

async function setupPair() {
  const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
  const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
  return { aliceBundle, bobBundle };
}

describe('DP item 15 (M1) — in-process replay test masks H3: incoming history locks on room re-open', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('MASKING PROOF: an OWN message re-displays (cache) but an INCOMING message re-decrypt FAILS in the same process', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    // Incoming message: decrypt once (network path), then again (room re-open).
    const incoming = await encryptMessageText('hello-bob', ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle });
    assert.equal((await decryptMessageText(incoming, ROOM, decOpts(aliceBundle))).text, 'hello-bob');
    await assert.rejects(
      decryptMessageText(incoming, ROOM, decOpts(aliceBundle)),
      (err: unknown) => err instanceof E2EEError && err.code === 'REPLAY_DETECTED'
    );
    // Own message: the sender's own decrypt path hits the RAM cache and works.
    const own = await encryptMessageText('hello-alice', ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle });
    const ownDec = await decryptMessageText(own, ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle, sender: 'alice' });
    assert.equal(ownDec.text, 'hello-alice');
    // The existing suite tests ONLY the own-message half (F7) and the
    // network-path replay half (A1-style) — never the re-open half.
    console.log('[dp-masking M1] incoming re-decrypt -> REPLAY_DETECTED; own re-decrypt -> ok. Suite covers only the own half.');
  });

  it('MASKING PROOF (restart): after clearRatchetSession the same incoming message decrypts again (A2, restated for the adequacy record)', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const m = await encryptMessageText('restart-target', ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle });
    assert.equal((await decryptMessageText(m, ROOM, decOpts(aliceBundle))).text, 'restart-target');
    clearRatchetSession('bob', ROOM);
    assert.equal((await decryptMessageText(m, ROOM, decOpts(aliceBundle))).text, 'restart-target');
  });
});

describe('DP item 15 (M2) — in-order rotation test masks H4: late pre-rotation message is lost', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('MASKING PROOF + H4 CORRECTION: in-order 51/51 passes (mirrors the existing test) — late msg-49 after msg-50 DECRYPTS (H4 as stated is wrong), but it destroys the new session so msg-50 then REPLAYS (H1)', async () => {
    const { aliceBundle, bobBundle } = await setupPair();
    const payloads: string[] = [];
    for (let i = 0; i < 51; i++) {
      payloads.push(await encryptMessageText(`msg-${i}`, ROOM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle }));
    }
    // In-order half (what the existing test does): all 51 decrypt.
    for (let i = 0; i < 51; i++) {
      assert.equal((await decryptMessageText(payloads[i], ROOM, decOpts(aliceBundle))).text, `msg-${i}`);
    }
    // Reset ONLY Bob's ratchet state for this room (identities stay in
    // the keystore — resetAllCryptoStateForTests would also wipe the
    // in-memory identities and is not usable mid-test), then replay the
    // boundary out of order: 0..48, then 50, then 49.
    clearRatchetSession('bob', ROOM);
    for (let i = 0; i <= 48; i++) {
      assert.equal((await decryptMessageText(payloads[i], ROOM, decOpts(aliceBundle))).text, `msg-${i}`);
    }
    assert.equal((await decryptMessageText(payloads[50], ROOM, decOpts(aliceBundle))).text, 'msg-50');
    // CORRECTION TO H4: the late pre-rotation message decrypts — the old
    // session is re-established from the old capsule. It is NOT lost.
    assert.equal((await decryptMessageText(payloads[49], ROOM, decOpts(aliceBundle))).text, 'msg-49');
    // ...but re-establishing it destroyed the post-rotation session's
    // consumed-step set, so msg-50 now decrypts a SECOND time (H1).
    assert.equal((await decryptMessageText(payloads[50], ROOM, decOpts(aliceBundle))).text, 'msg-50');
    console.log('[dp-masking M2] H4 CORRECTED: late msg-49 decrypts; the cost is that msg-50 then replays. In-order test masks the session destruction, not a lost message.');
  });
});

describe('DP item 15 (M3) — Google redirect-mode auth had ZERO tests; pinning the gate now', () => {
  it('checkGoogleRedirectRequest: ok only when credential present and field == cookie', () => {
    assert.equal(checkGoogleRedirectRequest({ credential: 'cred', csrfField: 't', csrfCookie: 't' }), 'ok');
    assert.equal(checkGoogleRedirectRequest({ credential: '', csrfField: 't', csrfCookie: 't' }), 'bad_request');
    assert.equal(checkGoogleRedirectRequest({ credential: '   ', csrfField: 't', csrfCookie: 't' }), 'bad_request');
    assert.equal(checkGoogleRedirectRequest({ credential: 'cred', csrfField: '', csrfCookie: 't' }), 'forbidden');
    assert.equal(checkGoogleRedirectRequest({ credential: 'cred', csrfField: 't', csrfCookie: null }), 'forbidden');
    assert.equal(checkGoogleRedirectRequest({ credential: 'cred', csrfField: 'a', csrfCookie: 'b' }), 'forbidden');
  });

  it('parseGoogleCsrfCookie: finds the token among other cookies, tolerates spacing', () => {
    assert.equal(parseGoogleCsrfCookie(undefined), null);
    assert.equal(parseGoogleCsrfCookie(''), null);
    assert.equal(parseGoogleCsrfCookie('other=1; g_csrf_token=abc123; x=2'), 'abc123');
    assert.equal(parseGoogleCsrfCookie('g_csrf_token=; other=1'), null);
    assert.equal(parseGoogleCsrfCookie('g_csrf_token = spaced'), 'spaced');
    assert.equal(parseGoogleCsrfCookie('G_CSRF_TOKEN=upper'), null, 'cookie name is case-sensitive');
  });

  it('buildGoogleRedirectUrl: session token is URL-encoded, new=1 only for new users, no recovery code in the URL', () => {
    const u = buildGoogleRedirectUrl('tok+en/with?chars&x=1', true);
    assert.ok(u.startsWith('/?session='), u);
    assert.ok(u.includes('&new=1'), u);
    assert.ok(!u.includes('tok+en'), 'raw token must not appear unencoded');
    assert.ok(u.includes(encodeURIComponent('tok+en/with?chars&x=1')), u);
    assert.equal(buildGoogleRedirectUrl('abc', false), '/?session=abc');
  });

  it('PendingRecoveryCodes: take-once, expiry, and take deletes even when expired', () => {
    const p = new PendingRecoveryCodes();
    p.store('s1', 'CODE-1', 1000);
    assert.equal(p.take('s1', 1000 + 60 * 1000), 'CODE-1');
    assert.equal(p.take('s1', 1000 + 61 * 1000), undefined, 'second fetch finds nothing (burned)');
    p.store('s2', 'CODE-2', 1000, 10 * 60 * 1000);
    assert.equal(p.take('s2', 1000 + 10 * 60 * 1000 + 1), undefined, 'expired code returns nothing');
    assert.equal(p.take('missing', 1000), undefined);
    // Overwrite replaces the pending code for a session.
    p.store('s3', 'OLD', 1000);
    p.store('s3', 'NEW', 1000);
    assert.equal(p.take('s3', 2000), 'NEW');
  });
});
