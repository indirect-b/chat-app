// PQ-MPRBA hardened-protocol tests (Bun).
// Each simulated user is a separate driver process (own localStorage, own
// module state) — the closest thing to two devices without a browser.
// Run: bun test tests/pq-mprba.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';

const DRIVER = new URL('./harness/client-driver.ts', import.meta.url).pathname;

function b64(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
  return btoa(s);
}
function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

class Client {
  proc: any;
  username: string;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
  private buf = '';

  constructor(username: string) {
    this.username = username;
    this.proc = Bun.spawn([process.execPath, DRIVER], { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' });
    const reader = this.proc.stdout.getReader();
    (async () => {
      const dec = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        this.buf += dec.decode(value, { stream: true });
        let idx: number;
        while ((idx = this.buf.indexOf('\n')) >= 0) {
          const line = this.buf.slice(0, idx).trim();
          this.buf = this.buf.slice(idx + 1);
          if (!line) continue;
          const msg = JSON.parse(line);
          const p = this.pending.get(msg.id);
          if (p) {
            this.pending.delete(msg.id);
            if (msg.ok) p.resolve(msg.result);
            else p.reject(new Error(`${msg.error || 'driver error'}${msg.name ? ` [${msg.name}]` : ''}`));
          }
        }
      }
    })();
  }

  call(cmd: string, args: any = {}): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.proc.stdin.write(JSON.stringify({ id, cmd, args }) + '\n');
    });
  }

  kill() {
    try {
      this.proc.kill();
    } catch {}
  }
}

function roomId(a: string, b: string) {
  return [a, b].sort().join('__');
}

describe('PQ-MPRBA hardened protocol', () => {
  let alice: Client;
  let bob: Client;
  let carol: Client;
  let aliceBundle: string;
  let bobBundle: string;
  let carolBundle: string;
  const room = roomId('alice', 'bob');

  beforeAll(async () => {
    alice = new Client('alice');
    bob = new Client('bob');
    carol = new Client('carol');
    aliceBundle = (await alice.call('init', { username: 'alice' })).bundle;
    bobBundle = (await bob.call('init', { username: 'bob' })).bundle;
    carolBundle = (await carol.call('init', { username: 'carol' })).bundle;
  }, 30000);

  afterAll(() => {
    alice.kill();
    bob.kill();
    carol.kill();
  });

  test('F1: keys are random, not derivable from the username', async () => {
    // Same username in a fresh process must get different keys.
    const alice2 = new Client('alice');
    const bundle2 = (await alice2.call('init', { username: 'alice' })).bundle;
    expect(bundle2).not.toBe(aliceBundle);
    // The old deterministic derivation must not reproduce the stored keys.
    const stored = await alice.call('getSecretKeys', { username: 'alice' });
    const old = await alice.call('oldDerivation', { username: 'alice' });
    expect(stored.mlkemSecretB64).not.toBe(old.mlkemSecretB64);
    expect(stored.mldsaSecretB64).not.toBe(old.mldsaSecretB64);
    expect(stored.ecdhPrivD).not.toBe(
      b64(unb64(old.ecdhPrivB64)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    );
    expect(stored.versions).toEqual({ ecdh: 3, kem: 3, dsa: 3 });
    alice2.kill();
  }, 30000);

  test('interop: two clients exchange PQ messages, signatures verify', async () => {
    const p1 = (await alice.call('encrypt', { roomId: room, text: 'hello bob', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    expect(p1.startsWith('e2ee:pq:v2:')).toBe(true);
    const d1 = await bob.call('decrypt', { payload: p1, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' });
    expect(d1.text).toBe('hello bob');
    expect(d1.mode).toBe('PQ-MLKEM-RATCHET');
    expect(d1.mldsaVerified).toBe(true);
    expect(d1.failed).toBe(false);

    const p2 = (await bob.call('encrypt', { roomId: room, text: 'hello alice', peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob' })).payload;
    const d2 = await alice.call('decrypt', { payload: p2, roomId: room, peerBundle: bobBundle, peerUsername: 'bob', username: 'alice', sender: 'bob' });
    expect(d2.text).toBe('hello alice');
    expect(d2.mldsaVerified).toBe(true);

    const st = await alice.call('roomStatus', { roomId: room, isGroup: false, peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' });
    expect(st.isPQ).toBe(true);
    expect(st.type).toBe('PQ_HYBRID_VERIFIED');
    expect(st.badge).toContain('PQ-KEM');
  }, 30000);

  test('tampered ciphertext / capsule / signature must fail', async () => {
    const p = (await alice.call('encrypt', { roomId: room, text: 'tamper me', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    const parts = p.split(':');
    // e2ee:pq:v2:<step>:<kem>:<iv>:<cipher>:<sig>  ->  [3]=step [4]=kem [5]=iv [6]=cipher [7]=sig
    const flip = (s: string) => {
      const bytes = unb64(s);
      bytes[0] ^= 0x01;
      return b64(bytes);
    };
    const tamperCipher = [...parts];
    tamperCipher[6] = flip(parts[6]);
    const d1 = await bob.call('decrypt', { payload: tamperCipher.join(':'), roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice', allowCache: false });
    expect(d1.failed).toBe(true);

    const tamperSig = [...parts];
    tamperSig[7] = flip(parts[7]);
    const d2 = await bob.call('decrypt', { payload: tamperSig.join(':'), roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice', allowCache: false });
    expect(d2.failed).toBe(true);

    const tamperCapsule = [...parts];
    tamperCapsule[4] = flip(parts[4]);
    const d3 = await bob.call('decrypt', { payload: tamperCapsule.join(':'), roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice', allowCache: false });
    expect(d3.failed).toBe(true);

    // Stripped signature must fail when the sender has an ML-DSA key.
    const stripped = parts.slice(0, 7).join(':');
    const d4 = await bob.call('decrypt', { payload: stripped, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice', allowCache: false });
    expect(d4.failed).toBe(true);
  }, 30000);

  test('F7: replayed message must fail on the network path', async () => {
    const p = (await alice.call('encrypt', { roomId: room, text: 'do not replay me', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    const d1 = await bob.call('decrypt', { payload: p, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice', allowCache: false });
    expect(d1.text).toBe('do not replay me');
    const d2 = await bob.call('decrypt', { payload: p, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice', allowCache: false });
    expect(d2.failed).toBe(true);
  }, 30000);

  test('F7: display path still re-reads an already-decrypted message from cache', async () => {
    const p = (await alice.call('encrypt', { roomId: room, text: 'read me twice', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    const d1 = await bob.call('decrypt', { payload: p, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice', allowCache: false });
    expect(d1.text).toBe('read me twice');
    // Re-opening the room (display path, allowCache default true) shows it again.
    const d2 = await bob.call('decrypt', { payload: p, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' });
    expect(d2.failed).toBe(false);
    expect(d2.text).toBe('read me twice');
  }, 30000);

  test('wrong key (third party) must fail', async () => {
    const p = (await alice.call('encrypt', { roomId: room, text: 'for bob only', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    const d = await carol.call('decrypt', { payload: p, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'carol', sender: 'alice' });
    expect(d.failed).toBe(true);
    // Wrong room must fail too.
    const dRoom = await bob.call('decrypt', { payload: p, roomId: roomId('alice', 'carol'), peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' });
    expect(dRoom.failed).toBe(true);
  }, 30000);

  test('out-of-order messages all decrypt (skipped keys)', async () => {
    const p1 = (await alice.call('encrypt', { roomId: room, text: 'one', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    const p2 = (await alice.call('encrypt', { roomId: room, text: 'two', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    const p3 = (await alice.call('encrypt', { roomId: room, text: 'three', peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
    // Deliver 3, then 1, then 2.
    expect((await bob.call('decrypt', { payload: p3, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' })).text).toBe('three');
    expect((await bob.call('decrypt', { payload: p1, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' })).text).toBe('one');
    expect((await bob.call('decrypt', { payload: p2, roomId: room, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' })).text).toBe('two');
  }, 30000);

  test('F5/F4: encrypt without a peer bundle or secret throws, never returns plaintext', async () => {
    let threw = false;
    try {
      await alice.call('encrypt', { roomId: roomId('alice', 'dave'), text: 'secret text', peerBundle: null, peerUsername: 'dave', username: 'alice' });
    } catch (e: any) {
      threw = true;
      expect(e.message).toContain('E2EEError');
    }
    expect(threw).toBe(true);
  }, 30000);

  test('F6: forged bundle signature / missing ML-DSA cannot start a PQ session', async () => {
    // Bundle with a forged ML-DSA signature (flip a byte in the signature).
    const parsed = JSON.parse(bobBundle);
    const sigBytes = unb64(parsed.mldsaSigB64);
    sigBytes[0] ^= 0x01;
    parsed.mldsaSigB64 = b64(sigBytes);
    const forged = JSON.stringify(parsed);
    const flags = await alice.call('parseBundle', { bundle: forged, expected: 'bob' });
    expect(flags.isFullyPostQuantum).toBe(false);
    expect(flags.isMldsaSignatureInvalid).toBe(true);
    const st = await alice.call('roomStatus', { roomId: room, isGroup: false, peerBundle: forged, peerUsername: 'bob', username: 'alice' });
    expect(st.isPQ).toBe(false);
    expect(st.reason).toBe('INVALID_MLDSA_SIGNATURE');
    // Sending to the forged bundle falls back to explicit ECDH, never PQ.
    const p = (await alice.call('encrypt', { roomId: room, text: 'fallback?', peerBundle: forged, peerUsername: 'bob', username: 'alice' })).payload;
    expect(p.startsWith('e2ee:ecdh:')).toBe(true);
  }, 30000);

  test('F9: forward secrecy — compromised old state cannot read post-rotation messages', async () => {
    // Fresh room (distinct localStorage key + HKDF salt) so the 50-message
    // rotation boundary is exact and independent of other tests.
    const room2 = 'alice__bob__fs-test';
    // Send 10 messages, snapshot Bob's state (the "compromise").
    for (let i = 0; i < 10; i++) {
      const p = (await alice.call('encrypt', { roomId: room2, text: `m${i}`, peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
      await bob.call('decrypt', { payload: p, roomId: room2, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' });
    }
    const compromised = (await bob.call('getState', { username: 'bob', roomId: room2 })).state;
    expect(compromised).not.toBeNull();
    expect(compromised.sessionEpoch).toBe(1);

    // Keep sending until rotation (50 sent messages trigger it).
    let postRotationPayload = '';
    for (let i = 10; i < 56; i++) {
      const p = (await alice.call('encrypt', { roomId: room2, text: `m${i}`, peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
      const d = await bob.call('decrypt', { payload: p, roomId: room2, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' });
      expect(d.text).toBe(`m${i}`);
      if (i === 55) postRotationPayload = p;
    }
    const bobState = (await bob.call('getState', { username: 'bob', roomId: room2 })).state;
    expect(bobState.sessionEpoch).toBeGreaterThan(1);

    // Eve: Bob's old ratchet state, but fresh long-term keys (she never had them).
    const eve = new Client('bob');
    await eve.call('init', { username: 'bob' });
    await eve.call('setState', { username: 'bob', roomId: room2, state: compromised });
    const dEve = await eve.call('decrypt', { payload: postRotationPayload, roomId: room2, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' });
    expect(dEve.failed).toBe(true);
    eve.kill();
  }, 60000);

  test('F9: late pre-rotation message still decrypts via the previous session slot', async () => {
    const room3 = 'alice__bob__late-msg';
    const payloads: string[] = [];
    for (let i = 0; i < 52; i++) {
      const p = (await alice.call('encrypt', { roomId: room3, text: `g${i}`, peerBundle: bobBundle, peerUsername: 'bob', username: 'alice' })).payload;
      payloads.push(p);
      if (i < 50) {
        await bob.call('decrypt', { payload: p, roomId: room3, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' });
      }
    }
    // Messages 51, 52 rotate Bob to epoch 2; now deliver 50 (epoch 1) late.
    expect((await bob.call('decrypt', { payload: payloads[50], roomId: room3, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' })).text).toBe('g50');
    expect((await bob.call('decrypt', { payload: payloads[51], roomId: room3, peerBundle: aliceBundle, peerUsername: 'alice', username: 'bob', sender: 'alice' })).text).toBe('g51');
  }, 60000);

  test('F3: group epoch key via ML-KEM encapsulation', async () => {
    const groupId = 'test-group-1';
    const groupRoom = `group__${groupId}`;
    const members = ['alice', 'bob', 'carol'];
    const bundles = { alice: aliceBundle, bob: bobBundle, carol: carolBundle };
    // Alice (creator) makes the packet for epoch 1.
    const packet = await alice.call('groupPacket', { members: bundles });
    expect(packet.missing).toEqual([]);
    expect(Object.keys(packet.keys).sort()).toEqual(['alice', 'bob', 'carol']);
    // Bob decapsulates his capsule and rotates.
    const bobKey = (await bob.call('groupDecap', { username: 'bob', ctB64: packet.keys['bob'] })).keyB64;
    expect(bobKey).toBe(packet.epochKeyB64);
    await bob.call('groupRotate', { groupId, epoch: 1, members, keyB64: bobKey });
    // Carol decapsulates too.
    const carolKey = (await carol.call('groupDecap', { username: 'carol', ctB64: packet.keys['carol'] })).keyB64;
    await carol.call('groupRotate', { groupId, epoch: 1, members, keyB64: carolKey });
    // Alice rotates with her raw key.
    await alice.call('groupRotate', { groupId, epoch: 1, members, keyB64: packet.epochKeyB64 });

    const gp = (await alice.call('encryptGroup', { roomId: groupRoom, text: 'hello group', username: 'alice', groupMembers: members })).payload;
    expect(gp.startsWith('e2ee:gep:v2:1:')).toBe(true);
    const dBob = await bob.call('decryptGroup', { payload: gp, roomId: groupRoom, username: 'bob', groupMembers: members, allowCache: false });
    expect(dBob.text).toBe('hello group');
    expect(dBob.mode).toBe('GROUP-EPOCH-FSM');
    const dCarol = await carol.call('decryptGroup', { payload: gp, roomId: groupRoom, username: 'carol', groupMembers: members, allowCache: false });
    expect(dCarol.text).toBe('hello group');

    // F7 (group): replaying the same group payload on the network path fails.
    const dReplay = await bob.call('decryptGroup', { payload: gp, roomId: groupRoom, username: 'bob', groupMembers: members, allowCache: false });
    expect(dReplay.failed).toBe(true);
    // ...but the display path still re-reads it from cache.
    const dDisplay = await bob.call('decryptGroup', { payload: gp, roomId: groupRoom, username: 'bob', groupMembers: members });
    expect(dDisplay.failed).toBe(false);
    expect(dDisplay.text).toBe('hello group');

    // A non-member (Dave) cannot decapsulate or decrypt.
    const dave = new Client('dave');
    await dave.call('init', { username: 'dave' });
    const daveKey = (await dave.call('groupDecap', { username: 'dave', ctB64: packet.keys['bob'] })).keyB64;
    expect(daveKey).toBeNull();
    const dDave = await dave.call('decryptGroup', { payload: gp, roomId: groupRoom, username: 'dave', groupMembers: members, allowCache: false });
    expect(dDave.failed).toBe(true);
    dave.kill();

    // Tampered capsule fails to decapsulate (flip a byte in the KEM ciphertext part).
    const ctParts = packet.keys['bob'].split(':');
    const ctBytes = unb64(ctParts[0]);
    ctBytes[0] ^= 0x01;
    ctParts[0] = b64(ctBytes);
    const bad = (await bob.call('groupDecap', { username: 'bob', ctB64: ctParts.join(':') })).keyB64;
    expect(bad).toBeNull();
  }, 60000);

  test('safety numbers: same keys both sides, change on key rotation', async () => {
    const s1 = await alice.call('safetyNumber', { username: 'alice', peerBundle: bobBundle, peerUsername: 'bob' });
    const s2 = await bob.call('safetyNumber', { username: 'bob', peerBundle: aliceBundle, peerUsername: 'alice' });
    expect(s1.digits60).toBe(s2.digits60);
    expect(s1.groups12.length).toBe(12);
    expect(s1.digits60.length).toBe(60);
    // Bob rotates identity (fresh keys) -> safety number changes.
    await bob.call('reset', {});
    const bobBundle2 = (await bob.call('init', { username: 'bob' })).bundle;
    const s3 = await alice.call('safetyNumber', { username: 'alice', peerBundle: bobBundle2, peerUsername: 'bob' });
    expect(s3.digits60).not.toBe(s1.digits60);
  }, 30000);
});

describe('VOPRF (RFC 9497) round-trip', () => {
  test('blind -> evaluate -> finalize verifies; wrong server key fails', () => {
    const serverSeed = sha256(new TextEncoder().encode('test-server-seed'));
    const serverKeys = ristretto255_oprf.voprf.deriveKeyPair(
      serverSeed,
      new TextEncoder().encode('PersianMessenger-Ristretto255-VOPRF-v2')
    );
    const rawInput = new TextEncoder().encode('blind-identity::alice::v2');
    const { blind, blinded } = ristretto255_oprf.voprf.blind(rawInput);
    const { evaluated, proof } = ristretto255_oprf.voprf.blindEvaluate(
      serverKeys.secretKey,
      serverKeys.publicKey,
      blinded
    );
    const out = ristretto255_oprf.voprf.finalize(rawInput, blind, evaluated, blinded, serverKeys.publicKey, proof);
    // Ristretto255-SHA512 OPRF output is Nh = 64 bytes; the app hashes it
    // with SHA-256 and uses the first 22 base64 chars as the anonymous token id.
    expect(out.length).toBe(64);
    const tokenId = b64(sha256(out)).slice(0, 22);
    expect(tokenId.length).toBe(22);
    // Wrong server public key must throw.
    const wrongKeys = ristretto255_oprf.voprf.deriveKeyPair(
      sha256(new TextEncoder().encode('other-seed')),
      new TextEncoder().encode('PersianMessenger-Ristretto255-VOPRF-v2')
    );
    expect(() =>
      ristretto255_oprf.voprf.finalize(rawInput, blind, evaluated, blinded, wrongKeys.publicKey, proof)
    ).toThrow();
  });
});
