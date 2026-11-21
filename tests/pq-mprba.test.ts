import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  E2EEError,
  KEY_STORAGE_VERSION,
  base64ToBuf,
  bufToBase64,
  clearRatchetSession,
  clearVerifiedBundleCache,
  createGroupEpochPacket,
  decapsulateGroupEpochKey,
  decryptMessageText,
  encryptMessageText,
  ensureUserHybridKeyPair,
  getGroupSecurityBadge,
  getRoomSecret,
  getVerifiedBundleCacheStats,
  HKDF_RATCHET_SALT_V2,
  parsePeerKeyBundle,
  parsePeerKeyBundleStrict,
  resetAllCryptoStateForTests,
  rotateGroupEpoch,
  serializeEpochPacketForSigning,
  serializeMessageForSigning,
  setRoomSecret,
  withUnwrappedMLDSASecretKey,
  zeroizeBuffer,
} from '../src/utils/crypto';
import {
  KEY_STORAGE_VERSION_MARKER,
  loadIdentityRecordV4,
} from '../src/utils/keystore';
import {
  computeSafetyNumberForContact,
  computeSafetyNumberFromRawKeysV2,
  generateQrCodeMatrix,
  markContactVerified,
  observeContactPublicKey,
  parseAndCompareQrPayload,
  rotateSessionRatchetOnly,
  SAFETY_PROTOCOL_ID_V2,
  SAFETY_QR_PREFIX_V2,
} from '../src/utils/safetyNumber';
import {
  RecoveryRateLimiter,
  generateRecoveryCode,
  hashRecoveryCode,
  verifyRecoveryCode,
} from '../src/server/recovery';
import { config, verifyAdminSecret } from '../src/server/config';

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  clear(): void {
    this.map.clear();
  }
  getItem(key: string): string | null {
    return this.map.has(key) ? this.map.get(key)! : null;
  }
  key(index: number): string | null {
    return Array.from(this.map.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.map.set(key, String(value));
  }
}

const mockLocalStorage = new MemoryStorage();
const mockSessionStorage = new MemoryStorage();
Object.defineProperty(globalThis, 'localStorage', {
  value: mockLocalStorage,
  configurable: true,
  writable: true,
});
Object.defineProperty(globalThis, 'sessionStorage', {
  value: mockSessionStorage,
  configurable: true,
  writable: true,
});

describe('PQ-MPRBA v4 Hardened Protocol & Storage Suite', () => {
  beforeEach(() => {
    mockLocalStorage.clear();
    mockSessionStorage.clear();
    resetAllCryptoStateForTests();
  });

  it('stores v4 identity & wrapping keys as non-extractable WebCrypto CryptoKeys and never writes private keys to localStorage', async () => {
    const bundleStr = await ensureUserHybridKeyPair('alice');
    assert.ok(bundleStr, 'Bundle should be generated');
    const parsed = JSON.parse(bundleStr);
    assert.equal(parsed.v, 4);
    assert.equal(KEY_STORAGE_VERSION, 4);

    const record = await loadIdentityRecordV4('alice');
    assert.ok(record, 'IndexedDB v4 identity record must exist');
    assert.equal(record.v, 4);
    assert.equal(record.ecdhPrivateKey.extractable, false, 'ECDH private CryptoKey must be non-extractable');
    assert.equal(record.wrappingKey.extractable, false, 'AES-GCM wrapping CryptoKey must be non-extractable');

    await assert.rejects(
      () => globalThis.crypto.subtle.exportKey('jwk', record.ecdhPrivateKey),
      'Exporting non-extractable ECDH private key must reject'
    );
    await assert.rejects(
      () => globalThis.crypto.subtle.exportKey('raw', record.wrappingKey),
      'Exporting non-extractable AES-GCM wrapping key must reject'
    );

    // Ensure no private key material or ratchet state leaked into localStorage
    for (let i = 0; i < mockLocalStorage.length; i++) {
      const k = mockLocalStorage.key(i)!;
      const v = mockLocalStorage.getItem(k) || '';
      assert.equal(k.startsWith('chat_ecdh_kp_'), false);
      assert.equal(k.startsWith('chat_mlkem768_kp_'), false);
      assert.equal(k.startsWith('chat_mldsa65_kp_'), false);
      assert.equal(k.startsWith('chat_pq_ratchet_'), false);
      assert.equal(v.includes('"d":'), false, 'No private JWK "d" parameter allowed in localStorage');
      assert.equal(v.includes('secretKey'), false, 'No secretKey field allowed in localStorage');
    }
  });

  it('discards legacy v2/v3 plaintext localStorage keys and bumps storage marker to v4', async () => {
    mockLocalStorage.setItem(KEY_STORAGE_VERSION_MARKER, '3');
    mockLocalStorage.setItem('chat_ecdh_kp_alice', '{"privateKey":{"d":"SECRET"}}');
    mockLocalStorage.setItem('chat_mlkem768_kp_alice', '{"secretKey":"SECRET"}');
    mockLocalStorage.setItem('chat_mldsa65_kp_alice', '{"secretKey":"SECRET"}');
    mockLocalStorage.setItem('chat_pq_ratchet_alice_alice__bob', '{"sendChainKey":"SECRET"}');
    mockLocalStorage.setItem('chat_identity_v3_alice', '{"v":3,"secret":"SECRET"}');
    mockLocalStorage.setItem('chat_decrypted_v2_alice_room', '{"k":"plaintext"}');

    const bundleStr = await ensureUserHybridKeyPair('alice');
    assert.ok(bundleStr);
    assert.equal(mockLocalStorage.getItem(KEY_STORAGE_VERSION_MARKER), '4');
    assert.equal(mockLocalStorage.getItem('chat_ecdh_kp_alice'), null);
    assert.equal(mockLocalStorage.getItem('chat_mlkem768_kp_alice'), null);
    assert.equal(mockLocalStorage.getItem('chat_mldsa65_kp_alice'), null);
    assert.equal(mockLocalStorage.getItem('chat_pq_ratchet_alice_alice__bob'), null);
    assert.equal(mockLocalStorage.getItem('chat_identity_v3_alice'), null);
    assert.equal(mockLocalStorage.getItem('chat_decrypted_v2_alice_room'), null);
  });

  it('generates fresh CSPRNG identity keys rather than deterministic username-derived keys', async () => {
    const first = JSON.parse((await ensureUserHybridKeyPair('alice'))!);
    resetAllCryptoStateForTests();
    mockLocalStorage.clear();
    const second = JSON.parse((await ensureUserHybridKeyPair('alice'))!);

    assert.notEqual(first.mlkemPubB64, second.mlkemPubB64);
    assert.notEqual(first.mldsaPubB64, second.mldsaPubB64);
    assert.notEqual(first.ecdhJwk.x, second.ecdhJwk.x);
  });

  it('binds ML-KEM-768 and ECDH P-256 public keys under a verified ML-DSA-65 bundle signature', async () => {
    const aliceBundleStr = (await ensureUserHybridKeyPair('alice'))!;
    const valid = parsePeerKeyBundleStrict(aliceBundleStr, 'alice', { skipCache: true });
    assert.equal(valid.isFullyPostQuantum, true);
    assert.equal(valid.isMldsaVerified, true);

    // Tamper username binding
    assert.throws(
      () => parsePeerKeyBundleStrict(aliceBundleStr, 'mallory', { skipCache: true }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_SIGNATURE'
    );

    // Tamper ML-KEM public key inside bundle
    const tampered = JSON.parse(aliceBundleStr);
    const kemBuf = Buffer.from(tampered.mlkemPubB64, 'base64');
    kemBuf[0] ^= 0xff;
    tampered.mlkemPubB64 = kemBuf.toString('base64');

    assert.throws(
      () => parsePeerKeyBundleStrict(JSON.stringify(tampered), 'alice', { skipCache: true }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_SIGNATURE'
    );
  });

  it('encryptMessageText fails closed (throws E2EEError, never returns plaintext)', async () => {
    const aliceBundleStr = (await ensureUserHybridKeyPair('alice'))!;

    await assert.rejects(
      () => encryptMessageText('secret message', 'alice__bob', { myUsername: 'alice' }),
      (err: unknown) => err instanceof E2EEError && err.code === 'MISSING_KEYS'
    );

    await assert.rejects(
      () => encryptMessageText('secret message', '', { myUsername: 'alice' }),
      (err: unknown) => err instanceof E2EEError && err.code === 'ENCRYPTION_FAILED'
    );

    const forged = JSON.parse(aliceBundleStr);
    forged.ecdhJwk = { ...forged.ecdhJwk, x: 'AAAA' };
    await assert.rejects(
      () =>
        encryptMessageText('secret message', 'alice__bob', {
          myUsername: 'alice',
          peerUsername: 'bob',
          peerPublicKey: JSON.stringify(forged),
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_SIGNATURE'
    );
  });

  it('completes bidirectional PQ-MPRBA v2 round-trip with RAM-only ratchet state', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';

    const c1 = await encryptMessageText('سلام باب! پیام اول پساکوانتومی', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });
    assert.ok(c1.startsWith('e2ee:pq:v2:0:'));

    const d1 = await decryptMessageText(c1, roomId, {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    });
    assert.equal(d1.text, 'سلام باب! پیام اول پساکوانتومی');
    assert.equal(d1.mode, 'PQ-MLKEM-RATCHET');
    assert.equal(d1.mldsaVerified, true);
    assert.equal(d1.ratchetStep, 0);

    // Bob replies back to Alice
    const c2 = await encryptMessageText('سلام آلیس! دریافت شد.', roomId, {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
    });
    const d2 = await decryptMessageText(c2, roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
      sender: 'bob',
    });
    assert.equal(d2.text, 'سلام آلیس! دریافت شد.');
    assert.equal(d2.mldsaVerified, true);

    // Ratchet state must stay RAM-only
    for (let i = 0; i < mockLocalStorage.length; i++) {
      const k = mockLocalStorage.key(i)!;
      assert.equal(k.includes('ratchet'), false);
    }
  });

  it('verifies ML-DSA-65 signature BEFORE decrypting or advancing ratchet state', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';

    const validCipher = await encryptMessageText('authentic payload', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });

    // Tamper ciphertext field without re-signing
    const prefix = 'e2ee:pq:v2:';
    const parts = validCipher.slice(prefix.length).split(':');
    const ctBuf = Buffer.from(parts[3], 'base64');
    ctBuf[0] ^= 0x01;
    parts[3] = ctBuf.toString('base64');
    const tamperedCipher = prefix + parts.join(':');

    await assert.rejects(
      () =>
        decryptMessageText(tamperedCipher, roomId, {
          myUsername: 'bob',
          peerUsername: 'alice',
          peerPublicKey: aliceBundle,
          sender: 'alice',
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'INVALID_SIGNATURE'
    );

    // Because signature failed before ratchet mutation, the original valid message must still decrypt!
    const ok = await decryptMessageText(validCipher, roomId, {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    });
    assert.equal(ok.text, 'authentic payload');
  });

  it('rejects replayed PQ messages with E2EEError(REPLAY_DETECTED)', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';

    const msg = await encryptMessageText('one-time command', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });

    const first = await decryptMessageText(msg, roomId, {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    });
    assert.equal(first.text, 'one-time command');

    await assert.rejects(
      () =>
        decryptMessageText(msg, roomId, {
          myUsername: 'bob',
          peerUsername: 'alice',
          peerPublicKey: aliceBundle,
          sender: 'alice',
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'REPLAY_DETECTED'
    );
  });

  it('handles out-of-order messages via skipped keys and burns each skipped key after single use', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';

    const m0 = await encryptMessageText('msg-0', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });
    const m1 = await encryptMessageText('msg-1', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });
    const m2 = await encryptMessageText('msg-2', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });

    // Deliver out of order: 2 -> 0 -> 1
    assert.equal(
      (await decryptMessageText(m2, roomId, { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, sender: 'alice' })).text,
      'msg-2'
    );
    assert.equal(
      (await decryptMessageText(m0, roomId, { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, sender: 'alice' })).text,
      'msg-0'
    );
    assert.equal(
      (await decryptMessageText(m1, roomId, { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, sender: 'alice' })).text,
      'msg-1'
    );

    // Replaying skipped message 0 must fail closed
    await assert.rejects(
      () =>
        decryptMessageText(m0, roomId, {
          myUsername: 'bob',
          peerUsername: 'alice',
          peerPublicKey: aliceBundle,
          sender: 'alice',
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'REPLAY_DETECTED'
    );
  });

  it('enforces MAX_SKIP bound (100) to prevent ratchet DoS', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const roomId = 'alice__bob';

    // پیام قانونی اول — نشست را نزد گیرنده برقرار می‌کند (recvStep = 1 پس از رمزگشایی)
    const first = await encryptMessageText('step-0', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });
    await decryptMessageText(first, roomId, {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
      sender: 'alice',
    });

    // حمله: فرستنده (با کلید امضای واقعی خودش) پیامی با قدم ۱۵۱ می‌سازد.
    // چرخش دوره‌ای پس از ۵۰ پیام، پرش بیش از ۱۰۰ قدم را در مسیر عادی ناممکن کرده،
    // پس مرز MAX_SKIP فقط در برابر چنین بار جعلی معنا دارد — و باید بسته بماند.
    const parts = first.split(':');
    // قالب بار: e2ee:pq:v2:{step}:{kem}:{iv}:{cipher}:{sig}
    const forgedStep = 151;
    const signTarget = serializeMessageForSigning({
      roomId,
      step: forgedStep,
      kemCipherB64: parts[4],
      ivB64: parts[5],
      cipherB64: parts[6],
    });
    const sig = await withUnwrappedMLDSASecretKey('alice', sec => ml_dsa65.sign(signTarget, sec));
    const forged = `e2ee:pq:v2:${forgedStep}:${parts[4]}:${parts[5]}:${parts[6]}:${bufToBase64(sig)}`;

    await assert.rejects(
      () =>
        decryptMessageText(forged, roomId, {
          myUsername: 'bob',
          peerUsername: 'alice',
          peerPublicKey: aliceBundle,
          sender: 'alice',
        }),
      (err: unknown) => err instanceof E2EEError && err.code === 'MAX_SKIP_EXCEEDED'
    );
  });

  it('supports Group Epoch FSM rotation with ML-KEM-768 epoch packets, 3-epoch grace buffer, and expires older epochs', async () => {
    const roomId = 'group__sec-team';
    const members = ['alice', 'bob', 'carol'];
    // باندل‌های تأییدشده اعضا برای ساخت بسته کلید اپوک
    const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
    for (const m of members) {
      const bundleStr = (await ensureUserHybridKeyPair(m))!;
      bundles[m] = parsePeerKeyBundle(bundleStr, m);
    }
    const rotateWithPacket = async (epoch: number) => {
      const packet = await createGroupEpochPacket(bundles);
      await rotateGroupEpoch('sec-team', epoch, members, packet.epochKeyB64);
      return packet;
    };

    const p1 = await rotateWithPacket(1);
    const e1 = await encryptMessageText('epoch-1-msg', roomId, { groupMembers: members });
    await rotateWithPacket(2);
    await rotateWithPacket(3);
    const e3 = await encryptMessageText('epoch-3-msg', roomId, { groupMembers: members });
    await rotateWithPacket(4);
    await rotateWithPacket(5);
    const e5 = await encryptMessageText('epoch-5-msg', roomId, { groupMembers: members });

    // Epochs 3 and 5 are inside the 3-epoch window (3, 4, 5)
    assert.equal((await decryptMessageText(e5, roomId, { groupMembers: members })).text, 'epoch-5-msg');
    assert.equal((await decryptMessageText(e3, roomId, { groupMembers: members })).text, 'epoch-3-msg');

    // Epoch 1 is evicted & outside grace window
    await assert.rejects(
      () => decryptMessageText(e1, roomId, { groupMembers: members }),
      (err: unknown) => err instanceof E2EEError && err.code === 'DECRYPTION_FAILED'
    );

    // بسته کلید اپوک: هر عضو کپسول خودش را باز می‌کند و به همان کلید توزیع‌کننده می‌رسد
    assert.equal(await decapsulateGroupEpochKey('bob', p1.keys['bob']), p1.epochKeyB64);
    assert.equal(await decapsulateGroupEpochKey('carol', p1.keys['carol']), p1.epochKeyB64);
    // کپسول خراب باز نمی‌شود
    assert.equal(await decapsulateGroupEpochKey('bob', 'AAAA:BBBB:CCCC'), null);
  });

  it('refuses to encrypt a group message without an epoch key, refuses keyless rotation (F3), and rejects replayed group messages (F7)', async () => {
    const roomId = 'group__replay-team';
    const members = ['alice', 'bob'];

    // بدون کلید اپوک، رمزگذاری گروهی خطا می‌دهد — هرگز کلید مشتق‌شده از ورودی عمومی نمی‌سازد
    await assert.rejects(
      () => encryptMessageText('no-key-msg', roomId, { groupMembers: members }),
      (err: unknown) => err instanceof E2EEError && err.code === 'MISSING_KEYS'
    );
    // چرخش بدون کلید کپسوله‌شده خطا می‌دهد
    await assert.rejects(
      () => rotateGroupEpoch('replay-team', 2, members),
      (err: unknown) => err instanceof E2EEError && err.code === 'MISSING_KEYS'
    );

    const bundles: Record<string, ReturnType<typeof parsePeerKeyBundle>> = {};
    for (const m of members) {
      bundles[m] = parsePeerKeyBundle((await ensureUserHybridKeyPair(m))!, m);
    }
    const packet = await createGroupEpochPacket(bundles);
    await rotateGroupEpoch('replay-team', 1, members, packet.epochKeyB64);
    const payload = await encryptMessageText('once-only', roomId, { groupMembers: members });
    assert.equal((await decryptMessageText(payload, roomId, { groupMembers: members })).text, 'once-only');
    await assert.rejects(
      () => decryptMessageText(payload, roomId, { groupMembers: members }),
      (err: unknown) => err instanceof E2EEError && err.code === 'REPLAY_DETECTED'
    );
  });

  it('rotates the PQ ratchet session after 50 sent messages (F9)', async () => {
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const roomId = 'alice__bob';
    const payloads: string[] = [];
    for (let i = 0; i < 51; i++) {
      payloads.push(
        await encryptMessageText(`msg-${i}`, roomId, {
          myUsername: 'alice',
          peerUsername: 'bob',
          peerPublicKey: bobBundle,
        })
      );
    }
    // قالب بار: e2ee:pq:v2:{step}:{kemCipher}:{iv}:{cipher}:{sig} — کپسول در بخش ۴ است
    const capsule = (p: string) => p.split(':')[4];
    assert.equal(capsule(payloads[0]), capsule(payloads[49]));
    assert.notEqual(capsule(payloads[50]), capsule(payloads[49]));
    // همه پیام‌ها هنوز رمزگشایی می‌شوند
    for (let i = 0; i < 51; i++) {
      const out = await decryptMessageText(payloads[i], roomId, {
        myUsername: 'bob',
        peerUsername: 'alice',
        peerPublicKey: aliceBundle,
        sender: 'alice',
      });
      assert.equal(out.text, `msg-${i}`);
    }
  });

  it('requires an explicit manual passphrase for PBKDF2 and never uses a public default (F4)', async () => {
    const roomId = 'alice__bob';
    // بدون کلید مخاطب و بدون رمز دستی، رمزگذاری خطا می‌دهد
    await assert.rejects(
      () => encryptMessageText('hello', roomId, { myUsername: 'alice' }),
      (err: unknown) => err instanceof E2EEError && err.code === 'MISSING_KEYS'
    );
    // با رمز دستی صریح، رمزگذاری و رمزگشایی کار می‌کند
    const payload = await encryptMessageText('secret-note', roomId, {
      myUsername: 'alice',
      customSecret: 'correct horse battery staple',
    });
    const out = await decryptMessageText(payload, roomId, {
      myUsername: 'bob',
      customSecret: 'correct horse battery staple',
    });
    assert.equal(out.text, 'secret-note');
    assert.equal(out.mode, 'PBKDF2');
  });

  it('caches verified bundles for UI reads while forcing fresh verification when skipCache is true', async () => {
    clearVerifiedBundleCache();
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;

    const b1 = parsePeerKeyBundle(aliceBundle, 'alice');
    assert.equal(b1.isMldsaVerified, true);
    assert.equal(getVerifiedBundleCacheStats().hits, 0);

    const b2 = parsePeerKeyBundle(aliceBundle, 'alice');
    assert.equal(b2.isMldsaVerified, true);
    assert.equal(getVerifiedBundleCacheStats().hits, 1);

    // Session establishment path uses skipCache: true and must not increment cache hits
    const b3 = parsePeerKeyBundleStrict(aliceBundle, 'alice', { skipCache: true });
    assert.equal(b3.isMldsaVerified, true);
    assert.equal(getVerifiedBundleCacheStats().hits, 1);
  });

  it('computes symmetric Safety Numbers, preserves VERIFIED on session rekey, and marks CHANGED on identity key rotation', async () => {
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;

    const snAlice = computeSafetyNumberForContact('alice', bobBundle, 'bob');
    const snBob = computeSafetyNumberForContact('bob', aliceBundle, 'alice');
    assert.ok(snAlice && snBob);
    assert.equal(snAlice.digits60, snBob.digits60);
    assert.equal(snAlice.sha256Hex, snBob.sha256Hex);
    assert.equal(snAlice.groups12.length, 12);

    const verified = markContactVerified('alice', 'bob', bobBundle);
    assert.equal(verified?.state, 'VERIFIED');

    // Rekeying session ratchet must NOT change safety number or clear VERIFIED
    rotateSessionRatchetOnly('alice', 'alice__bob');
    clearRatchetSession('alice', 'alice__bob');
    const afterRekey = observeContactPublicKey('alice', 'bob', bobBundle);
    assert.equal(afterRekey.state, 'VERIFIED');

    // Simulate Bob logging in on a second device (brand-new CSPRNG identity key)
    resetAllCryptoStateForTests();
    const bobNewBundle = (await ensureUserHybridKeyPair('bob'))!;
    assert.notEqual(bobNewBundle, bobBundle);

    const afterKeyChange = observeContactPublicKey('alice', 'bob', bobNewBundle);
    assert.equal(afterKeyChange.state, 'CHANGED');
    assert.equal(afterKeyChange.verifiedMldsaPubB64, null);
    assert.equal(afterKeyChange.auditHistory.length, 1);
  });

  it('zeroizes sensitive Uint8Array buffers in place', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 255, 128, 64, 32]);
    zeroizeBuffer(secret);
    assert.deepEqual(Array.from(secret), [0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('hashes Bale fallback recovery codes with salted scrypt and enforces strict RecoveryRateLimiter bounds', async () => {
    const code = generateRecoveryCode();
    assert.match(code, /^[0-9A-F]{4}(-[0-9A-F]{4}){7}$/);

    const hash1 = await hashRecoveryCode(code);
    const hash2 = await hashRecoveryCode(code);
    assert.ok(hash1.startsWith('scrypt$16384$8$1$'));
    assert.notEqual(hash1, hash2, 'Salted scrypt hashes must differ for identical inputs');

    assert.equal(await verifyRecoveryCode(code, hash1), true);
    assert.equal(await verifyRecoveryCode(code.toLowerCase().replace(/-/g, ''), hash1), true);
    assert.equal(await verifyRecoveryCode('0000-0000-0000-0000-0000-0000-0000-0000', hash1), false);
    assert.equal(await verifyRecoveryCode('not-a-code', hash1), false);

    const limiter = new RecoveryRateLimiter(5, 15 * 60 * 1000);
    const t0 = 1_700_000_000_000;
    for (let i = 0; i < 5; i++) {
      const r = limiter.checkAndConsume('203.0.113.10', 'alice', t0 + i * 1000);
      assert.equal(r.allowed, true);
    }
    // 6th attempt from same IP must be blocked
    const blockedIp = limiter.checkAndConsume('203.0.113.10', 'bob', t0 + 6000);
    assert.equal(blockedIp.allowed, false);
    assert.ok(blockedIp.retryAfterSec > 0);

    // 6th attempt targeting same username from a different IP must also be blocked
    const blockedUser = limiter.checkAndConsume('198.51.100.22', 'alice', t0 + 7000);
    assert.equal(blockedUser.allowed, false);
    assert.ok(blockedUser.retryAfterSec > 0);

    // After window passes, requests are allowed again
    const afterWindow = limiter.checkAndConsume('203.0.113.10', 'alice', t0 + 16 * 60 * 1000);
    assert.equal(afterWindow.allowed, true);
  });

  it('M5: rejects tampered-signature bundle before extracting safety-number keys', async () => {
    const aliceBundleStr = (await ensureUserHybridKeyPair('alice-m5'))!;
    const aliceBundle = JSON.parse(aliceBundleStr);
    aliceBundle.mldsaSigB64 = bufToBase64(new Uint8Array(3309).fill(0x42));
    const tamperedStr = JSON.stringify(aliceBundle);

    assert.equal(computeSafetyNumberForContact('bob-m5', tamperedStr, 'alice-m5'), null);
    assert.equal(markContactVerified('bob-m5', 'alice-m5', tamperedStr), null);
  });

  it('M7: group security badge is shown only when active epoch key exists in memory', async () => {
    const badgeNoKey = getGroupSecurityBadge('group__no-key-group', 0);
    assert.equal(badgeNoKey.isPQ, false);
    assert.match(badgeNoKey.badge, /بدون کلید/);

    const bundleStr = (await ensureUserHybridKeyPair('alice-m7'))!;
    const bundle = parsePeerKeyBundleStrict(bundleStr, 'alice-m7');
    const packet = await createGroupEpochPacket({ 'alice-m7': bundle });
    await rotateGroupEpoch('with-key-group', 1, ['alice-m7'], packet.epochKeyB64);

    const badgeWithKey = getGroupSecurityBadge('group__with-key-group', 1);
    assert.equal(badgeWithKey.isPQ, true);
    assert.match(badgeWithKey.badge, /Epoch #1/);
  });

  it('L10: throws E2EEError instead of swallowing errors in ensureUserHybridKeyPair', async () => {
    await assert.rejects(
      () => ensureUserHybridKeyPair(''),
      (err: unknown) => err instanceof E2EEError && err.code === 'MISSING_KEYS'
    );
  });

  it('I2: validates QR matrix output dimensions, finder patterns, and timing tracks against standard specs', () => {
    const payload = 'PQ-MPRBA-SAFETY-v1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const matrix = generateQrCodeMatrix(payload);

    // 1. Dimensions: QR Version 5 must be exactly 37x37
    assert.equal(matrix.length, 37);
    assert.ok(matrix.every(row => row.length === 37));

    // 2. Top-left finder pattern 7x7 outer border and center
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const isBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const isCenter = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        if (isBorder || isCenter) {
          assert.equal(matrix[r][c], true, `top-left finder module (${r},${c}) must be dark`);
        } else {
          assert.equal(matrix[r][c], false, `top-left finder ring (${r},${c}) must be light`);
        }
      }
    }

    // 3. Timing pattern on row 6 alternates
    for (let c = 8; c <= 28; c++) {
      assert.equal(matrix[6][c], c % 2 === 0, `timing row module (6,${c}) must alternate`);
    }

    // 4. Deterministic reproducibility
    const matrix2 = generateQrCodeMatrix(payload);
    assert.deepEqual(matrix, matrix2);
  });

  it('I4: verifies admin secret with SHA-256 pre-hashing without leaking password length via timing path', () => {
    // Valid password matches
    assert.equal(verifyAdminSecret(config.ADMIN_PASSWORD), true);

    // Wrong passwords of various lengths fail in constant-time path
    assert.equal(verifyAdminSecret('wrong'), false);
    assert.equal(verifyAdminSecret('x'.repeat(config.ADMIN_PASSWORD.length)), false);
    assert.equal(verifyAdminSecret('x'.repeat(config.ADMIN_PASSWORD.length + 10)), false);
    assert.equal(verifyAdminSecret(''), false);
    assert.equal(verifyAdminSecret(undefined), false);
  });

  it('enforces strict Helmet CSP without unsafe-inline, unsafe-eval, or unpinned CDN assets', () => {
    const serverSrc = fs.readFileSync(path.resolve(process.cwd(), 'server.ts'), 'utf8');
    const adminHtml = fs.readFileSync(path.resolve(process.cwd(), 'public/admin.html'), 'utf8');

    assert.match(serverSrc, /defaultSrc:\s*\["'self'"\]/);
    // The global Helmet CSP (the app shell) must stay strict: no
    // unsafe-inline, no unsafe-eval anywhere in the Helmet directives.
    const helmetBlock = serverSrc.slice(
      serverSrc.indexOf('helmet({'),
      serverSrc.indexOf('}));', serverSrc.indexOf('helmet({'))
    );
    assert.equal(helmetBlock.includes('unsafe-inline'), false, 'Helmet CSP must not allow unsafe-inline');
    assert.equal(helmetBlock.includes('unsafe-eval'), false, 'Helmet CSP must not allow unsafe-eval');
    assert.equal(serverSrc.includes('unsafe-eval'), false, 'CSP must not allow unsafe-eval');
    assert.equal(serverSrc.includes('fonts.googleapis.com'), false, 'CSP must not allow unpinned Google Fonts CDN');
    assert.equal(serverSrc.includes('fonts.gstatic.com'), false, 'CSP must not allow unpinned Google Fonts CDN');

    // Deliberate, scoped exception: the public /privacy page is a
    // static document with one inline <style> block and no scripts, no
    // external resources, no user data. Its route overrides the CSP
    // with a tighter page-specific policy — inline styles allowed,
    // scripts forbidden. 'unsafe-inline' may appear ONLY in that one
    // override, never in the Helmet directives or anywhere else.
    const inlineOccurrences = (serverSrc.match(/unsafe-inline/g) || []).length;
    assert.equal(inlineOccurrences, 1, "'unsafe-inline' must appear exactly once (the /privacy override)");
    const privacyStart = serverSrc.indexOf("app.get('/privacy'");
    const privacyOverride = serverSrc.slice(privacyStart, privacyStart + 1400);
    assert.match(privacyOverride, /style-src 'unsafe-inline'/);
    assert.match(privacyOverride, /script-src 'none'/);
    assert.match(privacyOverride, /default-src 'none'/);

    assert.equal(adminHtml.includes('fonts.googleapis.com'), false, 'admin.html must not load unpinned Google Fonts CDN');
    assert.equal(/<style[\s>]/i.test(adminHtml), false, 'admin.html must not contain inline <style> blocks');
    assert.equal(/<script(?![^>]*\bsrc=)[^>]*>/i.test(adminHtml), false, 'admin.html must not contain inline <script> blocks');
  });

  it('stores room passphrases in ephemeral sessionStorage and never in localStorage (M9)', () => {
    const roomId = 'confidential-team-room';
    const secret = 'ultra-secure-passphrase-2026';
    setRoomSecret(roomId, secret);

    assert.equal(getRoomSecret(roomId), secret);
    assert.equal(mockSessionStorage.getItem(`chat_e2ee_pass_${roomId}`), secret);
    assert.equal(mockLocalStorage.getItem(`chat_e2ee_pass_${roomId}`), null);

    // Also verify cleanup of legacy localStorage entry if one existed prior to setRoomSecret
    mockLocalStorage.setItem(`chat_e2ee_pass_${roomId}`, 'stale-leaked-secret');
    setRoomSecret(roomId, secret);
    assert.equal(mockLocalStorage.getItem(`chat_e2ee_pass_${roomId}`), null);
    assert.equal(mockSessionStorage.getItem(`chat_e2ee_pass_${roomId}`), secret);

    // Verify clearing
    setRoomSecret(roomId, '');
    assert.equal(getRoomSecret(roomId), '');
    assert.equal(mockSessionStorage.getItem(`chat_e2ee_pass_${roomId}`), null);
  });

  it('uses domain-separated HKDF salt v2 for ratchet chain steps (I3)', async () => {
    assert.deepEqual(
      HKDF_RATCHET_SALT_V2,
      new TextEncoder().encode('PQ-MPRBA-RATCHET-SALT-v2'),
      'HKDF_RATCHET_SALT_V2 must be domain-separated'
    );

    const bobBundle = (await ensureUserHybridKeyPair('bob'))!;
    const aliceBundle = (await ensureUserHybridKeyPair('alice'))!;
    const roomId = 'alice__bob';

    const enc = await encryptMessageText('v2-ratchet-test', roomId, {
      myUsername: 'alice',
      peerUsername: 'bob',
      peerPublicKey: bobBundle,
    });
    assert.ok(enc.startsWith('e2ee:pq:v2:0:'));

    const dec = await decryptMessageText(enc, roomId, {
      myUsername: 'bob',
      peerUsername: 'alice',
      peerPublicKey: aliceBundle,
    });
    assert.equal(dec.text, 'v2-ratchet-test');
    assert.equal(dec.mode, 'PQ-MLKEM-RATCHET');
  });

  it('computes Safety Number v2 binding both ML-DSA and ML-KEM keys (L2)', async () => {
    const bobBundleStr = (await ensureUserHybridKeyPair('bob'))!;
    const aliceBundleStr = (await ensureUserHybridKeyPair('alice'))!;

    const snAlice = computeSafetyNumberForContact('alice', bobBundleStr, 'bob');
    assert.ok(snAlice, 'Safety number should be computed');
    assert.equal(snAlice.version, 'v2');
    assert.ok(snAlice.qrPayload.startsWith(SAFETY_QR_PREFIX_V2));

    const snBob = computeSafetyNumberForContact('bob', aliceBundleStr, 'alice');
    assert.ok(snBob, 'Safety number should be computed');
    assert.equal(snBob.version, 'v2');

    // Both parties compute the identical 60-digit number and hash
    assert.equal(snAlice.digits60, snBob.digits60);
    assert.equal(snAlice.sha256Hex, snBob.sha256Hex);

    // Tampering with peer's ML-KEM key alters the Safety Number (proving ML-KEM binding)
    const tamperedBob = JSON.parse(bobBundleStr);
    const fakeKem = new Uint8Array(1184);
    fakeKem.fill(0x42);
    tamperedBob.mlkemPubB64 = bufToBase64(fakeKem);
    // Even if signature is re-signed on the bundle, safety number must differ
    const snTampered = computeSafetyNumberFromRawKeysV2(
      base64ToBuf(snAlice.myMldsaPubB64),
      base64ToBuf(snAlice.myMlkemPubB64!),
      base64ToBuf(tamperedBob.mldsaPubB64),
      fakeKem
    );
    assert.notEqual(snTampered.sha256Hex, snAlice.sha256Hex);
    assert.notEqual(snTampered.digits60, snAlice.digits60);

    // QR comparison validates v2 code matching local hex
    const qrMatch = parseAndCompareQrPayload(snAlice.qrPayload, snAlice.sha256Hex);
    assert.equal(qrMatch.status, 'MATCH');

    // QR comparison also supports backward-compatible v1 QR
    const v1Qr = `PQ-MPRBA-SAFETY-v1:${snAlice.sha256Hex}`;
    const qrV1Match = parseAndCompareQrPayload(v1Qr, snAlice.sha256Hex);
    assert.equal(qrV1Match.status, 'MATCH');
  });

  it('signs group epoch packets with distributor ML-DSA signature and validates signature integrity (H2)', async () => {
    const aliceBundleStr = (await ensureUserHybridKeyPair('alice'))!;
    const bobBundleStr = (await ensureUserHybridKeyPair('bob'))!;

    const aliceParsed = parsePeerKeyBundle(aliceBundleStr, 'alice');
    const bobParsed = parsePeerKeyBundle(bobBundleStr, 'bob');

    const bundles = { alice: aliceParsed, bob: bobParsed };
    const epoch = 3;
    const packet = await createGroupEpochPacket(bundles, 'alice', epoch);

    assert.ok(packet.distributorSigB64, 'Distributor ML-DSA signature must be present');
    assert.equal(packet.epoch, epoch);

    const members = Object.keys(bundles).sort();
    const signTarget = serializeEpochPacketForSigning(epoch, members, packet.keys);
    const sigBytes = base64ToBuf(packet.distributorSigB64);
    const mldsaPub = aliceParsed.mldsaPub!;

    // Valid signature must verify
    assert.equal(ml_dsa65.verify(sigBytes, signTarget, mldsaPub), true);

    // Tampered epoch fails verification
    const tamperedEpochTarget = serializeEpochPacketForSigning(epoch + 1, members, packet.keys);
    assert.equal(ml_dsa65.verify(sigBytes, tamperedEpochTarget, mldsaPub), false);

    // Tampered keys fail verification
    const tamperedKeys = { ...packet.keys, bob: 'AAAA' };
    const tamperedKeysTarget = serializeEpochPacketForSigning(epoch, members, tamperedKeys);
    assert.equal(ml_dsa65.verify(sigBytes, tamperedKeysTarget, mldsaPub), false);
  });
});
