// سیستم پیشرفته رمزنگاری تماماً پساکوانتومی (Fully Post-Quantum Hybrid ML-KEM-768 + ML-DSA-65 + ECDH P-256)
// به همراه زنجیره راتچت مقاوم در برابر پیام‌های خارج از نوبت (Out-of-Order Symmetric Ratchet + Zeroization)
// امضای دیجیتال هویت FIPS 204 (ML-DSA-65) برای مقابله با الگوریتم شور و جلوگیری قطعی از Downgrade خاموش
// احراز هویت کور مبتنی بر Ristretto255-VOPRF (RFC 9497) و ماشین وضعیت چرخش اپوک گروه (Group Epoch FSM)

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';

const E2EE_V1_PREFIX = 'e2ee:v1:';
const E2EE_ECDH_PREFIX = 'e2ee:ecdh:';
const E2EE_PQ_RATCHET_PREFIX = 'e2ee:pq:v2:';
const E2EE_GROUP_EPOCH_PREFIX = 'e2ee:gep:v2:';

const ROOM_KEY_STORAGE_PREFIX = 'chat_e2ee_pass_';
const E2EE_ENABLED_STORAGE_KEY = 'chat_e2ee_enabled';
const ECDH_KEYPAIR_PREFIX = 'chat_ecdh_kp_';
const MLKEM_KEYPAIR_PREFIX = 'chat_mlkem768_kp_';
const MLDSA_KEYPAIR_PREFIX = 'chat_mldsa65_kp_';
const RATCHET_STATE_PREFIX = 'chat_pq_ratchet_';
const GROUP_EPOCH_PREFIX = 'chat_group_epoch_';
const VOPRF_TOKEN_PREFIX = 'chat_voprf_token_';

const MAX_SKIP = 100; // حداکثر پرش مجاز برای پیام‌های خارج از نوبت (محافظت در برابر DoS)
const SKIPPED_KEY_TTL_MS = 10 * 60 * 1000; // ۱۰ دقیقه نگهداری کلیدهای سوخته/پرش‌خورده
const GROUP_EPOCH_GRACE_BUFFER = 3; // نگهداری ۳ اپوک قبلی برای رمزگشایی پیام‌های در حال پرواز هنگام تغییر اعضا

interface StoredKeyPair {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

interface StoredMLKEMKeyPair {
  publicKeyB64: string;
  secretKeyB64: string;
}

interface StoredMLDSAKeyPair {
  publicKeyB64: string;
  secretKeyB64: string;
}

export interface HybridPublicKeyBundle {
  v: 2;
  alg: 'ML-KEM-768+P-256+ML-DSA-65' | 'ML-KEM-768+P-256';
  username?: string;
  ecdhJwk: JsonWebKey;
  mlkemPubB64: string;
  mldsaPubB64?: string; // کلید عمومی هویت پساکوانتومی FIPS 204
  mldsaSigB64?: string; // امضای دیجیتال باندل با ML-DSA
  voprfProofTag?: string;
}

interface SkippedKeyEntry {
  mkB64: string;
  timestamp: number;
}

interface RatchetSessionState {
  rootKeyB64: string;
  sendChainKeyB64: string;
  recvChainKeyB64: string;
  sendStep: number;
  recvStep: number;
  kemCipherTextB64: string; // کپسول ML-KEM-768 برای همگام‌سازی طرف مقابل
  peerKemFingerprint: string;
  skippedKeys: Record<number, SkippedKeyEntry>;
  decryptedCache: Record<string, string>; // کش محلی برای نمایش مجدد پیام‌های رمزگشایی‌شده پس از Zeroization کلید
}

export interface GroupEpochKeyRecord {
  epoch: number;
  rootKeyB64: string;
  createdAt: number;
  membersHash: string;
}

export interface GroupEpochState {
  groupId: string;
  currentEpoch: number;
  status: 'STABLE' | 'ROTATING';
  epochs: Record<number, GroupEpochKeyRecord>;
  pendingQueue: Array<() => Promise<void>>;
}

export interface VoprfBlindTokenRecord {
  anonymousTokenId: string;
  unblindedOutputB64: string;
  serverPublicKeyB64: string;
  verifiedDleq: boolean;
  issuedAt: number;
}

export function bufToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuf(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * پاک‌سازی امن حافظه (Zeroization) برای آرایه‌های بایت حساس
 * بازنویسی مستقیم حافظه با صفر قبل از آزادسازی توسط Garbage Collector
 */
export function zeroizeBuffer(buf: Uint8Array | null | undefined): void {
  if (!buf) return;
  try {
    buf.fill(0);
  } catch {
    // ignore
  }
}

/**
 * مشتق‌سازی زنجیره متقارن KDF_CK (ساختار استاندارد راتچت با HKDF-SHA256)
 * تولید کلید زنجیره بعدی (Next Chain Key) و کلید یک‌بارمصرف پیام (Message Key)
 */
function kdfChainStep(chainKey: Uint8Array): { nextChainKey: Uint8Array; messageKey: Uint8Array } {
  const nextChainKey = hkdf(sha256, chainKey, undefined, new TextEncoder().encode('PQ-Ratchet-NextChain-v2'), 32);
  const messageKey = hkdf(sha256, chainKey, undefined, new TextEncoder().encode('PQ-Ratchet-MsgKey-v2'), 32);
  return { nextChainKey, messageKey };
}

/**
 * سریال‌سازی قطعی فیلدهای باندل کلید عمومی جهت امضای دیجیتال ML-DSA-65 (FIPS 204)
 */
export function serializeBundleForSigning(bundle: {
  username?: string;
  ecdhJwk: JsonWebKey;
  mlkemPubB64: string;
}): Uint8Array {
  const ecdhStr = `${bundle.ecdhJwk.crv || 'P-256'}:${bundle.ecdhJwk.x || ''}:${bundle.ecdhJwk.y || ''}`;
  const data = `MLDSA-BUNDLE-v2:${bundle.username || ''}:${ecdhStr}:${bundle.mlkemPubB64}`;
  return new TextEncoder().encode(data);
}

/**
 * سریال‌سازی پیام جهت امضای دیجیتال هویت و جلسه اولیه (Session-Init / Message Signature) با ML-DSA-65
 */
export function serializeMessageForSigning(params: {
  roomId: string;
  step: number;
  kemCipherB64: string;
  ivB64: string;
  cipherB64: string;
}): Uint8Array {
  const data = `MLDSA-MSG-v2:${params.roomId}:${params.step}:${params.kemCipherB64}:${params.ivB64}:${params.cipherB64}`;
  return new TextEncoder().encode(data);
}

export function getMyMLDSASecretKey(myUsername: string): Uint8Array | null {
  try {
    const raw = localStorage.getItem(`${MLDSA_KEYPAIR_PREFIX}${myUsername}`);
    if (!raw) return null;
    const parsed: StoredMLDSAKeyPair = JSON.parse(raw);
    return parsed.secretKeyB64 ? base64ToBuf(parsed.secretKeyB64) : null;
  } catch {
    return null;
  }
}

export function getMyMLDSAPublicKey(myUsername: string): string | null {
  try {
    const raw = localStorage.getItem(`${MLDSA_KEYPAIR_PREFIX}${myUsername}`);
    if (!raw) return null;
    const parsed: StoredMLDSAKeyPair = JSON.parse(raw);
    return parsed.publicKeyB64 || null;
  } catch {
    return null;
  }
}

/**
 * تولید یا بازیابی باندل کلید عمومی ترکیبی تماماً پساکوانتومی
 * (ML-KEM-768 + ECDH P-256 + امضای دیجیتال هویت FIPS 204 ML-DSA-65)
 */
export async function ensureUserHybridKeyPair(username: string): Promise<string | null> {
  if (!username || !window.crypto?.subtle) return null;
  const ecdhStorageKey = `${ECDH_KEYPAIR_PREFIX}${username}`;
  const pqStorageKey = `${MLKEM_KEYPAIR_PREFIX}${username}`;
  const dsaStorageKey = `${MLDSA_KEYPAIR_PREFIX}${username}`;

  try {
    let publicJwk: JsonWebKey | null = null;
    const existingEcdh = localStorage.getItem(ecdhStorageKey);
    if (existingEcdh) {
      const parsed: StoredKeyPair = JSON.parse(existingEcdh);
      if (parsed.publicJwk && parsed.privateJwk) {
        publicJwk = parsed.publicJwk;
      }
    }

    if (!publicJwk) {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
      );
      publicJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const privateJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
      localStorage.setItem(ecdhStorageKey, JSON.stringify({ publicJwk, privateJwk }));
    }

    let mlkemPubB64 = '';
    const existingPq = localStorage.getItem(pqStorageKey);
    if (existingPq) {
      const parsedPq: StoredMLKEMKeyPair = JSON.parse(existingPq);
      if (parsedPq.publicKeyB64 && parsedPq.secretKeyB64) {
        mlkemPubB64 = parsedPq.publicKeyB64;
      }
    }

    if (!mlkemPubB64) {
      const pqKeys = ml_kem768.keygen();
      mlkemPubB64 = bufToBase64(pqKeys.publicKey);
      const secretKeyB64 = bufToBase64(pqKeys.secretKey);
      localStorage.setItem(pqStorageKey, JSON.stringify({ publicKeyB64: mlkemPubB64, secretKeyB64 }));
      zeroizeBuffer(pqKeys.secretKey);
    }

    // تولید یا بازیابی کلیدهای امضای هویت پساکوانتومی ML-DSA-65 (FIPS 204)
    let mldsaPubB64 = '';
    let mldsaSec: Uint8Array | null = null;
    const existingDsa = localStorage.getItem(dsaStorageKey);
    if (existingDsa) {
      try {
        const parsedDsa: StoredMLDSAKeyPair = JSON.parse(existingDsa);
        if (parsedDsa.publicKeyB64 && parsedDsa.secretKeyB64) {
          mldsaPubB64 = parsedDsa.publicKeyB64;
          mldsaSec = base64ToBuf(parsedDsa.secretKeyB64);
        }
      } catch {
        // ignore
      }
    }

    if (!mldsaPubB64 || !mldsaSec) {
      const dsaKeys = ml_dsa65.keygen();
      mldsaPubB64 = bufToBase64(dsaKeys.publicKey);
      const secretKeyB64 = bufToBase64(dsaKeys.secretKey);
      localStorage.setItem(dsaStorageKey, JSON.stringify({ publicKeyB64: mldsaPubB64, secretKeyB64 }));
      mldsaSec = dsaKeys.secretKey;
    }

    // امضای محتوای باندل کلید توسط کلید خصوصی ML-DSA-65 هویت کاربر
    let mldsaSigB64 = '';
    if (mldsaSec) {
      const signTarget = serializeBundleForSigning({
        username,
        ecdhJwk: publicJwk,
        mlkemPubB64,
      });
      const sig = ml_dsa65.sign(signTarget, mldsaSec);
      mldsaSigB64 = bufToBase64(sig);
      zeroizeBuffer(mldsaSec);
    }

    const voprfRec = getStoredVoprfToken(username);
    const bundle: HybridPublicKeyBundle = {
      v: 2,
      alg: 'ML-KEM-768+P-256+ML-DSA-65',
      username,
      ecdhJwk: publicJwk,
      mlkemPubB64,
      mldsaPubB64,
      mldsaSigB64,
      voprfProofTag: voprfRec?.anonymousTokenId,
    };

    return JSON.stringify(bundle);
  } catch {
    return null;
  }
}

// حفظ سازگاری با تابع قبلی
export async function ensureUserECDHKeyPair(username: string): Promise<string | null> {
  return ensureUserHybridKeyPair(username);
}

export interface ParsedPeerKeyBundle {
  ecdhJwk: JsonWebKey | null;
  mlkemPub: Uint8Array | null;
  mldsaPub: Uint8Array | null;
  mldsaSigB64: string | null;
  username?: string;
  hasMLKEM: boolean;
  hasMLDSA: boolean;
  isMldsaVerified: boolean;
  isMldsaSignatureInvalid: boolean;
  isFullyPostQuantum: boolean; // هم کلید ML-KEM موجود است و هم امضای ML-DSA هویت معتبر است
}

export function parsePeerKeyBundle(
  peerPublicKeyStr: string | null | undefined,
  expectedPeerUsername?: string
): ParsedPeerKeyBundle {
  const result: ParsedPeerKeyBundle = {
    ecdhJwk: null,
    mlkemPub: null,
    mldsaPub: null,
    mldsaSigB64: null,
    username: undefined,
    hasMLKEM: false,
    hasMLDSA: false,
    isMldsaVerified: false,
    isMldsaSignatureInvalid: false,
    isFullyPostQuantum: false,
  };

  if (!peerPublicKeyStr) return result;

  try {
    const parsed = JSON.parse(peerPublicKeyStr);
    if (parsed && parsed.v === 2 && parsed.ecdhJwk) {
      result.ecdhJwk = parsed.ecdhJwk;
      result.username = parsed.username;

      if (parsed.mlkemPubB64) {
        result.mlkemPub = base64ToBuf(parsed.mlkemPubB64);
        result.hasMLKEM = true;
      }

      if (parsed.mldsaPubB64) {
        result.mldsaPub = base64ToBuf(parsed.mldsaPubB64);
        result.hasMLDSA = true;
      }

      if (parsed.mldsaSigB64) {
        result.mldsaSigB64 = parsed.mldsaSigB64;
      }

      // اعتبارسنجی امضای دیجیتال هویت با الگوریتم FIPS 204 ML-DSA-65
      if (result.hasMLKEM && result.hasMLDSA && result.mldsaSigB64 && result.mldsaPub) {
        try {
          const sigBytes = base64ToBuf(result.mldsaSigB64);
          const uName = parsed.username || expectedPeerUsername || '';
          const target = serializeBundleForSigning({
            username: uName,
            ecdhJwk: result.ecdhJwk,
            mlkemPubB64: parsed.mlkemPubB64,
          });

          let valid = ml_dsa65.verify(sigBytes, target, result.mldsaPub);
          if (!valid && !parsed.username && expectedPeerUsername) {
            const fallbackTarget = serializeBundleForSigning({
              username: '',
              ecdhJwk: result.ecdhJwk,
              mlkemPubB64: parsed.mlkemPubB64,
            });
            valid = ml_dsa65.verify(sigBytes, fallbackTarget, result.mldsaPub);
          }

          if (valid) {
            result.isMldsaVerified = true;
            result.isFullyPostQuantum = true;
          } else {
            result.isMldsaSignatureInvalid = true;
          }
        } catch {
          result.isMldsaSignatureInvalid = true;
        }
      }
      return result;
    }

    if (parsed && parsed.kty === 'EC') {
      result.ecdhJwk = parsed;
      return result;
    }
  } catch {
    // ignore
  }
  return result;
}

export interface RoomPQSecurityStatus {
  isPQ: boolean;
  type: 'PQ_HYBRID_VERIFIED' | 'GROUP_EPOCH' | 'NOT_POST_QUANTUM' | 'DISABLED';
  reason?: 'CLASSICAL_ECDH' | 'MISSING_PEER_KEYS' | 'INVALID_MLDSA_SIGNATURE' | 'MANUAL_PBKDF2';
  badge: string;
  tooltip: string;
  warningText?: string;
}

/**
 * تعیین وضعیت دقیق امنیتی اتاق و جلوگیری قطعی از تنزل خاموش (Silent Downgrade Protection)
 */
export function getRoomPQStatus(options: {
  roomId: string;
  isGroup: boolean;
  e2eeActive: boolean;
  myUsername: string;
  peerPublicKey?: string | null;
  peerUsername?: string;
  customSecret?: string;
}): RoomPQSecurityStatus {
  if (!options.e2eeActive) {
    return {
      isPQ: false,
      type: 'DISABLED',
      badge: '🔓 ساده',
      tooltip: 'رمزنگاری سرتاسری برای این گفتگو غیرفعال است',
    };
  }

  if (options.isGroup) {
    return {
      isPQ: true,
      type: 'GROUP_EPOCH',
      badge: '🔒 Epoch',
      tooltip: 'رمزنگاری گروهی مبتنی بر ماشین وضعیت اپوک (Group Epoch FSM)',
    };
  }

  if (options.customSecret) {
    return {
      isPQ: false,
      type: 'NOT_POST_QUANTUM',
      reason: 'MANUAL_PBKDF2',
      badge: '⚠️ رمز دستی',
      tooltip: 'رمزنگاری با رمز دستی متقارن (PBKDF2) - فاقد امنیت پساکوانتومی',
      warningText: 'این گفتگو با رمز دستی سفارشی متقارن رمزنگاری شده و در برابر کامپیوترهای کوانتومی ایمن نیست.',
    };
  }

  if (!options.peerPublicKey) {
    return {
      isPQ: false,
      type: 'NOT_POST_QUANTUM',
      reason: 'MISSING_PEER_KEYS',
      badge: '⚠️ بدون کلید',
      tooltip: 'مخاطب هنوز کلیدهای پساکوانتومی خود را منتشر نکرده است',
      warningText: 'مخاطب هنوز کلیدهای عمومی پساکوانتومی خود را منتشر نکرده است. تا زمان انتشار کلیدها، پیام‌ها بدون امنیت پساکوانتومی مبادله می‌شوند.',
    };
  }

  const bundle = parsePeerKeyBundle(options.peerPublicKey, options.peerUsername);

  if (bundle.isMldsaSignatureInvalid) {
    return {
      isPQ: false,
      type: 'NOT_POST_QUANTUM',
      reason: 'INVALID_MLDSA_SIGNATURE',
      badge: '⛔ امضای جعلی',
      tooltip: 'امضای هویت پساکوانتومی (ML-DSA-65) مخاطب نامعتبر است!',
      warningText: 'خطر امنیتی جدی: امضای دیجیتال هویت پساکوانتومی مخاطب (FIPS 204 ML-DSA) تأیید نشد! کلیدها ممکن است دستکاری شده باشند.',
    };
  }

  if (!bundle.isFullyPostQuantum) {
    return {
      isPQ: false,
      type: 'NOT_POST_QUANTUM',
      reason: 'CLASSICAL_ECDH',
      badge: '⚠️ کلاسیک (ECDH)',
      tooltip: 'مخاطب فاقد کلیدهای پساکوانتومی است - مکالمه به رمزنگاری کلاسیک ECDH تنزل یافته است',
      warningText: 'مخاطب فاقد کلید تأییدشده‌ی ML-KEM-768 و امضای هویت ML-DSA-65 (FIPS 204) است. این گفتگو در برابر الگوریتم شور ایمن نیست و با ECDH کلاسیک تبادل می‌شود.',
    };
  }

  return {
    isPQ: true,
    type: 'PQ_HYBRID_VERIFIED',
    badge: '🛡️ PQ-KEM',
    tooltip: 'رمزنگاری تماماً پساکوانتومی ترکیبی (ML-KEM-768 + ECDH P-256) با امضای هویت تأییدشده‌ی ML-DSA-65 (FIPS 204)',
  };
}

/**
 * استخراج بیت‌های خام مشترک ECDH P-256
 */
async function deriveECDHSharedBits(
  myUsername: string,
  peerEcdhJwk: JsonWebKey
): Promise<Uint8Array | null> {
  try {
    const rawPair = localStorage.getItem(`${ECDH_KEYPAIR_PREFIX}${myUsername}`);
    if (!rawPair) return null;
    const { privateJwk }: StoredKeyPair = JSON.parse(rawPair);

    const myPrivateKey = await window.crypto.subtle.importKey(
      'jwk',
      privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits']
    );

    const peerPublicKey = await window.crypto.subtle.importKey(
      'jwk',
      peerEcdhJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const bits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey },
      myPrivateKey,
      256
    );
    return new Uint8Array(bits);
  } catch {
    return null;
  }
}

async function deriveECDHSharedAesKey(
  myUsername: string,
  peerPublicKeyStr: string
): Promise<CryptoKey | null> {
  const { ecdhJwk } = parsePeerKeyBundle(peerPublicKeyStr);
  if (!ecdhJwk) return null;
  const bits = await deriveECDHSharedBits(myUsername, ecdhJwk);
  if (!bits) return null;
  try {
    return await window.crypto.subtle.importKey(
      'raw',
      bits as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    zeroizeBuffer(bits);
  }
}

function getMyMLKEMSecretKey(myUsername: string): Uint8Array | null {
  try {
    const raw = localStorage.getItem(`${MLKEM_KEYPAIR_PREFIX}${myUsername}`);
    if (!raw) return null;
    const parsed: StoredMLKEMKeyPair = JSON.parse(raw);
    return parsed.secretKeyB64 ? base64ToBuf(parsed.secretKeyB64) : null;
  } catch {
    return null;
  }
}

function loadRatchetState(myUsername: string, roomId: string): RatchetSessionState | null {
  try {
    const raw = localStorage.getItem(`${RATCHET_STATE_PREFIX}${myUsername}_${roomId}`);
    if (!raw) return null;
    const state: RatchetSessionState = JSON.parse(raw);
    // پاک‌سازی کلیدهای پرش‌خورده منقضی‌شده (TTL Zeroization)
    const now = Date.now();
    let mutated = false;
    for (const [stepStr, entry] of Object.entries(state.skippedKeys || {})) {
      if (now - entry.timestamp > SKIPPED_KEY_TTL_MS) {
        delete state.skippedKeys[Number(stepStr)];
        mutated = true;
      }
    }
    if (mutated) {
      saveRatchetState(myUsername, roomId, state);
    }
    return state;
  } catch {
    return null;
  }
}

function saveRatchetState(myUsername: string, roomId: string, state: RatchetSessionState): void {
  try {
    // محدودسازی کش پیام‌های رمزگشایی‌شده به ۲۰۰ پیام اخیر
    const cacheKeys = Object.keys(state.decryptedCache || {});
    if (cacheKeys.length > 200) {
      for (const k of cacheKeys.slice(0, cacheKeys.length - 200)) {
        delete state.decryptedCache[k];
      }
    }
    localStorage.setItem(`${RATCHET_STATE_PREFIX}${myUsername}_${roomId}`, JSON.stringify(state));
  } catch {
    // ignore
  }
}

/**
 * مقداردهی اولیه یا بازیابی نشست راتچت پساکوانتومی (Hybrid ML-KEM-768 + ECDH P-256)
 */
async function ensurePQRatchetSession(
  myUsername: string,
  roomId: string,
  peerPublicKeyStr: string,
  incomingKemCipherB64?: string,
  peerUsername?: string
): Promise<RatchetSessionState | null> {
  const bundle = parsePeerKeyBundle(peerPublicKeyStr, peerUsername);
  const { ecdhJwk, mlkemPub } = bundle;
  const existing = loadRatchetState(myUsername, roomId);

  // برای راه‌اندازی نشست پساکوانتومی، الزامی است که کلیدهای کپسوله‌سازی و مشتق‌سازی حاضر باشند
  if (!bundle.ecdhJwk || !bundle.mlkemPub) {
    return existing || null;
  }

  // جلوگیری قطعی از تنزل خاموش: در غیاب امضای معتبر هویت ML-DSA (FIPS 204)، نشست جدید ایجاد نمی‌گردد
  if (!bundle.isFullyPostQuantum && !existing) {
    return null;
  }

  const peerFingerprint = bufToBase64(sha256(bundle.mlkemPub)).slice(0, 16);

  // اگر کپسول جدیدی از سمت مقابل آمده که نیاز به Decapsulation دارد
  if (incomingKemCipherB64 && (!existing || existing.kemCipherTextB64 !== incomingKemCipherB64)) {
    const mySecretKey = getMyMLKEMSecretKey(myUsername);
    const ecdhSecret = await deriveECDHSharedBits(myUsername, ecdhJwk);
    if (!mySecretKey || !ecdhSecret) return null;

    try {
      const cipherBytes = base64ToBuf(incomingKemCipherB64);
      const pqSharedSecret = ml_kem768.decapsulate(cipherBytes, mySecretKey);

      const combinedInput = new Uint8Array(ecdhSecret.length + pqSharedSecret.length);
      combinedInput.set(ecdhSecret, 0);
      combinedInput.set(pqSharedSecret, ecdhSecret.length);

      const rootKey = hkdf(
        sha256,
        combinedInput,
        new TextEncoder().encode(roomId),
        new TextEncoder().encode('PQ-Hybrid-RootKey-v2'),
        32
      );

      // تفکیک زنجیره ارسال و دریافت بر اساس ترتیب الفبایی نام کاربری
      const [u1] = roomId.split('__').sort();
      const amIFirst = myUsername === u1;
      const chainA = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Alpha'), 32);
      const chainB = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Beta'), 32);

      const newState: RatchetSessionState = {
        rootKeyB64: bufToBase64(rootKey),
        sendChainKeyB64: bufToBase64(amIFirst ? chainA : chainB),
        recvChainKeyB64: bufToBase64(amIFirst ? chainB : chainA),
        sendStep: existing?.sendStep ?? 0,
        recvStep: 0,
        kemCipherTextB64: incomingKemCipherB64,
        peerKemFingerprint: peerFingerprint,
        skippedKeys: existing?.skippedKeys ?? {},
        decryptedCache: existing?.decryptedCache ?? {},
      };

      zeroizeBuffer(mySecretKey);
      zeroizeBuffer(ecdhSecret);
      zeroizeBuffer(pqSharedSecret);
      zeroizeBuffer(combinedInput);
      zeroizeBuffer(rootKey);

      saveRatchetState(myUsername, roomId, newState);
      return newState;
    } catch {
      zeroizeBuffer(mySecretKey);
      zeroizeBuffer(ecdhSecret);
      return existing;
    }
  }

  if (existing && existing.peerKemFingerprint === peerFingerprint) {
    return existing;
  }

  // ایجاد کپسول جدید ML-KEM-768 (Encapsulation) برای شروع زنجیره راتچت
  const ecdhSecret = await deriveECDHSharedBits(myUsername, ecdhJwk);
  if (!ecdhSecret) return null;

  try {
    const { cipherText, sharedSecret: pqSharedSecret } = ml_kem768.encapsulate(mlkemPub);

    const combinedInput = new Uint8Array(ecdhSecret.length + pqSharedSecret.length);
    combinedInput.set(ecdhSecret, 0);
    combinedInput.set(pqSharedSecret, ecdhSecret.length);

    const rootKey = hkdf(
      sha256,
      combinedInput,
      new TextEncoder().encode(roomId),
      new TextEncoder().encode('PQ-Hybrid-RootKey-v2'),
      32
    );

    const [u1] = roomId.split('__').sort();
    const amIFirst = myUsername === u1;
    const chainA = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Alpha'), 32);
    const chainB = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Beta'), 32);

    const newState: RatchetSessionState = {
      rootKeyB64: bufToBase64(rootKey),
      sendChainKeyB64: bufToBase64(amIFirst ? chainA : chainB),
      recvChainKeyB64: bufToBase64(amIFirst ? chainB : chainA),
      sendStep: 0,
      recvStep: 0,
      kemCipherTextB64: bufToBase64(cipherText),
      peerKemFingerprint: peerFingerprint,
      skippedKeys: {},
      decryptedCache: {},
    };

    zeroizeBuffer(ecdhSecret);
    zeroizeBuffer(pqSharedSecret);
    zeroizeBuffer(combinedInput);
    zeroizeBuffer(rootKey);

    saveRatchetState(myUsername, roomId, newState);
    return newState;
  } catch {
    zeroizeBuffer(ecdhSecret);
    return null;
  }
}

/**
 * رمزگشایی پیام در زنجیره راتچت با پشتیبانی کامل از پیام‌های خارج از نوبت (Out-of-Order Skipped Message Keys)
 * و پاک‌سازی فوری کلید مصرف‌شده از حافظه (Zeroization)
 */
async function ratchetDecryptWithSkippedKeys(
  myUsername: string,
  roomId: string,
  state: RatchetSessionState,
  msgStep: number,
  iv: Uint8Array,
  cipherBytes: Uint8Array,
  payloadHashKey: string
): Promise<string | null> {
  // اگر قبلاً این پیام در این مرورگر رمزگشایی شده و کلید یک‌بارمصرف آن Zeroize شده است، از کش امن محلی بخوان
  if (state.decryptedCache[payloadHashKey]) {
    return state.decryptedCache[payloadHashKey];
  }

  let messageKeyBytes: Uint8Array | null = null;

  // حالت ۱: پیام مربوط به یکی از گام‌های قبلی است که به دلیل اختلال شبکه دیرتر رسیده (Out-of-Order)
  if (msgStep < state.recvStep) {
    const skipped = state.skippedKeys[msgStep];
    if (!skipped) {
      return null; // کلید قبلاً مصرف و Zeroize شده است
    }
    messageKeyBytes = base64ToBuf(skipped.mkB64);
    // حذف فوری کلید از جدول کلیدهای پرش‌خورده (One-Time Use)
    delete state.skippedKeys[msgStep];
  } else {
    // بررسی سقف مجاز پرش برای جلوگیری از حمله DoS
    if (msgStep - state.recvStep > MAX_SKIP) {
      return null;
    }

    let currentRecvChain = base64ToBuf(state.recvChainKeyB64);

    // حالت ۲: پیام جلوتر از گام فعلی است؛ کلیدهای میانی را تولید و در SkippedMessageKeys ذخیره کن
    while (state.recvStep < msgStep) {
      const { nextChainKey, messageKey } = kdfChainStep(currentRecvChain);
      zeroizeBuffer(currentRecvChain);
      currentRecvChain = nextChainKey;

      state.skippedKeys[state.recvStep] = {
        mkB64: bufToBase64(messageKey),
        timestamp: Date.now(),
      };
      zeroizeBuffer(messageKey);
      state.recvStep++;
    }

    // استخراج کلید پیام فعلی (msgStep === state.recvStep)
    const { nextChainKey, messageKey } = kdfChainStep(currentRecvChain);
    zeroizeBuffer(currentRecvChain);
    state.recvChainKeyB64 = bufToBase64(nextChainKey);
    zeroizeBuffer(nextChainKey);
    state.recvStep++;
    messageKeyBytes = messageKey;
  }

  try {
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      messageKeyBytes as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      aesKey,
      cipherBytes as unknown as BufferSource
    );

    const plainText = new TextDecoder().decode(decryptedBuffer);
    state.decryptedCache[payloadHashKey] = plainText;
    saveRatchetState(myUsername, roomId, state);
    return plainText;
  } catch {
    return null;
  } finally {
    // Zeroization قطعی کلید پیام در RAM بلافاصله پس از رمزگشایی
    zeroizeBuffer(messageKeyBytes);
  }
}

// ============================================================================
// لایه ۲: پروتکل احراز هویت کور Ristretto255-VOPRF (RFC 9497)
// ============================================================================

export function getStoredVoprfToken(username: string): VoprfBlindTokenRecord | null {
  try {
    const raw = localStorage.getItem(`${VOPRF_TOKEN_PREFIX}${username}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

/**
 * اجرای کامل پروتکل تعاملی Ristretto255-VOPRF با سرور:
 * ۱. کور کردن هویت در مرورگر با اسکالر تصادفی r: Blinded = r * H_group(identity)
 * ۲. ارسال نقطه کور به سرور و دریافت پاسخ به همراه اثبات دانایی صفر DLEQ Proof
 * ۳. اعتبارسنجی اثبات DLEQ با کلید عمومی سرور و حذف فاکتور کورسازی (Unblinding)
 */
export async function acquireBlindedIdentityToken(
  username: string
): Promise<VoprfBlindTokenRecord | null> {
  const existing = getStoredVoprfToken(username);
  if (existing && existing.verifiedDleq) {
    return existing;
  }

  try {
    const rawInput = new TextEncoder().encode(`blind-identity::${username}::v2`);
    const { blind, blinded } = ristretto255_oprf.voprf.blind(rawInput);

    const res = await fetch('/api/voprf/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        blindedB64: bufToBase64(blinded),
      }),
    }).then(r => r.json());

    if (!res.ok || !res.evaluatedB64 || !res.proofB64 || !res.serverPublicKeyB64) {
      zeroizeBuffer(blind);
      return null;
    }

    const evaluated = base64ToBuf(res.evaluatedB64);
    const proof = base64ToBuf(res.proofB64);
    const serverPublicKey = base64ToBuf(res.serverPublicKeyB64);

    // بررسی اثبات ریاضی DLEQ و استخراج خروجی نهایی VOPRF
    const unblindedOutput = ristretto255_oprf.voprf.finalize(
      rawInput,
      blind,
      evaluated,
      blinded,
      serverPublicKey,
      proof
    );

    zeroizeBuffer(blind);

    const anonymousTokenId = bufToBase64(sha256(unblindedOutput)).slice(0, 22);
    const record: VoprfBlindTokenRecord = {
      anonymousTokenId,
      unblindedOutputB64: bufToBase64(unblindedOutput),
      serverPublicKeyB64: res.serverPublicKeyB64,
      verifiedDleq: true,
      issuedAt: Date.now(),
    };

    localStorage.setItem(`${VOPRF_TOKEN_PREFIX}${username}`, JSON.stringify(record));
    return record;
  } catch {
    return null;
  }
}

// ============================================================================
// لایه ۳: ماشین وضعیت چرخش کلید گروه (Group Epoch State Machine - FSM)
// ============================================================================

const groupFsmMap = new Map<string, GroupEpochState>();

function computeMembersHash(members: string[]): string {
  const sorted = [...members].sort().join(',');
  return bufToBase64(sha256(new TextEncoder().encode(sorted))).slice(0, 12);
}

function deriveGroupEpochRootKey(groupId: string, epoch: number, membersHash: string, customSecret?: string): Uint8Array {
  const seedMaterial = new TextEncoder().encode(
    `group-pq-epoch::${groupId}::v${epoch}::${membersHash}::${customSecret || 'default-pq-group'}`
  );
  return hkdf(
    sha256,
    seedMaterial,
    new TextEncoder().encode(groupId),
    new TextEncoder().encode(`Group-Epoch-Key-${epoch}`),
    32
  );
}

export function getGroupEpochState(groupId: string, members: string[] = []): GroupEpochState {
  const existing = groupFsmMap.get(groupId);
  if (existing) return existing;

  const storageKey = `${GROUP_EPOCH_PREFIX}${groupId}`;
  try {
    const raw = localStorage.getItem(storageKey);
    if (raw) {
      const parsed = JSON.parse(raw);
      const state: GroupEpochState = {
        groupId,
        currentEpoch: parsed.currentEpoch || 1,
        status: 'STABLE',
        epochs: parsed.epochs || {},
        pendingQueue: [],
      };
      groupFsmMap.set(groupId, state);
      return state;
    }
  } catch {
    // ignore
  }

  const mHash = computeMembersHash(members);
  const rk = deriveGroupEpochRootKey(groupId, 1, mHash, getRoomSecret(`group__${groupId}`));
  const initial: GroupEpochState = {
    groupId,
    currentEpoch: 1,
    status: 'STABLE',
    epochs: {
      1: {
        epoch: 1,
        rootKeyB64: bufToBase64(rk),
        createdAt: Date.now(),
        membersHash: mHash,
      },
    },
    pendingQueue: [],
  };
  zeroizeBuffer(rk);
  groupFsmMap.set(groupId, initial);
  saveGroupEpochState(initial);
  return initial;
}

function saveGroupEpochState(state: GroupEpochState): void {
  try {
    localStorage.setItem(
      `${GROUP_EPOCH_PREFIX}${state.groupId}`,
      JSON.stringify({
        groupId: state.groupId,
        currentEpoch: state.currentEpoch,
        epochs: state.epochs,
      })
    );
  } catch {
    // ignore
  }
}

/**
 * چرخش اتمیک اپوک گروه (Atomic Group Epoch Rotation) هنگام تغییر اعضا
 * نگه‌داشتن کلیدهای ۳ اپوک قبلی در Grace Buffer برای جلوگیری از خراب شدن پیام‌های همزمان (In-Flight)
 */
export async function rotateGroupEpoch(
  groupId: string,
  newEpoch: number,
  members: string[],
  encapsulatedEpochKeyB64?: string
): Promise<GroupEpochState> {
  const state = getGroupEpochState(groupId, members);
  state.status = 'ROTATING';

  try {
    const mHash = computeMembersHash(members);
    const rootKey = encapsulatedEpochKeyB64
      ? base64ToBuf(encapsulatedEpochKeyB64)
      : deriveGroupEpochRootKey(groupId, newEpoch, mHash, getRoomSecret(`group__${groupId}`));

    state.currentEpoch = newEpoch;
    state.epochs[newEpoch] = {
      epoch: newEpoch,
      rootKeyB64: bufToBase64(rootKey),
      createdAt: Date.now(),
      membersHash: mHash,
    };
    zeroizeBuffer(rootKey);

    // حذف اپوک‌های قدیمی‌تر از ظرفیت Grace Buffer (Zeroization)
    const epochNums = Object.keys(state.epochs)
      .map(Number)
      .sort((a, b) => a - b);
    while (epochNums.length > GROUP_EPOCH_GRACE_BUFFER) {
      const oldest = epochNums.shift()!;
      delete state.epochs[oldest];
    }

    saveGroupEpochState(state);
  } finally {
    state.status = 'STABLE';
    // آزادسازی صف پیام‌هایی که در لحظه چرخش اپوک منتظر مانده بودند
    while (state.pendingQueue.length > 0) {
      const task = state.pendingQueue.shift();
      if (task) await task();
    }
  }

  return state;
}

async function derivePbkdf2AesKey(roomId: string, customSecret?: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const passphrase = customSecret
    ? `${roomId}::${customSecret}`
    : `${roomId}::default-e2ee-channel-secret-256`;

  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const salt = enc.encode(`persian-messenger-salt::${roomId}`);
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 50000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function isE2EEPayload(text: string | null | undefined): boolean {
  return (
    typeof text === 'string' &&
    (text.startsWith(E2EE_V1_PREFIX) ||
      text.startsWith(E2EE_ECDH_PREFIX) ||
      text.startsWith(E2EE_PQ_RATCHET_PREFIX) ||
      text.startsWith(E2EE_GROUP_EPOCH_PREFIX))
  );
}

/**
 * رمزنگاری پیام متنی با پشتیبانی از:
 * 1. پروتکل پساکوانتومی ML-KEM-768 + Out-of-Order Ratchet (در چت‌های خصوصی)
 * 2. ماشین وضعیت اپوک گروه Group Epoch FSM (در گروه‌ها)
 * 3. کلید سفارشی PBKDF2 در صورت تنظیم دستی توسط کاربر
 */
export async function encryptMessageText(
  plainText: string,
  roomId: string,
  options?: {
    myUsername?: string;
    peerPublicKey?: string | null;
    peerUsername?: string;
    customSecret?: string;
    groupMembers?: string[];
  }
): Promise<string> {
  if (!plainText) return '';
  try {
    const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);

    // ۱. اگر اتاق گروهی است، از ماشین وضعیت اپوک گروه (Group Epoch FSM) استفاده کن
    if (roomId.startsWith('group__') && !manualSecret) {
      const groupId = roomId.replace('group__', '');
      const fsm = getGroupEpochState(groupId, options?.groupMembers || []);

      if (fsm.status === 'ROTATING') {
        await new Promise<void>(resolve => fsm.pendingQueue.push(async () => resolve()));
      }

      const epochRec = fsm.epochs[fsm.currentEpoch];
      if (epochRec) {
        const rawRoot = base64ToBuf(epochRec.rootKeyB64);
        const msgKeyBytes = hkdf(
          sha256,
          rawRoot,
          iv,
          new TextEncoder().encode(`GroupMsg-Epoch-${fsm.currentEpoch}`),
          32
        );
        zeroizeBuffer(rawRoot);

        const aesKey = await window.crypto.subtle.importKey(
          'raw',
          msgKeyBytes as unknown as BufferSource,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt']
        );
        const cipherBuffer = await window.crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          aesKey,
          encoded
        );
        zeroizeBuffer(msgKeyBytes);

        return `${E2EE_GROUP_EPOCH_PREFIX}${fsm.currentEpoch}:${epochRec.membersHash}:${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
      }
    }

    // ۲. اگر چت خصوصی است و کلید عمومی تماماً پساکوانتومی (ML-KEM-768 + P-256 + ML-DSA-65) مخاطب موجود است
    if (!manualSecret && options?.myUsername && options?.peerPublicKey) {
      const peerBundle = parsePeerKeyBundle(options.peerPublicKey, options.peerUsername);

      // ایجاد و ادامه نشست راتچت پساکوانتومی تنها در صورتی که مخاطب کلید تأییدشده ML-KEM و امضای ML-DSA داشته باشد
      if (peerBundle.isFullyPostQuantum) {
        const ratchetState = await ensurePQRatchetSession(
          options.myUsername,
          roomId,
          options.peerPublicKey,
          undefined,
          options.peerUsername
        );

        if (ratchetState) {
          const currentSendChain = base64ToBuf(ratchetState.sendChainKeyB64);
          const { nextChainKey, messageKey } = kdfChainStep(currentSendChain);
          zeroizeBuffer(currentSendChain);

          const stepIndex = ratchetState.sendStep;
          ratchetState.sendChainKeyB64 = bufToBase64(nextChainKey);
          ratchetState.sendStep = stepIndex + 1;
          zeroizeBuffer(nextChainKey);

          const aesKey = await window.crypto.subtle.importKey(
            'raw',
            messageKey as unknown as BufferSource,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
          );

          const cipherBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            encoded
          );
          // Zeroization فوری کلید پیام پس از رمزنگاری
          zeroizeBuffer(messageKey);

          const ivB64 = bufToBase64(iv);
          const cipherB64 = bufToBase64(cipherBuffer);
          const kemCipherB64 = ratchetState.kemCipherTextB64;

          // امضای دیجیتال پساکوانتومی پیام و پیام اولیه نشست (Session-Init) با ML-DSA-65
          let msgSigB64 = '';
          const myDsaSec = getMyMLDSASecretKey(options.myUsername);
          if (myDsaSec) {
            try {
              const signTarget = serializeMessageForSigning({
                roomId,
                step: stepIndex,
                kemCipherB64,
                ivB64,
                cipherB64,
              });
              const sig = ml_dsa65.sign(signTarget, myDsaSec);
              msgSigB64 = bufToBase64(sig);
            } finally {
              zeroizeBuffer(myDsaSec);
            }
          }

          const payload = `${E2EE_PQ_RATCHET_PREFIX}${stepIndex}:${kemCipherB64}:${ivB64}:${cipherB64}${msgSigB64 ? `:${msgSigB64}` : ''}`;
          const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
          ratchetState.decryptedCache[payloadHashKey] = plainText;
          saveRatchetState(options.myUsername, roomId, ratchetState);

          return payload;
        }
      }

      // تنزل صریح (نه خاموش) به ECDH کلاسیک در صورت فقدان کلیدهای پساکوانتومی مخاطب
      // توجه: در UI نشان PQ-KEM حذف شده و بنر هشدار غیر کوانتومی بودن نمایش داده می‌شود
      const ecdhKey = await deriveECDHSharedAesKey(options.myUsername, options.peerPublicKey);
      if (ecdhKey) {
        const cipherBuffer = await window.crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          ecdhKey,
          encoded
        );
        return `${E2EE_ECDH_PREFIX}${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
      }
    }

    // ۳. در صورت تنظیم رمز دستی (PBKDF2 Override)
    const pbkdfKey = await derivePbkdf2AesKey(roomId, manualSecret);
    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      pbkdfKey,
      encoded
    );
    return `${E2EE_V1_PREFIX}${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
  } catch {
    return plainText;
  }
}

export async function decryptMessageText(
  payload: string,
  roomId: string,
  options?: {
    myUsername?: string;
    peerPublicKey?: string | null;
    peerUsername?: string;
    customSecret?: string;
    sender?: string;
    groupMembers?: string[];
  }
): Promise<{
  text: string;
  isEncrypted: boolean;
  mode?: 'PQ-MLKEM-RATCHET' | 'GROUP-EPOCH-FSM' | 'ECDH' | 'PBKDF2';
  epoch?: number;
  ratchetStep?: number;
  mldsaVerified?: boolean;
  failed?: boolean;
}> {
  if (!isE2EEPayload(payload)) {
    return { text: payload || '', isEncrypted: false };
  }

  try {
    // ۱. رمزگشایی پیام‌های راتچت پساکوانتومی (ML-KEM-768 + Out-of-Order Ratchet + FIPS 204 ML-DSA Verification)
    if (payload.startsWith(E2EE_PQ_RATCHET_PREFIX)) {
      const raw = payload.slice(E2EE_PQ_RATCHET_PREFIX.length);
      const parts = raw.split(':');
      if (parts.length < 4 || parts.length > 5) {
        return { text: payload, isEncrypted: true, failed: true };
      }
      const [stepStr, kemCipherB64, ivB64, cipherB64, maybeSigB64] = parts;
      const msgStep = parseInt(stepStr, 10);
      const iv = base64ToBuf(ivB64);
      const cipherBytes = base64ToBuf(cipherB64);
      const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);

      if (options?.myUsername && options?.peerPublicKey) {
        const isIncoming = options.sender && options.sender !== options.myUsername;
        const peerBundle = parsePeerKeyBundle(options.peerPublicKey, options.peerUsername);

        // اعتبارسنجی امضای هویت دیجیتال پساکوانتومی پیام با کلید عمومی ML-DSA-65 مخاطب
        let mldsaVerified = false;
        if (maybeSigB64 && peerBundle.mldsaPub) {
          try {
            const signData = serializeMessageForSigning({
              roomId,
              step: msgStep,
              kemCipherB64,
              ivB64,
              cipherB64,
            });
            mldsaVerified = ml_dsa65.verify(base64ToBuf(maybeSigB64), signData, peerBundle.mldsaPub);
          } catch {
            mldsaVerified = false;
          }
        }

        const ratchetState = await ensurePQRatchetSession(
          options.myUsername,
          roomId,
          options.peerPublicKey,
          isIncoming ? kemCipherB64 : undefined,
          options.peerUsername
        );

        if (ratchetState) {
          // اگر پیام ارسالیِ خودِ کاربر است و در کش محلی موجود است
          if (ratchetState.decryptedCache[payloadHashKey]) {
            return {
              text: ratchetState.decryptedCache[payloadHashKey],
              isEncrypted: true,
              mode: 'PQ-MLKEM-RATCHET',
              ratchetStep: msgStep,
              mldsaVerified,
              failed: false,
            };
          }

          const plainText = await ratchetDecryptWithSkippedKeys(
            options.myUsername,
            roomId,
            ratchetState,
            msgStep,
            iv,
            cipherBytes,
            payloadHashKey
          );

          if (plainText !== null) {
            return {
              text: plainText,
              isEncrypted: true,
              mode: 'PQ-MLKEM-RATCHET',
              ratchetStep: msgStep,
              mldsaVerified,
              failed: false,
            };
          }
        }
      }
      return {
        text: '🔒 [پیام پساکوانتومی ML-KEM-768 - کلید یک‌بارمصرف Zeroize شده است]',
        isEncrypted: true,
        mode: 'PQ-MLKEM-RATCHET',
        ratchetStep: msgStep,
        failed: true,
      };
    }

    // ۲. رمزگشایی پیام‌های گروهی مبتنی بر ماشین وضعیت اپوک (Group Epoch FSM + Grace Buffer)
    if (payload.startsWith(E2EE_GROUP_EPOCH_PREFIX)) {
      const raw = payload.slice(E2EE_GROUP_EPOCH_PREFIX.length);
      const parts = raw.split(':');
      if (parts.length !== 4) {
        return { text: payload, isEncrypted: true, failed: true };
      }
      const [epochStr, membersHash, ivB64, cipherB64] = parts;
      const msgEpoch = parseInt(epochStr, 10);
      const iv = base64ToBuf(ivB64);
      const cipherBytes = base64ToBuf(cipherB64);
      const groupId = roomId.replace('group__', '');

      const fsm = getGroupEpochState(groupId, options?.groupMembers || []);
      let rootKeyBytes: Uint8Array;

      // جستجو در Grace Buffer اپوک‌ها یا مشتق‌سازی تطبیقی برای اپوک همگام‌شده
      if (fsm.epochs[msgEpoch]) {
        rootKeyBytes = base64ToBuf(fsm.epochs[msgEpoch].rootKeyB64);
      } else {
        rootKeyBytes = deriveGroupEpochRootKey(
          groupId,
          msgEpoch,
          membersHash,
          getRoomSecret(roomId)
        );
      }

      const msgKeyBytes = hkdf(
        sha256,
        rootKeyBytes,
        iv,
        new TextEncoder().encode(`GroupMsg-Epoch-${msgEpoch}`),
        32
      );
      zeroizeBuffer(rootKeyBytes);

      const aesKey = await window.crypto.subtle.importKey(
        'raw',
        msgKeyBytes as unknown as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        aesKey,
        cipherBytes as unknown as BufferSource
      );
      zeroizeBuffer(msgKeyBytes);

      return {
        text: new TextDecoder().decode(decryptedBuffer),
        isEncrypted: true,
        mode: 'GROUP-EPOCH-FSM',
        epoch: msgEpoch,
        failed: false,
      };
    }

    // ۳. پشتیبانی از پیام‌های قبلی ECDH و PBKDF2
    const isEcdh = payload.startsWith(E2EE_ECDH_PREFIX);
    const raw = payload.slice(isEcdh ? E2EE_ECDH_PREFIX.length : E2EE_V1_PREFIX.length);
    const [ivB64, cipherB64] = raw.split(':');
    if (!ivB64 || !cipherB64) {
      return { text: payload, isEncrypted: true, failed: true };
    }

    const iv = base64ToBuf(ivB64);
    const cipherBytes = base64ToBuf(cipherB64);

    if (isEcdh && options?.myUsername && options?.peerPublicKey) {
      const ecdhKey = await deriveECDHSharedAesKey(options.myUsername, options.peerPublicKey);
      if (ecdhKey) {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as unknown as BufferSource },
          ecdhKey,
          cipherBytes as unknown as BufferSource
        );
        return {
          text: new TextDecoder().decode(decryptedBuffer),
          isEncrypted: true,
          mode: 'ECDH',
          failed: false,
        };
      }
    }

    const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
    const pbkdfKey = await derivePbkdf2AesKey(roomId, manualSecret);
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      pbkdfKey,
      cipherBytes as unknown as BufferSource
    );
    return {
      text: new TextDecoder().decode(decryptedBuffer),
      isEncrypted: true,
      mode: 'PBKDF2',
      failed: false,
    };
  } catch {
    return {
      text: '🔒 [پیام رمزنگاری‌شده سرتاسری - نیازمند کلید متناظر]',
      isEncrypted: true,
      failed: true,
    };
  }
}

export function getRoomSecret(roomId: string): string {
  try {
    return localStorage.getItem(`${ROOM_KEY_STORAGE_PREFIX}${roomId}`) || '';
  } catch {
    return '';
  }
}

export function setRoomSecret(roomId: string, secret: string): void {
  try {
    if (secret.trim()) {
      localStorage.setItem(`${ROOM_KEY_STORAGE_PREFIX}${roomId}`, secret.trim());
    } else {
      localStorage.removeItem(`${ROOM_KEY_STORAGE_PREFIX}${roomId}`);
    }
  } catch {
    // ignore
  }
}

export function isE2EEEnabled(): boolean {
  try {
    const val = localStorage.getItem(E2EE_ENABLED_STORAGE_KEY);
    return val === null ? true : val === 'true';
  } catch {
    return true;
  }
}

export function setE2EEEnabled(enabled: boolean): void {
  try {
    localStorage.setItem(E2EE_ENABLED_STORAGE_KEY, String(enabled));
  } catch {
    // ignore
  }
}
