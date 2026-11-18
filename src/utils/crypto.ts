// سیستم پیشرفته رمزنگاری تماماً پساکوانتومی (Fully Post-Quantum Hybrid ML-KEM-768 + ML-DSA-65 + ECDH P-256)
// به همراه زنجیره راتچت مقاوم در برابر پیام‌های خارج از نوبت (Out-of-Order Symmetric Ratchet + Zeroization)
// امضای دیجیتال هویت FIPS 204 (ML-DSA-65) برای مقابله با الگوریتم شور و جلوگیری قطعی از Downgrade خاموش
// احراز هویت کور مبتنی بر Ristretto255-VOPRF (RFC 9497) و ماشین وضعیت چرخش اپوک گروه (Group Epoch FSM)

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
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
const DECRYPTED_CACHE_PREFIX = 'chat_decrypted_v2_';
const GROUP_EPOCH_PREFIX = 'chat_group_epoch_';
const VOPRF_TOKEN_PREFIX = 'chat_voprf_token_';

const MAX_SKIP = 100; // حداکثر پرش مجاز برای پیام‌های خارج از نوبت (محافظت در برابر DoS)
const SKIPPED_KEY_TTL_MS = 10 * 60 * 1000; // ۱۰ دقیقه نگهداری کلیدهای سوخته/پرش‌خورده
const GROUP_EPOCH_GRACE_BUFFER = 3; // نگهداری ۳ اپوک قبلی برای رمزگشایی پیام‌های در حال پرواز هنگام تغییر اعضا
const PQ_REKEY_AFTER_MESSAGES = 50; // چرخش نشست راتچت پس از هر ۵۰ پیام ارسالی (Forward Secrecy / PCS)
const PBKDF2_ITERATIONS_NEW = 600000; // OWASP 2023 برای PBKDF2-HMAC-SHA-256
const PBKDF2_ITERATIONS_LEGACY = 50000; // مقدار پیشین؛ فقط برای رمزگشایی تاریخچه قدیمی
const KEY_STORAGE_VERSION = 3; // نسخه ذخیره کلیدها؛ ورودی‌های بدون این نسخه، کلیدهای قطعی قدیمی‌اند و دور ریخته می‌شوند

/**
 * خطای رمزنگاری سرتاسری. هرگز نباید به‌جای آن متن ساده برگردد.
 * (رفع F5: شکست رمزنگاری پیش‌تر بی‌صدا به ارسال متن ساده منجر می‌شد.)
 */
export class E2EEError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'E2EEError';
  }
}

interface StoredKeyPair {
  v?: number;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

interface StoredMLKEMKeyPair {
  v?: number;
  publicKeyB64: string;
  secretKeyB64: string;
}

interface StoredMLDSAKeyPair {
  v?: number;
  publicKeyB64: string;
  secretKeyB64: string;
}

/**
 * پاک‌سازی وضعیت رمزنگاری کاربر هنگام جایگزینی کلیدهای قدیمی.
 * (رفع F1: کلیدهای پیش از نسخه ۳ به‌صورت قطعی از نام کاربری مشتق می‌شدند و
 * بنابراین قابل بازتولید توسط هر کسی بودند. با چرخش هویت، نشست‌های راتچت و
 * اپوک‌های گروهی قدیمی — که با کلیدهای به‌خطرافتاده ساخته شده‌اند — نیز
 * دور ریخته می‌شوند. کش متن‌های رمزگشایی‌شده حفظ می‌شود تا تاریخچه
 * خوانده‌شده از دست نرود.)
 */
export function clearUserCryptoState(myUsername: string): void {
  try {
    const ratchetPrefix = `${RATCHET_STATE_PREFIX}${myUsername}_`;
    const groupPrefix = GROUP_EPOCH_PREFIX;
    const doomed: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (!k) continue;
      if (k.startsWith(ratchetPrefix) || k.startsWith(groupPrefix)) doomed.push(k);
    }
    for (const k of doomed) localStorage.removeItem(k);
  } catch {
    // ignore
  }
}

export function getPersistentDecryptedCache(myUsername: string, roomId: string): Record<string, string> {
  try {
    const raw = localStorage.getItem(`${DECRYPTED_CACHE_PREFIX}${myUsername}_${roomId}`);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function savePersistentDecryptedMessage(
  myUsername: string,
  roomId: string,
  hashKey: string,
  plainText: string
): void {
  try {
    const cache = getPersistentDecryptedCache(myUsername, roomId);
    cache[hashKey] = plainText;
    const keys = Object.keys(cache);
    if (keys.length > 2000) {
      for (const k of keys.slice(0, keys.length - 2000)) {
        delete cache[k];
      }
    }
    localStorage.setItem(`${DECRYPTED_CACHE_PREFIX}${myUsername}_${roomId}`, JSON.stringify(cache));
  } catch {
    // ignore
  }
}

export function getStoredPeerPublicKey(peerUsername: string): string | null {
  try {
    return localStorage.getItem(`chat_peer_key_${peerUsername}`);
  } catch {
    return null;
  }
}

export function setStoredPeerPublicKey(peerUsername: string, key: string): void {
  try {
    if (key) {
      localStorage.setItem(`chat_peer_key_${peerUsername}`, key);
    }
  } catch {
    // ignore
  }
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
  sessionEpoch: number; // با هر چرخش نشست (re-key) یک واحد بیشتر می‌شود
  sentSinceRekey: number; // پیام‌های ارسالی از آخرین چرخش
  consumedRecvSteps: number[]; // گام‌های دریافتی مصرف‌شده (محافظت در برابر Replay)
  skippedKeys: Record<number, SkippedKeyEntry>;
  decryptedCache: Record<string, string>; // کش محلی برای نمایش مجدد پیام‌های رمزگشایی‌شده پس از Zeroization کلید
  previousSession: RatchetSessionState | null; // فقط یک نشست قبلی، برای پیام‌های در حال پرواز هنگام چرخش
}

export interface GroupEpochKeyRecord {
  epoch: number;
  rootKeyB64: string;
  createdAt: number;
  membersHash: string;
  distributedViaMlkem: boolean; // true یعنی کلید اپوک با ML-KEM به اعضا کپسوله شده است (F3)
  seenMessageKeys?: string[]; // هش پیام‌های گروهی تحویل‌شده در این اپوک — ضد Replay (F7)
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
  // (رفع F1) اگر کلید ذخیره‌شده نباشد، null برمی‌گردد؛ کلید هرگز به‌صورت
  // قطعی بازتولید نمی‌شود. تولید کلید فقط در ensureUserHybridKeyPair انجام می‌شود.
  try {
    const raw = localStorage.getItem(`${MLDSA_KEYPAIR_PREFIX}${myUsername}`);
    if (raw) {
      const parsed: StoredMLDSAKeyPair = JSON.parse(raw);
      if (parsed.v === KEY_STORAGE_VERSION && parsed.secretKeyB64) {
        return base64ToBuf(parsed.secretKeyB64);
      }
    }
    return null;
  } catch {
    return null;
  }
}

export function getMyMLDSAPublicKey(myUsername: string): string | null {
  try {
    const raw = localStorage.getItem(`${MLDSA_KEYPAIR_PREFIX}${myUsername}`);
    if (raw) {
      const parsed: StoredMLDSAKeyPair = JSON.parse(raw);
      if (parsed.v === KEY_STORAGE_VERSION && parsed.publicKeyB64) return parsed.publicKeyB64;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * تولید یا بازیابی باندل کلید عمومی ترکیبی تماماً پساکوانتومی
 * (ML-KEM-768 + ECDH P-256 + امضای دیجیتال هویت FIPS 204 ML-DSA-65)
 * مجهز به اشتقاق قطعی کلیدها از Master Seed هویت کاربر جهت بقای صددرصدی پیام‌ها پس از Logout و Fresh Login
 */
export async function ensureUserHybridKeyPair(username: string): Promise<string | null> {
  if (!username || !window.crypto?.subtle) return null;
  const ecdhStorageKey = `${ECDH_KEYPAIR_PREFIX}${username}`;
  const pqStorageKey = `${MLKEM_KEYPAIR_PREFIX}${username}`;
  const dsaStorageKey = `${MLDSA_KEYPAIR_PREFIX}${username}`;

  try {
    // مهاجرت F1: ورودی‌های ذخیره‌شده بدون نشان نسخه ۳، کلیدهای قطعی قدیمی‌اند
    // (قابل بازتولید از نام کاربری) — دور ریخته و با کلیدهای تصادفی جایگزین می‌شوند.
    const legacyDetected = [ecdhStorageKey, pqStorageKey, dsaStorageKey].some(k => {
      try {
        const raw = localStorage.getItem(k);
        if (!raw) return false;
        return JSON.parse(raw).v !== KEY_STORAGE_VERSION;
      } catch {
        return true;
      }
    });
    if (legacyDetected) {
      for (const k of [ecdhStorageKey, pqStorageKey, dsaStorageKey]) localStorage.removeItem(k);
      clearUserCryptoState(username);
    }

    let publicJwk: JsonWebKey | null = null;
    const existingEcdh = localStorage.getItem(ecdhStorageKey);
    if (existingEcdh) {
      try {
        const parsed: StoredKeyPair = JSON.parse(existingEcdh);
        if (parsed.publicJwk && parsed.privateJwk) {
          publicJwk = parsed.publicJwk;
        }
      } catch {
        publicJwk = null;
      }
    }

    if (!publicJwk) {
      // کلید خصوصی تصادفی (F1): هرگز از نام کاربری یا مقدار قطعی مشتق نمی‌شود.
      const ecdhPriv = p256.utils.randomSecretKey();
      const pubBytes = p256.getPublicKey(ecdhPriv, false);
      const toB64Url = (buf: Uint8Array) => {
        let binary = '';
        for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      };
      publicJwk = {
        kty: 'EC',
        crv: 'P-256',
        x: toB64Url(pubBytes.slice(1, 33)),
        y: toB64Url(pubBytes.slice(33, 65)),
      };
      const privateJwk = {
        ...publicJwk,
        d: toB64Url(ecdhPriv),
      };
      localStorage.setItem(ecdhStorageKey, JSON.stringify({ v: KEY_STORAGE_VERSION, publicJwk, privateJwk }));
      zeroizeBuffer(ecdhPriv);
    }

    let mlkemPubB64 = '';
    const existingPq = localStorage.getItem(pqStorageKey);
    if (existingPq) {
      try {
        const parsedPq: StoredMLKEMKeyPair = JSON.parse(existingPq);
        if (parsedPq.v === KEY_STORAGE_VERSION && parsedPq.publicKeyB64 && parsedPq.secretKeyB64) {
          mlkemPubB64 = parsedPq.publicKeyB64;
        }
      } catch {
        mlkemPubB64 = '';
      }
    }

    if (!mlkemPubB64) {
      const pqKeys = ml_kem768.keygen(); // کلید تصادفی با CSPRNG (F1)
      mlkemPubB64 = bufToBase64(pqKeys.publicKey);
      const secretKeyB64 = bufToBase64(pqKeys.secretKey);
      localStorage.setItem(pqStorageKey, JSON.stringify({ v: KEY_STORAGE_VERSION, publicKeyB64: mlkemPubB64, secretKeyB64 }));
      zeroizeBuffer(pqKeys.secretKey);
    }

    // تولید یا بازیابی کلیدهای امضای هویت پساکوانتومی ML-DSA-65 (FIPS 204)
    let mldsaPubB64 = '';
    let mldsaSec: Uint8Array | null = null;
    const existingDsa = localStorage.getItem(dsaStorageKey);
    if (existingDsa) {
      try {
        const parsedDsa: StoredMLDSAKeyPair = JSON.parse(existingDsa);
        if (parsedDsa.v === KEY_STORAGE_VERSION && parsedDsa.publicKeyB64 && parsedDsa.secretKeyB64) {
          mldsaPubB64 = parsedDsa.publicKeyB64;
          mldsaSec = base64ToBuf(parsedDsa.secretKeyB64);
        }
      } catch {
        mldsaSec = null;
      }
    }

    if (!mldsaPubB64 || !mldsaSec) {
      const dsaKeys = ml_dsa65.keygen(); // کلید تصادفی با CSPRNG (F1)
      mldsaPubB64 = bufToBase64(dsaKeys.publicKey);
      const secretKeyB64 = bufToBase64(dsaKeys.secretKey);
      localStorage.setItem(dsaStorageKey, JSON.stringify({ v: KEY_STORAGE_VERSION, publicKeyB64: mldsaPubB64, secretKeyB64 }));
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
      // (رفع F11) نام کاربری باندل باید موجود و برابر مخاطب موردانتظار باشد؛
      // باندل بدون نام کاربری یا با نام ناهمخوان، امضایش نامعتبر شمرده می‌شود.
      if (expectedPeerUsername && parsed.username !== expectedPeerUsername) {
        result.isMldsaSignatureInvalid = true;
        return result;
      }
      if (result.hasMLKEM && result.hasMLDSA && result.mldsaSigB64 && result.mldsaPub) {
        try {
          const sigBytes = base64ToBuf(result.mldsaSigB64);
          const uName = parsed.username || '';
          const target = serializeBundleForSigning({
            username: uName,
            ecdhJwk: result.ecdhJwk,
            mlkemPubB64: parsed.mlkemPubB64,
          });

          const valid = ml_dsa65.verify(sigBytes, target, result.mldsaPub);

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
  reason?: 'CLASSICAL_ECDH' | 'MISSING_PEER_KEYS' | 'INVALID_MLDSA_SIGNATURE' | 'MANUAL_PBKDF2' | 'LEGACY_GROUP_EPOCH';
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
    // (رفع F3) گروه فقط وقتی پساکوانتومی شمرده می‌شود که کلید اپوک جاری
    // واقعاً با ML-KEM توزیع شده باشد؛ اپوک‌های قدیمیِ مشتق‌شده از ورودی‌های
    // عمومی، این نشان را نمی‌گیرند.
    try {
      const groupId = options.roomId.replace('group__', '');
      const fsm = getGroupEpochState(groupId, []);
      const rec = fsm.epochs[fsm.currentEpoch];
      if (rec && rec.distributedViaMlkem) {
        return {
          isPQ: true,
          type: 'GROUP_EPOCH',
          badge: '🔒 Epoch',
          tooltip: 'رمزنگاری گروهی: کلید اپوک با ML-KEM-768 به اعضا توزیع شده است',
        };
      }
    } catch {
      // ignore — fall through to NOT_POST_QUANTUM
    }
    return {
      isPQ: false,
      type: 'NOT_POST_QUANTUM',
      reason: 'LEGACY_GROUP_EPOCH',
      badge: '⚠️ گروه کلاسیک',
      tooltip: 'کلید اپوک این گروه با ML-KEM توزیع نشده است',
      warningText: 'کلید اپوک گروه به‌صورت امن توزیع نشده است. تا زمان دریافت بسته کلید اپوک، پیام‌های گروهی امنیت پساکوانتومی ندارند.',
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
    let privateJwk: JsonWebKey | null = null;
    const rawPair = localStorage.getItem(`${ECDH_KEYPAIR_PREFIX}${myUsername}`);
    if (rawPair) {
      try {
        const parsed: StoredKeyPair = JSON.parse(rawPair);
        privateJwk = parsed.privateJwk;
      } catch {
        privateJwk = null;
      }
    }

    if (!privateJwk) {
      await ensureUserHybridKeyPair(myUsername);
      const freshRaw = localStorage.getItem(`${ECDH_KEYPAIR_PREFIX}${myUsername}`);
      if (freshRaw) {
        privateJwk = JSON.parse(freshRaw).privateJwk;
      }
    }

    if (!privateJwk) return null;

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
  peerPublicKeyStr: string,
  roomId: string,
  peerUsername?: string
): Promise<CryptoKey | null> {
  const { ecdhJwk } = parsePeerKeyBundle(peerPublicKeyStr, peerUsername);
  if (!ecdhJwk) return null;
  const bits = await deriveECDHSharedBits(myUsername, ecdhJwk);
  if (!bits) return null;
  try {
    // (رفع F10) خروجی خام ECDH مستقیم به‌عنوان کلید AES استفاده نمی‌شود؛
    // نخست از HKDF با salt شناسه اتاق و info وابسته به هویت مخاطب می‌گذرد،
    // تا کلید هر اتاق جدا باشد.
    const keyBytes = hkdf(
      sha256,
      bits,
      new TextEncoder().encode(roomId),
      new TextEncoder().encode(`ECDH-Legacy-AES-v2:${peerUsername || ''}`),
      32
    );
    return await window.crypto.subtle.importKey(
      'raw',
      keyBytes as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    zeroizeBuffer(bits);
  }
}

function getMyMLKEMSecretKey(myUsername: string): Uint8Array | null {
  // (رفع F1) اگر کلید ذخیره‌شده نباشد، null برمی‌گردد؛ کلید هرگز به‌صورت
  // قطعی بازتولید نمی‌شود. تولید کلید فقط در ensureUserHybridKeyPair انجام می‌شود.
  try {
    const raw = localStorage.getItem(`${MLKEM_KEYPAIR_PREFIX}${myUsername}`);
    if (raw) {
      const parsed: StoredMLKEMKeyPair = JSON.parse(raw);
      if (parsed.v === KEY_STORAGE_VERSION && parsed.secretKeyB64) {
        return base64ToBuf(parsed.secretKeyB64);
      }
    }
    return null;
  } catch {
    return null;
  }
}

// (رفع F7/F9) اشتقاق کلید تاریخی حذف شد: کلید اولیه زنجیره دیگر ذخیره
// نمی‌شود و پیام قدیمی فقط از کش متن‌های رمزگشایی‌شده خوانده می‌شود.


function loadRatchetState(myUsername: string, roomId: string): RatchetSessionState | null {
  try {
    const raw = localStorage.getItem(`${RATCHET_STATE_PREFIX}${myUsername}_${roomId}`);
    if (!raw) return null;
    const parsed: RatchetSessionState = JSON.parse(raw);
    const state = normalizeRatchetState(parsed);
    const now = Date.now();
    let mutated = false;
    for (const [stepStr, entry] of Object.entries(state.skippedKeys || {})) {
      if (now - entry.timestamp > SKIPPED_KEY_TTL_MS) {
        delete state.skippedKeys[Number(stepStr)];
        mutated = true;
      }
    }
    // ادغام با Persistent Decrypted Cache
    const persistentCache = getPersistentDecryptedCache(myUsername, roomId);
    state.decryptedCache = { ...persistentCache, ...(state.decryptedCache || {}) };
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
    const cacheKeys = Object.keys(state.decryptedCache || {});
    if (cacheKeys.length > 2000) {
      for (const k of cacheKeys.slice(0, cacheKeys.length - 2000)) {
        delete state.decryptedCache[k];
      }
    }
    localStorage.setItem(`${RATCHET_STATE_PREFIX}${myUsername}_${roomId}`, JSON.stringify(state));
  } catch {
    // ignore
  }
}

/** حذف لایه previousSession از یک نشست، برای اینکه فقط یک سطح قبلی ذخیره شود
 *  (و کش متن‌ها در شکاف قبلی تکثیر نشود). */
function stripPreviousSession(state: RatchetSessionState): RatchetSessionState {
  return { ...state, previousSession: null, decryptedCache: {} };
}

/** عادی‌سازی نشست خوانده‌شده از حافظه (مهاجرت از نسخه‌های قدیمی). */
function normalizeRatchetState(state: RatchetSessionState, depth = 0): RatchetSessionState {
  const s = state as unknown as Record<string, unknown>;
  delete s.initialSendChainKeyB64;
  delete s.initialRecvChainKeyB64;
  return {
    ...state,
    sessionEpoch: typeof state.sessionEpoch === 'number' ? state.sessionEpoch : 0,
    sentSinceRekey: typeof state.sentSinceRekey === 'number' ? state.sentSinceRekey : 0,
    consumedRecvSteps: Array.isArray(state.consumedRecvSteps) ? state.consumedRecvSteps : [],
    skippedKeys: state.skippedKeys || {},
    decryptedCache: state.decryptedCache || {},
    previousSession:
      state.previousSession && depth < 1
        ? normalizeRatchetState(state.previousSession, depth + 1)
        : null,
  };
}

/**
 * اشتقاق یک نشست راتچت تازه از اسرار مشترک (ECDH + KEM).
 * (رفع F8/F9) کپسوله‌سازی همیشه با کوین‌های تصادفی تازه انجام می‌شود و
 * هر نشست تازه، کلید ریشه و زنجیره‌های تازه دارد؛ گام‌ها از صفر شروع می‌شوند.
 */
async function deriveFreshRatchetSession(
  myUsername: string,
  roomId: string,
  ecdhSecret: Uint8Array,
  pqSharedSecret: Uint8Array,
  kemCipherB64: string,
  peerFingerprint: string,
  existing: RatchetSessionState | null
): Promise<RatchetSessionState> {
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

  const sendChain = amIFirst ? chainA : chainB;
  const recvChain = amIFirst ? chainB : chainA;

  const persistentCache = getPersistentDecryptedCache(myUsername, roomId);
  const newState: RatchetSessionState = {
    rootKeyB64: bufToBase64(rootKey),
    sendChainKeyB64: bufToBase64(sendChain),
    recvChainKeyB64: bufToBase64(recvChain),
    sendStep: 0,
    recvStep: 0,
    kemCipherTextB64: kemCipherB64,
    peerKemFingerprint: peerFingerprint,
    sessionEpoch: (existing?.sessionEpoch ?? 0) + 1,
    sentSinceRekey: 0,
    consumedRecvSteps: [],
    skippedKeys: {},
    decryptedCache: {
      ...(existing?.decryptedCache || {}),
      ...persistentCache,
    },
    previousSession: existing ? stripPreviousSession(existing) : null,
  };

  zeroizeBuffer(combinedInput);
  zeroizeBuffer(rootKey);
  return newState;
}

/**
 * مقداردهی اولیه یا بازیابی نشست راتچت پساکوانتومی (Hybrid ML-KEM-768 + ECDH P-256)
 * (رفع F6/F8/F9)
 * - برقراری نشست تازه یا چرخش به کپسول تازه، فقط با باندل کاملاً پساکوانتومی
 *   (امضای ML-DSA-65 معتبر) انجام می‌شود.
 * - کپسوله‌سازی با کوین‌های تصادفی تازه است؛ fallback بازکپسوله‌سازی حذف شد.
 * - کپسولِ نشست فعلی یا قبلی، بدون مشتق‌سازی دوباره برگردانده می‌شود.
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

  if (!bundle.ecdhJwk || !bundle.mlkemPub) {
    return existing || null;
  }

  const peerFingerprint = bufToBase64(sha256(bundle.mlkemPub)).slice(0, 16);

  // کپسول ورودی متعلق به نشست فعلی یا قبلی است — نیازی به مشتق‌سازی نیست.
  if (incomingKemCipherB64 && existing) {
    if (existing.kemCipherTextB64 === incomingKemCipherB64) return existing;
    if (existing.previousSession?.kemCipherTextB64 === incomingKemCipherB64) return existing;
  }

  // بدون کپسول تازه و با همان کلید مخاطب: نشست موجود ادامه می‌یابد.
  if (!incomingKemCipherB64 && existing && existing.peerKemFingerprint === peerFingerprint) {
    return existing;
  }

  // برقراری نشست تازه (یا چرخش) فقط با باندل تأییدشده پساکوانتومی (F6).
  if (!bundle.isFullyPostQuantum) {
    return existing || null;
  }

  const ecdhSecret = await deriveECDHSharedBits(myUsername, ecdhJwk);
  if (!ecdhSecret) return existing || null;

  try {
    let pqSharedSecret: Uint8Array | null = null;
    let kemCipherB64: string;
    if (incomingKemCipherB64) {
      const mySecretKey = getMyMLKEMSecretKey(myUsername);
      if (!mySecretKey) {
        zeroizeBuffer(ecdhSecret);
        return existing || null;
      }
      try {
        pqSharedSecret = ml_kem768.decapsulate(base64ToBuf(incomingKemCipherB64), mySecretKey);
      } catch {
        // (رفع F8) شکست Decapsulation به‌معنای کپسول نامعتبر است؛
        // بازتولید مخفیانه Secret با Preimage حذف شد — Fail closed.
        zeroizeBuffer(mySecretKey);
        zeroizeBuffer(ecdhSecret);
        return existing || null;
      }
      zeroizeBuffer(mySecretKey);
      kemCipherB64 = incomingKemCipherB64;
    } else {
      // (رفع F8) کپسوله‌سازی با کوین‌های تصادفی تازه.
      const enc = ml_kem768.encapsulate(mlkemPub);
      pqSharedSecret = enc.sharedSecret;
      kemCipherB64 = bufToBase64(enc.cipherText);
    }

    if (!pqSharedSecret) {
      zeroizeBuffer(ecdhSecret);
      return existing || null;
    }

    const newState = await deriveFreshRatchetSession(
      myUsername,
      roomId,
      ecdhSecret,
      pqSharedSecret,
      kemCipherB64,
      peerFingerprint,
      existing
    );
    zeroizeBuffer(ecdhSecret);
    zeroizeBuffer(pqSharedSecret);
    saveRatchetState(myUsername, roomId, newState);
    return newState;
  } catch {
    zeroizeBuffer(ecdhSecret);
    return existing;
  }
}

/**
 * چرخش صریح نشست برای ارسال (F9): پس از PQ_REKEY_AFTER_MESSAGES پیام،
 * کپسول تازه با کوین تصادفی ساخته و نشست با epoch بالاتر جایگزین می‌شود.
 */
export async function rotateRatchetSessionForSend(
  myUsername: string,
  roomId: string,
  peerPublicKeyStr: string,
  peerUsername?: string
): Promise<RatchetSessionState | null> {
  const bundle = parsePeerKeyBundle(peerPublicKeyStr, peerUsername);
  if (!bundle.isFullyPostQuantum || !bundle.mlkemPub || !bundle.ecdhJwk) return null;
  const existing = loadRatchetState(myUsername, roomId);
  const ecdhSecret = await deriveECDHSharedBits(myUsername, bundle.ecdhJwk);
  if (!ecdhSecret) return existing || null;
  try {
    const enc = ml_kem768.encapsulate(bundle.mlkemPub);
    const peerFingerprint = bufToBase64(sha256(bundle.mlkemPub)).slice(0, 16);
    const newState = await deriveFreshRatchetSession(
      myUsername,
      roomId,
      ecdhSecret,
      enc.sharedSecret,
      bufToBase64(enc.cipherText),
      peerFingerprint,
      existing
    );
    zeroizeBuffer(ecdhSecret);
    zeroizeBuffer(enc.sharedSecret);
    saveRatchetState(myUsername, roomId, newState);
    return newState;
  } catch {
    zeroizeBuffer(ecdhSecret);
    return existing;
  }
}

/**
 * رمزگشایی پیام در زنجیره راتچت (F7/F9)
 * - گام دریافتیِ پیش‌تر مصرف‌شده، Replay است و رد می‌شود.
 * - کلید تاریخی از زنجیره اولیه بازتولید نمی‌شود؛ نمایش تاریخچه فقط از کش
 *   متن‌های رمزگشایی‌شده است.
 * - `root` نشست ریشه‌ای است که ذخیره می‌شود؛ `session` شکافی (فعلی یا قبلی)
 *   است که پیام به آن تعلق دارد.
 */
async function ratchetDecryptWithSkippedKeys(
  myUsername: string,
  roomId: string,
  root: RatchetSessionState,
  session: RatchetSessionState,
  msgStep: number,
  iv: Uint8Array,
  cipherBytes: Uint8Array,
  payloadHashKey: string,
  isSender?: boolean,
  allowCache = true
): Promise<string | null> {
  // (رفع F7) کش نمایش فقط در مسیر نمایش یا پیام خودِ فرستنده خوانده می‌شود؛
  // در مسیر شبکه (allowCache=false) کش دور زده می‌شود تا Replay از طریق
  // کشِ پیامِ پیش‌تر رمزگشایی‌شده دوباره پذیرفته نشود.
  if (isSender || allowCache !== false) {
    if (session.decryptedCache && session.decryptedCache[payloadHashKey]) {
      return session.decryptedCache[payloadHashKey];
    }
    const persistent = getPersistentDecryptedCache(myUsername, roomId)[payloadHashKey];
    if (persistent) {
      if (!session.decryptedCache) session.decryptedCache = {};
      session.decryptedCache[payloadHashKey] = persistent;
      return persistent;
    }
  }

  // (رفع F7) گام دریافتیِ پیش‌تر مصرف‌شده، Replay است — رد می‌شود.
  if (!isSender && session.consumedRecvSteps.includes(msgStep)) {
    return null;
  }

  let messageKeyBytes: Uint8Array | null = null;
  const isPastStep = isSender ? (msgStep < session.sendStep) : (msgStep < session.recvStep);

  // حالت ۱: پیام مربوط به یکی از گام‌های قبلی است
  if (isPastStep) {
    const skipped = session.skippedKeys[msgStep];
    if (skipped) {
      messageKeyBytes = base64ToBuf(skipped.mkB64);
      delete session.skippedKeys[msgStep];
    } else {
      // بدون کلید تاریخی (F9): پیام قدیمی که کلیدش نگه داشته نشده، قفل می‌ماند.
      return null;
    }
  } else if (isSender) {
    // پیام خود فرستنده فقط از کش خوانده می‌شود؛ بازتولید تاریخی حذف شد (F9).
    return null;
  } else {
    // بررسی سقف مجاز پرش برای جلوگیری از حمله DoS
    if (msgStep - session.recvStep > MAX_SKIP) {
      return null;
    }

    let currentRecvChain = base64ToBuf(session.recvChainKeyB64);

    // پیام جلوتر از گام فعلی است؛ کلیدهای میانی را تولید و در SkippedMessageKeys ذخیره کن
    while (session.recvStep < msgStep) {
      const { nextChainKey, messageKey } = kdfChainStep(currentRecvChain);
      zeroizeBuffer(currentRecvChain);
      currentRecvChain = nextChainKey;

      session.skippedKeys[session.recvStep] = {
        mkB64: bufToBase64(messageKey),
        timestamp: Date.now(),
      };
      zeroizeBuffer(messageKey);
      session.recvStep++;
    }

    // استخراج کلید پیام فعلی (msgStep === session.recvStep)
    const { nextChainKey, messageKey } = kdfChainStep(currentRecvChain);
    zeroizeBuffer(currentRecvChain);
    session.recvChainKeyB64 = bufToBase64(nextChainKey);
    zeroizeBuffer(nextChainKey);
    session.recvStep++;
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
    if (!session.decryptedCache) session.decryptedCache = {};
    session.decryptedCache[payloadHashKey] = plainText;
    if (!isSender) {
      session.consumedRecvSteps.push(msgStep);
      if (session.consumedRecvSteps.length > 2000) {
        session.consumedRecvSteps = session.consumedRecvSteps.filter(
          s => s >= session.recvStep - 1000
        );
      }
    }
    savePersistentDecryptedMessage(myUsername, roomId, payloadHashKey, plainText);
    saveRatchetState(myUsername, roomId, root);
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

/**
 * (رفع F3) کلید اپوک گروه هرگز به‌صورت قطعی از ورودی‌های عمومی مشتق نمی‌شود.
 * توزیع‌کننده اپوک (سازنده گروه) یک کلید تصادفی ۳۲ بایتی می‌سازد و آن را
 * برای هر عضو با ML-KEM-768 به کلید عمومی تأییدشده باندل او کپسوله می‌کند؛
 * سرور فقط کپسول‌ها را جابه‌جا می‌کند و کلید را نمی‌بیند.
 */
export interface GroupEpochPacket {
  epochKeyB64: string; // کلید خام اپوک — فقط نزد توزیع‌کننده می‌ماند
  keys: Record<string, string>; // username -> کپسول ML-KEM-768 (Base64)
  missing: string[]; // اعضایی که باندل تأییدشده ندارند و نمی‌توانند بخوانند
}

export async function createGroupEpochPacket(
  memberBundles: Record<string, ParsedPeerKeyBundle | null | undefined>
): Promise<GroupEpochPacket> {
  const epochKey = window.crypto.getRandomValues(new Uint8Array(32));
  const keys: Record<string, string> = {};
  const missing: string[] = [];
  for (const [username, bundle] of Object.entries(memberBundles)) {
    if (bundle && bundle.isFullyPostQuantum && bundle.mlkemPub) {
      try {
        // کپسوله‌سازی ML-KEM-768 با کوین‌های تصادفی تازه؛ کلید اپوک با
        // کلید مشتق‌شده از Secret مشترک (HKDF با دامنهٔ نام گیرنده) و
        // AES-256-GCM پیچیده می‌شود. بدون این پیچش، کپسول هیچ‌گاه کلید
        // اپوک را منتقل نمی‌کرد (باگ نسخهٔ اول این رفع).
        const enc = ml_kem768.encapsulate(bundle.mlkemPub); // کوین‌های تصادفی تازه
        const wrapKey = hkdf(
          sha256,
          enc.sharedSecret,
          undefined,
          new TextEncoder().encode(`Group-Epoch-Wrap-v1:${username}`),
          32
        );
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const aesKey = await window.crypto.subtle.importKey(
          'raw',
          wrapKey as unknown as BufferSource,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt']
        );
        const wrapped = await window.crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: iv as unknown as BufferSource },
          aesKey,
          epochKey as unknown as BufferSource
        );
        keys[username] = `${bufToBase64(enc.cipherText)}:${bufToBase64(iv)}:${bufToBase64(
          new Uint8Array(wrapped)
        )}`;
        zeroizeBuffer(enc.sharedSecret);
        zeroizeBuffer(wrapKey);
      } catch {
        missing.push(username);
      }
    } else {
      missing.push(username);
    }
  }
  const epochKeyB64 = bufToBase64(epochKey);
  zeroizeBuffer(epochKey);
  return { epochKeyB64, keys, missing };
}

/** باز کردن کپسول کلید اپوک گروه با کلید خصوصی ML-KEM-768 خود کاربر. */
export async function decapsulateGroupEpochKey(
  myUsername: string,
  wrappedB64: string
): Promise<string | null> {
  try {
    const parts = wrappedB64.split(':');
    if (parts.length !== 3) return null;
    const [ctB64, ivB64, wrappedKeyB64] = parts;
    const mySecretKey = getMyMLKEMSecretKey(myUsername);
    if (!mySecretKey) return null;
    const shared = ml_kem768.decapsulate(base64ToBuf(ctB64), mySecretKey);
    zeroizeBuffer(mySecretKey);
    const wrapKey = hkdf(
      sha256,
      shared,
      undefined,
      new TextEncoder().encode(`Group-Epoch-Wrap-v1:${myUsername}`),
      32
    );
    zeroizeBuffer(shared);
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      wrapKey as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    zeroizeBuffer(wrapKey);
    const plain = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuf(ivB64) as unknown as BufferSource },
      aesKey,
      base64ToBuf(wrappedKeyB64) as unknown as BufferSource
    );
    return bufToBase64(new Uint8Array(plain));
  } catch {
    return null;
  }
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

  // (رفع F3) بدون بسته کلید اپوک، هیچ کلیدی ساخته نمی‌شود؛ اپوک ۱ هم
  // باید از طریق بسته ML-KEM برسد. تا آن زمان پیام گروهی ارسال نمی‌شود.
  const initial: GroupEpochState = {
    groupId,
    currentEpoch: 1,
    status: 'STABLE',
    epochs: {},
    pendingQueue: [],
  };
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
 * (رفع F3) کلید اپوک الزامی است و باید از بسته ML-KEM آمده باشد؛
 * در غیاب آن، به‌جای مشتق قطعی، خطا پرتاب می‌شود (Fail closed).
 */
export async function rotateGroupEpoch(
  groupId: string,
  newEpoch: number,
  members: string[],
  epochKeyB64?: string
): Promise<GroupEpochState> {
  if (!epochKeyB64) {
    throw new E2EEError(
      'Group epoch key unavailable: the epoch key packet has not arrived yet. Refusing to derive a group key from public inputs.'
    );
  }
  const state = getGroupEpochState(groupId, members);
  state.status = 'ROTATING';

  try {
    const mHash = computeMembersHash(members);
    const rootKey = base64ToBuf(epochKeyB64);

    state.currentEpoch = newEpoch;
    state.epochs[newEpoch] = {
      epoch: newEpoch,
      rootKeyB64: bufToBase64(rootKey),
      createdAt: Date.now(),
      membersHash: mHash,
      distributedViaMlkem: true,
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

async function derivePbkdf2AesKey(
  roomId: string,
  customSecret: string,
  iterations: number = PBKDF2_ITERATIONS_NEW
): Promise<CryptoKey> {
  // (رفع F4) رمز دستی الزامی است؛ عبارت پیش‌فرض عمومی حذف شد. بدون رمز،
  // این تابع صدا زده نمی‌شود و encryptMessageText خطا می‌دهد.
  if (!customSecret) {
    throw new E2EEError('A manual passphrase is required: no default passphrase exists.');
  }
  const enc = new TextEncoder();
  const passphrase = `${roomId}::${customSecret}`;

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
      iterations,
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
      if (!epochRec) {
        // (رفع F3/F5) بدون کلید اپوک گروه، پیام ارسال نمی‌شود؛
        // هرگز با کلید مشتق‌شده از ورودی‌های عمومی جایگزین نمی‌شود.
        throw new E2EEError(
          'Group epoch key unavailable: the epoch key packet has not arrived yet.'
        );
      }
      {
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
        let ratchetState = await ensurePQRatchetSession(
          options.myUsername,
          roomId,
          options.peerPublicKey,
          undefined,
          options.peerUsername
        );

        // (رفع F9) چرخش دوره‌ای نشست پس از PQ_REKEY_AFTER_MESSAGES پیام ارسالی.
        if (ratchetState && ratchetState.sentSinceRekey >= PQ_REKEY_AFTER_MESSAGES) {
          const rotated = await rotateRatchetSessionForSend(
            options.myUsername,
            roomId,
            options.peerPublicKey,
            options.peerUsername
          );
          if (rotated) ratchetState = rotated;
        }

        if (ratchetState) {
          const currentSendChain = base64ToBuf(ratchetState.sendChainKeyB64);
          const { nextChainKey, messageKey } = kdfChainStep(currentSendChain);
          zeroizeBuffer(currentSendChain);

          const stepIndex = ratchetState.sendStep;
          ratchetState.sendChainKeyB64 = bufToBase64(nextChainKey);
          ratchetState.sendStep = stepIndex + 1;
          ratchetState.sentSinceRekey = (ratchetState.sentSinceRekey || 0) + 1;
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
          // (رفع F6) پیام PQ بدون امضای هویت معتبر ارسال نمی‌شود.
          const myDsaSec = getMyMLDSASecretKey(options.myUsername);
          if (!myDsaSec) {
            throw new E2EEError('Identity signing key unavailable: cannot sign a PQ message.');
          }
          let msgSigB64 = '';
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

          const payload = `${E2EE_PQ_RATCHET_PREFIX}${stepIndex}:${kemCipherB64}:${ivB64}:${cipherB64}${msgSigB64 ? `:${msgSigB64}` : ''}`;
          const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
          if (!ratchetState.decryptedCache) ratchetState.decryptedCache = {};
          ratchetState.decryptedCache[payloadHashKey] = plainText;
          savePersistentDecryptedMessage(options.myUsername, roomId, payloadHashKey, plainText);
          saveRatchetState(options.myUsername, roomId, ratchetState);

          return payload;
        }
      }

      // تنزل صریح (نه خاموش) به ECDH کلاسیک در صورت فقدان کلیدهای پساکوانتومی مخاطب
      // توجه: در UI نشان PQ-KEM حذف شده و بنر هشدار غیر کوانتومی بودن نمایش داده می‌شود
      const ecdhKey = await deriveECDHSharedAesKey(
        options.myUsername,
        options.peerPublicKey,
        roomId,
        options.peerUsername
      );
      if (ecdhKey) {
        const cipherBuffer = await window.crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          ecdhKey,
          encoded
        );
        const payload = `${E2EE_ECDH_PREFIX}${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
        const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
        savePersistentDecryptedMessage(options.myUsername, roomId, payloadHashKey, plainText);
        return payload;
      }
    }

    // ۳. در صورت تنظیم رمز دستی (PBKDF2 Override) — بدون رمز، خطا (F4/F5).
    if (!manualSecret) {
      throw new E2EEError(
        'Cannot establish end-to-end encryption: no verified post-quantum peer bundle and no manual passphrase.'
      );
    }
    const pbkdfKey = await derivePbkdf2AesKey(roomId, manualSecret);
    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      pbkdfKey,
      encoded
    );
    const payload = `${E2EE_V1_PREFIX}${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
    if (options?.myUsername) {
      const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
      savePersistentDecryptedMessage(options.myUsername, roomId, payloadHashKey, plainText);
    }
    return payload;
  } catch (err) {
    // (رفع F5) شکست رمزنگاری هرگز به ارسال متن ساده منجر نمی‌شود.
    if (err instanceof E2EEError) throw err;
    throw new E2EEError(`Encryption failed: ${err instanceof Error ? err.message : 'unknown error'}`);
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
    // allowCache=false یعنی «مسیر شبکه»: پیام تازه‌رسیده است و نباید از کش
    // پیام‌های پیش‌تر رمزگشایی‌شده خوانده شود (ضد Replay — F7). مسیر نمایش
    // (باز کردن دوبارهٔ اتاق، پیش‌نمایش فهرست) مقدار پیش‌فرض true را می‌گیرد.
    allowCache?: boolean;
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
    const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
    const isOwnMessage = Boolean(
      options?.sender && options?.myUsername && options.sender === options.myUsername
    );

    // ۱. بررسی فوری در Persistent Local Cache برای پیام‌هایی که قبلاً با موفقیت رمزگشایی شده‌اند
    // (رفع F7) در مسیر شبکه (allowCache=false) کش دور زده می‌شود؛ پیام خودِ
    // فرستنده استثناست چون کلید گام‌های گذشته‌اش پس از ارسال حذف شده است.
    if (options?.myUsername && (isOwnMessage || options.allowCache !== false)) {
      const persistent = getPersistentDecryptedCache(options.myUsername, roomId)[payloadHashKey];
      if (persistent) {
        const isPQ = payload.startsWith(E2EE_PQ_RATCHET_PREFIX);
        const isGroup = payload.startsWith(E2EE_GROUP_EPOCH_PREFIX);
        const isEcdh = payload.startsWith(E2EE_ECDH_PREFIX);
        let mode: 'PQ-MLKEM-RATCHET' | 'GROUP-EPOCH-FSM' | 'ECDH' | 'PBKDF2' = 'PBKDF2';
        if (isPQ) mode = 'PQ-MLKEM-RATCHET';
        else if (isGroup) mode = 'GROUP-EPOCH-FSM';
        else if (isEcdh) mode = 'ECDH';

        let rStep: number | undefined;
        if (isPQ) {
          const raw = payload.slice(E2EE_PQ_RATCHET_PREFIX.length);
          rStep = parseInt(raw.split(':')[0], 10);
        }

        return {
          text: persistent,
          isEncrypted: true,
          mode,
          ratchetStep: rStep,
          mldsaVerified: true,
          failed: false,
        };
      }
    }

    // کلید عمومی طرف مقابل از پارامتر ورودی یا از حافظه دائمی کلیدهای مخاطبین
    const effectivePeerKey =
      options?.peerPublicKey ||
      (options?.peerUsername ? getStoredPeerPublicKey(options.peerUsername) : null);

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

      if (options?.myUsername && effectivePeerKey) {
        const isIncoming = Boolean(options.sender && options.sender !== options.myUsername);
        const isSender = Boolean(options.sender && options.sender === options.myUsername);
        const peerBundle = parsePeerKeyBundle(effectivePeerKey, options.peerUsername);

        // (رفع F6) اعتبارسنجی امضای هویت دیجیتال پساکوانتومی پیام *پیش از*
        // برقراری نشست یا رمزگشایی. کلید تأیید، کلید فرستنده است: برای پیام
        // ورودی کلید ML-DSA-65 مخاطب، برای پیام خودم کلید ML-DSA-65 خودم.
        // امضای نامعتبر همیشه رد می‌شود؛ نبود امضا وقتی فرستنده کلید ML-DSA
        // دارد هم رد می‌شود (فرستنده‌های نسخه فعلی همیشه امضا می‌کنند).
        const senderMldsaPub: Uint8Array | null = isSender
          ? (getMyMLDSAPublicKey(options.myUsername)
              ? base64ToBuf(getMyMLDSAPublicKey(options.myUsername) as string)
              : null)
          : peerBundle.mldsaPub;
        let mldsaVerified = false;
        if (senderMldsaPub) {
          if (!maybeSigB64) {
            return {
              text: '🔒 [پیام پساکوانتومی ML-KEM-768 - امضای هویت ML-DSA-65 ندارد]',
              isEncrypted: true,
              mode: 'PQ-MLKEM-RATCHET',
              ratchetStep: msgStep,
              mldsaVerified: false,
              failed: true,
            };
          }
          try {
            const signData = serializeMessageForSigning({
              roomId,
              step: msgStep,
              kemCipherB64,
              ivB64,
              cipherB64,
            });
            mldsaVerified = ml_dsa65.verify(base64ToBuf(maybeSigB64), signData, senderMldsaPub);
          } catch {
            mldsaVerified = false;
          }
          if (!mldsaVerified) {
            return {
              text: '🔒 [پیام پساکوانتومی ML-KEM-768 - امضای هویت ML-DSA-65 نامعتبر است]',
              isEncrypted: true,
              mode: 'PQ-MLKEM-RATCHET',
              ratchetStep: msgStep,
              mldsaVerified: false,
              failed: true,
            };
          }
        }

        const rootState = await ensurePQRatchetSession(
          options.myUsername,
          roomId,
          effectivePeerKey,
          isIncoming ? kemCipherB64 : undefined,
          options.peerUsername
        );

        if (rootState) {
          // پیام به کدام شکاف نشست تعلق دارد: فعلی یا قبلی (پس از چرخش)؟
          let session = rootState;
          if (rootState.kemCipherTextB64 !== kemCipherB64) {
            if (rootState.previousSession?.kemCipherTextB64 === kemCipherB64) {
              session = rootState.previousSession;
            } else {
              return {
                text: '🔒 [پیام پساکوانتومی ML-KEM-768 - کپسول نشست ناشناخته است]',
                isEncrypted: true,
                mode: 'PQ-MLKEM-RATCHET',
                ratchetStep: msgStep,
                mldsaVerified,
                failed: true,
              };
            }
          }

          // اگر پیام در کش محلی رم موجود است (فقط مسیر نمایش یا پیام خودم — F7)
          if (
            (isSender || options.allowCache !== false) &&
            session.decryptedCache &&
            session.decryptedCache[payloadHashKey]
          ) {
            return {
              text: session.decryptedCache[payloadHashKey],
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
            rootState,
            session,
            msgStep,
            iv,
            cipherBytes,
            payloadHashKey,
            isSender,
            options.allowCache
          );

          if (plainText !== null) {
            savePersistentDecryptedMessage(options.myUsername, roomId, payloadHashKey, plainText);
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

      // (رفع F3) بدون کلید اپوک ذخیره‌شده، پیام قفل می‌ماند؛
      // مشتق قطعی کلید از ورودی‌های عمومی حذف شد.
      if (!fsm.epochs[msgEpoch]) {
        return {
          text: '🔒 [پیام گروهی - کلید اپوک در دسترس نیست]',
          isEncrypted: true,
          mode: 'GROUP-EPOCH-FSM',
          epoch: msgEpoch,
          failed: true,
        };
      }
      const rootKeyBytes = base64ToBuf(fsm.epochs[msgEpoch].rootKeyB64);

      // (رفع F7) Replay پیام گروهی: همان بار (اپوک + IV) نباید دو بار
      // پذیرفته شود. مسیر نمایش پیامِ پیش‌تر رمزگشایی‌شده از کش خوانده
      // می‌شود و به اینجا نمی‌رسد؛ رسیدن به اینجا یعنی تلاش تازه برای
      // رمزگشایی همان بار.
      const epochRec = fsm.epochs[msgEpoch];
      if (epochRec.seenMessageKeys?.includes(payloadHashKey)) {
        return {
          text: '🔒 [پیام گروهی تکراری — Replay رد شد]',
          isEncrypted: true,
          mode: 'GROUP-EPOCH-FSM',
          epoch: msgEpoch,
          failed: true,
        };
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

      const plainText = new TextDecoder().decode(decryptedBuffer);
      if (options?.myUsername) {
        savePersistentDecryptedMessage(options.myUsername, roomId, payloadHashKey, plainText);
      }
      // (رفع F7) ثبت بار تحویل‌شده تا Replay بعدی همین پیام رد شود.
      if (!epochRec.seenMessageKeys) epochRec.seenMessageKeys = [];
      epochRec.seenMessageKeys.push(payloadHashKey);
      if (epochRec.seenMessageKeys.length > 500) {
        epochRec.seenMessageKeys = epochRec.seenMessageKeys.slice(-500);
      }
      saveGroupEpochState(fsm);

      return {
        text: plainText,
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

    if (isEcdh && options?.myUsername && effectivePeerKey) {
      const ecdhKey = await deriveECDHSharedAesKey(
        options.myUsername,
        effectivePeerKey,
        roomId,
        options.peerUsername
      );
      if (ecdhKey) {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as unknown as BufferSource },
          ecdhKey,
          cipherBytes as unknown as BufferSource
        );
        const text = new TextDecoder().decode(decryptedBuffer);
        savePersistentDecryptedMessage(options.myUsername, roomId, payloadHashKey, text);
        return {
          text,
          isEncrypted: true,
          mode: 'ECDH',
          failed: false,
        };
      }
    }

    const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
    if (!manualSecret) {
      // (رفع F4) بدون رمز دستی، پیام PBKDF2 قابل رمزگشایی نیست؛
      // عبارت پیش‌فرض عمومی حذف شد.
      throw new Error('Manual passphrase required for PBKDF2 message.');
    }
    // نخست با تعداد تکرار جدید، سپس با مقدار قدیمی (سازگاری با تاریخچه).
    let decryptedBuffer: ArrayBuffer | null = null;
    for (const iterations of [PBKDF2_ITERATIONS_NEW, PBKDF2_ITERATIONS_LEGACY]) {
      try {
        const pbkdfKey = await derivePbkdf2AesKey(roomId, manualSecret, iterations);
        decryptedBuffer = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as unknown as BufferSource },
          pbkdfKey,
          cipherBytes as unknown as BufferSource
        );
        break;
      } catch {
        decryptedBuffer = null;
      }
    }
    if (!decryptedBuffer) throw new Error('PBKDF2 decrypt failed.');
    const text = new TextDecoder().decode(decryptedBuffer);
    if (options?.myUsername) {
      savePersistentDecryptedMessage(options.myUsername, roomId, payloadHashKey, text);
    }
    return {
      text,
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
