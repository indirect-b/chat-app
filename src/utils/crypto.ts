// سیستم پیشرفته رمزنگاری تماماً پساکوانتومی (Fully Post-Quantum Hybrid ML-KEM-768 + ML-DSA-65 + ECDH P-256)
// به همراه زنجیره راتچت درون‌حافظه‌ای مقاوم در برابر پیام‌های خارج از نوبت و حملات Replay (Out-of-Order Symmetric Ratchet + Zeroization)
// نگهداری کلیدهای خصوصی در IndexedDB با کلیدهای غیرقابل‌استخراج WebCrypto (v: 4, extractable: false)
// امضای دیجیتال هویت FIPS 204 (ML-DSA-65) پیش از رمزگشایی و جلوگیری قطعی از Fail-Open و Downgrade خاموش
// احراز هویت کور مبتنی بر Ristretto255-VOPRF (RFC 9497) و ماشین وضعیت چرخش اپوک گروه (Group Epoch FSM)

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import {
  KEY_STORAGE_VERSION,
  StoredIdentityRecordV4,
  discardLegacyLocalStorageKeys,
  generateNonExtractableEcdhKeyPair,
  generateNonExtractableWrappingKey,
  getCachedPublicKeyMetadataV4,
  getWebCrypto,
  loadIdentityRecordV4,
  normalizeKeystoreUsername,
  resetInMemoryKeyStoreForTests,
  saveIdentityRecordV4,
  unwrapSecretBytes,
  wrapSecretBytes,
} from './keystore';

export { KEY_STORAGE_VERSION } from './keystore';

const E2EE_V1_PREFIX = 'e2ee:v1:';
const E2EE_ECDH_PREFIX = 'e2ee:ecdh:';
const E2EE_PQ_RATCHET_PREFIX = 'e2ee:pq:v2:';
const E2EE_GROUP_EPOCH_PREFIX = 'e2ee:gep:v2:';

const ROOM_KEY_STORAGE_PREFIX = 'chat_e2ee_pass_';
const E2EE_ENABLED_STORAGE_KEY = 'chat_e2ee_enabled';
const VOPRF_TOKEN_PREFIX = 'chat_voprf_token_';

const MAX_SKIP = 100; // حداکثر پرش مجاز برای پیام‌های خارج از نوبت (محافظت در برابر DoS)
const SKIPPED_KEY_TTL_MS = 10 * 60 * 1000; // ۱۰ دقیقه نگهداری کلیدهای پرش‌خورده در RAM
const GROUP_EPOCH_GRACE_BUFFER = 3; // نگهداری ۳ اپوک قبلی برای رمزگشایی پیام‌های در حال پرواز هنگام تغییر اعضا
const PQ_REKEY_AFTER_MESSAGES = 50; // چرخش دوره‌ای نشست راتچت پس از هر ۵۰ پیام ارسالی (Forward Secrecy)
const PBKDF2_ITERATIONS_NEW = 600000; // تعداد تکرار بر اساس استاندارد OWASP برای PBKDF2-HMAC-SHA-256
const PBKDF2_ITERATIONS_LEGACY = 50000; // مقدار پیشین؛ فقط برای رمزگشایی تاریخچه قدیمی
const MAX_VERIFIED_BUNDLE_CACHE = 256;
const MAX_SENT_PLAINTEXT_CACHE = 500;
const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;

export type E2EEErrorCode =
  | 'ENCRYPTION_FAILED'
  | 'DECRYPTION_FAILED'
  | 'INVALID_BUNDLE'
  | 'INVALID_SIGNATURE'
  | 'MISSING_SIGNATURE'
  | 'REPLAY_DETECTED'
  | 'MALFORMED_PAYLOAD'
  | 'MISSING_KEYS'
  | 'MAX_SKIP_EXCEEDED'
  | 'UNVERIFIED_PEER_KEY';

export class E2EEError extends Error {
  public readonly code: E2EEErrorCode;

  constructor(code: E2EEErrorCode, message: string) {
    super(message);
    this.name = 'E2EEError';
    this.code = code;
  }
}

function getSafeLocalStorage(): Storage | null {
  try {
    if (typeof globalThis !== 'undefined' && 'localStorage' in globalThis && globalThis.localStorage) {
      return globalThis.localStorage;
    }
  } catch {
    // ignore
  }
  return null;
}

function getSafeSessionStorage(): Storage | null {
  try {
    if (typeof globalThis !== 'undefined' && 'sessionStorage' in globalThis && globalThis.sessionStorage) {
      return globalThis.sessionStorage;
    }
  } catch {
    // ignore
  }
  return null;
}

export function getStoredPeerPublicKey(peerUsername: string): string | null {
  const ls = getSafeLocalStorage();
  if (!ls) return null;
  try {
    return ls.getItem(`chat_peer_key_${peerUsername}`);
  } catch {
    return null;
  }
}

export function setStoredPeerPublicKey(peerUsername: string, key: string): void {
  const ls = getSafeLocalStorage();
  if (!ls) return;
  try {
    if (key) {
      ls.setItem(`chat_peer_key_${peerUsername}`, key);
    }
  } catch {
    // ignore
  }
}

export interface HybridPublicKeyBundle {
  v: 4 | 3 | 2;
  alg: 'ML-KEM-768+P-256+ML-DSA-65' | 'ML-KEM-768+P-256';
  username?: string;
  ecdhJwk: JsonWebKey;
  mlkemPubB64: string;
  mldsaPubB64?: string; // کلید عمومی هویت پساکوانتومی FIPS 204
  mldsaSigB64?: string; // امضای دیجیتال باندل با ML-DSA-65
  voprfProofTag?: string;
}

interface SkippedKeyEntry {
  mk: Uint8Array;
  timestamp: number;
}

interface RatchetSessionState {
  sendChainKey: Uint8Array;
  recvChainKey: Uint8Array;
  sendStep: number;
  recvStep: number;
  sentSinceRekey: number; // پیام‌های ارسالی از آخرین چرخش کلید
  seenRecvSteps: Set<number>;
  kemCipherTextB64: string; // کپسول ML-KEM-768 برای همگام‌سازی طرف مقابل
  peerKemFingerprint: string;
  skippedKeys: Map<number, SkippedKeyEntry>;
  sessionEpoch?: number;
  previousSession?: RatchetSessionState;
  hkdfSaltVersion?: 'v1' | 'v2';
}

export interface GroupEpochKeyRecord {
  epoch: number;
  rootKey: Uint8Array;
  createdAt: number;
  membersHash: string;
  seenMessageKeys?: string[]; // شناسه پیام‌های تحویل‌شده در این اپوک جهت جلوگیری از Replay
  seenMessageSet?: Set<string>;
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

// نشست‌های راتچت منحصراً در RAM نگهداری می‌شوند و هرگز در localStorage ذخیره نمی‌شوند
const ratchetStateMap = new Map<string, RatchetSessionState>();
// کش محدود درون‌حافظه‌ای پیام‌های ارسالی خود کاربر در همین نشست (هرگز در localStorage ذخیره نمی‌شود)
const sentPlaintextMemoryCache = new Map<string, string>();
// کش ایمن باندل‌های ازپیش‌تأییدشده برای مسیرهای غیرحساس UI (در ایجاد نشست و رمزگشایی همیشه skipCache: true است)
const verifiedBundleCache = new Map<string, ParsedPeerKeyBundle>();
let verifiedBundleCacheHits = 0;

export function bufToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuf(base64: string): Uint8Array {
  if (typeof base64 !== 'string' || base64.length === 0 || base64.length % 4 !== 0 || !BASE64_REGEX.test(base64)) {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid Base64 encoding');
  }
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    if (bufToBase64(bytes) !== base64) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Non-canonical Base64 encoding');
    }
    return bytes;
  } catch (err) {
    if (err instanceof E2EEError) throw err;
    throw new E2EEError('MALFORMED_PAYLOAD', 'Base64 decoding failed');
  }
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

export const HKDF_RATCHET_SALT_V2 = new TextEncoder().encode('PQ-MPRBA-RATCHET-SALT-v2');

/**
 * مشتق‌سازی زنجیره متقارن KDF_CK (ساختار استاندارد راتچت با HKDF-SHA256)
 * تولید کلید زنجیره بعدی (Next Chain Key) و کلید یک‌بارمصرف پیام (Message Key)
 * با نمک تفکیک دامنه (Domain Separation Salt v2) برای نشست‌های جدید (I3)
 */
function kdfChainStep(
  chainKey: Uint8Array,
  saltVersion: 'v1' | 'v2' = 'v2'
): { nextChainKey: Uint8Array; messageKey: Uint8Array } {
  const salt = saltVersion === 'v1' ? undefined : HKDF_RATCHET_SALT_V2;
  const nextChainKey = hkdf(sha256, chainKey, salt, new TextEncoder().encode('PQ-Ratchet-NextChain-v2'), 32);
  const messageKey = hkdf(sha256, chainKey, salt, new TextEncoder().encode('PQ-Ratchet-MsgKey-v2'), 32);
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

/**
 * دریافت کلید عمومی ML-DSA-65 کاربر از حافظه متادیتای عمومی (بدون دسترسی به کلید خصوصی)
 */
export function getMyMLDSAPublicKey(myUsername: string): string | null {
  const meta = getCachedPublicKeyMetadataV4(myUsername);
  return meta?.mldsaPublicKeyB64 || null;
}

export function getMyMLKEMPublicKey(myUsername: string): string | null {
  const meta = getCachedPublicKeyMetadataV4(myUsername);
  return meta?.mlkemPublicKeyB64 || null;
}

export async function withUnwrappedMLDSASecretKey<T>(
  myUsername: string,
  fn: (secretKey: Uint8Array) => Promise<T> | T
): Promise<T> {
  const record = await loadIdentityRecordV4(myUsername);
  if (!record) {
    throw new E2EEError('MISSING_KEYS', 'ML-DSA-65 identity key is not initialized in IndexedDB');
  }
  const secretKey = await unwrapSecretBytes(
    record.wrappingKey,
    record.username,
    'ML-DSA-65',
    record.mldsaSecretWrapped
  );
  try {
    return await fn(secretKey);
  } finally {
    zeroizeBuffer(secretKey);
  }
}

async function withUnwrappedMLKEMSecretKey<T>(
  myUsername: string,
  fn: (secretKey: Uint8Array) => Promise<T> | T
): Promise<T> {
  const record = await loadIdentityRecordV4(myUsername);
  if (!record) {
    throw new E2EEError('MISSING_KEYS', 'ML-KEM-768 decapsulation key is not initialized in IndexedDB');
  }
  const secretKey = await unwrapSecretBytes(
    record.wrappingKey,
    record.username,
    'ML-KEM-768',
    record.mlkemSecretWrapped
  );
  try {
    return await fn(secretKey);
  } finally {
    zeroizeBuffer(secretKey);
  }
}

/**
 * تولید یا بازیابی باندل کلید عمومی ترکیبی تماماً پساکوانتومی (v: 4)
 * - کلیدهای خصوصی ECDH P-256 و کلید پوششی AES-GCM با `extractable: false` در IndexedDB ذخیره می‌شوند.
 * - کلیدهای خصوصی ML-KEM-768 و ML-DSA-65 با CSPRNG تولید، با کلید غیرقابل‌استخراج پوشانده و در IndexedDB ذخیره می‌شوند.
 * - در صورت وجود کلیدهای قدیمی (v: 2 یا v: 3) در localStorage، به‌طور کامل حذف و کلید تازه تولید می‌شود.
 */
export async function ensureUserHybridKeyPair(username: string): Promise<string> {
  const normUser = normalizeKeystoreUsername(username);
  if (!normUser) {
    throw new E2EEError('MISSING_KEYS', 'Username cannot be empty');
  }

  try {
    const webCrypto = getWebCrypto();

    // مهاجرت و حذف کامل کلیدهای خصوصی قدیمی (v2/v3) از localStorage
    discardLegacyLocalStorageKeys(normUser);

    let record = await loadIdentityRecordV4(normUser);

    if (!record) {
      const wrappingKey = await generateNonExtractableWrappingKey();
      const { publicJwk: ecdhPublicJwk, privateKey: ecdhPrivateKey } =
        await generateNonExtractableEcdhKeyPair();

      const kemSeed = webCrypto.getRandomValues(new Uint8Array(64));
      const pqKeys = ml_kem768.keygen(kemSeed);
      zeroizeBuffer(kemSeed);

      let mlkemSecretWrapped;
      try {
        mlkemSecretWrapped = await wrapSecretBytes(
          wrappingKey,
          normUser,
          'ML-KEM-768',
          pqKeys.secretKey
        );
      } finally {
        zeroizeBuffer(pqKeys.secretKey);
      }

      const dsaSeed = webCrypto.getRandomValues(new Uint8Array(32));
      const dsaKeys = ml_dsa65.keygen(dsaSeed);
      zeroizeBuffer(dsaSeed);

      let mldsaSecretWrapped;
      try {
        mldsaSecretWrapped = await wrapSecretBytes(
          wrappingKey,
          normUser,
          'ML-DSA-65',
          dsaKeys.secretKey
        );
      } finally {
        zeroizeBuffer(dsaKeys.secretKey);
      }

      const newRecord: StoredIdentityRecordV4 = {
        v: KEY_STORAGE_VERSION,
        username: normUser,
        createdAt: Date.now(),
        ecdhPublicJwk,
        ecdhPrivateKey,
        wrappingKey,
        mlkemPublicKeyB64: bufToBase64(pqKeys.publicKey),
        mlkemSecretWrapped,
        mldsaPublicKeyB64: bufToBase64(dsaKeys.publicKey),
        mldsaSecretWrapped,
      };

      await saveIdentityRecordV4(newRecord);
      record = newRecord;
    }

    // امضای محتوای باندل کلید توسط کلید خصوصی ML-DSA-65 هویت کاربر (از داخل IndexedDB)
    const signTarget = serializeBundleForSigning({
      username: normUser,
      ecdhJwk: record.ecdhPublicJwk,
      mlkemPubB64: record.mlkemPublicKeyB64,
    });

    const mldsaSigB64 = await withUnwrappedMLDSASecretKey(normUser, mldsaSec => {
      const sig = ml_dsa65.sign(signTarget, mldsaSec);
      return bufToBase64(sig);
    });

    const voprfRec = getStoredVoprfToken(normUser);
    const bundle: HybridPublicKeyBundle = {
      v: KEY_STORAGE_VERSION,
      alg: 'ML-KEM-768+P-256+ML-DSA-65',
      username: normUser,
      ecdhJwk: record.ecdhPublicJwk,
      mlkemPubB64: record.mlkemPublicKeyB64,
      mldsaPubB64: record.mldsaPublicKeyB64,
      mldsaSigB64,
      voprfProofTag: voprfRec?.anonymousTokenId,
    };

    return JSON.stringify(bundle);
  } catch (err: unknown) {
    if (err instanceof E2EEError) throw err;
    throw new E2EEError(
      'MISSING_KEYS',
      `Failed to generate or load hybrid key pair: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

export async function ensureUserECDHKeyPair(username: string): Promise<string> {
  return ensureUserHybridKeyPair(username);
}

export interface ParsedPeerKeyBundle {
  v?: number;
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

function makeBundleCacheKey(peerPublicKeyStr: string, expectedPeerUsername?: string): string {
  const normPeer = expectedPeerUsername ? normalizeKeystoreUsername(expectedPeerUsername) : '';
  const digest = bufToBase64(sha256(new TextEncoder().encode(peerPublicKeyStr)));
  return `${digest}|${normPeer}`;
}

function cloneParsedBundle(b: ParsedPeerKeyBundle): ParsedPeerKeyBundle {
  return {
    ...b,
    ecdhJwk: b.ecdhJwk ? { ...b.ecdhJwk } : null,
    mlkemPub: b.mlkemPub ? new Uint8Array(b.mlkemPub) : null,
    mldsaPub: b.mldsaPub ? new Uint8Array(b.mldsaPub) : null,
  };
}

export function getVerifiedBundleCacheStats(): { size: number; hits: number } {
  return { size: verifiedBundleCache.size, hits: verifiedBundleCacheHits };
}

export function clearVerifiedBundleCache(): void {
  verifiedBundleCache.clear();
  verifiedBundleCacheHits = 0;
}

export function parsePeerKeyBundle(
  peerPublicKeyStr: string | null | undefined,
  expectedPeerUsername?: string,
  options?: { skipCache?: boolean }
): ParsedPeerKeyBundle {
  const result: ParsedPeerKeyBundle = {
    v: undefined,
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

  if (!peerPublicKeyStr || typeof peerPublicKeyStr !== 'string') return result;

  const cacheKey = options?.skipCache ? '' : makeBundleCacheKey(peerPublicKeyStr, expectedPeerUsername);
  if (cacheKey) {
    const cached = verifiedBundleCache.get(cacheKey);
    if (cached) {
      verifiedBundleCacheHits++;
      return cloneParsedBundle(cached);
    }
  }

  try {
    const parsed = JSON.parse(peerPublicKeyStr);
    if (!parsed || typeof parsed !== 'object') return result;

    if ((parsed.v === 4 || parsed.v === 3 || parsed.v === 2) && parsed.ecdhJwk && typeof parsed.ecdhJwk === 'object') {
      result.v = parsed.v;
      result.ecdhJwk = parsed.ecdhJwk;
      result.username = typeof parsed.username === 'string' ? parsed.username : undefined;

      // اگر نام کاربری مورد انتظار مشخص شده باشد و با فیلد username باندل همخوانی نداشته باشد، رد کن
      if (
        expectedPeerUsername &&
        result.username &&
        normalizeKeystoreUsername(result.username) !== normalizeKeystoreUsername(expectedPeerUsername)
      ) {
        result.isMldsaSignatureInvalid = true;
        return result;
      }

      if (typeof parsed.mlkemPubB64 === 'string' && parsed.mlkemPubB64.length > 0) {
        const kemBytes = base64ToBuf(parsed.mlkemPubB64);
        if (kemBytes.byteLength !== ml_kem768.lengths.publicKey) {
          result.isMldsaSignatureInvalid = true;
          return result;
        }
        result.mlkemPub = kemBytes;
        result.hasMLKEM = true;
      }

      if (typeof parsed.mldsaPubB64 === 'string' && parsed.mldsaPubB64.length > 0) {
        const dsaBytes = base64ToBuf(parsed.mldsaPubB64);
        if (dsaBytes.byteLength !== ml_dsa65.lengths.publicKey) {
          result.isMldsaSignatureInvalid = true;
          return result;
        }
        result.mldsaPub = dsaBytes;
        result.hasMLDSA = true;
      }

      if (typeof parsed.mldsaSigB64 === 'string' && parsed.mldsaSigB64.length > 0) {
        result.mldsaSigB64 = parsed.mldsaSigB64;
      }

      // اعتبارسنجی امضای دیجیتال هویت با الگوریتم FIPS 204 ML-DSA-65
      if (result.hasMLKEM && result.hasMLDSA && result.mldsaSigB64 && result.mldsaPub) {
        try {
          const sigBytes = base64ToBuf(result.mldsaSigB64);
          if (sigBytes.byteLength !== ml_dsa65.lengths.signature) {
            result.isMldsaSignatureInvalid = true;
            return result;
          }
          const targetUsername = expectedPeerUsername
            ? normalizeKeystoreUsername(expectedPeerUsername)
            : normalizeKeystoreUsername(result.username || '');
          const target = serializeBundleForSigning({
            username: targetUsername,
            ecdhJwk: result.ecdhJwk,
            mlkemPubB64: parsed.mlkemPubB64,
          });

          const valid = ml_dsa65.verify(sigBytes, target, result.mldsaPub);
          if (valid) {
            result.isMldsaVerified = true;
            result.isFullyPostQuantum = true;
            if (cacheKey) {
              if (verifiedBundleCache.size >= MAX_VERIFIED_BUNDLE_CACHE) {
                const firstKey = verifiedBundleCache.keys().next().value;
                if (firstKey !== undefined) verifiedBundleCache.delete(firstKey);
              }
              verifiedBundleCache.set(cacheKey, cloneParsedBundle(result));
            }
          } else {
            result.isMldsaSignatureInvalid = true;
          }
        } catch {
          result.isMldsaSignatureInvalid = true;
        }
      }
      return result;
    }

    if (parsed.kty === 'EC' && parsed.crv === 'P-256' && typeof parsed.x === 'string' && typeof parsed.y === 'string') {
      result.ecdhJwk = parsed;
      return result;
    }
  } catch {
    // malformed JSON or base64
  }
  return result;
}

/**
 * Strict key bundle parser that throws E2EEError on any malformed, incomplete, or unverified bundle.
 */
export function parsePeerKeyBundleStrict(
  peerPublicKeyStr: string | null | undefined,
  expectedPeerUsername?: string,
  options?: { skipCache?: boolean }
): ParsedPeerKeyBundle {
  if (!peerPublicKeyStr || typeof peerPublicKeyStr !== 'string') {
    throw new E2EEError('INVALID_BUNDLE', 'Peer public key bundle is missing');
  }
  const bundle = parsePeerKeyBundle(peerPublicKeyStr, expectedPeerUsername, options);
  if (bundle.isMldsaSignatureInvalid) {
    throw new E2EEError('INVALID_SIGNATURE', 'Peer ML-DSA-65 key bundle signature is invalid');
  }
  if (!bundle.isFullyPostQuantum || !bundle.ecdhJwk || !bundle.mlkemPub || !bundle.mldsaPub) {
    throw new E2EEError('INVALID_BUNDLE', 'Peer key bundle is not a valid verified PQ-MPRBA bundle');
  }
  return bundle;
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
export function hasActiveGroupEpochKey(roomId: string): boolean {
  const cleanId = roomId.startsWith('group__') ? roomId.slice('group__'.length) : roomId;
  const fsm = groupFsmMap.get(cleanId);
  if (!fsm) return false;
  const epochRec = fsm.epochs[fsm.currentEpoch];
  return !!(epochRec && epochRec.rootKey && epochRec.rootKey.byteLength === 32);
}

export function getGroupSecurityBadge(roomId: string, currentEpoch: number): { isPQ: boolean; badge: string; tooltip: string } {
  if (hasActiveGroupEpochKey(roomId) && currentEpoch > 0) {
    return {
      isPQ: true,
      badge: `🔒 Epoch #${currentEpoch}`,
      tooltip: 'رمزنگاری گروهی پساکوانتومی فعال و دارای کلید اپوک معتبر است',
    };
  }
  return {
    isPQ: false,
    badge: '⚠️ بدون کلید اپوک',
    tooltip: 'کلید اپوک برای این گروه هنوز ایجاد یا دریافت نشده است',
  };
}

export function getRoomPQStatus(options: {
  roomId: string;
  isGroup: boolean;
  e2eeActive?: boolean;
  myUsername: string;
  peerPublicKey?: string | null;
  peerUsername?: string;
  customSecret?: string;
}): RoomPQSecurityStatus {
  if (options.e2eeActive === false) {
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
    tooltip: 'رمزنگاری هیبریدی پساکوانتومی (Hybrid PQ: ML-KEM-768 + ECDH P-256) با امضای هویت تأییدشده‌ی ML-DSA-65 (FIPS 204)',
  };
}

/**
 * استخراج بیت‌های خام مشترک ECDH P-256 با استفاده مستقیم از کلید خصوصی غیرقابل‌استخراج WebCrypto در IndexedDB
 */
async function deriveECDHSharedBits(
  myUsername: string,
  peerEcdhJwk: JsonWebKey
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const normUser = normalizeKeystoreUsername(myUsername);
  let record = await loadIdentityRecordV4(normUser);
  if (!record) {
    await ensureUserHybridKeyPair(normUser);
    record = await loadIdentityRecordV4(normUser);
  }
  if (!record || !record.ecdhPrivateKey) {
    throw new E2EEError('MISSING_KEYS', 'Non-extractable ECDH private key not found');
  }

  try {
    const peerPublicKey = await webCrypto.subtle.importKey(
      'jwk',
      peerEcdhJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const bits = await webCrypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey },
      record.ecdhPrivateKey,
      256
    );
    return new Uint8Array(bits);
  } catch {
    throw new E2EEError('INVALID_BUNDLE', 'ECDH P-256 key derivation failed');
  }
}

async function deriveECDHSharedAesKey(
  myUsername: string,
  peerPublicKeyStr: string,
  roomId: string,
  peerUsername?: string
): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const { ecdhJwk } = parsePeerKeyBundle(peerPublicKeyStr, undefined, { skipCache: true });
  if (!ecdhJwk) {
    throw new E2EEError('INVALID_BUNDLE', 'Peer ECDH public key is missing or invalid');
  }
  const bits = await deriveECDHSharedBits(myUsername, ecdhJwk);
  try {
    // خروجی خام ECDH مستقیم به‌عنوان کلید AES استفاده نمی‌شود؛ مشتق‌سازی با HKDF انجام می‌شود؛
    // نخست از HKDF با salt شناسه اتاق و info وابسته به هویت مخاطب می‌گذرد،
    // تا کلید هر اتاق جدا باشد.
    const keyBytes = hkdf(
      sha256,
      bits,
      new TextEncoder().encode(roomId),
      new TextEncoder().encode(`ECDH-Legacy-AES-v2:${peerUsername || ''}`),
      32
    );
    return await webCrypto.subtle.importKey(
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

function getRatchetMapKey(myUsername: string, roomId: string): string {
  return `${normalizeKeystoreUsername(myUsername)}::${roomId}`;
}

function pruneExpiredSkippedKeys(state: RatchetSessionState): void {
  const now = Date.now();
  for (const [step, entry] of state.skippedKeys.entries()) {
    if (now - entry.timestamp > SKIPPED_KEY_TTL_MS) {
      zeroizeBuffer(entry.mk);
      state.skippedKeys.delete(step);
    }
  }
}

function zeroizeRatchetState(state: RatchetSessionState): void {
  zeroizeBuffer(state.sendChainKey);
  zeroizeBuffer(state.recvChainKey);
  for (const entry of state.skippedKeys.values()) {
    zeroizeBuffer(entry.mk);
  }
  state.skippedKeys.clear();
  state.seenRecvSteps.clear();
  if (state.previousSession) {
    zeroizeRatchetState(state.previousSession);
    state.previousSession = undefined;
  }
}

export function clearRatchetSession(myUsername: string, roomId: string): void {
  const key = getRatchetMapKey(myUsername, roomId);
  const existing = ratchetStateMap.get(key);
  if (existing) {
    zeroizeRatchetState(existing);
    ratchetStateMap.delete(key);
  }
  // Remove any legacy localStorage ratchet state if present
  const ls = getSafeLocalStorage();
  if (ls) {
    try {
      ls.removeItem(`chat_pq_ratchet_${myUsername}_${roomId}`);
      ls.removeItem(`chat_pq_ratchet_${normalizeKeystoreUsername(myUsername)}_${roomId}`);
    } catch {
      // ignore
    }
  }
}

export function resetAllCryptoStateForTests(): void {
  for (const state of ratchetStateMap.values()) {
    zeroizeRatchetState(state);
  }
  ratchetStateMap.clear();
  sentPlaintextMemoryCache.clear();
  for (const gsm of groupFsmMap.values()) {
    for (const rec of Object.values(gsm.epochs)) {
      zeroizeBuffer(rec.rootKey);
    }
  }
  groupFsmMap.clear();
  clearVerifiedBundleCache();
  resetInMemoryKeyStoreForTests();
}

function loadRatchetState(myUsername: string, roomId: string): RatchetSessionState | null {
  const key = getRatchetMapKey(myUsername, roomId);
  const state = ratchetStateMap.get(key) || null;
  if (state) {
    pruneExpiredSkippedKeys(state);
  }
  return state;
}

function saveRatchetState(myUsername: string, roomId: string, state: RatchetSessionState): void {
  const key = getRatchetMapKey(myUsername, roomId);
  ratchetStateMap.set(key, state);
}

function saveSentPlaintextInMemory(myUsername: string, roomId: string, payloadHashKey: string, plainText: string): void {
  const cacheKey = `${normalizeKeystoreUsername(myUsername)}::${roomId}::${payloadHashKey}`;
  if (sentPlaintextMemoryCache.size >= MAX_SENT_PLAINTEXT_CACHE) {
    const first = sentPlaintextMemoryCache.keys().next().value;
    if (first !== undefined) sentPlaintextMemoryCache.delete(first);
  }
  sentPlaintextMemoryCache.set(cacheKey, plainText);
}

function getSentPlaintextFromMemory(myUsername: string, roomId: string, payloadHashKey: string): string | null {
  const cacheKey = `${normalizeKeystoreUsername(myUsername)}::${roomId}::${payloadHashKey}`;
  return sentPlaintextMemoryCache.get(cacheKey) ?? null;
}

/**
 * مقداردهی اولیه یا بازیابی نشست راتچت پساکوانتومی درون‌حافظه‌ای (Hybrid ML-KEM-768 + ECDH P-256)
 * نکته امنیتی (Item 4.1): هنگام ایجاد نشست، اعتبارسنجی امضای ML-DSA-65 باندل همیشه به‌صورت تازه (`skipCache: true`) اجرا می‌شود.
 */
async function ensurePQRatchetSession(
  myUsername: string,
  roomId: string,
  peerPublicKeyStr: string,
  incomingKemCipherB64?: string,
  peerUsername?: string,
  forceFreshSession = false
): Promise<RatchetSessionState> {
  // هرگز در زمان ایجاد نشست امضا را از کش نخوان (always verify fresh)
  const bundle = parsePeerKeyBundleStrict(peerPublicKeyStr, peerUsername, { skipCache: true });
  const ecdhJwk = bundle.ecdhJwk!;
  const mlkemPub = bundle.mlkemPub!;

  const normMyUser = normalizeKeystoreUsername(myUsername);
  const existing = loadRatchetState(normMyUser, roomId);
  const peerFingerprint = bufToBase64(sha256(mlkemPub)).slice(0, 16);

  // اگر کپسول جدیدی از سمت مقابل آمده که نیاز به Decapsulation دارد
  if (incomingKemCipherB64 && (!existing || existing.kemCipherTextB64 !== incomingKemCipherB64 || existing.peerKemFingerprint !== peerFingerprint)) {
    // اگر کپسول ورودی با نشست جدیدتر (previousSession که sessionEpoch بالاتری دارد) مطابقت دارد،
    // آن را با حفظ کامل seenRecvSteps بازیابی کن تا حمله Replay از طریق تناوب کپسول (H1) مسدود شود
    if (
      existing &&
      existing.previousSession &&
      existing.previousSession.kemCipherTextB64 === incomingKemCipherB64 &&
      existing.previousSession.peerKemFingerprint === peerFingerprint &&
      (existing.previousSession.sessionEpoch ?? 0) > (existing.sessionEpoch ?? 0)
    ) {
      const restored = existing.previousSession;
      restored.previousSession = existing;
      existing.previousSession = undefined;
      saveRatchetState(normMyUser, roomId, restored);
      return restored;
    }

    const cipherBytes = base64ToBuf(incomingKemCipherB64);
    if (cipherBytes.byteLength !== ml_kem768.lengths.cipherText) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid ML-KEM-768 ciphertext length');
    }

    const ecdhSecret = await deriveECDHSharedBits(normMyUser, ecdhJwk);
    let pqSharedSecret: Uint8Array | null = null;
    let combinedInput: Uint8Array | null = null;
    let rootKey: Uint8Array | null = null;

    try {
      pqSharedSecret = await withUnwrappedMLKEMSecretKey(normMyUser, mySecretKey =>
        ml_kem768.decapsulate(cipherBytes, mySecretKey)
      );

      combinedInput = new Uint8Array(ecdhSecret.length + pqSharedSecret.length);
      combinedInput.set(ecdhSecret, 0);
      combinedInput.set(pqSharedSecret, ecdhSecret.length);

      rootKey = hkdf(
        sha256,
        combinedInput,
        new TextEncoder().encode(roomId),
        new TextEncoder().encode('PQ-Hybrid-RootKey-v2'),
        32
      );

      const sortedUsers = roomId.split('__').map(u => normalizeKeystoreUsername(u)).sort();
      const amIFirst = normMyUser === sortedUsers[0];
      const chainA = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Alpha'), 32);
      const chainB = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Beta'), 32);

      const sendChain = amIFirst ? chainA : chainB;
      const recvChain = amIFirst ? chainB : chainA;

      const isRevertingToPrevious = existing?.previousSession?.kemCipherTextB64 === incomingKemCipherB64;
      const targetEpoch = isRevertingToPrevious
        ? (existing?.previousSession?.sessionEpoch ?? 0)
        : (existing?.sessionEpoch ?? 0) + 1;

      if (existing && existing.previousSession) {
        zeroizeRatchetState(existing.previousSession);
        existing.previousSession = undefined;
      }

      const newState: RatchetSessionState = {
        sendChainKey: sendChain,
        recvChainKey: recvChain,
        sendStep: 0,
        recvStep: 0,
        sentSinceRekey: 0,
        seenRecvSteps: new Set<number>(),
        kemCipherTextB64: incomingKemCipherB64,
        peerKemFingerprint: peerFingerprint,
        skippedKeys: new Map<number, SkippedKeyEntry>(),
        sessionEpoch: targetEpoch,
        previousSession: existing || undefined,
        hkdfSaltVersion: 'v2',
      };

      saveRatchetState(normMyUser, roomId, newState);
      return newState;
    } catch (err) {
      if (err instanceof E2EEError) throw err;
      throw new E2EEError('DECRYPTION_FAILED', 'Failed to establish PQ ratchet session from incoming KEM ciphertext');
    } finally {
      zeroizeBuffer(ecdhSecret);
      zeroizeBuffer(pqSharedSecret);
      zeroizeBuffer(combinedInput);
      zeroizeBuffer(rootKey);
    }
  }

  if (!forceFreshSession && existing && existing.peerKemFingerprint === peerFingerprint) {
    return existing;
  }

  // ایجاد کپسول جدید ML-KEM-768 با آنتروپی تصادفی CSPRNG
  const ecdhSecret = await deriveECDHSharedBits(normMyUser, ecdhJwk);
  let pqSharedSecret: Uint8Array | null = null;
  let combinedInput: Uint8Array | null = null;
  let rootKey: Uint8Array | null = null;

  try {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(mlkemPub);
    pqSharedSecret = sharedSecret;

    combinedInput = new Uint8Array(ecdhSecret.length + pqSharedSecret.length);
    combinedInput.set(ecdhSecret, 0);
    combinedInput.set(pqSharedSecret, ecdhSecret.length);

    rootKey = hkdf(
      sha256,
      combinedInput,
      new TextEncoder().encode(roomId),
      new TextEncoder().encode('PQ-Hybrid-RootKey-v2'),
      32
    );

    const sortedUsers = roomId.split('__').map(u => normalizeKeystoreUsername(u)).sort();
    const amIFirst = normMyUser === sortedUsers[0];
    const chainA = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Alpha'), 32);
    const chainB = hkdf(sha256, rootKey, undefined, new TextEncoder().encode('Chain-Beta'), 32);

    const sendChain = amIFirst ? chainA : chainB;
    const recvChain = amIFirst ? chainB : chainA;

    if (existing && existing.previousSession) {
      zeroizeRatchetState(existing.previousSession);
      existing.previousSession = undefined;
    }

    const newState: RatchetSessionState = {
      sendChainKey: sendChain,
      recvChainKey: recvChain,
      sendStep: 0,
      recvStep: 0,
      sentSinceRekey: 0,
      seenRecvSteps: new Set<number>(),
      kemCipherTextB64: bufToBase64(cipherText),
      peerKemFingerprint: peerFingerprint,
      skippedKeys: new Map<number, SkippedKeyEntry>(),
      sessionEpoch: (existing?.sessionEpoch ?? 0) + 1,
      previousSession: existing || undefined,
      hkdfSaltVersion: 'v2',
    };

    saveRatchetState(normMyUser, roomId, newState);
    return newState;
  } catch (err) {
    if (err instanceof E2EEError) throw err;
    throw new E2EEError('ENCRYPTION_FAILED', 'Failed to encapsulate ML-KEM-768 session key');
  } finally {
    zeroizeBuffer(ecdhSecret);
    zeroizeBuffer(pqSharedSecret);
    zeroizeBuffer(combinedInput);
    zeroizeBuffer(rootKey);
  }
}

/**
 * رمزگشایی پیام در زنجیره راتچت با پشتیبانی از پیام‌های خارج از نوبت، محافظت قطعی در برابر Replay، و Zeroization فوری
 */
async function ratchetDecryptWithSkippedKeys(
  state: RatchetSessionState,
  msgStep: number,
  iv: Uint8Array,
  cipherBytes: Uint8Array
): Promise<string> {
  const webCrypto = getWebCrypto();
  pruneExpiredSkippedKeys(state);

  // محافظت قطعی در برابر Replay Attack
  if (state.seenRecvSteps.has(msgStep)) {
    throw new E2EEError('REPLAY_DETECTED', `Replayed ratchet step ${msgStep} rejected`);
  }

  let messageKeyBytes: Uint8Array | null = null;
  let usedSkippedKey = false;
  let newRecvChain: Uint8Array | null = null;
  const newlySkipped = new Map<number, SkippedKeyEntry>();
  let targetRecvStep = state.recvStep;

  if (msgStep < state.recvStep) {
    const skipped = state.skippedKeys.get(msgStep);
    if (!skipped) {
      throw new E2EEError('REPLAY_DETECTED', `Ratchet step ${msgStep} already consumed or expired`);
    }
    messageKeyBytes = new Uint8Array(skipped.mk);
    usedSkippedKey = true;
  } else {
    if (msgStep - state.recvStep > MAX_SKIP) {
      throw new E2EEError('MAX_SKIP_EXCEEDED', `Ratchet jump ${msgStep - state.recvStep} exceeds MAX_SKIP (${MAX_SKIP})`);
    }

    let currentRecvChain: Uint8Array = new Uint8Array(state.recvChainKey);

    while (targetRecvStep < msgStep) {
      const { nextChainKey, messageKey } = kdfChainStep(currentRecvChain, state.hkdfSaltVersion);
      zeroizeBuffer(currentRecvChain);
      currentRecvChain = nextChainKey;

      newlySkipped.set(targetRecvStep, {
        mk: messageKey,
        timestamp: Date.now(),
      });
      targetRecvStep++;
    }

    const { nextChainKey, messageKey } = kdfChainStep(currentRecvChain, state.hkdfSaltVersion);
    zeroizeBuffer(currentRecvChain);
    newRecvChain = nextChainKey;
    targetRecvStep++;
    messageKeyBytes = messageKey;
  }

  try {
    const aesKey = await webCrypto.subtle.importKey(
      'raw',
      messageKeyBytes as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decryptedBuffer = await webCrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      aesKey,
      cipherBytes as unknown as BufferSource
    );

    const plainText = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBuffer);

    // فقط پس از موفقیت کامل AES-GCM Auth Tag، وضعیت راتچت را commit کن و کلید استفاده‌شده را بسوزان
    if (usedSkippedKey) {
      const entry = state.skippedKeys.get(msgStep);
      if (entry) {
        zeroizeBuffer(entry.mk);
        state.skippedKeys.delete(msgStep);
      }
    } else if (newRecvChain) {
      zeroizeBuffer(state.recvChainKey);
      state.recvChainKey = newRecvChain;
      newRecvChain = null;
      state.recvStep = targetRecvStep;
      for (const [step, entry] of newlySkipped.entries()) {
        state.skippedKeys.set(step, entry);
      }
      newlySkipped.clear();
    }

    state.seenRecvSteps.add(msgStep);
    return plainText;
  } catch (err) {
    // در صورت خطا، هیچ تغییری در وضعیت راتچت commit نمی‌شود و بافرهای موقت zeroize می‌گردند
    zeroizeBuffer(newRecvChain);
    for (const entry of newlySkipped.values()) {
      zeroizeBuffer(entry.mk);
    }
    newlySkipped.clear();
    if (err instanceof E2EEError) throw err;
    throw new E2EEError('DECRYPTION_FAILED', 'AES-GCM authentication or decryption failed');
  } finally {
    // Zeroization قطعی کلید پیام در RAM بلافاصله پس از رمزگشایی
    zeroizeBuffer(messageKeyBytes);
  }
}

// ============================================================================
// لایه ۲: پروتکل احراز هویت کور Ristretto255-VOPRF (RFC 9497)
// ============================================================================

export function getStoredVoprfToken(username: string): VoprfBlindTokenRecord | null {
  const ls = getSafeLocalStorage();
  if (!ls) return null;
  try {
    const raw = ls.getItem(`${VOPRF_TOKEN_PREFIX}${normalizeKeystoreUsername(username)}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export async function acquireBlindedIdentityToken(
  username: string
): Promise<VoprfBlindTokenRecord | null> {
  const normUser = normalizeKeystoreUsername(username);
  const existing = getStoredVoprfToken(normUser);
  if (existing && existing.verifiedDleq) {
    return existing;
  }

  try {
    const rawInput = new TextEncoder().encode(`blind-identity::${normUser}::v2`);
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

    const ls = getSafeLocalStorage();
    if (ls) {
      ls.setItem(`${VOPRF_TOKEN_PREFIX}${normUser}`, JSON.stringify(record));
    }
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
 * کلید اپوک گروه هرگز به‌صورت قطعی از ورودی‌های عمومی مشتق نمی‌شود.
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
  const webCrypto = getWebCrypto();
  const epochKey = webCrypto.getRandomValues(new Uint8Array(32));
  const keys: Record<string, string> = {};
  const missing: string[] = [];
  for (const [username, bundle] of Object.entries(memberBundles)) {
    if (bundle && bundle.isFullyPostQuantum && bundle.mlkemPub) {
      try {
        // کپسوله‌سازی ML-KEM-768 با کوین‌های تصادفی تازه؛ کلید اپوک با
        // کلید مشتق‌شده از Secret مشترک (HKDF با دامنهٔ نام گیرنده) و
        // AES-256-GCM پیچیده می‌شود.
        const enc = ml_kem768.encapsulate(bundle.mlkemPub); // کوین‌های تصادفی تازه
        const wrapKey = hkdf(
          sha256,
          enc.sharedSecret,
          undefined,
          new TextEncoder().encode(`Group-Epoch-Wrap-v1:${username}`),
          32
        );
        const iv = webCrypto.getRandomValues(new Uint8Array(12));
        const aesKey = await webCrypto.subtle.importKey(
          'raw',
          wrapKey as unknown as BufferSource,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt']
        );
        const wrapped = await webCrypto.subtle.encrypt(
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

/** باز کردن کپسول کلید اپوک گروه با کلید خصوصی ML-KEM-768 خود کاربر (IndexedDB v4). */
export async function decapsulateGroupEpochKey(
  myUsername: string,
  wrappedB64: string
): Promise<string | null> {
  try {
    const parts = wrappedB64.split(':');
    if (parts.length !== 3) return null;
    const [ctB64, ivB64, wrappedKeyB64] = parts;
    const webCrypto = getWebCrypto();
    const shared = await withUnwrappedMLKEMSecretKey(
      normalizeKeystoreUsername(myUsername),
      mySecretKey => ml_kem768.decapsulate(base64ToBuf(ctB64), mySecretKey)
    );
    const wrapKey = hkdf(
      sha256,
      shared,
      undefined,
      new TextEncoder().encode(`Group-Epoch-Wrap-v1:${myUsername}`),
      32
    );
    zeroizeBuffer(shared);
    const aesKey = await webCrypto.subtle.importKey(
      'raw',
      wrapKey as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    zeroizeBuffer(wrapKey);
    const plain = await webCrypto.subtle.decrypt(
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

  // بدون بسته کلید اپوک، هیچ کلیدی ساخته نمی‌شود؛ اپوک ۱ هم
  // باید از طریق بسته ML-KEM برسد. تا آن زمان پیام گروهی ارسال نمی‌شود.
  const initial: GroupEpochState = {
    groupId,
    currentEpoch: 1,
    status: 'STABLE',
    epochs: {},
    pendingQueue: [],
  };
  groupFsmMap.set(groupId, initial);
  return initial;
}

/**
 * چرخش اتمیک اپوک گروه (Atomic Group Epoch Rotation) هنگام تغییر اعضا
 * نگه‌داشتن کلیدهای ۳ اپوک قبلی در Grace Buffer در RAM و Zeroization اپوک‌های خارج‌شده
 */
export async function rotateGroupEpoch(
  groupId: string,
  newEpoch: number,
  members: string[],
  epochKeyB64?: string
): Promise<GroupEpochState> {
  if (!Number.isInteger(newEpoch) || newEpoch < 1) {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid group epoch number');
  }
  if (!epochKeyB64) {
    throw new E2EEError(
      'MISSING_KEYS',
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
      rootKey,
      createdAt: Date.now(),
      membersHash: mHash,
    };

    // حذف و Zeroization اپوک‌های قدیمی‌تر از ظرفیت Grace Buffer
    const epochNums = Object.keys(state.epochs)
      .map(Number)
      .sort((a, b) => a - b);
    while (epochNums.length > GROUP_EPOCH_GRACE_BUFFER) {
      const oldest = epochNums.shift()!;
      if (state.epochs[oldest]) {
        zeroizeBuffer(state.epochs[oldest].rootKey);
        delete state.epochs[oldest];
      }
    }
  } finally {
    state.status = 'STABLE';
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
  iterations: number = PBKDF2_ITERATIONS_NEW,
  purpose: string = ''
): Promise<CryptoKey> {
  // تعیین رمز عبور الزامی است؛ بدون رمز،
  // این تابع صدا زده نمی‌شود و encryptMessageText خطا می‌دهد.
  if (!customSecret) {
    throw new E2EEError('MISSING_KEYS', 'A manual passphrase is required: no default passphrase exists.');
  }
  const webCrypto = getWebCrypto();
  const enc = new TextEncoder();
  const passphrase = `${roomId}::${customSecret}`;

  const keyMaterial = await webCrypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // purpose جدا می‌کند: کلید پیام (purpose='') با کلید فایل (purpose='file-v1')
  // از یک رمز ساخته می‌شوند اما با salt متفاوت، پس کاملاً از هم جدایند.
  const salt = enc.encode(`persian-messenger-salt::${roomId}${purpose ? `::${purpose}` : ''}`);
  return webCrypto.subtle.deriveKey(
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
 * رمزنگاری پیام متنی (Fail-Closed: در صورت هرگونه خطای رمزنگاری، E2EEError پرتاب می‌شود و هرگز متن ساده برگردانده نمی‌شود)
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
  if (!roomId || typeof roomId !== 'string') {
    throw new E2EEError('ENCRYPTION_FAILED', 'Missing roomId for E2EE encryption');
  }

  try {
    const webCrypto = getWebCrypto();
    const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
    const iv = webCrypto.getRandomValues(new Uint8Array(12));
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
        throw new E2EEError('MISSING_KEYS', 'Current group epoch key is unavailable');
      }

      const msgKeyBytes = hkdf(
        sha256,
        epochRec.rootKey,
        iv,
        new TextEncoder().encode(`GroupMsg-Epoch-${fsm.currentEpoch}`),
        32
      );

      try {
        const aesKey = await webCrypto.subtle.importKey(
          'raw',
          msgKeyBytes as unknown as BufferSource,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt']
        );
        const cipherBuffer = await webCrypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          aesKey,
          encoded
        );
        const payload = `${E2EE_GROUP_EPOCH_PREFIX}${fsm.currentEpoch}:${epochRec.membersHash}:${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
        const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
        if (options?.myUsername) {
          saveSentPlaintextInMemory(options.myUsername, roomId, payloadHashKey, plainText);
        }
        return payload;
      } finally {
        zeroizeBuffer(msgKeyBytes);
      }
    }

    // ۲. اگر چت خصوصی است و کلید عمومی مخاطب موجود است
    if (!manualSecret && options?.myUsername && options?.peerPublicKey) {
      const peerBundle = parsePeerKeyBundle(options.peerPublicKey, options.peerUsername, { skipCache: true });

      if (peerBundle.isMldsaSignatureInvalid) {
        throw new E2EEError('INVALID_SIGNATURE', 'Refusing to encrypt to peer with invalid ML-DSA-65 signature');
      }

      if (peerBundle.isFullyPostQuantum) {
        let ratchetState = await ensurePQRatchetSession(
          options.myUsername,
          roomId,
          options.peerPublicKey,
          undefined,
          options.peerUsername
        );

        // چرخش دوره‌ای نشست پس از PQ_REKEY_AFTER_MESSAGES پیام ارسالی —
        // کلید زنجیره قدیمی صفر می‌شود و کپسول تازه برای طرف مقابل ارسال می‌شود.
        if (ratchetState.sentSinceRekey >= PQ_REKEY_AFTER_MESSAGES) {
          ratchetState = await ensurePQRatchetSession(
            options.myUsername,
            roomId,
            options.peerPublicKey,
            undefined,
            options.peerUsername,
            true
          );
        }

        const { nextChainKey, messageKey } = kdfChainStep(ratchetState.sendChainKey, ratchetState.hkdfSaltVersion);
        const stepIndex = ratchetState.sendStep;

        let cipherBuffer: ArrayBuffer;
        try {
          const aesKey = await webCrypto.subtle.importKey(
            'raw',
            messageKey as unknown as BufferSource,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
          );

          cipherBuffer = await webCrypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            encoded
          );
        } catch (err) {
          zeroizeBuffer(nextChainKey);
          throw err;
        } finally {
          zeroizeBuffer(messageKey);
        }

        const ivB64 = bufToBase64(iv);
        const cipherB64 = bufToBase64(cipherBuffer);
        const kemCipherB64 = ratchetState.kemCipherTextB64;

        // امضای دیجیتال پساکوانتومی الزامی پیام با کلید خصوصی ML-DSA-65 در IndexedDB
        let msgSigB64: string;
        try {
          msgSigB64 = await withUnwrappedMLDSASecretKey(options.myUsername, myDsaSec => {
            const signTarget = serializeMessageForSigning({
              roomId,
              step: stepIndex,
              kemCipherB64,
              ivB64,
              cipherB64,
            });
            const sig = ml_dsa65.sign(signTarget, myDsaSec);
            return bufToBase64(sig);
          });
        } catch (err) {
          zeroizeBuffer(nextChainKey);
          throw err;
        }

        // Commit send chain step only after both encryption and ML-DSA-65 signing succeed
        zeroizeBuffer(ratchetState.sendChainKey);
        ratchetState.sendChainKey = nextChainKey;
        ratchetState.sendStep = stepIndex + 1;
        ratchetState.sentSinceRekey = (ratchetState.sentSinceRekey || 0) + 1;
        saveRatchetState(options.myUsername, roomId, ratchetState);

        const payload = `${E2EE_PQ_RATCHET_PREFIX}${stepIndex}:${kemCipherB64}:${ivB64}:${cipherB64}:${msgSigB64}`;
        const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
        saveSentPlaintextInMemory(options.myUsername, roomId, payloadHashKey, plainText);
        return payload;
      }

      // تنزل صریح (نه خاموش) به ECDH کلاسیک فقط در صورت وجود کلید معتبر ECDH بدون کلید پساکوانتومی
      if (peerBundle.ecdhJwk && !peerBundle.hasMLKEM && !peerBundle.hasMLDSA) {
        const ecdhKey = await deriveECDHSharedAesKey(options.myUsername, options.peerPublicKey, roomId, options.peerUsername);
        const cipherBuffer = await webCrypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          ecdhKey,
          encoded
        );
        const payload = `${E2EE_ECDH_PREFIX}${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
        const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
        saveSentPlaintextInMemory(options.myUsername, roomId, payloadHashKey, plainText);
        return payload;
      }

      throw new E2EEError('INVALID_BUNDLE', 'Peer public key bundle is invalid or incomplete');
    }

    // ۳. در صورت تنظیم رمز دستی (PBKDF2 Override)
    if (manualSecret) {
      const pbkdfKey = await derivePbkdf2AesKey(roomId, manualSecret);
      const cipherBuffer = await webCrypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        pbkdfKey,
        encoded
      );
      return `${E2EE_V1_PREFIX}${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
    }

    throw new E2EEError(
      'MISSING_KEYS',
      'Cannot encrypt message: missing verified peer public key and no manual room secret configured'
    );
  } catch (err) {
    // F5 Fail-Closed: هرگز متن ساده برنگردان — همیشه E2EEError پرتاب کن
    if (err instanceof E2EEError) throw err;
    throw new E2EEError(
      'ENCRYPTION_FAILED',
      err instanceof Error ? err.message : 'E2EE encryption failed'
    );
  }
}

/**
 * رمزگشایی پیام متنی (Fail-Closed: ورودی‌های ناقص، دستکاری‌شده، فاقد امضای معتبر یا تکراری با E2EEError رد می‌شوند)
 *
 * [SECURITY INVARIANT — AUDIT L16 / SIDE-CHANNEL & ORACLE CONFINEMENT]:
 * All distinct decryption error codes thrown by this function (such as 'REPLAY_DETECTED',
 * 'SIGNATURE_INVALID', 'DECRYPTION_FAILED', 'MAX_SKIP_EXCEEDED', 'MALFORMED_PAYLOAD') are
 * strictly confined to client-side runtime evaluation and local UI diagnostic state. They are
 * NEVER transmitted over network sockets or REST endpoints to the server or to remote peers,
 * preventing any remote error-oracle or padding/plaintext-leakage attack.
 */
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
  if (typeof payload !== 'string') {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Payload must be a string');
  }
  if (!isE2EEPayload(payload)) {
    return { text: payload || '', isEncrypted: false };
  }
  if (!roomId || typeof roomId !== 'string') {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Missing roomId for decryption');
  }

  const webCrypto = getWebCrypto();
  const payloadHashKey = bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
  const effectivePeerKey =
    options?.peerPublicKey ||
    (options?.peerUsername ? getStoredPeerPublicKey(options.peerUsername) : null);

  // ۱. رمزگشایی پیام‌های راتچت پساکوانتومی (ML-KEM-768 + Out-of-Order Ratchet + Mandatory ML-DSA-65 Verification BEFORE Decrypt)
  if (payload.startsWith(E2EE_PQ_RATCHET_PREFIX)) {
    const raw = payload.slice(E2EE_PQ_RATCHET_PREFIX.length);
    const parts = raw.split(':');
    if (parts.length !== 5) {
      throw new E2EEError(
        parts.length === 4 ? 'MISSING_SIGNATURE' : 'MALFORMED_PAYLOAD',
        'PQ-MPRBA packet must contain 5 fields including mandatory ML-DSA-65 signature'
      );
    }

    const [stepStr, kemCipherB64, ivB64, cipherB64, sigB64] = parts;
    if (!/^\d+$/.test(stepStr)) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid ratchet step format');
    }
    const msgStep = Number(stepStr);
    if (!Number.isSafeInteger(msgStep) || msgStep < 0) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Ratchet step out of safe range');
    }
    if (!sigB64) {
      throw new E2EEError('MISSING_SIGNATURE', 'Missing ML-DSA-65 signature on PQ message');
    }

    const kemCipherBytes = base64ToBuf(kemCipherB64);
    if (kemCipherBytes.byteLength !== ml_kem768.lengths.cipherText) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid ML-KEM-768 ciphertext size');
    }
    const iv = base64ToBuf(ivB64);
    if (iv.byteLength !== 12) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid AES-GCM IV length (must be 12 bytes)');
    }
    const cipherBytes = base64ToBuf(cipherB64);
    if (cipherBytes.byteLength < 16) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Ciphertext too short to contain AES-GCM auth tag');
    }
    const sigBytes = base64ToBuf(sigB64);
    if (sigBytes.byteLength !== ml_dsa65.lengths.signature) {
      throw new E2EEError('INVALID_SIGNATURE', 'Invalid ML-DSA-65 signature byte length');
    }

    if (!options?.myUsername || !effectivePeerKey) {
      throw new E2EEError('MISSING_KEYS', 'Missing local user or peer public key for PQ decryption');
    }

    const normMyUser = normalizeKeystoreUsername(options.myUsername);
    const normSender = options.sender ? normalizeKeystoreUsername(options.sender) : '';
    const isSender = Boolean(normSender && normSender === normMyUser);

    const signData = serializeMessageForSigning({
      roomId,
      step: msgStep,
      kemCipherB64,
      ivB64,
      cipherB64,
    });

    if (isSender) {
      // تأیید امضای پیام ارسالی خود کاربر با کلید عمومی ML-DSA-65 خود کاربر
      const myPubB64 = getMyMLDSAPublicKey(normMyUser);
      if (!myPubB64) {
        throw new E2EEError('MISSING_KEYS', 'Local ML-DSA-65 public key unavailable');
      }
      const myPubBytes = base64ToBuf(myPubB64);
      const selfSigOk = ml_dsa65.verify(sigBytes, signData, myPubBytes);
      if (!selfSigOk) {
        throw new E2EEError('INVALID_SIGNATURE', 'Self-sent ML-DSA-65 message signature invalid');
      }
      const cachedSent = getSentPlaintextFromMemory(normMyUser, roomId, payloadHashKey);
      if (cachedSent !== null) {
        return {
          text: cachedSent,
          isEncrypted: true,
          mode: 'PQ-MLKEM-RATCHET',
          ratchetStep: msgStep,
          mldsaVerified: true,
          failed: false,
        };
      }
      throw new E2EEError(
        'DECRYPTION_FAILED',
        'Sent message key was zeroized for forward secrecy and is not in current session memory'
      );
    }

    // پیام دریافتی از مخاطب: ابتدا باندل کلید مخاطب و سپس امضای ML-DSA-65 پیام را پیش از هرگونه تغییر در راتچت یا رمزگشایی بررسی کن
    const peerBundle = parsePeerKeyBundleStrict(effectivePeerKey, options.peerUsername, { skipCache: true });
    let mldsaVerified = false;
    try {
      mldsaVerified = ml_dsa65.verify(sigBytes, signData, peerBundle.mldsaPub!);
    } catch {
      mldsaVerified = false;
    }

    if (!mldsaVerified) {
      throw new E2EEError('INVALID_SIGNATURE', 'ML-DSA-65 message signature verification failed before decryption');
    }

    const ratchetState = await ensurePQRatchetSession(
      normMyUser,
      roomId,
      effectivePeerKey,
      kemCipherB64,
      options.peerUsername
    );

    const plainText = await ratchetDecryptWithSkippedKeys(
      ratchetState,
      msgStep,
      iv,
      cipherBytes
    );

    return {
      text: plainText,
      isEncrypted: true,
      mode: 'PQ-MLKEM-RATCHET',
      ratchetStep: msgStep,
      mldsaVerified: true,
      failed: false,
    };
  }

  // ۲. رمزگشایی پیام‌های گروهی مبتنی بر ماشین وضعیت اپوک (Group Epoch FSM + Grace Buffer)
  if (payload.startsWith(E2EE_GROUP_EPOCH_PREFIX)) {
    const raw = payload.slice(E2EE_GROUP_EPOCH_PREFIX.length);
    const parts = raw.split(':');
    if (parts.length !== 4) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group epoch packet must have exactly 4 parts');
    }
    const [epochStr, membersHash, ivB64, cipherB64] = parts;
    if (!/^\d+$/.test(epochStr)) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid group epoch number');
    }
    const msgEpoch = Number(epochStr);
    if (!Number.isSafeInteger(msgEpoch) || msgEpoch < 1) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group epoch must be a positive integer');
    }
    if (!membersHash || membersHash.length > 64) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid group membersHash');
    }

    const iv = base64ToBuf(ivB64);
    if (iv.byteLength !== 12) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid group AES-GCM IV length');
    }
    const cipherBytes = base64ToBuf(cipherB64);
    if (cipherBytes.byteLength < 16) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group ciphertext too short');
    }

    const groupId = roomId.replace('group__', '');
    const fsm = getGroupEpochState(groupId, options?.groupMembers || []);

    // بدون کلید اپوک ذخیره‌شده، پیام قفل می‌ماند؛
    // مشتق قطعی کلید از ورودی‌های عمومی حذف شد.
    const epochRec = fsm.epochs[msgEpoch];
    if (!epochRec) {
      throw new E2EEError('DECRYPTION_FAILED', 'Group epoch key is unavailable');
    }
    if (epochRec.membersHash !== membersHash) {
      throw new E2EEError('DECRYPTION_FAILED', 'Group epoch membersHash mismatch');
    }

    const normMy = options?.myUsername ? normalizeKeystoreUsername(options.myUsername) : '';
    const normSender = options?.sender ? normalizeKeystoreUsername(options.sender) : '';
    const isSelfSent = Boolean(normMy && normSender && normMy === normSender);

    if (isSelfSent) {
      const cached = getSentPlaintextFromMemory(normMy, roomId, payloadHashKey);
      if (cached !== null) {
        return {
          text: cached,
          isEncrypted: true,
          mode: 'GROUP-EPOCH-FSM',
          epoch: msgEpoch,
          mldsaVerified: true,
          failed: false,
        };
      }
    }

    // جلوگیری از Replay پیام گروهی: همان بار نباید دو بار پذیرفته شود (مگر خود فرستنده در حال نمایش پیامش باشد)
    const seenSet = epochRec.seenMessageSet || (epochRec.seenMessageSet = new Set(epochRec.seenMessageKeys || []));
    if (!isSelfSent && seenSet.has(payloadHashKey)) {
      throw new E2EEError('REPLAY_DETECTED', 'Replayed group message rejected');
    }
    const rootKeyBytes = epochRec.rootKey;

    const msgKeyBytes = hkdf(
      sha256,
      rootKeyBytes,
      iv,
      new TextEncoder().encode(`GroupMsg-Epoch-${msgEpoch}`),
      32
    );

    try {
      const aesKey = await webCrypto.subtle.importKey(
        'raw',
        msgKeyBytes as unknown as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      const decryptedBuffer = await webCrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        aesKey,
        cipherBytes as unknown as BufferSource
      );
      const plainText = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBuffer);
      // ثبت پیام به‌عنوان تحویل‌شده پس از رمزگشایی موفق بدون فراموشی خاموش در طول اپوک (M2)
      seenSet.add(payloadHashKey);
      if (!epochRec.seenMessageKeys) epochRec.seenMessageKeys = [];
      epochRec.seenMessageKeys.push(payloadHashKey);
      return {
        text: plainText,
        isEncrypted: true,
        mode: 'GROUP-EPOCH-FSM',
        epoch: msgEpoch,
        failed: false,
      };
    } catch {
      throw new E2EEError('DECRYPTION_FAILED', 'Group epoch AES-GCM decryption failed');
    } finally {
      zeroizeBuffer(msgKeyBytes);
    }
  }

  // ۳. پیام‌های ECDH و PBKDF2
  const isEcdh = payload.startsWith(E2EE_ECDH_PREFIX);
  const raw = payload.slice(isEcdh ? E2EE_ECDH_PREFIX.length : E2EE_V1_PREFIX.length);
  const parts = raw.split(':');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Malformed legacy E2EE packet');
  }

  const iv = base64ToBuf(parts[0]);
  if (iv.byteLength !== 12) {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid IV length in legacy packet');
  }
  const cipherBytes = base64ToBuf(parts[1]);
  if (cipherBytes.byteLength < 16) {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Ciphertext too short in legacy packet');
  }

  if (isEcdh) {
    if (!options?.myUsername || !effectivePeerKey) {
      throw new E2EEError('MISSING_KEYS', 'Missing keys for ECDH decryption');
    }
    try {
      const ecdhKey = await deriveECDHSharedAesKey(options.myUsername, effectivePeerKey, roomId, options.peerUsername);
      const decryptedBuffer = await webCrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        ecdhKey,
        cipherBytes as unknown as BufferSource
      );
      const text = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBuffer);
      return {
        text,
        isEncrypted: true,
        mode: 'ECDH',
        failed: false,
      };
    } catch (err) {
      if (err instanceof E2EEError) throw err;
      throw new E2EEError('DECRYPTION_FAILED', 'ECDH AES-GCM decryption failed');
    }
  }

  const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
  if (!manualSecret) {
    throw new E2EEError('MISSING_KEYS', 'Missing manual room secret for PBKDF2 decryption');
  }
  // رمزگذاری داده‌های جدید با ۶۰۰٬۰۰۰ تکرار انجام می‌شود؛ سازگاری با داده‌های قدیمی (۵۰٬۰۰۰ تکرار) هم حفظ می‌شود.
  let decryptedBuffer: ArrayBuffer | null = null;
  for (const iterations of [PBKDF2_ITERATIONS_NEW, PBKDF2_ITERATIONS_LEGACY]) {
    try {
      const pbkdfKey = await derivePbkdf2AesKey(roomId, manualSecret, iterations);
      decryptedBuffer = await webCrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        pbkdfKey,
        cipherBytes as unknown as BufferSource
      );
      break;
    } catch {
      // try the legacy iteration count next
    }
  }
  if (!decryptedBuffer) {
    throw new E2EEError('DECRYPTION_FAILED', 'PBKDF2 AES-GCM decryption failed');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBuffer);
  return {
    text,
    isEncrypted: true,
    mode: 'PBKDF2',
    failed: false,
  };
}

// ===== رمزنگاری سرتاسری فایل (Media E2EE) =====
//
// کلید فایل، یک کلید پایدارِ هر اتاق است که با HKDF از «راز مشترکِ تثبیت‌شدهٔ
// اتاق» مشتق می‌شود و هرگز از راتچت پیام استفاده نمی‌کند — پس آپلود فایل هیچ
// گام راتچتی مصرف نمی‌کند و ترتیب پیام‌ها به هم نمی‌ریزد:
//   - اتاق گروهی: کلید ریشهٔ اپوک جاری (همان کلیدی که پیام‌های گروهی با آن
//     رمز می‌شوند). شمارهٔ اپوک در سربرگ فایل ذخیره می‌شود تا گیرنده کلید
//     همان اپوک را از Grace Buffer بردارد (مثل پیام‌های گروهی).
//   - چت خصوصی: بیت‌های مشترک ECDH P-256 (قطعی و پایدار تا وقتی کلید هویت
//     عوض نشده) با HKDF و info جدا. توجه صادقانه: این کلید از ECDH کلاسیک
//     مشتق می‌شود، نه از ML-KEM — چون کلید ریشهٔ راتچت PQ پس از هر چرخش
//     (۵۰ پیام) صفر می‌شود و نگه داشته نمی‌شود، پس نمی‌تواند کلید پایدار فایل
//     باشد. سرور هرگز این کلید را نمی‌بیند.
//   - رمز دستی: PBKDF2 با salt جداگانه (purpose='file-v1')، جدا از کلید پیام.
// قالب باینری فایل رمز شده: 'PQF1' (۴ بایت) + kind (۱ بایت: 1=DM-ECDH،
// 2=group-epoch، 3=manual) + epoch (۴ بایت BE، فقط گروهی) + iv (۱۲ بایت) +
// ciphertext با AES-256-GCM (شامل ۱۶ بایت auth tag).

export const FILE_ENCRYPTION_MAGIC = 'PQF1';
export const FILE_ENCRYPTION_KIND_DM = 1;
export const FILE_ENCRYPTION_KIND_GROUP = 2;
export const FILE_ENCRYPTION_KIND_MANUAL = 3;
const FILE_ENCRYPTION_HEADER_LEN = 21;

export interface FileEncryptionOptions {
  myUsername?: string;
  peerPublicKey?: string | null;
  peerUsername?: string;
  customSecret?: string;
  groupMembers?: string[];
}

interface RoomFileKey {
  key: CryptoKey;
  kind: number;
  epoch: number;
}

function fileKeyInfo(roomId: string, epoch: number): Uint8Array {
  const suffix = epoch > 0 ? `:epoch-${epoch}` : '';
  return new TextEncoder().encode(`PQ-MPRBA-file-v1:${roomId}${suffix}`);
}

async function getRoomFileKey(
  roomId: string,
  options?: FileEncryptionOptions
): Promise<RoomFileKey> {
  if (!roomId || typeof roomId !== 'string') {
    throw new E2EEError('MISSING_KEYS', 'Missing roomId for file encryption');
  }
  const webCrypto = getWebCrypto();
  const manualSecret = options?.customSecret ?? getRoomSecret(roomId);

  // ۱. رمز دستی: PBKDF2 با salt جدا (purpose='file-v1').
  if (manualSecret) {
    const key = await derivePbkdf2AesKey(roomId, manualSecret, PBKDF2_ITERATIONS_NEW, 'file-v1');
    return { key, kind: FILE_ENCRYPTION_KIND_MANUAL, epoch: 0 };
  }

  // ۲. اتاق گروهی: کلید ریشهٔ اپوک جاری.
  if (roomId.startsWith('group__')) {
    const groupId = roomId.replace('group__', '');
    const fsm = getGroupEpochState(groupId, options?.groupMembers || []);
    const epochRec = fsm.epochs[fsm.currentEpoch];
    if (!epochRec) {
      throw new E2EEError('MISSING_KEYS', 'Current group epoch key is unavailable');
    }
    const keyBytes = hkdf(sha256, epochRec.rootKey, new TextEncoder().encode(roomId), fileKeyInfo(roomId, fsm.currentEpoch), 32);
    try {
      const key = await webCrypto.subtle.importKey(
        'raw',
        keyBytes as unknown as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      return { key, kind: FILE_ENCRYPTION_KIND_GROUP, epoch: fsm.currentEpoch };
    } finally {
      zeroizeBuffer(keyBytes);
    }
  }

  // ۳. چت خصوصی: بیت‌های مشترک ECDH (پایدار، بدون دست‌زدن به راتچت).
  if (!options?.myUsername || !options?.peerPublicKey) {
    throw new E2EEError(
      'MISSING_KEYS',
      'No room key available for file encryption: peer public key is missing'
    );
  }
  const { ecdhJwk } = parsePeerKeyBundle(options.peerPublicKey, options.peerUsername, { skipCache: true });
  if (!ecdhJwk) {
    throw new E2EEError('INVALID_BUNDLE', 'Peer ECDH public key is missing or invalid');
  }
  const bits = await deriveECDHSharedBits(options.myUsername, ecdhJwk);
  try {
    const keyBytes = hkdf(sha256, bits, new TextEncoder().encode(roomId), fileKeyInfo(roomId, 0), 32);
    try {
      const key = await webCrypto.subtle.importKey(
        'raw',
        keyBytes as unknown as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      return { key, kind: FILE_ENCRYPTION_KIND_DM, epoch: 0 };
    } finally {
      zeroizeBuffer(keyBytes);
    }
  } finally {
    zeroizeBuffer(bits);
  }
}

/** رمزنگاری بایت‌های خام فایل با کلید پایدار اتاق. بدون کلید اتاق، Fail-Closed (پرتاب E2EEError، هرگز بایت ساده برنمی‌گردد). */
export async function encryptFileBytes(
  data: Uint8Array,
  roomId: string,
  options?: FileEncryptionOptions
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const { key, kind, epoch } = await getRoomFileKey(roomId, options);
  const iv = webCrypto.getRandomValues(new Uint8Array(12));
  const cipherBuffer = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data as unknown as BufferSource
  );
  const out = new Uint8Array(FILE_ENCRYPTION_HEADER_LEN + cipherBuffer.byteLength);
  out.set(new TextEncoder().encode(FILE_ENCRYPTION_MAGIC), 0);
  out[4] = kind;
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(5, epoch, false);
  out.set(iv, 9);
  out.set(new Uint8Array(cipherBuffer), FILE_ENCRYPTION_HEADER_LEN);
  return out;
}

/** رمزگشایی بایت‌های فایل رمز شده (قالب PQF1). سربرگ خراب یا کلید نادرست → E2EEError (Fail-Closed). */
export async function decryptFileBytes(
  data: Uint8Array,
  roomId: string,
  options?: FileEncryptionOptions
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  if (!isEncryptedFileBytes(data)) {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Not an encrypted file payload');
  }
  const kind = data[4];
  const epoch = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(5, false);
  const iv = data.slice(9, FILE_ENCRYPTION_HEADER_LEN);
  const cipherBytes = data.slice(FILE_ENCRYPTION_HEADER_LEN);

  let key: CryptoKey;
  if (kind === FILE_ENCRYPTION_KIND_GROUP) {
    if (!roomId.startsWith('group__')) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group file payload in a non-group room');
    }
    const groupId = roomId.replace('group__', '');
    const fsm = getGroupEpochState(groupId, options?.groupMembers || []);
    const epochRec = fsm.epochs[epoch];
    if (!epochRec) {
      throw new E2EEError('MISSING_KEYS', 'Group epoch key for this file is no longer available');
    }
    const keyBytes = hkdf(sha256, epochRec.rootKey, new TextEncoder().encode(roomId), fileKeyInfo(roomId, epoch), 32);
    try {
      key = await webCrypto.subtle.importKey(
        'raw',
        keyBytes as unknown as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
    } finally {
      zeroizeBuffer(keyBytes);
    }
  } else if (kind === FILE_ENCRYPTION_KIND_MANUAL) {
    const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
    if (!manualSecret) {
      throw new E2EEError('MISSING_KEYS', 'Manual passphrase is required to decrypt this file');
    }
    key = await derivePbkdf2AesKey(roomId, manualSecret, PBKDF2_ITERATIONS_NEW, 'file-v1');
  } else if (kind === FILE_ENCRYPTION_KIND_DM) {
    // کلید را مستقیم از بیت‌های ECDH می‌سازیم (همان مسیر رمزنگاری) تا
    // نیازی به دانستن kind در زمان رمزگشایی نباشد؛ خطا یعنی کلید نادرست.
    const derived = await getRoomFileKey(roomId, options);
    if (derived.kind !== FILE_ENCRYPTION_KIND_DM) {
      throw new E2EEError('MISSING_KEYS', 'DM file key is unavailable');
    }
    key = derived.key;
  } else {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Unknown encrypted file kind');
  }

  try {
    const plainBuffer = await webCrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      key,
      cipherBytes as unknown as BufferSource
    );
    return new Uint8Array(plainBuffer);
  } catch {
    throw new E2EEError('DECRYPTION_FAILED', 'File AES-GCM authentication or decryption failed');
  }
}

/** آیا این بایت‌ها یک فایل رمز شده با قالب PQF1 هستند؟ */
export function isEncryptedFileBytes(data: Uint8Array | null | undefined): boolean {
  if (!data || data.length < FILE_ENCRYPTION_HEADER_LEN) return false;
  return (
    data[0] === 0x50 && data[1] === 0x51 && data[2] === 0x46 && data[3] === 0x31 // 'PQF1'
  );
}

export function getRoomSecret(roomId: string): string {
  const ss = getSafeSessionStorage();
  if (!ss) return '';
  try {
    return ss.getItem(`${ROOM_KEY_STORAGE_PREFIX}${roomId}`) || '';
  } catch {
    return '';
  }
}

export function setRoomSecret(roomId: string, secret: string): void {
  const ss = getSafeSessionStorage();
  if (!ss) return;
  try {
    // M9 Remediation: ensure room passphrases are stored in ephemeral sessionStorage only,
    // and actively clean up any stale legacy copy that may exist in persistent localStorage.
    const ls = getSafeLocalStorage();
    if (ls) {
      try {
        ls.removeItem(`${ROOM_KEY_STORAGE_PREFIX}${roomId}`);
      } catch {
        // ignore
      }
    }
    if (secret.trim()) {
      ss.setItem(`${ROOM_KEY_STORAGE_PREFIX}${roomId}`, secret.trim());
    } else {
      ss.removeItem(`${ROOM_KEY_STORAGE_PREFIX}${roomId}`);
    }
  } catch {
    // ignore
  }
}

export function isE2EEEnabled(): boolean {
  // L11: E2EE is permanently enabled and mandatory across the application
  return true;
}

export function setE2EEEnabled(_enabled: boolean): void {
  // L11: Plaintext downgrade toggle is removed; E2EE cannot be disabled
}

// M15: آزمون سلامت خودکار پساکوانتومی هنگام لود ماژول (KAT Round-Trip Self-Test)
export function runStartupCryptoSelfTest(): boolean {
  try {
    const kem = ml_kem768.keygen();
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(kem.publicKey);
    const decSec = ml_kem768.decapsulate(cipherText, kem.secretKey);
    if (sharedSecret.length !== 32 || decSec.length !== 32) return false;
    for (let i = 0; i < 32; i++) {
      if (sharedSecret[i] !== decSec[i]) return false;
    }
    const dsa = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('PQ-MPRBA-SELF-TEST');
    const sig = ml_dsa65.sign(msg, dsa.secretKey);
    return ml_dsa65.verify(sig, msg, dsa.publicKey);
  } catch (err) {
    console.error('CRITICAL: Post-quantum crypto self-test failed at startup:', err);
    return false;
  }
}
runStartupCryptoSelfTest();
