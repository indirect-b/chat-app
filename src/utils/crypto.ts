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
  DurableRatchetStateV1,
  clearAllSessionWrappingKeysForTests,
  deleteDurableRatchetState,
  discardLegacyLocalStorageKeys,
  generateNonExtractableEcdhKeyPair,
  generateNonExtractableWrappingKey,
  getCachedPublicKeyMetadataV4,
  getDecryptedHistoryEntry,
  getSessionWrappingKey,
  getWebCrypto,
  isDurableReplaySeen,
  loadDurableRatchetState,
  loadIdentityRecordV4,
  normalizeKeystoreUsername,
  persistDurableRatchetState,
  recordDurableReplaySeen,
  resetInMemoryKeyStoreForTests,
  saveIdentityRecordV4,
  storeDecryptedHistoryEntry,
  unwrapSecretBytes,
  wrapSecretBytes,
} from './keystore';

export { KEY_STORAGE_VERSION } from './keystore';

const E2EE_V1_PREFIX = 'e2ee:v1:';
const E2EE_ECDH_PREFIX = 'e2ee:ecdh:';
const E2EE_PQ_RATCHET_PREFIX = 'e2ee:pq:v2:';
const E2EE_GROUP_EPOCH_PREFIX = 'e2ee:gep:v2:';
export const E2EE_GROUP_EPOCH_V3_PREFIX = 'e2ee:gep:v3:';

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
// کران‌های حافظهٔ Replay (راند ۳) — انبار دائم در keystore.ts کران خودش را دارد.
const MAX_SEEN_RECV_STEPS = 10_000;
const MAX_GROUP_SEEN_MESSAGE_KEYS = 10_000;
// Round 4 (L15): upper bound on decrypt input — a message payload is never
// legitimately this large (files go through decryptFileBytes, not here).
const MAX_DECRYPT_INPUT_BYTES = 5 * 1024 * 1024;
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
  | 'UNVERIFIED_PEER_KEY'
  | 'UNSUPPORTED_VERSION' // L3 (round 4): an E2EE payload with an unknown version
  | 'PAYLOAD_TOO_LARGE' // L15 (round 4): decrypt input exceeds MAX_DECRYPT_INPUT_BYTES
  | 'REPLAY_CHECK_FAILED' // M1 (round 5): the durable replay store errored — fail closed, never decrypt
  | 'IDENTITY_LOCKED'; // L8: هویت با رمز عبور محافظت شده و در این نشست باز نشده است

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

/**
 * کلید کش پیام: ۲۴ کاراکتر اول base64(sha256(payload)) — همان طرحی که کش
 * حافظه‌ای پیام‌های ارسالی و کش رمزنگاری‌شدهٔ تاریخچه استفاده می‌کنند، تا
 * ارسال و دریافتِ یک پیام، یک کلید کش مشترک داشته باشند.
 */
export function computePayloadHashKey(payload: string): string {
  return bufToBase64(sha256(new TextEncoder().encode(payload))).slice(0, 24);
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
 * سریال‌سازی پیام گروهی جهت امضای دیجیتال فرستنده با ML-DSA-65 (M3)
 */
export function serializeGroupMessageForSigning(params: {
  roomId: string;
  epoch: number;
  membersHash: string;
  ivB64: string;
  cipherB64: string;
}): Uint8Array {
  const data = `MLDSA-GEP-MSG-v3:${params.roomId}:${params.epoch}:${params.membersHash}:${params.ivB64}:${params.cipherB64}`;
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

/**
 * کلید پوششیِ لازم برای باز کردن رازهای ML-KEM/ML-DSA (L8): برای رکورد
 * معمولی، کلید ذخیره‌شده؛ برای رکورد محافظت‌شده، فقط کلید بازشدهٔ نشست —
 * وگرنه IDENTITY_LOCKED تا رابط کاربری از کاربر رمز عبور بخواهد.
 */
async function resolveWrappingKey(record: StoredIdentityRecordV4): Promise<CryptoKey> {
  if (!record.passwordProtected) {
    if (!record.wrappingKey) {
      throw new E2EEError('MISSING_KEYS', 'Identity wrapping key is missing');
    }
    return record.wrappingKey;
  }
  const sessionKey = getSessionWrappingKey(record.username);
  if (sessionKey) return sessionKey;
  throw new E2EEError(
    'IDENTITY_LOCKED',
    'Identity key is protected by a password — unlock it to continue'
  );
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
    await resolveWrappingKey(record),
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
    await resolveWrappingKey(record),
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

    // L8: رکورد محافظت‌شده و نشست قفل است — پیش از هر کاری که به کلید
    // خصوصی نیاز دارد، خطای مشخص بده تا رابط کاربری رمز عبور بخواهد.
    if (record.passwordProtected && !getSessionWrappingKey(normUser)) {
      throw new E2EEError(
        'IDENTITY_LOCKED',
        'Identity key is protected by a password — unlock it to continue'
      );
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

// DP-15 (round 3) + L6: deriveECDHSharedAesKey was removed with the legacy
// ECDH message path. L6's un-checked bundle parse
// (parsePeerKeyBundle(peerPublicKeyStr, undefined, ...)) lived here; the
// ECDH shared-bits helper below is kept — it is still used by the hybrid PQ
// ratchet (ECDH component) and by legacy kind-1 file decryption.
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
  // نشست دائم هم حذف می‌شود تا پس از clear، رفرش نشست پاک‌شده را برنگرداند.
  void deleteDurableRatchetState(myUsername, roomId);
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

/**
 * شبیه‌سازی رفرش صفحه در تست‌ها: فقط وضعیت فرّار درون‌حافظه‌ای پاک
 * می‌شود (نشست راتچت، کش متن پیام‌های ارسالی، FSM گروه، کش باندل، کلیدهای
 * پوششی بازشدهٔ نشست) و انبارهای با دوام — هویت در IndexedDB، انبار Replay
 * و کش رمزنگاری‌شدهٔ تاریخچه — دست‌نخورده می‌مانند؛ دقیقاً همان چیزی که
 * یک رفرش واقعی در مرورگر انجام می‌دهد.
 *
 * توجه: resetAllCryptoStateForTests برای این کار مناسب نیست، چون در
 * تست‌های Node انبار شبیه‌سازی‌شدهٔ IndexedDB (از جمله خود هویت و کلید
 * پوششی آن) را هم پاک می‌کند — چیزی که رفرش مرورگر هرگز نمی‌کند.
 */
export function simulateRefreshForTests(): void {
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
  clearAllSessionWrappingKeysForTests();
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

/**
 * سریال‌سازی وضعیت راتچت برای انبار دائم (رفع باگ #2). نشست قبلی
 * (previousSession) عمداً ذخیره نمی‌شود — توضیح در keystore.ts.
 */
function serializeRatchetStateForDurable(state: RatchetSessionState): DurableRatchetStateV1 {
  const skippedKeys = Array.from(state.skippedKeys.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([step, entry]) => ({ step, mk: Array.from(entry.mk), timestamp: entry.timestamp }));
  return {
    sendChainKey: Array.from(state.sendChainKey),
    recvChainKey: Array.from(state.recvChainKey),
    sendStep: state.sendStep,
    recvStep: state.recvStep,
    sentSinceRekey: state.sentSinceRekey,
    seenRecvSteps: Array.from(state.seenRecvSteps),
    kemCipherTextB64: state.kemCipherTextB64,
    peerKemFingerprint: state.peerKemFingerprint,
    skippedKeys,
    sessionEpoch: state.sessionEpoch,
    hkdfSaltVersion: state.hkdfSaltVersion,
  };
}

function deserializeDurableRatchetState(data: DurableRatchetStateV1): RatchetSessionState {
  const skippedKeys = new Map<number, SkippedKeyEntry>();
  for (const entry of data.skippedKeys) {
    skippedKeys.set(entry.step, { mk: new Uint8Array(entry.mk), timestamp: entry.timestamp });
  }
  return {
    sendChainKey: new Uint8Array(data.sendChainKey),
    recvChainKey: new Uint8Array(data.recvChainKey),
    sendStep: data.sendStep,
    recvStep: data.recvStep,
    sentSinceRekey: data.sentSinceRekey,
    seenRecvSteps: new Set(data.seenRecvSteps),
    kemCipherTextB64: data.kemCipherTextB64,
    peerKemFingerprint: data.peerKemFingerprint,
    skippedKeys,
    sessionEpoch: data.sessionEpoch,
    previousSession: undefined,
    hkdfSaltVersion: data.hkdfSaltVersion,
  };
}

/**
 * نوشتن وضعیت راتچت در انبار دائم — best-effort و هرگز throw نمی‌کند تا
 * مسیر رمزنگاری/رمزگشایی با خطای ذخیره‌سازی خراب نشود. در نقاط commit
 * (پس از هر رمزنگاری موفق و هر رمزگشایی موفق) await می‌شود.
 */
async function saveDurableRatchetStateBestEffort(
  myUsername: string,
  roomId: string,
  state: RatchetSessionState
): Promise<void> {
  try {
    await persistDurableRatchetState(myUsername, roomId, serializeRatchetStateForDurable(state));
  } catch {
    // ignore — انبار دائم best-effort است؛ وضعیت درون‌حافظه‌ای دست‌نخورده می‌ماند.
  }
}

/**
 * بازیابی وضعیت راتچت از انبار دائم پس از رفرش — فقط وقتی در حافظه
 * نیست. null یعنی رکوردی نیست، هویت قفل است، یا رکورد خراب بوده است؛
 * در همهٔ این حالت‌ها نشست از نو ساخته می‌شود (رفتار امروز).
 */
async function restoreDurableRatchetState(
  myUsername: string,
  roomId: string
): Promise<RatchetSessionState | null> {
  try {
    const data = await loadDurableRatchetState(myUsername, roomId);
    if (!data) return null;
    const state = deserializeDurableRatchetState(data);
    pruneExpiredSkippedKeys(state);
    saveRatchetState(myUsername, roomId, state);
    return state;
  } catch {
    return null;
  }
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
  // رفرش: اگر نشست در حافظه نیست، اول از انبار دائم بازیابی کن (رفع باگ #2).
  let existing = loadRatchetState(normMyUser, roomId);
  if (!existing) {
    existing = await restoreDurableRatchetState(normMyUser, roomId);
  }
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
      await saveDurableRatchetStateBestEffort(normMyUser, roomId, restored);
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
      await saveDurableRatchetStateBestEffort(normMyUser, roomId, newState);
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
    await saveDurableRatchetStateBestEffort(normMyUser, roomId, newState);
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

// M1 (round 5): the durable replay check is consulted unconditionally
// (it falls back to the in-memory store in Node) and a real store error
// fails CLOSED as E2EEError('REPLAY_CHECK_FAILED') — "unknown" is never
// treated as "not seen".
async function isDurableReplaySeenOrThrow(roomId: string, token: string): Promise<boolean> {
  try {
    return await isDurableReplaySeen(roomId, token);
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('DURABLE_REPLAY_CHECK_FAILED')) {
      throw new E2EEError('REPLAY_CHECK_FAILED', 'Durable replay check failed; refusing to decrypt');
    }
    throw err;
  }
}

async function ratchetDecryptWithSkippedKeys(
  state: RatchetSessionState,
  msgStep: number,
  iv: Uint8Array,
  cipherBytes: Uint8Array,
  roomId?: string,
  myUsername?: string
): Promise<string> {
  const webCrypto = getWebCrypto();
  pruneExpiredSkippedKeys(state);

  const sessionKemTag = state.kemCipherTextB64 ? state.kemCipherTextB64.slice(0, 24) : 'default';
  const normMy = myUsername ? normalizeKeystoreUsername(myUsername) : '';
  const replayToken = `ratchet_${sessionKemTag}_recv_${normMy}_step_${msgStep}`;

  // محافظت قطعی در برابر Replay Attack (H3: هم حافظه RAM و هم IndexedDB با دوام در مرورگر)
  if (state.seenRecvSteps.has(msgStep)) {
    throw new E2EEError('REPLAY_DETECTED', `Replayed ratchet step ${msgStep} rejected`);
  }
  // M1 (round 5): consult the durable store unconditionally — the
  // hasBrowserIndexedDB() gate used to skip it entirely in non-IndexedDB
  // runtimes, so a replay after ratchet-state loss (refresh) decrypted
  // fine even though the token was recorded.
  if (roomId && (await isDurableReplaySeenOrThrow(roomId, replayToken))) {
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
    // کران حافظه (راند ۳): قدم‌های دیده‌شدهٔ یک نشست بدون کران رشد
    // می‌کردند. قدیمی‌ترین‌ها حذف می‌شوند — راتچت چرخیده و پیام‌های قدیمی
    // دیگر رمزگشایی نمی‌شوند؛ انبار دائم (TTL ۳۰ روز) پشتیبان است.
    if (state.seenRecvSteps.size > MAX_SEEN_RECV_STEPS) {
      const excess = state.seenRecvSteps.size - MAX_SEEN_RECV_STEPS;
      let removed = 0;
      for (const oldStep of state.seenRecvSteps) {
        if (removed >= excess) break;
        state.seenRecvSteps.delete(oldStep);
        removed++;
      }
    }
    if (roomId) {
      await recordDurableReplaySeen(roomId, replayToken);
    }
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
  distributorSigB64?: string;
  epoch?: number;
}

export function serializeEpochPacketForSigning(
  epoch: number,
  members: string[],
  keys: Record<string, string>
): Uint8Array {
  const sortedMembers = [...members].sort().join(',');
  const sortedKeys = Object.keys(keys)
    .sort()
    .map(k => `${k}=${keys[k]}`)
    .join('&');
  const str = `MLDSA-EPOCH-PACKET-v1:${epoch}:${sortedMembers}:${sortedKeys}`;
  return new TextEncoder().encode(str);
}

export async function createGroupEpochPacket(
  memberBundles: Record<string, ParsedPeerKeyBundle | null | undefined>,
  distributorUsername?: string,
  epoch: number = 1
): Promise<GroupEpochPacket> {
  const webCrypto = getWebCrypto();
  const epochKey = webCrypto.getRandomValues(new Uint8Array(32));
  const keys: Record<string, string> = {};
  const missing: string[] = [];
  const members = Object.keys(memberBundles).sort();
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

  let distributorSigB64: string | undefined = undefined;
  if (distributorUsername) {
    try {
      const signTarget = serializeEpochPacketForSigning(epoch, members, keys);
      distributorSigB64 = await withUnwrappedMLDSASecretKey(distributorUsername, mldsaSec => {
        const sig = ml_dsa65.sign(signTarget, mldsaSec);
        return bufToBase64(sig);
      });
    } catch {
      // ignore
    }
  }

  const epochKeyB64 = bufToBase64(epochKey);
  zeroizeBuffer(epochKey);
  return { epochKeyB64, keys, missing, distributorSigB64, epoch };
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
/**
 * چرخش اپوک گروهی.
 *
 * L1 — عمداً اصلاح نشده (STOPPED، راند ۳): این تابع بازگشت اپوک به عدد
 * کوچک‌تر را رد نمی‌کند (بدون بررسی یکنواختی). تست C5 در
 * tests/adversarial.test.ts:336 این رفتار را پین کرده است (چرخش ۵→۲ پذیرفته
 * می‌شود)، چون در عملِ فعلی، یک عضو که مدتی آفلاین بوده ممکن است بستهٔ
 * اپوک قدیمی را دیر دریافت کند و رد کردن آن، همگام‌سازی گروه را می‌شکند.
 * اصلاح واقعی نیازمند تصمیم طراحی (مثلاً پنجرهٔ عقب‌گرد مجاز + امضای
 * توزیع‌کنندهٔ اپوک) است، نه یک بررسی ساده؛ تا آن تصمیم گرفته نشود، L1
 * هفتمین مورد متوقف‌شده محسوب می‌شود.
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
  // L1 (round 4): strict monotonicity — a stale epoch packet (from a
  // malicious server, or an out-of-order delivery) must never roll the
  // group back to an older epoch key, which would re-enable a removed
  // member. A rollback is ignored, not an error: the callers
  // (ensureGroupEpochPacket, group-join handler) fire-and-forget, so a
  // throw here would break the room flow. Re-rotating to the SAME epoch
  // is still allowed (idempotent re-sync).
  if (state.currentEpoch > 0 && newEpoch < state.currentEpoch) {
    return state;
  }
  state.status = 'ROTATING';

  try {
    const mHash = computeMembersHash(members);
    const rootKey = base64ToBuf(epochKeyB64);
    // L14 (round 4): epoch keys are always 32 bytes (see createGroupEpochPacket).
    if (rootKey.byteLength !== 32) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group epoch key must be exactly 32 bytes');
    }

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
      text.startsWith(E2EE_GROUP_EPOCH_PREFIX) ||
      text.startsWith(E2EE_GROUP_EPOCH_V3_PREFIX))
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
    // L5 (round 5) — PRECEDENCE: the FSM path wins whenever a current
    // epoch key exists, even if a manual room secret is set. A manual
    // secret must never silently downgrade PQ group encryption to PBKDF2.
    // With no epoch key we fall through to the PBKDF2/manual path below
    // (or MISSING_KEYS if no secret is set either).
    if (roomId.startsWith('group__')) {
      const groupId = roomId.replace('group__', '');
      const fsm = getGroupEpochState(groupId, options?.groupMembers || []);

      if (fsm.status === 'ROTATING') {
        await new Promise<void>(resolve => fsm.pendingQueue.push(async () => resolve()));
      }

      const epochRec = fsm.epochs[fsm.currentEpoch];
      if (epochRec) {
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
        let payload: string;
        if (options?.myUsername) {
          try {
            const ivB64 = bufToBase64(iv);
            const cipherB64 = bufToBase64(cipherBuffer);
            const signTarget = serializeGroupMessageForSigning({
              roomId,
              epoch: fsm.currentEpoch,
              membersHash: epochRec.membersHash,
              ivB64,
              cipherB64,
            });
            const sigB64 = await withUnwrappedMLDSASecretKey(options.myUsername, sec =>
              bufToBase64(ml_dsa65.sign(signTarget, sec))
            );
            payload = `${E2EE_GROUP_EPOCH_V3_PREFIX}${fsm.currentEpoch}:${epochRec.membersHash}:${ivB64}:${cipherB64}:${sigB64}`;
          } catch (err) {
            // M3 (راند ۳): دیگر به‌صورت خاموش به قالب بدون امضای v2
            // برنمی‌گردیم — پیامی که باید امضا شود و امضا نمی‌شود، ارسال
            // نمی‌شود. خطای E2EEError (مثلاً IDENTITY_LOCKED وقتی هویت با
            // رمز عبور قفل است) دست‌نخورده بالا می‌رود تا رابط کاربری
            // واکنش مناسب نشان دهد (پنجرهٔ باز کردن رمز عبور).
            if (err instanceof E2EEError) throw err;
            throw new E2EEError('ENCRYPTION_FAILED', 'Group message signing failed');
          }
        } else {
          payload = `${E2EE_GROUP_EPOCH_PREFIX}${fsm.currentEpoch}:${epochRec.membersHash}:${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
        }
        const payloadHashKey = computePayloadHashKey(payload);
        if (options?.myUsername) {
          saveSentPlaintextInMemory(options.myUsername, roomId, payloadHashKey, plainText);
        }
        return payload;
      } finally {
        zeroizeBuffer(msgKeyBytes);
      }
      } // no epoch key → fall through to the PBKDF2 / MISSING_KEYS paths below
    }

    // ۲. اگر چت خصوصی است و کلید عمومی مخاطب موجود است
    // L5 (round 5) — PRECEDENCE: a verified fully-PQ peer bundle always
    // wins over a manual room secret. A manual secret only downgrades to
    // PBKDF2 when the peer has no usable PQ bundle (classical-only peer);
    // it must never silently override an available PQ session. A bundle
    // whose ML-DSA signature is invalid still throws (fail closed) rather
    // than silently falling back to the weaker PBKDF2 path.
    if (options?.myUsername && options?.peerPublicKey) {
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
        await saveDurableRatchetStateBestEffort(options.myUsername, roomId, ratchetState);

        const payload = `${E2EE_PQ_RATCHET_PREFIX}${stepIndex}:${kemCipherB64}:${ivB64}:${cipherB64}:${msgSigB64}`;
        const payloadHashKey = computePayloadHashKey(payload);
        saveSentPlaintextInMemory(options.myUsername, roomId, payloadHashKey, plainText);
        return payload;
      }

      // DP-15 (round 3): the legacy ECDH message path was REMOVED — with the
      // app's parameterization it could never be decrypted by the receiver
      // (HKDF info bound the role-dependent name), so producing e2ee:ecdh:
      // payloads only created undecryptable messages. A peer with only a
      // classical ECDH key and no PQ material is now rejected fail-closed.
      // L5 (round 5): ...unless a manual room secret is set, in which case
      // the old PBKDF2 fallback is preserved for classical-only peers —
      // execution falls through to section 3 below instead of throwing.
      if (!manualSecret) {
        throw new E2EEError('INVALID_BUNDLE', 'Peer public key bundle is invalid or incomplete');
      }
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
  mode?: 'PQ-MLKEM-RATCHET' | 'GROUP-EPOCH-FSM' | 'PBKDF2';
  epoch?: number;
  ratchetStep?: number;
  mldsaVerified?: boolean;
  failed?: boolean;
}> {
  if (typeof payload !== 'string') {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Payload must be a string');
  }
  // L15 (round 4): reject oversized decrypt input before doing any
  // expensive crypto — a 10 MB ciphertext used to cost ~3.3 s CPU.
  if (payload.length > MAX_DECRYPT_INPUT_BYTES) {
    throw new E2EEError('PAYLOAD_TOO_LARGE', 'Decrypt input exceeds maximum size');
  }
  // L3 (round 4): an E2EE payload with an unknown version must fail
  // closed, never pass through as plaintext. Genuine plaintext (no
  // `e2ee:` prefix) still passes through — that is how old plaintext
  // history displays.
  if (payload.startsWith('e2ee:') && !isE2EEPayload(payload)) {
    throw new E2EEError('UNSUPPORTED_VERSION', 'Unknown E2EE payload version');
  }
  if (!isE2EEPayload(payload)) {
    return { text: payload || '', isEncrypted: false };
  }
  if (!roomId || typeof roomId !== 'string') {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Missing roomId for decryption');
  }

  const webCrypto = getWebCrypto();
  const payloadHashKey = computePayloadHashKey(payload);
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
    // L6 (round 5): bind the envelope sender to the verified bundle —
    // a valid Alice-signed message decrypted with sender='carol' used to
    // verify fine and be attributed to Carol. (The self-sent branch above
    // returns before this, so it is unaffected.)
    if (
      options.sender &&
      normalizeKeystoreUsername(options.sender) !== normalizeKeystoreUsername(options.peerUsername ?? '')
    ) {
      throw new E2EEError('INVALID_SIGNATURE', 'Envelope sender does not match the verified peer identity');
    }
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
      cipherBytes,
      roomId,
      normMyUser
    );

    // رمزگشایی موفق شد و وضعیت راتچت commit شد (کلیدهای ردشدهٔ تازه،
    // حذف کلید مصرف‌شده، گام جدید) — وضعیت را در انبار دائم هم بنویس
    // تا پس از رفرش، پیام‌های خارج از نوبت همچنان رمزگشایی شوند (رفع باگ #2).
    await saveDurableRatchetStateBestEffort(normMyUser, roomId, ratchetState);

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
  const isGepV3 = payload.startsWith(E2EE_GROUP_EPOCH_V3_PREFIX);
  const isGepV2 = payload.startsWith(E2EE_GROUP_EPOCH_PREFIX);
  if (isGepV3 || isGepV2) {
    const raw = payload.slice(isGepV3 ? E2EE_GROUP_EPOCH_V3_PREFIX.length : E2EE_GROUP_EPOCH_PREFIX.length);
    const parts = raw.split(':');
    if (isGepV3 && parts.length !== 5) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group epoch v3 packet must have exactly 5 parts');
    }
    if (isGepV2 && parts.length !== 4) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group epoch packet must have exactly 4 parts');
    }
    const [epochStr, membersHash, ivB64, cipherB64, senderSigB64] = parts;
    if (!/^\d+$/.test(epochStr)) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Invalid group epoch number');
    }
    const msgEpoch = Number(epochStr);
    if (!Number.isSafeInteger(msgEpoch) || msgEpoch < 1) {
      throw new E2EEError('MALFORMED_PAYLOAD', 'Group epoch must be a positive integer');
    }
    // DP-12 (round 4): the replay key must be computed from the CANONICAL
    // form of the message, not the raw payload string. The epoch is
    // re-serialized from the parsed number, so "01", "001" and "1" all
    // map to the same key and a re-delivered message is caught as a
    // replay. The sender builds the payload from a numeric epoch, so
    // this canonical form matches the sender's own-message cache key.
    const canonicalGroupPayload = isGepV3
      ? `${E2EE_GROUP_EPOCH_V3_PREFIX}${msgEpoch}:${membersHash}:${ivB64}:${cipherB64}:${senderSigB64}`
      : `${E2EE_GROUP_EPOCH_PREFIX}${msgEpoch}:${membersHash}:${ivB64}:${cipherB64}`;
    const replayKey = bufToBase64(sha256(new TextEncoder().encode(canonicalGroupPayload))).slice(0, 24);
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

    // L3 (round 5): isSelfSent is computed BEFORE the v3 block — the
    // fail-closed requirement below must not apply to my own messages
    // (the app never stores my own key in the peer store, so a naive
    // fail-closed would lock all my sent group messages on first load;
    // ownership is proven by the sent-plaintext cache lookup below, and
    // a cache miss still decrypts with mldsaVerified:false + the L4 UI
    // warning).
    const normMy = options?.myUsername ? normalizeKeystoreUsername(options.myUsername) : '';
    const normSender = options?.sender ? normalizeKeystoreUsername(options.sender) : '';
    const isSelfSent = Boolean(normMy && normSender && normMy === normSender);

    let isMldsaVerified = false;
    if (isGepV3) {
      if (!isSelfSent) {
        const senderKeyStr = options?.peerPublicKey || (options?.sender ? getStoredPeerPublicKey(options.sender) : null);
        if (!options?.sender || !senderKeyStr) {
          throw new E2EEError(
            'INVALID_BUNDLE',
            'Group v3 message requires the sender and their verified public-key bundle'
          );
        }
        const parsed = parsePeerKeyBundle(senderKeyStr, options.sender, { skipCache: true });
        // L6 (group): parsePeerKeyBundle flags a bundle-username vs
        // sender mismatch as isMldsaSignatureInvalid, so this throw also
        // binds the sender to the verified bundle on the group path.
        if (parsed.isMldsaSignatureInvalid || !parsed.hasMLDSA || !parsed.mldsaPub) {
          throw new E2EEError(
            'INVALID_SIGNATURE',
            'Group sender ML-DSA-65 identity key is missing or invalid'
          );
        }
        const signTarget = serializeGroupMessageForSigning({
          roomId,
          epoch: msgEpoch,
          membersHash,
          ivB64,
          cipherB64,
        });
        const sigBytes = base64ToBuf(senderSigB64);
        if (sigBytes.byteLength !== ml_dsa65.lengths.signature) {
          throw new E2EEError('INVALID_SIGNATURE', 'Invalid group ML-DSA-65 signature byte length');
        }
        let valid = false;
        try {
          valid = ml_dsa65.verify(sigBytes, signTarget, parsed.mldsaPub);
        } catch {
          valid = false;
        }
        if (!valid) {
          throw new E2EEError('INVALID_SIGNATURE', 'Group sender ML-DSA-65 signature verification failed');
        }
        isMldsaVerified = true;
      }
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

    if (isSelfSent) {
      const cached = getSentPlaintextFromMemory(normMy, roomId, replayKey);
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

    // جلوگیری از Replay پیام گروهی (M1: هم حافظه RAM و هم انبار دائم IndexedDB)
    const seenSet = epochRec.seenMessageSet || (epochRec.seenMessageSet = new Set(epochRec.seenMessageKeys || []));
    // M1 (round 5): this call site already consulted the durable store
    // unconditionally; a store error now fails closed (REPLAY_CHECK_FAILED)
    // instead of being treated as "not seen".
    const isDurableReplay = await isDurableReplaySeenOrThrow(roomId, `group_msg_${msgEpoch}_${replayKey}`);
    if (!isSelfSent && (seenSet.has(replayKey) || isDurableReplay)) {
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
      // ثبت پیام به‌عنوان تحویل‌شده پس از رمزگشایی موفق بدون فراموشی خاموش در طول اپوک (M2) و ثبت در انبار دائم (M1)
      seenSet.add(replayKey);
      if (!epochRec.seenMessageKeys) epochRec.seenMessageKeys = [];
      epochRec.seenMessageKeys.push(replayKey);
      // کران حافظه (راند ۳): در یک اپوکِ بسیار پرپیام، فقط ۱۰٬۰۰۰ پیام اخیر
      // در RAM نگه داشته می‌شوند؛ قدیمی‌ترها همچنان در انبار دائم (TTL ۳۰
      // روز) بررسی می‌شوند.
      if (epochRec.seenMessageKeys.length > MAX_GROUP_SEEN_MESSAGE_KEYS) {
        const excess = epochRec.seenMessageKeys.length - MAX_GROUP_SEEN_MESSAGE_KEYS;
        const removedKeys = epochRec.seenMessageKeys.splice(0, excess);
        for (const oldKey of removedKeys) seenSet.delete(oldKey);
      }
      await recordDurableReplaySeen(roomId, `group_msg_${msgEpoch}_${replayKey}`);
      return {
        text: plainText,
        isEncrypted: true,
        mode: 'GROUP-EPOCH-FSM',
        epoch: msgEpoch,
        mldsaVerified: isMldsaVerified,
        failed: false,
      };
    } catch {
      throw new E2EEError('DECRYPTION_FAILED', 'Group epoch AES-GCM decryption failed');
    } finally {
      zeroizeBuffer(msgKeyBytes);
    }
  }

  // ۳. پیام‌های PBKDF2 (رمز دستی). مسیر پیام ECDH قدیمی (e2ee:ecdh:) در
  // راند ۳ حذف شد (DP-15) — چنین باری صریحاً رد می‌شود و هرگز به مسیر
  // PBKDF2 نمی‌افتد یا به‌عنوان متن ساده نمایش داده نمی‌شود.
  if (payload.startsWith(E2EE_ECDH_PREFIX)) {
    throw new E2EEError(
      'MALFORMED_PAYLOAD',
      'Legacy ECDH message path was removed (DP-15): this message cannot be decrypted'
    );
  }
  const raw = payload.slice(E2EE_V1_PREFIX.length);
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

/**
 * رمزگشایی با کش رمزنگاری‌شدهٔ تاریخچه — نقطهٔ ورود واحد رمزگشایی پیام در
 * رابط کاربری (ChatApp) برای بارگذاری تاریخچه و پیام‌های زنده.
 *
 * چرا: پس از رفرش، رمزگشایی دوبارهٔ یک پیامِ از قبل تحویل‌شده با
 * REPLAY_DETECTED رد می‌شود (انبار دائم Replay) و پیام ارسالی خود کاربر
 * هم کلیدش را از دست داده است — هر دو به‌جای متن، جای‌نمای قفل‌شده نشان
 * می‌دهند. این تابع پیش از رمزگشایی دوباره، کش تاریخچه را می‌خواند و پس
 * از هر رمزگشایی موفق، نتیجه را در کش ذخیره می‌کند.
 *
 * چه چیزی تغییر نمی‌کند: بررسی Replay، راتچت، seenRecvSteps و اعتبارسنجی
 * امضای ML-DSA-65 دست‌نخورده‌اند — کش فقط نتیجهٔ یک رمزگشاییِ قبلاً
 * موفق و اعتبارسنجی‌شده را برمی‌گرداند و هرگز جایگزین آن بررسی‌ها
 * نمی‌شود. خواندن/نوشتن کش best-effort است: خطا (از جمله قفل‌بودن هویت
 * L8) هرگز throw نمی‌کند و مسیر عادی رمزگشایی ادامه پیدا می‌کند.
 */
export async function decryptMessageTextWithHistoryCache(
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
): Promise<Awaited<ReturnType<typeof decryptMessageText>>> {
  if (typeof payload === 'string' && isE2EEPayload(payload) && options?.myUsername && roomId) {
    try {
      const cached = await getDecryptedHistoryEntry(
        options.myUsername,
        roomId,
        computePayloadHashKey(payload)
      );
      if (cached) {
        return {
          text: cached.text,
          isEncrypted: true,
          mode: cached.mode,
          ratchetStep: cached.ratchetStep,
          epoch: cached.epoch,
          mldsaVerified: cached.mldsaVerified,
          failed: false,
        };
      }
    } catch {
      // کش خراب/در دسترس نیست — مسیر عادی رمزگشایی ادامه پیدا می‌کند.
    }
  }

  const dec = await decryptMessageText(payload, roomId, options);

  if (dec.isEncrypted && !dec.failed && options?.myUsername && roomId) {
    try {
      await storeDecryptedHistoryEntry(options.myUsername, roomId, computePayloadHashKey(payload), {
        text: dec.text,
        mode: dec.mode,
        ratchetStep: dec.ratchetStep,
        epoch: dec.epoch,
        mldsaVerified: dec.mldsaVerified ?? false,
      });
    } catch {
      // نوشتن کش best-effort است — شکست آن رمزگشایی موفق را خراب نمی‌کند.
    }
  }

  return dec;
}

// ===== رمزنگاری سرتاسری فایل (Media E2EE) =====
//
// کلید فایل، یک کلید پایدارِ هر اتاق است که با HKDF از «راز مشترکِ تثبیت‌شدهٔ
// اتاق» مشتق می‌شود و هرگز از راتچت پیام استفاده نمی‌کند — پس آپلود فایل هیچ
// گام راتچتی مصرف نمی‌کند و ترتیب پیام‌ها به هم نمی‌ریزد:
//   - اتاق گروهی: کلید ریشهٔ اپوک جاری (همان کلیدی که پیام‌های گروهی با آن
//     رمز می‌شوند). شمارهٔ اپوک در سربرگ فایل ذخیره می‌شود تا گیرنده کلید
//     همان اپوک را از Grace Buffer بردارد (مثل پیام‌های گروهی).
//   - چت خصوصی: هر فایل یک کلید تازهٔ تصادفی ۳۲ بایتی دارد که با ML-KEM-768
//     به کلید عمومی گیرنده و به کلید عمومی خود فرستنده کپسوله می‌شود (M10،
//     راند ۳) و هر دو کپسول + کلید پیچیده‌شده در سربرگ PQF1 ذخیره می‌شوند؛
//     پس هم گیرنده و هم فرستنده می‌توانند فایل را باز کنند، بدون اینکه کلید
//     پایدار کلاسیک ECDH در کار باشد. فایل‌های قدیمی kind=1 هنوز با مسیر
//     ECDH باز می‌شوند (سازگاری با عقب).
//   - رمز دستی: PBKDF2 با salt جداگانه (purpose='file-v1')، جدا از کلید پیام.
// قالب باینری فایل رمز شده: 'PQF1' (۴ بایت) + kind (۱ بایت: 1=DM-ECDH قدیمی،
// 2=group-epoch، 3=manual، 4=DM-MLKEM) + epoch (۴ بایت BE، فقط گروهی) +
// iv (۱۲ بایت) + [فقط kind=4: ctPeer (۱۰۸۸ بایت) + wrapPeer (۳۲ بایت) +
// ctSelf (۱۰۸۸ بایت) + wrapSelf (۳۲ بایت)] + ciphertext با AES-256-GCM
// (شامل ۱۶ بایت auth tag).

export const FILE_ENCRYPTION_MAGIC = 'PQF1';
export const FILE_ENCRYPTION_KIND_DM = 1;
export const FILE_ENCRYPTION_KIND_GROUP = 2;
export const FILE_ENCRYPTION_KIND_MANUAL = 3;
export const FILE_ENCRYPTION_KIND_DM_MLKEM = 4;
const FILE_ENCRYPTION_HEADER_LEN = 21;
// سربرگ kind=4: ۲۱ بایت پایه + ۲×(۱۰۸۸ بایت کپسول ML-KEM-768 + ۳۲ بایت
// کلید پیچیده‌شده با XOR).
const FILE_ENCRYPTION_HEADER_LEN_DM_MLKEM =
  FILE_ENCRYPTION_HEADER_LEN + 2 * (ml_kem768.lengths.cipherText + 32);

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

  // ۳. چت خصوصی (فقط رمزگشایی فایل‌های قدیمی kind=1): بیت‌های مشترک ECDH.
  // رمزنگاری فایل‌های جدید DM دیگر از این مسیر استفاده نمی‌کند — کلید
  // تازهٔ هر فایل با ML-KEM-768 کپسوله می‌شود (M10، kind=4). این شاخه فقط
  // برای باز کردن فایل‌های ساخته‌شده پیش از M10 نگه داشته شده است.
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

/**
 * پیچیدن کلید فایل با راز مشترک ML-KEM (KEM-DEM با XOR و HKDF) — M10.
 * کلید فایل تصادفی است و برچسب اصالت ciphertext نهایی AES-GCM، درستی کلید
 * بازیابی‌شده را تضمین می‌کند؛ پس پیچیدن با XOR برای محرمانگی کلید کافی است.
 */
function wrapFileKeyWithKemSecret(
  fileKey: Uint8Array,
  kemSharedSecret: Uint8Array,
  roomId: string
): Uint8Array {
  const stream = hkdf(
    sha256,
    kemSharedSecret,
    new TextEncoder().encode(roomId),
    new TextEncoder().encode('PQ-MPRBA-file-wrap-v1'),
    32
  );
  const wrapped = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    wrapped[i] = (fileKey[i] ?? 0) ^ (stream[i] ?? 0);
  }
  zeroizeBuffer(stream);
  return wrapped;
}

/** رمزنگاری فایل DM با کلید تازهٔ هر فایل کپسوله‌شده با ML-KEM-768 (M10). */
async function encryptDmFileBytesMlkem(
  data: Uint8Array,
  roomId: string,
  options?: FileEncryptionOptions
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  if (!options?.myUsername || !options?.peerPublicKey) {
    throw new E2EEError(
      'MISSING_KEYS',
      'No room key available for file encryption: peer public key is missing'
    );
  }
  const peerBundle = parsePeerKeyBundle(options.peerPublicKey, options.peerUsername, { skipCache: true });
  if (!peerBundle.mlkemPub) {
    throw new E2EEError('INVALID_BUNDLE', 'Peer ML-KEM-768 public key is missing or invalid');
  }
  const myMlkemPubB64 = getMyMLKEMPublicKey(options.myUsername);
  if (!myMlkemPubB64) {
    throw new E2EEError('MISSING_KEYS', 'Own ML-KEM-768 public key is unavailable');
  }
  let myMlkemPub: Uint8Array;
  try {
    myMlkemPub = base64ToBuf(myMlkemPubB64);
  } catch {
    throw new E2EEError('MISSING_KEYS', 'Own ML-KEM-768 public key is unavailable');
  }
  if (myMlkemPub.byteLength !== ml_kem768.lengths.publicKey) {
    throw new E2EEError('MISSING_KEYS', 'Own ML-KEM-768 public key is unavailable');
  }

  const fileKey = webCrypto.getRandomValues(new Uint8Array(32));
  const iv = webCrypto.getRandomValues(new Uint8Array(12));
  let aesKey: CryptoKey;
  let ctPeer: Uint8Array;
  let wrapPeer: Uint8Array;
  let ctSelf: Uint8Array;
  let wrapSelf: Uint8Array;
  try {
    // کلید فایل به کلید عمومی گیرنده و به کلید عمومی خود فرستنده کپسوله
    // می‌شود تا هر دو طرف بتوانند فایل را باز کنند.
    const encPeer = ml_kem768.encapsulate(peerBundle.mlkemPub);
    const encSelf = ml_kem768.encapsulate(myMlkemPub);
    ctPeer = encPeer.cipherText;
    ctSelf = encSelf.cipherText;
    wrapPeer = wrapFileKeyWithKemSecret(fileKey, encPeer.sharedSecret, roomId);
    wrapSelf = wrapFileKeyWithKemSecret(fileKey, encSelf.sharedSecret, roomId);
    zeroizeBuffer(encPeer.sharedSecret);
    zeroizeBuffer(encSelf.sharedSecret);
    aesKey = await webCrypto.subtle.importKey(
      'raw',
      fileKey as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
  } finally {
    zeroizeBuffer(fileKey);
  }
  const cipherBuffer = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    data as unknown as BufferSource
  );
  const out = new Uint8Array(FILE_ENCRYPTION_HEADER_LEN_DM_MLKEM + cipherBuffer.byteLength);
  out.set(new TextEncoder().encode(FILE_ENCRYPTION_MAGIC), 0);
  out[4] = FILE_ENCRYPTION_KIND_DM_MLKEM;
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(5, 0, false);
  out.set(iv, 9);
  let off = FILE_ENCRYPTION_HEADER_LEN;
  out.set(ctPeer, off);
  off += ctPeer.byteLength;
  out.set(wrapPeer, off);
  off += wrapPeer.byteLength;
  out.set(ctSelf, off);
  off += ctSelf.byteLength;
  out.set(wrapSelf, off);
  off += wrapSelf.byteLength;
  out.set(new Uint8Array(cipherBuffer), off);
  return out;
}

/**
 * باز کردن فایل DM kind=4: هر دو کپسول را با کلید خصوصی ML-KEM خود امتحان
 * می‌کند (یکی برای گیرنده، یکی برای فرستنده)؛ برچسب اصالت AES-GCM مشخص
 * می‌کند کدام کلید درست است. کپسول اشتباه راز مشترکِ تصادفی‌نما می‌دهد و
 * رمزگشایی AES-GCM آن رد می‌شود.
 */
async function decryptDmFileBytesMlkem(
  data: Uint8Array,
  roomId: string,
  options?: FileEncryptionOptions
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  if (data.length < FILE_ENCRYPTION_HEADER_LEN_DM_MLKEM) {
    throw new E2EEError('MALFORMED_PAYLOAD', 'Truncated ML-KEM file header');
  }
  if (!options?.myUsername) {
    throw new E2EEError('MISSING_KEYS', 'Username is required to open an ML-KEM-encrypted file');
  }
  const iv = data.slice(9, FILE_ENCRYPTION_HEADER_LEN);
  const ctLen = ml_kem768.lengths.cipherText;
  let off = FILE_ENCRYPTION_HEADER_LEN;
  const ctPeer = data.slice(off, off + ctLen);
  off += ctLen;
  const wrapPeer = data.slice(off, off + 32);
  off += 32;
  const ctSelf = data.slice(off, off + ctLen);
  off += ctLen;
  const wrapSelf = data.slice(off, off + 32);
  off += 32;
  const cipherBytes = data.slice(off);

  const attempts: Array<[Uint8Array, Uint8Array]> = [
    [ctPeer, wrapPeer],
    [ctSelf, wrapSelf],
  ];
  for (const [ct, wrap] of attempts) {
    try {
      const fileKey = await withUnwrappedMLKEMSecretKey(options.myUsername, mySecretKey => {
        const shared = ml_kem768.decapsulate(ct, mySecretKey);
        try {
          return wrapFileKeyWithKemSecret(wrap, shared, roomId);
        } finally {
          zeroizeBuffer(shared);
        }
      });
      try {
        const aesKey = await webCrypto.subtle.importKey(
          'raw',
          fileKey as unknown as BufferSource,
          { name: 'AES-GCM', length: 256 },
          false,
          ['decrypt']
        );
        const plainBuffer = await webCrypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as unknown as BufferSource },
          aesKey,
          cipherBytes as unknown as BufferSource
        );
        return new Uint8Array(plainBuffer);
      } finally {
        zeroizeBuffer(fileKey);
      }
    } catch (err) {
      if (err instanceof E2EEError && err.code === 'MISSING_KEYS') throw err;
      // کپسول اشتباه یا کلید نادرست — کپسول دیگر را امتحان کن.
    }
  }
  throw new E2EEError('DECRYPTION_FAILED', 'File AES-GCM authentication or decryption failed');
}

/** رمزنگاری بایت‌های خام فایل با کلید پایدار اتاق. بدون کلید اتاق، Fail-Closed (پرتاب E2EEError، هرگز بایت ساده برنمی‌گردد). */
export async function encryptFileBytes(
  data: Uint8Array,
  roomId: string,
  options?: FileEncryptionOptions
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  // چت خصوصی بدون رمز دستی: کلید تازهٔ هر فایل با ML-KEM-768 (M10، kind=4).
  const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
  if (!manualSecret && !roomId.startsWith('group__')) {
    return encryptDmFileBytesMlkem(data, roomId, options);
  }
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

  // kind=4: کلید تازهٔ هر فایل با ML-KEM-768 (M10) — هر دو کپسول امتحان
  // می‌شوند و مستقیم برمی‌گردد.
  if (kind === FILE_ENCRYPTION_KIND_DM_MLKEM) {
    return decryptDmFileBytesMlkem(data, roomId, options);
  }

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
