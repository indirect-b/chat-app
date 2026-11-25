/**
 * ============================================================================
 * PQ-MPRBA v4 Key Store — IndexedDB + Non-Extractable WebCrypto Keys
 * ============================================================================
 *
 * Security properties:
 * 1. ECDH P-256 private key is generated via WebCrypto with `extractable: false`
 *    and stored directly as a structured-clone `CryptoKey` in IndexedDB.
 * 2. Because WebCrypto does not yet provide native ML-KEM-768 or ML-DSA-65
 *    `CryptoKey` primitives, a per-user device wrapping key (AES-GCM 256-bit,
 *    `extractable: false`) is stored in IndexedDB and used to encrypt the raw
 *    ML-KEM-768 and ML-DSA-65 private key bytes at rest (with unique 96-bit IVs
 *    and AAD binding username + key type + version 4).
 * 3. Unwrapped post-quantum secret key bytes exist in JS memory only for the
 *    duration of a single sign/decapsulate call and are zeroized immediately
 *    in a `finally` block.
 * 4. Plaintext private keys are NEVER stored in `localStorage`. On load, any
 *    legacy `v: 2` or `v: 3` localStorage private keys / ratchet states are
 *    discarded and replaced with freshly generated CSPRNG `v: 4` keys.
 *
 * Honest Web Platform Limitation:
 * While `extractable: false` prevents exporting the ECDH private key or the
 * AES-GCM wrapping key via `crypto.subtle.exportKey`, an active same-origin XSS
 * attacker executing JavaScript in the page origin can still invoke the
 * IndexedDB wrapping key's `decrypt` operation to unwrap ML-KEM/ML-DSA secret
 * bytes at runtime. Strict CSP + out-of-band Safety Number verification remain
 * essential defenses.
 */

export const KEY_STORAGE_VERSION = 4;
export const KEY_STORAGE_VERSION_MARKER = 'chat_key_storage_version';
export const PUBLIC_KEY_CACHE_PREFIX = 'chat_pubkey_v4_';

const IDB_NAME = 'pq_mprba_keystore_v4';
const IDB_STORE = 'identity_keys';
const IDB_REPLAY_STORE = 'replay_protection_v1';
const IDB_PASSWORD_ROOT_STORE = 'password_wrapped_root_v1';
export const IDB_TOFU_STORE = 'tofu_pinned_keys_v1';
/** کش رمزنگاری‌شدهٔ تاریخچهٔ رمزگشایی‌شده (رفع باگ قفل‌شدن پیام‌ها پس از رفرش). */
export const IDB_HISTORY_STORE = 'decrypted_history_v1';
/** انبار دائم نشست‌های راتچت (رفع باگ #2 — vault کلیدهای ردشده فقط در RAM بود). */
export const IDB_RATCHET_STORE = 'ratchet_sessions_v1';
const IDB_VERSION = 6;

const LEGACY_STORAGE_PREFIXES = [
  'chat_ecdh_kp_',
  'chat_mlkem768_kp_',
  'chat_mldsa65_kp_',
  'chat_pq_ratchet_',
  'chat_decrypted_v2_',
  'chat_identity_v3_',
  'chat_key_v3_',
];

export interface WrappedSecretBlob {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

export interface PasswordProtectedWrappingKeyBlob {
  salt: Uint8Array;
  iv: Uint8Array;
  wrappedKeyBytes: Uint8Array;
  iterations: number;
}

/** Password blob as stored in IndexedDB (keyPath 'username'). */
interface StoredPasswordRootBlob extends PasswordProtectedWrappingKeyBlob {
  username: string;
}

export interface StoredIdentityRecordV4 {
  v: 4;
  username: string;
  createdAt: number;
  ecdhPublicJwk: JsonWebKey;
  ecdhPrivateKey: CryptoKey; // extractable: false
  wrappingKey: CryptoKey | null; // AES-GCM 256-bit, extractable: false — null وقتی هویت با رمز عبور محافظت می‌شود (L8): کلید پوششی فقط در حافظهٔ نشست باز می‌شود و هرگز ذخیره نمی‌شود
  passwordProtected?: boolean; // L8: true یعنی کلید پوششی با رمز عبور پیچیده شده و در IDB ذخیره نیست
  mlkemPublicKeyB64: string;
  mlkemSecretWrapped: WrappedSecretBlob;
  mldsaPublicKeyB64: string;
  mldsaSecretWrapped: WrappedSecretBlob;
}

export interface PublicKeyMetadataV4 {
  v: 4;
  username: string;
  ecdhPublicJwk: JsonWebKey;
  mlkemPublicKeyB64: string;
  mldsaPublicKeyB64: string;
}

// In-memory cache of public metadata (safe to expose synchronously to UI / safety numbers)
const publicMetaMemoryCache = new Map<string, PublicKeyMetadataV4>();

// In-memory IndexedDB fallback used ONLY when globalThis.indexedDB is absent (e.g. Node.js tests)
const nodeMemoryIdbStore = new Map<string, StoredIdentityRecordV4>();

// L8: fallback for the password-wrapped wrapping-key blob (Node tests only)
const nodeMemoryPasswordRootStore = new Map<string, StoredPasswordRootBlob>();

// L8: session-scoped cache of unlocked wrapping keys (memory only — never
// persisted). Cleared by lockIdentity() and by resetInMemoryKeyStoreForTests().
const sessionWrappingKeys = new Map<string, CryptoKey>();

/** Thrown when an identity is password-protected and not unlocked (L8). */
export class IdentityLockedError extends Error {
  readonly code = 'IDENTITY_LOCKED' as const;
  constructor(message = 'Identity key is protected by a password — unlock it to continue') {
    super(message);
    this.name = 'IdentityLockedError';
  }
}

function zeroizeBytes(buf: Uint8Array | null | undefined): void {
  if (!buf) return;
  buf.fill(0);
}

export function getWebCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error('WebCrypto API (crypto.subtle) is not available in this environment');
  }
  return c;
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

export function hasBrowserIndexedDB(): boolean {
  try {
    return typeof globalThis !== 'undefined' && typeof globalThis.indexedDB !== 'undefined' && globalThis.indexedDB !== null;
  } catch {
    return false;
  }
}

const nodeMemoryReplayStore = new Set<string>();

export interface PinnedPeerKeyRecord {
  key: string;
  myUsername: string;
  peerUsername: string;
  mldsaPubB64: string;
  mlkemPubB64?: string;
  pinnedAt: number;
}

const nodeMemoryTofuStore = new Map<string, PinnedPeerKeyRecord>();
const tofuMemoryCache = new Map<string, PinnedPeerKeyRecord>();

function openKeyStoreDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = globalThis.indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE, { keyPath: 'username' });
      }
      if (!db.objectStoreNames.contains(IDB_REPLAY_STORE)) {
        db.createObjectStore(IDB_REPLAY_STORE, { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains(IDB_TOFU_STORE)) {
        db.createObjectStore(IDB_TOFU_STORE, { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains(IDB_PASSWORD_ROOT_STORE)) {
        db.createObjectStore(IDB_PASSWORD_ROOT_STORE, { keyPath: 'username' });
      }
      if (!db.objectStoreNames.contains(IDB_HISTORY_STORE)) {
        db.createObjectStore(IDB_HISTORY_STORE, { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains(IDB_RATCHET_STORE)) {
        db.createObjectStore(IDB_RATCHET_STORE, { keyPath: 'key' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Failed to open IndexedDB keystore'));
  });
}

/**
 * دریافت کلید پین‌شده همتا در مدل TOFU (Trust On First Use - M4)
 */
export async function getPinnedPeerIdentityKeyTOFU(
  myUsername: string,
  peerUsername: string
): Promise<PinnedPeerKeyRecord | null> {
  const normMy = normalizeKeystoreUsername(myUsername);
  const normPeer = normalizeKeystoreUsername(peerUsername);
  const key = `${normMy}::${normPeer}`;

  if (tofuMemoryCache.has(key)) {
    return tofuMemoryCache.get(key)!;
  }

  if (!hasBrowserIndexedDB()) {
    return nodeMemoryTofuStore.get(key) || null;
  }

  try {
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_TOFU_STORE)) return null;
    return new Promise(resolve => {
      const tx = db.transaction(IDB_TOFU_STORE, 'readonly');
      const store = tx.objectStore(IDB_TOFU_STORE);
      const req = store.get(key);
      req.onsuccess = () => {
        const res = (req.result as PinnedPeerKeyRecord) || null;
        if (res) tofuMemoryCache.set(key, res);
        resolve(res);
      };
      req.onerror = () => resolve(null);
    });
  } catch {
    return null;
  }
}

/**
 * خواندن همگام کلید پین‌شده از کش حافظه (M4)
 */
export function getPinnedPeerIdentityKeyTOFUSync(
  myUsername: string,
  peerUsername: string
): PinnedPeerKeyRecord | null {
  const normMy = normalizeKeystoreUsername(myUsername);
  const normPeer = normalizeKeystoreUsername(peerUsername);
  const key = `${normMy}::${normPeer}`;
  return tofuMemoryCache.get(key) || nodeMemoryTofuStore.get(key) || null;
}

/**
 * پین کردن همگام کلید دیده‌شده در کش حافظه TOFU (M4)
 */
export function pinPeerIdentityKeyTOFUSync(
  myUsername: string,
  peerUsername: string,
  mldsaPubB64: string,
  mlkemPubB64?: string
): PinnedPeerKeyRecord {
  const normMy = normalizeKeystoreUsername(myUsername);
  const normPeer = normalizeKeystoreUsername(peerUsername);
  const key = `${normMy}::${normPeer}`;

  const existing = tofuMemoryCache.get(key) || nodeMemoryTofuStore.get(key);
  if (existing) {
    return existing;
  }

  const record: PinnedPeerKeyRecord = {
    key,
    myUsername: normMy,
    peerUsername: normPeer,
    mldsaPubB64,
    mlkemPubB64,
    pinnedAt: Date.now(),
  };

  tofuMemoryCache.set(key, record);
  nodeMemoryTofuStore.set(key, record);
  return record;
}

/**
 * پین کردن اولین کلید دیده‌شدهٔ همتا در مخزن با دوام IndexedDB (Trust On First Use - M4)
 */
export async function pinPeerIdentityKeyTOFU(
  myUsername: string,
  peerUsername: string,
  mldsaPubB64: string,
  mlkemPubB64?: string
): Promise<PinnedPeerKeyRecord> {
  const record = pinPeerIdentityKeyTOFUSync(myUsername, peerUsername, mldsaPubB64, mlkemPubB64);

  if (!hasBrowserIndexedDB()) {
    return record;
  }

  try {
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_TOFU_STORE)) return record;
    return new Promise(resolve => {
      const tx = db.transaction(IDB_TOFU_STORE, 'readwrite');
      const store = tx.objectStore(IDB_TOFU_STORE);
      store.put(record);
      tx.oncomplete = () => resolve(record);
      tx.onerror = () => resolve(record);
    });
  } catch {
    return record;
  }
}

/**
 * بازپین کردن همگام کلید هویت همتا (M4 — round 3). برخلاف pin که هرگز
 * روی پین موجود نمی‌نویسد، این تابع پین را بازنویسی می‌کند و فقط از مسیر
 * تأیید صریح کاربر (markContactVerified) فراخوانی می‌شود: وقتی کاربر پس از
 * چرخش قانونی کلید، کلید جدید را صریحاً تأیید می‌کند، پین باید به کلید جدید
 * منتقل شود؛ در غیر این صورت هر مشاهدهٔ بعدی دوباره CHANGED می‌زد و هشدار
 * برای همیشه گیر می‌کرد.
 */
export function repinPeerIdentityKeyTOFUSync(
  myUsername: string,
  peerUsername: string,
  mldsaPubB64: string,
  mlkemPubB64?: string
): PinnedPeerKeyRecord {
  const normMy = normalizeKeystoreUsername(myUsername);
  const normPeer = normalizeKeystoreUsername(peerUsername);
  const key = `${normMy}::${normPeer}`;

  const record: PinnedPeerKeyRecord = {
    key,
    myUsername: normMy,
    peerUsername: normPeer,
    mldsaPubB64,
    mlkemPubB64,
    pinnedAt: Date.now(),
  };

  tofuMemoryCache.set(key, record);
  nodeMemoryTofuStore.set(key, record);
  return record;
}

/**
 * بازپین کردن کلید هویت همتا در مخزن با دوام IndexedDB (M4 — round 3).
 * فقط از مسیر تأیید صریح کاربر فراخوانی می‌شود.
 */
export async function repinPeerIdentityKeyTOFU(
  myUsername: string,
  peerUsername: string,
  mldsaPubB64: string,
  mlkemPubB64?: string
): Promise<PinnedPeerKeyRecord> {
  const record = repinPeerIdentityKeyTOFUSync(myUsername, peerUsername, mldsaPubB64, mlkemPubB64);

  if (!hasBrowserIndexedDB()) {
    return record;
  }

  try {
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_TOFU_STORE)) return record;
    return new Promise(resolve => {
      const tx = db.transaction(IDB_TOFU_STORE, 'readwrite');
      const store = tx.objectStore(IDB_TOFU_STORE);
      store.put(record);
      tx.oncomplete = () => resolve(record);
      tx.onerror = () => resolve(record);
    });
  } catch {
    return record;
  }
}

/**
 * بررسی سابقه Replay در انبار با دوام IndexedDB (H3 / M1)
 */

// انبار دائم Replay بدون کران رشد می‌کرد — هر پیام یک ورودی برای همیشه.
// کران‌ها (راند ۳): TTL سی روز + حداکثر ۱۰٬۰۰۰ ورودی. پیام DM قدیمی پس از
// چرخش راتچت دیگر رمزگشایی نمی‌شود، پس حذف ورودی‌های قدیمی امن است؛ برای
// پیام گروهیِ همان اپوک، پس از این کران فقط پیام‌های قدیمی‌تر از ۱۰٬۰۰۰
// پیام اخیر یا ۳۰ روز از محافظت Replay خارج می‌شوند (مصالحهٔ مستند).
export const DURABLE_REPLAY_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const DURABLE_REPLAY_MAX_ENTRIES = 10_000;
const DURABLE_REPLAY_PRUNE_SAMPLE_RATE = 0.05;

export async function isDurableReplaySeen(roomId: string, token: string): Promise<boolean> {
  const key = `${roomId}::${token}`;
  if (!hasBrowserIndexedDB()) {
    return nodeMemoryReplayStore.has(key);
  }
  try {
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_REPLAY_STORE)) return false;
    return new Promise<boolean>((resolve, reject) => {
      const tx = db.transaction(IDB_REPLAY_STORE, 'readonly');
      const store = tx.objectStore(IDB_REPLAY_STORE);
      const req = store.get(key);
      req.onsuccess = () => resolve(Boolean(req.result));
      // M1 (round 5): fail CLOSED on a real IndexedDB error — "unknown"
      // must never be treated as "not seen", or a replay could slip
      // through whenever the durable store is unreadable. The only
      // fail-open case kept is a missing store (no store = no recorded
      // tokens = legitimately not seen).
      req.onerror = () => reject(new Error(`DURABLE_REPLAY_CHECK_FAILED: IndexedDB replay lookup failed (${req.error?.message || 'unknown error'})`));
    });
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('DURABLE_REPLAY_CHECK_FAILED')) throw err;
    throw new Error(`DURABLE_REPLAY_CHECK_FAILED: ${err instanceof Error ? err.message : 'IndexedDB replay check failed'}`);
  }
}

/**
 * ثبت توکن پیام تحویل‌شده در انبار با دوام IndexedDB (H3 / M1)
 */
export async function recordDurableReplaySeen(roomId: string, token: string): Promise<void> {
  const key = `${roomId}::${token}`;
  if (!hasBrowserIndexedDB()) {
    nodeMemoryReplayStore.add(key);
    // کران حافظه در تست‌های Node: قدیمی‌ترین‌ها (ترتیب درج) حذف می‌شوند.
    if (nodeMemoryReplayStore.size > DURABLE_REPLAY_MAX_ENTRIES) {
      const excess = nodeMemoryReplayStore.size - DURABLE_REPLAY_MAX_ENTRIES;
      let removed = 0;
      for (const oldKey of nodeMemoryReplayStore) {
        if (removed >= excess) break;
        nodeMemoryReplayStore.delete(oldKey);
        removed++;
      }
    }
    return;
  }
  try {
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_REPLAY_STORE)) return;
    return new Promise(resolve => {
      const tx = db.transaction(IDB_REPLAY_STORE, 'readwrite');
      const store = tx.objectStore(IDB_REPLAY_STORE);
      store.put({ key, timestamp: Date.now() });
      tx.oncomplete = () => {
        resolve();
        // هرس نمونه‌ای (۵٪) تا هزینهٔ اسکن روی هر پیام نیفتد.
        if (Math.random() < DURABLE_REPLAY_PRUNE_SAMPLE_RATE) {
          void pruneDurableReplaySeen();
        }
      };
      tx.onerror = () => resolve();
    });
  } catch {
    // ignore
  }
}

/**
 * هرس انبار دائم Replay: ورودی‌های قدیمی‌تر از TTL و — اگر هنوز بیش از
 * حداکثر بود — قدیمی‌ترین ورودی‌ها حذف می‌شوند. Best-effort؛ خطا نادیده
 * گرفته می‌شود تا هرگز مسیر پیام را خراب نکند.
 */
export async function pruneDurableReplaySeen(nowMs: number = Date.now()): Promise<void> {
  if (!hasBrowserIndexedDB()) {
    if (nodeMemoryReplayStore.size > DURABLE_REPLAY_MAX_ENTRIES) {
      const excess = nodeMemoryReplayStore.size - DURABLE_REPLAY_MAX_ENTRIES;
      let removed = 0;
      for (const oldKey of nodeMemoryReplayStore) {
        if (removed >= excess) break;
        nodeMemoryReplayStore.delete(oldKey);
        removed++;
      }
    }
    return;
  }
  try {
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_REPLAY_STORE)) return;
    const entries = await new Promise<Array<{ key: string; timestamp: number }>>(resolve => {
      const tx = db.transaction(IDB_REPLAY_STORE, 'readonly');
      const store = tx.objectStore(IDB_REPLAY_STORE);
      const req = store.getAll();
      req.onsuccess = () => resolve((req.result as Array<{ key: string; timestamp: number }>) || []);
      req.onerror = () => resolve([]);
    });
    const cutoff = nowMs - DURABLE_REPLAY_TTL_MS;
    const stale = entries.filter(e => (e.timestamp || 0) < cutoff).map(e => e.key);
    let toDelete = stale;
    if (entries.length - stale.length > DURABLE_REPLAY_MAX_ENTRIES) {
      const fresh = entries
        .filter(e => (e.timestamp || 0) >= cutoff)
        .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      const excess = fresh.length - DURABLE_REPLAY_MAX_ENTRIES;
      toDelete = [...stale, ...fresh.slice(0, excess).map(e => e.key)];
    }
    if (toDelete.length === 0) return;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_REPLAY_STORE, 'readwrite');
      const store = tx.objectStore(IDB_REPLAY_STORE);
      for (const key of toDelete) store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch {
    // ignore
  }
}

/**
 * ============================================================================
 * کش رمزنگاری‌شدهٔ تاریخچهٔ رمزگشایی‌شده (Decrypted History Cache)
 * ============================================================================
 *
 * چرا این کش لازم است: نشست راتچت PQ فقط در حافظهٔ RAM نگه داشته می‌شود و
 * انبار دائم Replay هر پیام تحویل‌شده را تا ۳۰ روز به‌خاطر می‌سپارد. پس از هر
 * رفرش، رمزگشایی دوبارهٔ تاریخچه با REPLAY_DETECTED رد می‌شود و پیام‌های
 * ارسالی خود کاربر هم — چون متن آن‌ها فقط در کش حافظه‌ای
 * sentPlaintextMemoryCache بود — دیگر قابل بازیابی نیستند. نتیجه: همهٔ
 * پیام‌های قبلی قفل‌شده نمایش داده می‌شوند.
 *
 * راه‌حل (همان رویکرد Signal): پس از هر رمزگشایی موفق، متن سادهٔ پیام با
 * AES-GCM زیر همان کلید پوششی دستگاه که رازهای ML-KEM/ML-DSA را می‌پوشاند،
 * در IndexedDB ذخیره می‌شود و رمزگشایی تاریخچه پیش از رمزگشایی دوباره،
 * اول این کش را می‌خواند. این کار هیچ‌یک از محافظت‌ها را تغییر نمی‌دهد:
 * بررسی Replay، راتچت، seenRecvSteps و اعتبارسنجی امضا دست‌نخورده‌اند؛
 * متن ساده هرگز به سرور نمی‌رود و هرگز بدون رمز در دیسک نمی‌نشیند.
 *
 * کلید کش: `<username>::<roomId>::<payloadHash24>` — دقیقاً همان طرحی که
 * کش حافظه‌ای پیام‌های ارسالی استفاده می‌کند، تا ارسال و دریافت کلید
 * مشترک داشته باشند.
 */
export const DECRYPTED_HISTORY_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const DECRYPTED_HISTORY_MAX_ENTRIES = 10_000;
const DECRYPTED_HISTORY_PRUNE_SAMPLE_RATE = 0.05;

export interface DecryptedHistoryEntry {
  text: string;
  mode?: 'PQ-MLKEM-RATCHET' | 'GROUP-EPOCH-FSM' | 'PBKDF2';
  ratchetStep?: number;
  epoch?: number;
  mldsaVerified: boolean;
  timestamp: number;
}

interface StoredDecryptedHistoryRecord {
  key: string;
  username: string;
  roomId: string;
  payloadHash: string;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  timestamp: number;
}

// In-memory IndexedDB fallback used ONLY when globalThis.indexedDB is absent (e.g. Node.js tests)
const nodeMemoryHistoryStore = new Map<string, StoredDecryptedHistoryRecord>();

function historyCacheKey(username: string, roomId: string, payloadHashKey: string): string {
  return `${normalizeKeystoreUsername(username)}::${roomId}::${payloadHashKey}`;
}

/**
 * کلید پوششی لازم برای کش تاریخچه: برای هویت معمولی، کلید ذخیره‌شده در
 * رکورد؛ برای هویت محافظت‌شده با رمز عبور (L8)، فقط کلید بازشدهٔ نشست —
 * در حالت قفل، null برمی‌گردد و کش خوانده/نوشته نمی‌شود (رفتار درست L8:
 * تاریخچه تا باز شدن هویت قفل می‌ماند).
 */
async function getHistoryWrappingKey(username: string): Promise<CryptoKey | null> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return null;
  const sessionKey = getSessionWrappingKey(norm);
  if (sessionKey) return sessionKey;
  let record: StoredIdentityRecordV4 | null = null;
  try {
    record = await loadIdentityRecordV4(norm);
  } catch {
    return null;
  }
  if (!record || record.passwordProtected) return null;
  return record.wrappingKey ?? null;
}

const HISTORY_AAD_LABEL = 'PQ-MPRBA:HISTORY-V1';

function historyAad(username: string, roomId: string, payloadHashKey: string): Uint8Array {
  return new TextEncoder().encode(
    `${HISTORY_AAD_LABEL}:${normalizeKeystoreUsername(username)}:${roomId}:${payloadHashKey}`
  );
}

async function encryptDecryptedHistoryEntry(
  wrappingKey: CryptoKey,
  username: string,
  roomId: string,
  payloadHashKey: string,
  entry: Omit<DecryptedHistoryEntry, 'timestamp'>
): Promise<WrappedSecretBlob> {
  const webCrypto = getWebCrypto();
  const iv = webCrypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(
    JSON.stringify({
      text: entry.text,
      mode: entry.mode,
      ratchetStep: entry.ratchetStep,
      epoch: entry.epoch,
      mldsaVerified: entry.mldsaVerified,
    })
  );
  const ctBuf = await webCrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
      additionalData: historyAad(username, roomId, payloadHashKey) as unknown as BufferSource,
    },
    wrappingKey,
    plain as unknown as BufferSource
  );
  return { iv, ciphertext: new Uint8Array(ctBuf) };
}

async function decryptDecryptedHistoryEntry(
  wrappingKey: CryptoKey,
  username: string,
  roomId: string,
  payloadHashKey: string,
  wrapped: WrappedSecretBlob
): Promise<Omit<DecryptedHistoryEntry, 'timestamp'>> {
  const webCrypto = getWebCrypto();
  const plainBuf = await webCrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: wrapped.iv as unknown as BufferSource,
      additionalData: historyAad(username, roomId, payloadHashKey) as unknown as BufferSource,
    },
    wrappingKey,
    wrapped.ciphertext as unknown as BufferSource
  );
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plainBuf));
  if (typeof parsed !== 'object' || parsed === null || typeof parsed.text !== 'string') {
    throw new Error('Decrypted history entry has an unexpected shape');
  }
  return {
    text: parsed.text,
    mode: parsed.mode,
    ratchetStep: parsed.ratchetStep,
    epoch: parsed.epoch,
    mldsaVerified: Boolean(parsed.mldsaVerified),
  };
}

/**
 * ذخیرهٔ یک پیام رمزگشایی‌شده در کش تاریخچه (best-effort: بدون کلید یا
 * با خطا، false برمی‌گردد و هرگز throw نمی‌کند تا مسیر پیام خراب نشود).
 */
export async function storeDecryptedHistoryEntry(
  username: string,
  roomId: string,
  payloadHashKey: string,
  entry: Omit<DecryptedHistoryEntry, 'timestamp'>
): Promise<boolean> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm || !roomId || !payloadHashKey) return false;
  try {
    const wrappingKey = await getHistoryWrappingKey(norm);
    if (!wrappingKey) return false;
    const wrapped = await encryptDecryptedHistoryEntry(wrappingKey, norm, roomId, payloadHashKey, entry);
    const record: StoredDecryptedHistoryRecord = {
      key: historyCacheKey(norm, roomId, payloadHashKey),
      username: norm,
      roomId,
      payloadHash: payloadHashKey,
      iv: wrapped.iv,
      ciphertext: wrapped.ciphertext,
      timestamp: Date.now(),
    };
    if (!hasBrowserIndexedDB()) {
      nodeMemoryHistoryStore.set(record.key, record);
      if (nodeMemoryHistoryStore.size > DECRYPTED_HISTORY_MAX_ENTRIES) {
        void pruneDecryptedHistory();
      }
      return true;
    }
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_HISTORY_STORE)) return false;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_HISTORY_STORE, 'readwrite');
      const store = tx.objectStore(IDB_HISTORY_STORE);
      store.put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
    // هرس نمونه‌ای (۵٪) — همان الگوی انبار Replay.
    if (Math.random() < DECRYPTED_HISTORY_PRUNE_SAMPLE_RATE) {
      void pruneDecryptedHistory();
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * خواندن یک پیام از کش تاریخچه. نبود ورودی، انقضای TTL، قفل‌بودن هویت
 * (L8) یا هر خطای رمزگشایی → null (مسیر عادی رمزگشایی ادامه پیدا می‌کند).
 */
export async function getDecryptedHistoryEntry(
  username: string,
  roomId: string,
  payloadHashKey: string
): Promise<DecryptedHistoryEntry | null> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm || !roomId || !payloadHashKey) return null;
  try {
    const key = historyCacheKey(norm, roomId, payloadHashKey);
    let stored: StoredDecryptedHistoryRecord | undefined;
    if (!hasBrowserIndexedDB()) {
      stored = nodeMemoryHistoryStore.get(key);
    } else {
      const db = await openKeyStoreDB();
      if (!db.objectStoreNames.contains(IDB_HISTORY_STORE)) return null;
      stored = await new Promise<StoredDecryptedHistoryRecord | undefined>(resolve => {
        const tx = db.transaction(IDB_HISTORY_STORE, 'readonly');
        const store = tx.objectStore(IDB_HISTORY_STORE);
        const req = store.get(key);
        req.onsuccess = () => resolve((req.result as StoredDecryptedHistoryRecord) || undefined);
        req.onerror = () => resolve(undefined);
      });
      db.close();
    }
    if (!stored) return null;
    if (Date.now() - (stored.timestamp || 0) > DECRYPTED_HISTORY_TTL_MS) {
      void deleteDecryptedHistoryEntry(norm, roomId, payloadHashKey);
      return null;
    }
    const wrappingKey = await getHistoryWrappingKey(norm);
    if (!wrappingKey) return null;
    const entry = await decryptDecryptedHistoryEntry(
      wrappingKey,
      norm,
      roomId,
      payloadHashKey,
      { iv: stored.iv, ciphertext: stored.ciphertext }
    );
    return { ...entry, timestamp: stored.timestamp };
  } catch {
    return null;
  }
}

async function deleteDecryptedHistoryEntry(
  username: string,
  roomId: string,
  payloadHashKey: string
): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return;
  const key = historyCacheKey(norm, roomId, payloadHashKey);
  try {
    if (!hasBrowserIndexedDB()) {
      nodeMemoryHistoryStore.delete(key);
      return;
    }
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_HISTORY_STORE)) return;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_HISTORY_STORE, 'readwrite');
      const store = tx.objectStore(IDB_HISTORY_STORE);
      store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
  } catch {
    // ignore
  }
}

/**
 * حذف همهٔ ورودی‌های کش تاریخچهٔ یک کاربر — هنگام حذف هویت (deleteIdentityRecordV4)
 * فراخوانی می‌شود تا هیچ متن رمزنگاری‌شده‌ای از هویت حذف‌شده باقی نماند.
 */
export async function deleteDecryptedHistoryForUser(username: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return;
  try {
    if (!hasBrowserIndexedDB()) {
      for (const key of Array.from(nodeMemoryHistoryStore.keys())) {
        if (key.startsWith(`${norm}::`)) nodeMemoryHistoryStore.delete(key);
      }
      return;
    }
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_HISTORY_STORE)) return;
    const entries = await new Promise<Array<StoredDecryptedHistoryRecord>>(resolve => {
      const tx = db.transaction(IDB_HISTORY_STORE, 'readonly');
      const store = tx.objectStore(IDB_HISTORY_STORE);
      const req = store.getAll();
      req.onsuccess = () => resolve((req.result as Array<StoredDecryptedHistoryRecord>) || []);
      req.onerror = () => resolve([]);
    });
    const ownKeys = entries.filter(e => e.username === norm).map(e => e.key);
    if (ownKeys.length === 0) return;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_HISTORY_STORE, 'readwrite');
      const store = tx.objectStore(IDB_HISTORY_STORE);
      for (const key of ownKeys) store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
  } catch {
    // ignore
  }
}

/**
 * هرس کش تاریخچه: ورودی‌های قدیمی‌تر از TTL و — برای هر کاربر جداگانه —
 * قدیمی‌ترین ورودی‌های مازاد بر سقف حذف می‌شوند. Best-effort.
 */
export async function pruneDecryptedHistory(nowMs: number = Date.now()): Promise<void> {
  try {
    if (!hasBrowserIndexedDB()) {
      const byUser = new Map<string, Array<{ key: string; timestamp: number }>>();
      for (const [key, rec] of nodeMemoryHistoryStore) {
        const list = byUser.get(rec.username) || [];
        list.push({ key, timestamp: rec.timestamp || 0 });
        byUser.set(rec.username, list);
      }
      const cutoff = nowMs - DECRYPTED_HISTORY_TTL_MS;
      for (const list of byUser.values()) {
        const stale = list.filter(e => e.timestamp < cutoff).map(e => e.key);
        let toDelete = stale;
        const fresh = list
          .filter(e => e.timestamp >= cutoff)
          .sort((a, b) => a.timestamp - b.timestamp);
        if (fresh.length > DECRYPTED_HISTORY_MAX_ENTRIES) {
          toDelete = [...stale, ...fresh.slice(0, fresh.length - DECRYPTED_HISTORY_MAX_ENTRIES).map(e => e.key)];
        }
        for (const key of toDelete) nodeMemoryHistoryStore.delete(key);
      }
      return;
    }
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_HISTORY_STORE)) return;
    const entries = await new Promise<Array<StoredDecryptedHistoryRecord>>(resolve => {
      const tx = db.transaction(IDB_HISTORY_STORE, 'readonly');
      const store = tx.objectStore(IDB_HISTORY_STORE);
      const req = store.getAll();
      req.onsuccess = () => resolve((req.result as Array<StoredDecryptedHistoryRecord>) || []);
      req.onerror = () => resolve([]);
    });
    const cutoff = nowMs - DECRYPTED_HISTORY_TTL_MS;
    const byUser = new Map<string, Array<StoredDecryptedHistoryRecord>>();
    for (const e of entries) {
      const list = byUser.get(e.username) || [];
      list.push(e);
      byUser.set(e.username, list);
    }
    const toDelete: string[] = [];
    for (const list of byUser.values()) {
      const stale = list.filter(e => (e.timestamp || 0) < cutoff).map(e => e.key);
      toDelete.push(...stale);
      const fresh = list
        .filter(e => (e.timestamp || 0) >= cutoff)
        .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      if (fresh.length > DECRYPTED_HISTORY_MAX_ENTRIES) {
        toDelete.push(...fresh.slice(0, fresh.length - DECRYPTED_HISTORY_MAX_ENTRIES).map(e => e.key));
      }
    }
    if (toDelete.length === 0) return;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_HISTORY_STORE, 'readwrite');
      const store = tx.objectStore(IDB_HISTORY_STORE);
      for (const key of toDelete) store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
  } catch {
    // ignore
  }
}

/**
 * انبار دائم نشست راتچت (رفع باگ #2 — «تلهٔ حافظه و انقضای کلیدها»):
 * تا پیش از این، وضعیت راتچت (زنجیرهٔ دریافت، گام‌ها، و vault کلیدهای
 * ردشده) فقط در `ratchetStateMap` درون‌حافظه‌ای زندگی می‌کرد؛ با هر رفرش
 * یا بستن تب، همه‌چیز — از جمله کلیدهای پیام‌های خارج از نوبت — از بین
 * می‌رفت و پیام‌های قدیمی برای همیشه قفل می‌شدند. این بخش همان وضعیت را
 * در IndexedDB نگه می‌دارد، دقیقاً با همان الگوی کش تاریخچه (رفع راند ۵):
 * AES-256-GCM زیر کلید پوششی دستگاه، AAD متصل به کاربر + اتاق، و
 * هرگز متن ساده یا کلید خام روی دیسک نمی‌نشیند. در حالت قفل (L8) کلید
 * پوششی در دسترس نیست و خواندن/نوشتن بی‌صدا no-op می‌شود.
 *
 * چه چیزی ذخیره می‌شود: زنجیره‌های ارسال/دریافت، گام‌ها، seenRecvSteps،
 * کپسول ML-KEM نشست، و vault کلیدهای ردشده. نشست قبلی (previousSession)
 * عمداً ذخیره نمی‌شود — فقط برای محافظت Replay در برابر تناوب کپسول
 * (H1) در نشست زنده کاربرد دارد؛ پس از رفرش، پیام بعدی با کپسول جاری
 * نشست را از نو می‌سازد و این از دست‌رفتن، دقیقاً همان رفتار امروز است.
 */
export const DURABLE_RATCHET_SKIPPED_KEY_TTL_MS = 10 * 60 * 1000; // باید با SKIPPED_KEY_TTL_MS در crypto.ts برابر بماند
export const DURABLE_RATCHET_MAX_SKIPPED_KEYS = 100; // باید با MAX_SKIP در crypto.ts برابر بماند
export const DURABLE_RATCHET_MAX_SEEN_STEPS = 10_000; // باید با MAX_SEEN_RECV_STEPS در crypto.ts برابر بماند

/** شکل سریال‌شدهٔ نشست راتچت — بایت‌ها به‌صورت آرایهٔ عدد (بدون base64) تا در Node و مرورگر یکسان کار کند. */
export interface DurableRatchetStateV1 {
  sendChainKey: number[]; // ۳۲ بایت
  recvChainKey: number[]; // ۳۲ بایت
  sendStep: number;
  recvStep: number;
  sentSinceRekey: number;
  seenRecvSteps: number[];
  kemCipherTextB64: string;
  peerKemFingerprint: string;
  skippedKeys: Array<{ step: number; mk: number[]; timestamp: number }>;
  sessionEpoch?: number;
  hkdfSaltVersion?: 'v1' | 'v2';
}

interface StoredRatchetSessionRecord {
  key: string;
  username: string;
  roomId: string;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  timestamp: number;
}

// In-memory IndexedDB fallback used ONLY when globalThis.indexedDB is absent (e.g. Node.js tests)
const nodeMemoryRatchetStore = new Map<string, StoredRatchetSessionRecord>();

function ratchetSessionKey(username: string, roomId: string): string {
  return `${normalizeKeystoreUsername(username)}::${roomId}`;
}

const RATCHET_AAD_LABEL = 'PQ-MPRBA:RATCHET-V1';

function ratchetAad(username: string, roomId: string): Uint8Array {
  return new TextEncoder().encode(
    `${RATCHET_AAD_LABEL}:${normalizeKeystoreUsername(username)}:${roomId}`
  );
}

function isValidByteArray(v: unknown, len: number): v is number[] {
  return (
    Array.isArray(v) &&
    v.length === len &&
    v.every(b => Number.isInteger(b) && (b as number) >= 0 && (b as number) <= 255)
  );
}

function isValidSkippedEntry(v: unknown): v is { step: number; mk: number[]; timestamp: number } {
  if (typeof v !== 'object' || v === null) return false;
  const e = v as { step?: unknown; mk?: unknown; timestamp?: unknown };
  return (
    Number.isSafeInteger(e.step) &&
    (e.step as number) >= 0 &&
    isValidByteArray(e.mk, 32) &&
    Number.isSafeInteger(e.timestamp) &&
    (e.timestamp as number) >= 0
  );
}

/**
 * اعتبارسنجی سخت‌گیرانهٔ حالت بازیابی‌شده + هرس ورودی‌های منقضی‌شده
 * (TTL ۱۰ دقیقه) + سقف ۱۰۰ کلید ردشده (تازه‌ترین گام‌ها می‌مانند) و سقف
 * ۱۰٬۰۰۰ گام دیده‌شده. هر شکل نامعتبر → null (fail closed).
 */
function validateAndPruneDurableRatchetState(
  parsed: unknown,
  nowMs: number
): { state: DurableRatchetStateV1; dropped: number } | null {
  if (typeof parsed !== 'object' || parsed === null) return null;
  const s = parsed as Record<string, unknown>;
  if (!isValidByteArray(s.sendChainKey, 32) || !isValidByteArray(s.recvChainKey, 32)) return null;
  if (!Number.isSafeInteger(s.sendStep) || (s.sendStep as number) < 0) return null;
  if (!Number.isSafeInteger(s.recvStep) || (s.recvStep as number) < 0) return null;
  if (!Number.isSafeInteger(s.sentSinceRekey) || (s.sentSinceRekey as number) < 0) return null;
  if (
    !Array.isArray(s.seenRecvSteps) ||
    !s.seenRecvSteps.every(n => Number.isSafeInteger(n) && (n as number) >= 0)
  ) {
    return null;
  }
  if (typeof s.kemCipherTextB64 !== 'string' || !s.kemCipherTextB64) return null;
  if (typeof s.peerKemFingerprint !== 'string') return null;
  if (!Array.isArray(s.skippedKeys) || !s.skippedKeys.every(isValidSkippedEntry)) return null;
  if (
    s.sessionEpoch !== undefined &&
    (!Number.isSafeInteger(s.sessionEpoch) || (s.sessionEpoch as number) < 0)
  ) {
    return null;
  }
  if (
    s.hkdfSaltVersion !== undefined &&
    s.hkdfSaltVersion !== 'v1' &&
    s.hkdfSaltVersion !== 'v2'
  ) {
    return null;
  }

  const entries = s.skippedKeys as Array<{ step: number; mk: number[]; timestamp: number }>;
  const fresh = entries
    .filter(e => nowMs - e.timestamp <= DURABLE_RATCHET_SKIPPED_KEY_TTL_MS)
    .sort((a, b) => a.step - b.step);
  const dropped = entries.length - fresh.length;
  const kept =
    fresh.length > DURABLE_RATCHET_MAX_SKIPPED_KEYS
      ? fresh.slice(fresh.length - DURABLE_RATCHET_MAX_SKIPPED_KEYS)
      : fresh;
  const seen = Array.from(new Set(s.seenRecvSteps as number[]));
  const seenKept =
    seen.length > DURABLE_RATCHET_MAX_SEEN_STEPS
      ? seen.slice(seen.length - DURABLE_RATCHET_MAX_SEEN_STEPS)
      : seen;

  return {
    state: {
      sendChainKey: s.sendChainKey as number[],
      recvChainKey: s.recvChainKey as number[],
      sendStep: s.sendStep as number,
      recvStep: s.recvStep as number,
      sentSinceRekey: s.sentSinceRekey as number,
      seenRecvSteps: seenKept,
      kemCipherTextB64: s.kemCipherTextB64 as string,
      peerKemFingerprint: s.peerKemFingerprint as string,
      skippedKeys: kept,
      sessionEpoch: s.sessionEpoch as number | undefined,
      hkdfSaltVersion: s.hkdfSaltVersion as 'v1' | 'v2' | undefined,
    },
    dropped,
  };
}

async function encryptDurableRatchetState(
  wrappingKey: CryptoKey,
  username: string,
  roomId: string,
  state: DurableRatchetStateV1
): Promise<WrappedSecretBlob> {
  const webCrypto = getWebCrypto();
  const iv = webCrypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(state));
  const ctBuf = await webCrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
      additionalData: ratchetAad(username, roomId) as unknown as BufferSource,
    },
    wrappingKey,
    plain as unknown as BufferSource
  );
  return { iv, ciphertext: new Uint8Array(ctBuf) };
}

async function decryptDurableRatchetState(
  wrappingKey: CryptoKey,
  username: string,
  roomId: string,
  wrapped: WrappedSecretBlob
): Promise<{ state: DurableRatchetStateV1; dropped: number } | null> {
  const webCrypto = getWebCrypto();
  const plainBuf = await webCrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: wrapped.iv as unknown as BufferSource,
      additionalData: ratchetAad(username, roomId) as unknown as BufferSource,
    },
    wrappingKey,
    wrapped.ciphertext as unknown as BufferSource
  );
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plainBuf));
  return validateAndPruneDurableRatchetState(parsed, Date.now());
}

/**
 * ذخیرهٔ وضعیت راتچت در انبار دائم (best-effort: بدون کلید یا با خطا،
 * false برمی‌گردد و هرگز throw نمی‌کند تا مسیر پیام خراب نشود).
 */
export async function persistDurableRatchetState(
  username: string,
  roomId: string,
  state: DurableRatchetStateV1
): Promise<boolean> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm || !roomId) return false;
  try {
    const wrappingKey = await getHistoryWrappingKey(norm);
    if (!wrappingKey) return false;
    const wrapped = await encryptDurableRatchetState(wrappingKey, norm, roomId, state);
    const record: StoredRatchetSessionRecord = {
      key: ratchetSessionKey(norm, roomId),
      username: norm,
      roomId,
      iv: wrapped.iv,
      ciphertext: wrapped.ciphertext,
      timestamp: Date.now(),
    };
    if (!hasBrowserIndexedDB()) {
      nodeMemoryRatchetStore.set(record.key, record);
      return true;
    }
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_RATCHET_STORE)) return false;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_RATCHET_STORE, 'readwrite');
      const store = tx.objectStore(IDB_RATCHET_STORE);
      store.put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
    return true;
  } catch {
    return false;
  }
}

/**
 * خواندن وضعیت راتچت از انبار دائم. نبود رکورد، قفل‌بودن هویت (L8)،
 * یا هر خطای رمزگشایی/اعتبارسنجی → null (نشست از نو ساخته می‌شود — همان
 * رفتار امروز). رکورد خراب حذف می‌شود تا تلاش‌های بعدی تکراری نباشند.
 * اگر هرس TTL ورودی‌ای را انداخته باشد، حالت هرس‌شده دوباره نوشته
 * می‌شود تا کلیدهای منقضی در انبار باقی نمانند.
 */
export async function loadDurableRatchetState(
  username: string,
  roomId: string
): Promise<DurableRatchetStateV1 | null> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm || !roomId) return null;
  try {
    const key = ratchetSessionKey(norm, roomId);
    let stored: StoredRatchetSessionRecord | undefined;
    if (!hasBrowserIndexedDB()) {
      stored = nodeMemoryRatchetStore.get(key);
    } else {
      const db = await openKeyStoreDB();
      if (!db.objectStoreNames.contains(IDB_RATCHET_STORE)) return null;
      stored = await new Promise<StoredRatchetSessionRecord | undefined>(resolve => {
        const tx = db.transaction(IDB_RATCHET_STORE, 'readonly');
        const store = tx.objectStore(IDB_RATCHET_STORE);
        const req = store.get(key);
        req.onsuccess = () => resolve((req.result as StoredRatchetSessionRecord) || undefined);
        req.onerror = () => resolve(undefined);
      });
      db.close();
    }
    if (!stored) return null;
    const wrappingKey = await getHistoryWrappingKey(norm);
    if (!wrappingKey) return null;
    let result: { state: DurableRatchetStateV1; dropped: number } | null;
    try {
      result = await decryptDurableRatchetState(wrappingKey, norm, roomId, {
        iv: stored.iv,
        ciphertext: stored.ciphertext,
      });
    } catch {
      await deleteDurableRatchetState(norm, roomId);
      return null;
    }
    if (!result) {
      await deleteDurableRatchetState(norm, roomId);
      return null;
    }
    if (result.dropped > 0) {
      void persistDurableRatchetState(norm, roomId, result.state);
    }
    return result.state;
  } catch {
    return null;
  }
}

export async function deleteDurableRatchetState(username: string, roomId: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm || !roomId) return;
  const key = ratchetSessionKey(norm, roomId);
  try {
    if (!hasBrowserIndexedDB()) {
      nodeMemoryRatchetStore.delete(key);
      return;
    }
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_RATCHET_STORE)) return;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_RATCHET_STORE, 'readwrite');
      const store = tx.objectStore(IDB_RATCHET_STORE);
      store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
  } catch {
    // ignore
  }
}

/**
 * حذف همهٔ نشست‌های دائم یک کاربر — هنگام حذف هویت فراخوانی می‌شود تا
 * هیچ وضعیت راتچتی از هویت حذف‌شده باقی نماند.
 */
export async function deleteDurableRatchetStateForUser(username: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return;
  try {
    if (!hasBrowserIndexedDB()) {
      for (const key of Array.from(nodeMemoryRatchetStore.keys())) {
        if (key.startsWith(`${norm}::`)) nodeMemoryRatchetStore.delete(key);
      }
      return;
    }
    const db = await openKeyStoreDB();
    if (!db.objectStoreNames.contains(IDB_RATCHET_STORE)) return;
    const entries = await new Promise<Array<StoredRatchetSessionRecord>>(resolve => {
      const tx = db.transaction(IDB_RATCHET_STORE, 'readonly');
      const store = tx.objectStore(IDB_RATCHET_STORE);
      const req = store.getAll();
      req.onsuccess = () => resolve((req.result as Array<StoredRatchetSessionRecord>) || []);
      req.onerror = () => resolve([]);
    });
    const ownKeys = entries.filter(e => e.username === norm).map(e => e.key);
    if (ownKeys.length === 0) return;
    await new Promise<void>(resolve => {
      const tx = db.transaction(IDB_RATCHET_STORE, 'readwrite');
      const store = tx.objectStore(IDB_RATCHET_STORE);
      for (const key of ownKeys) store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
    db.close();
  } catch {
    // ignore
  }
}

/**
 * بازپیچیدن نشست‌های دائم یک کاربر زیر کلید پوششی تازه — هنگام
 * فعال/غیرفعال‌کردن محافظت با رمز عبور (L8) کلید پوششی عوض می‌شود؛ بدون
 * این مهاجرت، نشست‌های قدیمی زیر کلید قبلی یتیم و ناخوانا می‌ماندند و
 * پس از رفرش، پیام‌های خارج از نوبت دوباره قفل می‌شدند. Best-effort.
 */
export async function rewrapDurableRatchetStateForUser(
  username: string,
  oldWrappingKey: CryptoKey,
  newWrappingKey: CryptoKey
): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm || !oldWrappingKey || !newWrappingKey) return;
  try {
    let records: Array<StoredRatchetSessionRecord>;
    if (!hasBrowserIndexedDB()) {
      records = Array.from(nodeMemoryRatchetStore.values()).filter(r => r.username === norm);
    } else {
      const db = await openKeyStoreDB();
      if (!db.objectStoreNames.contains(IDB_RATCHET_STORE)) return;
      records = await new Promise<Array<StoredRatchetSessionRecord>>(resolve => {
        const tx = db.transaction(IDB_RATCHET_STORE, 'readonly');
        const store = tx.objectStore(IDB_RATCHET_STORE);
        const req = store.getAll();
        req.onsuccess = () => resolve((req.result as Array<StoredRatchetSessionRecord>) || []);
        req.onerror = () => resolve([]);
      });
      db.close();
    }
    for (const rec of records) {
      try {
        const decrypted = await decryptDurableRatchetState(oldWrappingKey, norm, rec.roomId, {
          iv: rec.iv,
          ciphertext: rec.ciphertext,
        });
        if (!decrypted) continue;
        const wrapped = await encryptDurableRatchetState(newWrappingKey, norm, rec.roomId, decrypted.state);
        const updated: StoredRatchetSessionRecord = { ...rec, iv: wrapped.iv, ciphertext: wrapped.ciphertext };
        if (!hasBrowserIndexedDB()) {
          nodeMemoryRatchetStore.set(rec.key, updated);
        } else {
          const db = await openKeyStoreDB();
          await new Promise<void>(resolve => {
            const tx = db.transaction(IDB_RATCHET_STORE, 'readwrite');
            const store = tx.objectStore(IDB_RATCHET_STORE);
            store.put(updated);
            tx.oncomplete = () => resolve();
            tx.onerror = () => resolve();
          });
          db.close();
        }
      } catch {
        // رکورد خراب/یتیم: همان‌طور بماند تا بارگذاری بعدی آن را حذف کند.
      }
    }
  } catch {
    // ignore — مهاجرت انبار هرگز عملیات L8 را شکست نمی‌دهد.
  }
}

/**
 * بازپیچیدن ورودی‌های کش تاریخچهٔ یک کاربر زیر کلید پوششی تازه — هنگام
 * فعال/غیرفعال‌کردن محافظت با رمز عبور (L8) کلید پوششی عوض می‌شود و بدون
 * این مهاجرت، ورودی‌های قدیمی زیر کلید قبلی یتیم و ناخوانا می‌ماندند.
 * Best-effort: خطا در یک ورودی، بقیه را متوقف نمی‌کند و هرگز عملیات L8 را
 * شکست نمی‌دهد.
 */
export async function rewrapDecryptedHistoryForUser(
  username: string,
  oldWrappingKey: CryptoKey,
  newWrappingKey: CryptoKey
): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm || !oldWrappingKey || !newWrappingKey) return;
  try {
    let records: Array<StoredDecryptedHistoryRecord>;
    if (!hasBrowserIndexedDB()) {
      records = Array.from(nodeMemoryHistoryStore.values()).filter(r => r.username === norm);
    } else {
      const db = await openKeyStoreDB();
      if (!db.objectStoreNames.contains(IDB_HISTORY_STORE)) return;
      records = await new Promise<Array<StoredDecryptedHistoryRecord>>(resolve => {
        const tx = db.transaction(IDB_HISTORY_STORE, 'readonly');
        const store = tx.objectStore(IDB_HISTORY_STORE);
        const req = store.getAll();
        req.onsuccess = () => resolve((req.result as Array<StoredDecryptedHistoryRecord>) || []);
        req.onerror = () => resolve([]);
      });
      db.close();
    }
    for (const rec of records) {
      try {
        const entry = await decryptDecryptedHistoryEntry(oldWrappingKey, norm, rec.roomId, rec.payloadHash, {
          iv: rec.iv,
          ciphertext: rec.ciphertext,
        });
        const wrapped = await encryptDecryptedHistoryEntry(newWrappingKey, norm, rec.roomId, rec.payloadHash, entry);
        const updated: StoredDecryptedHistoryRecord = { ...rec, iv: wrapped.iv, ciphertext: wrapped.ciphertext };
        if (!hasBrowserIndexedDB()) {
          nodeMemoryHistoryStore.set(rec.key, updated);
        } else {
          const db = await openKeyStoreDB();
          await new Promise<void>(resolve => {
            const tx = db.transaction(IDB_HISTORY_STORE, 'readwrite');
            const store = tx.objectStore(IDB_HISTORY_STORE);
            store.put(updated);
            tx.oncomplete = () => resolve();
            tx.onerror = () => resolve();
          });
          db.close();
        }
      } catch {
        // ورودی خراب/یتیم: همان‌طور بماند تا TTL آن را هرس کند.
      }
    }
  } catch {
    // ignore — مهاجرت کش هرگز عملیات L8 را شکست نمی‌دهد.
  }
}

export function normalizeKeystoreUsername(username: string): string {
  return String(username || '').toLowerCase().replace(/^@+/, '').trim();
}

/**
 * Discards all legacy v2 / v3 plaintext private keys and ratchet states from localStorage
 * and bumps the storage version marker to v4.
 * Returns true if any legacy items or older version markers were found and discarded.
 */
export function discardLegacyLocalStorageKeys(username?: string): boolean {
  const ls = getSafeLocalStorage();
  if (!ls) return false;

  let discardedAny = false;
  try {
    const currentMarker = Number(ls.getItem(KEY_STORAGE_VERSION_MARKER) || '0');
    if (currentMarker < KEY_STORAGE_VERSION) {
      discardedAny = true;
    }

    const keysToDelete: string[] = [];
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i);
      if (!k) continue;
      if (LEGACY_STORAGE_PREFIXES.some(prefix => k.startsWith(prefix))) {
        keysToDelete.push(k);
      }
    }

    if (username) {
      const norm = normalizeKeystoreUsername(username);
      for (const prefix of LEGACY_STORAGE_PREFIXES) {
        const direct1 = `${prefix}${username}`;
        const direct2 = `${prefix}${norm}`;
        if (ls.getItem(direct1) !== null) keysToDelete.push(direct1);
        if (ls.getItem(direct2) !== null) keysToDelete.push(direct2);
      }
    }

    const uniqueKeys = Array.from(new Set(keysToDelete));
    for (const k of uniqueKeys) {
      ls.removeItem(k);
      discardedAny = true;
    }

    ls.setItem(KEY_STORAGE_VERSION_MARKER, String(KEY_STORAGE_VERSION));
  } catch {
    // ignore storage quota/security errors
  }

  return discardedAny;
}

export function cachePublicKeyMetadataV4(meta: PublicKeyMetadataV4): void {
  const norm = normalizeKeystoreUsername(meta.username);
  publicMetaMemoryCache.set(norm, meta);
  const ls = getSafeLocalStorage();
  if (ls) {
    try {
      ls.setItem(`${PUBLIC_KEY_CACHE_PREFIX}${norm}`, JSON.stringify(meta));
    } catch {
      // ignore
    }
  }
}

export function getCachedPublicKeyMetadataV4(username: string): PublicKeyMetadataV4 | null {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return null;
  const mem = publicMetaMemoryCache.get(norm);
  if (mem && mem.v === KEY_STORAGE_VERSION) return mem;

  const ls = getSafeLocalStorage();
  if (ls) {
    try {
      const raw = ls.getItem(`${PUBLIC_KEY_CACHE_PREFIX}${norm}`);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && parsed.v === KEY_STORAGE_VERSION && parsed.mldsaPublicKeyB64) {
          publicMetaMemoryCache.set(norm, parsed);
          return parsed;
        }
        // Discard stale non-v4 public cache
        ls.removeItem(`${PUBLIC_KEY_CACHE_PREFIX}${norm}`);
      }
    } catch {
      // ignore
    }
  }
  return null;
}

export async function loadIdentityRecordV4(
  username: string
): Promise<StoredIdentityRecordV4 | null> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return null;

  let record: StoredIdentityRecordV4 | null = null;
  if (hasBrowserIndexedDB()) {
    const db = await openKeyStoreDB();
    record = await new Promise<StoredIdentityRecordV4 | null>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const store = tx.objectStore(IDB_STORE);
      const req = store.get(norm);
      req.onsuccess = () => resolve((req.result as StoredIdentityRecordV4) || null);
      req.onerror = () => reject(req.error || new Error('IndexedDB get failed'));
    });
    db.close();
  } else {
    record = nodeMemoryIdbStore.get(norm) || null;
  }

  if (!record) return null;

  // Enforce version marker v === 4 and non-extractable CryptoKey invariants.
  // L8: a password-protected record has wrappingKey === null by design — the
  // wrapping key is only held in the session cache after unlock.
  if (
    record.v !== KEY_STORAGE_VERSION ||
    !record.ecdhPrivateKey ||
    record.ecdhPrivateKey.extractable !== false ||
    (!record.passwordProtected && (!record.wrappingKey || record.wrappingKey.extractable !== false)) ||
    (record.passwordProtected && record.wrappingKey !== null && record.wrappingKey !== undefined) ||
    !record.mlkemSecretWrapped?.iv ||
    !record.mlkemSecretWrapped?.ciphertext ||
    !record.mldsaSecretWrapped?.iv ||
    !record.mldsaSecretWrapped?.ciphertext
  ) {
    await deleteIdentityRecordV4(norm);
    return null;
  }

  cachePublicKeyMetadataV4({
    v: 4,
    username: norm,
    ecdhPublicJwk: record.ecdhPublicJwk,
    mlkemPublicKeyB64: record.mlkemPublicKeyB64,
    mldsaPublicKeyB64: record.mldsaPublicKeyB64,
  });

  return record;
}

export async function saveIdentityRecordV4(record: StoredIdentityRecordV4): Promise<void> {
  const norm = normalizeKeystoreUsername(record.username);
  const normalizedRecord: StoredIdentityRecordV4 = {
    ...record,
    v: 4,
    username: norm,
  };

  if (
    normalizedRecord.ecdhPrivateKey.extractable !== false ||
    (!normalizedRecord.passwordProtected &&
      (!normalizedRecord.wrappingKey || normalizedRecord.wrappingKey.extractable !== false))
  ) {
    throw new Error('Refusing to store extractable private or wrapping CryptoKey');
  }
  // L8: never persist a usable wrapping key alongside a protected record.
  if (normalizedRecord.passwordProtected) {
    normalizedRecord.wrappingKey = null;
  }

  if (hasBrowserIndexedDB()) {
    const db = await openKeyStoreDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const store = tx.objectStore(IDB_STORE);
      const req = store.put(normalizedRecord);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error || new Error('IndexedDB put failed'));
    });
    db.close();
  } else {
    nodeMemoryIdbStore.set(norm, normalizedRecord);
  }

  cachePublicKeyMetadataV4({
    v: 4,
    username: norm,
    ecdhPublicJwk: normalizedRecord.ecdhPublicJwk,
    mlkemPublicKeyB64: normalizedRecord.mlkemPublicKeyB64,
    mldsaPublicKeyB64: normalizedRecord.mldsaPublicKeyB64,
  });
}

export async function deleteIdentityRecordV4(username: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  publicMetaMemoryCache.delete(norm);
  sessionWrappingKeys.delete(norm);
  await deletePasswordRootBlob(norm);
  // حذف هویت، کش تاریخچهٔ آن کاربر را هم پاک می‌کند (متن‌های رمزنگاری‌شده
  // زیر کلید هویت حذف‌شده باقی نمی‌مانند).
  await deleteDecryptedHistoryForUser(norm);
  // و نشست‌های دائم راتچت آن کاربر را هم پاک می‌کند.
  await deleteDurableRatchetStateForUser(norm);
  const ls = getSafeLocalStorage();
  if (ls) {
    try {
      ls.removeItem(`${PUBLIC_KEY_CACHE_PREFIX}${norm}`);
    } catch {
      // ignore
    }
  }
  if (hasBrowserIndexedDB()) {
    const db = await openKeyStoreDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const store = tx.objectStore(IDB_STORE);
      const req = store.delete(norm);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error || new Error('IndexedDB delete failed'));
    });
    db.close();
  } else {
    nodeMemoryIdbStore.delete(norm);
  }
}

export async function generateNonExtractableWrappingKey(): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  return webCrypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt']
  );
}

export async function generateNonExtractableEcdhKeyPair(): Promise<{
  publicJwk: JsonWebKey;
  privateKey: CryptoKey;
}> {
  const webCrypto = getWebCrypto();
  const keyPair = await webCrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false, // privateKey is non-extractable; publicKey remains exportable per WebCrypto spec
    ['deriveBits']
  );
  const publicJwk = await webCrypto.subtle.exportKey('jwk', keyPair.publicKey);
  return {
    publicJwk,
    privateKey: keyPair.privateKey,
  };
}

export async function wrapSecretBytes(
  wrappingKey: CryptoKey,
  username: string,
  keyType: 'ML-KEM-768' | 'ML-DSA-65',
  secretBytes: Uint8Array
): Promise<WrappedSecretBlob> {
  const webCrypto = getWebCrypto();
  const iv = webCrypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(
    `PQ-MPRBA-v${KEY_STORAGE_VERSION}:${normalizeKeystoreUsername(username)}:${keyType}`
  );
  const ctBuf = await webCrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
      additionalData: aad as unknown as BufferSource,
    },
    wrappingKey,
    secretBytes as unknown as BufferSource
  );
  return {
    iv,
    ciphertext: new Uint8Array(ctBuf),
  };
}

export async function unwrapSecretBytes(
  wrappingKey: CryptoKey,
  username: string,
  keyType: 'ML-KEM-768' | 'ML-DSA-65',
  wrapped: WrappedSecretBlob
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const aad = new TextEncoder().encode(
    `PQ-MPRBA-v${KEY_STORAGE_VERSION}:${normalizeKeystoreUsername(username)}:${keyType}`
  );
  const plainBuf = await webCrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: wrapped.iv as unknown as BufferSource,
      additionalData: aad as unknown as BufferSource,
    },
    wrappingKey,
    wrapped.ciphertext as unknown as BufferSource
  );
  return new Uint8Array(plainBuf);
}

/**
 * حفاظت اختیاری از کلید ریشه‌ای (Root Wrapping Key) با رمز عبور کاربر و PBKDF2 (L8)
 */
export async function wrapRootKeyWithPassphrase(
  keyBytes: Uint8Array,
  passphrase: string,
  iterations = 100_000
): Promise<PasswordProtectedWrappingKeyBlob> {
  const webCrypto = getWebCrypto();
  const salt = webCrypto.getRandomValues(new Uint8Array(16));
  const iv = webCrypto.getRandomValues(new Uint8Array(12));

  const pwKey = await webCrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const derivedKey = await webCrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    pwKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const aad = new TextEncoder().encode('PQ-MPRBA:ROOT-WRAPPING-KEY-V1');
  const ctBuf = await webCrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
      additionalData: aad as unknown as BufferSource,
    },
    derivedKey,
    keyBytes as unknown as BufferSource
  );

  return {
    salt,
    iv,
    wrappedKeyBytes: new Uint8Array(ctBuf),
    iterations,
  };
}

/**
 * گشودن کلید ریشه‌ای حفاظت‌شده با رمز عبور کاربر (L8)
 */
export async function unwrapRootKeyWithPassphrase(
  blob: PasswordProtectedWrappingKeyBlob,
  passphrase: string
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const pwKey = await webCrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const derivedKey = await webCrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: blob.salt as unknown as BufferSource,
      iterations: blob.iterations,
      hash: 'SHA-256',
    },
    pwKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const aad = new TextEncoder().encode('PQ-MPRBA:ROOT-WRAPPING-KEY-V1');
  const plainBuf = await webCrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: blob.iv as unknown as BufferSource,
      additionalData: aad as unknown as BufferSource,
    },
    derivedKey,
    blob.wrappedKeyBytes as unknown as BufferSource
  );

  return new Uint8Array(plainBuf);
}

/**
 * L8 — ذخیره‌سازی blob کلید پوششیِ پیچیده‌شده با رمز عبور.
 * Blob در IndexedDB (store جدا، keyPath 'username') یا در تست‌های Node در
 * حافظه نگه داشته می‌شود. ترتیب ذخیره‌سازی در enablePasswordProtection
 * عمدی است: اول blob، بعد رکورد — اگر ذخیرهٔ رکورد شکست بخورد، رکورد هنوز
 * محافظت‌نشده و کلید قدیمی سالم است و blob یتیم فقط بازنویسی می‌شود.
 */
async function savePasswordRootBlob(
  username: string,
  blob: PasswordProtectedWrappingKeyBlob
): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  const stored: StoredPasswordRootBlob = { ...blob, username: norm };
  if (hasBrowserIndexedDB()) {
    const db = await openKeyStoreDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_PASSWORD_ROOT_STORE, 'readwrite');
      const store = tx.objectStore(IDB_PASSWORD_ROOT_STORE);
      const req = store.put(stored);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error || new Error('IndexedDB put failed'));
    });
    db.close();
  } else {
    nodeMemoryPasswordRootStore.set(norm, stored);
  }
}

async function loadPasswordRootBlob(
  username: string
): Promise<PasswordProtectedWrappingKeyBlob | null> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return null;
  if (hasBrowserIndexedDB()) {
    const db = await openKeyStoreDB();
    const res = await new Promise<StoredPasswordRootBlob | null>((resolve, reject) => {
      const tx = db.transaction(IDB_PASSWORD_ROOT_STORE, 'readonly');
      const store = tx.objectStore(IDB_PASSWORD_ROOT_STORE);
      const req = store.get(norm);
      req.onsuccess = () => resolve((req.result as StoredPasswordRootBlob) || null);
      req.onerror = () => reject(req.error || new Error('IndexedDB get failed'));
    });
    db.close();
    return res;
  }
  return nodeMemoryPasswordRootStore.get(norm) || null;
}

async function deletePasswordRootBlob(username: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return;
  if (hasBrowserIndexedDB()) {
    const db = await openKeyStoreDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_PASSWORD_ROOT_STORE, 'readwrite');
      const store = tx.objectStore(IDB_PASSWORD_ROOT_STORE);
      const req = store.delete(norm);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error || new Error('IndexedDB delete failed'));
    });
    db.close();
  } else {
    nodeMemoryPasswordRootStore.delete(norm);
  }
}

/** کلید پوششیِ بازشدهٔ نشست (فقط حافظه) — برای crypto.ts. */
export function getSessionWrappingKey(username: string): CryptoKey | null {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return null;
  return sessionWrappingKeys.get(norm) || null;
}

/** آیا محافظت با رمز عبور برای این هویت فعال است؟ (blob + پرچم رکورد هر دو لازم‌اند) */
export async function isPasswordProtectionEnabled(username: string): Promise<boolean> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return false;
  const blob = await loadPasswordRootBlob(norm);
  if (!blob) return false;
  const record = await loadIdentityRecordV4(norm);
  return !!record?.passwordProtected;
}

/** آیا هویت در این نشست قابل استفاده است؟ (محافظت‌نشده، یا بازشده) */
export async function isIdentityUnlocked(username: string): Promise<boolean> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) return false;
  const record = await loadIdentityRecordV4(norm);
  if (!record?.passwordProtected) return true;
  return sessionWrappingKeys.has(norm);
}

/**
 * فعال‌کردن محافظت با رمز عبور (L8): یک کلید پوششی تازهٔ EXTRACTABLE ساخته
 * می‌شود، بایت‌های خام آن با رمز عبور پیچیده و ذخیره می‌شود، رازهای ML-KEM و
 * ML-DSA زیر کلید تازه دوباره پیچیده می‌شوند و رکورد با wrappingKey=null و
 * passwordProtected=true ذخیره می‌شود. نشست بلافاصله با نسخهٔ
 * non-extractable کلید تازه باز می‌ماند تا کاربر مجبور به باز کردن فوری نشود.
 */
export async function enablePasswordProtection(username: string, passphrase: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) throw new Error('Username cannot be empty');
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters');
  }
  const record = await loadIdentityRecordV4(norm);
  if (!record) throw new Error('Identity key is not initialized');
  if (record.passwordProtected) throw new Error('Password protection is already enabled');
  if (!record.wrappingKey) throw new Error('Identity wrapping key is missing');

  const webCrypto = getWebCrypto();
  // ۱. کلید پوششی تازهٔ قابل‌استخراج + بایت‌های خام آن.
  const newWrappingKey = await webCrypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const rawBytes = new Uint8Array(await webCrypto.subtle.exportKey('raw', newWrappingKey));
  let blob: PasswordProtectedWrappingKeyBlob;
  try {
    blob = await wrapRootKeyWithPassphrase(rawBytes, passphrase);
  } catch (err) {
    zeroizeBytes(rawBytes);
    throw err;
  }
  // نسخهٔ non-extractable برای استفاده در نشست (invariant کلیدهای پوششی حفظ می‌شود).
  const runtimeKey = await webCrypto.subtle.importKey(
    'raw',
    rawBytes as unknown as BufferSource,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  zeroizeBytes(rawBytes);

  // ۲. باز کردن رازها با کلید قدیمی و دوباره پیچیدن زیر کلید تازه.
  const mlkemSecret = await unwrapSecretBytes(record.wrappingKey, norm, 'ML-KEM-768', record.mlkemSecretWrapped);
  const mldsaSecret = await unwrapSecretBytes(record.wrappingKey, norm, 'ML-DSA-65', record.mldsaSecretWrapped);
  let mlkemSecretWrapped: WrappedSecretBlob;
  let mldsaSecretWrapped: WrappedSecretBlob;
  try {
    mlkemSecretWrapped = await wrapSecretBytes(newWrappingKey, norm, 'ML-KEM-768', mlkemSecret);
    mldsaSecretWrapped = await wrapSecretBytes(newWrappingKey, norm, 'ML-DSA-65', mldsaSecret);
  } finally {
    zeroizeBytes(mlkemSecret);
    zeroizeBytes(mldsaSecret);
  }

  // ۳. اول blob، بعد رکورد (ترتیب امن — توضیح در savePasswordRootBlob).
  await savePasswordRootBlob(norm, blob);
  await saveIdentityRecordV4({
    ...record,
    wrappingKey: null,
    passwordProtected: true,
    mlkemSecretWrapped,
    mldsaSecretWrapped,
  });
  sessionWrappingKeys.set(norm, runtimeKey);
  // کلید پوششی عوض شد — ورودی‌های کش تاریخچه زیر کلید تازه بازپیچیده
  // می‌شوند تا تاریخچهٔ قبلی پس از فعال‌کردن محافظت هم خوانا بماند.
  await rewrapDecryptedHistoryForUser(norm, record.wrappingKey, newWrappingKey);
  await rewrapDurableRatchetStateForUser(norm, record.wrappingKey, newWrappingKey);
}

/**
 * غیرفعال‌کردن محافظت با رمز عبور (L8): رمز عبور فعلی بررسی می‌شود، یک
 * کلید پوششی تازهٔ non-extractable ساخته و رازها زیر آن دوباره پیچیده
 * می‌شوند، رکورد بدون پرچم ذخیره و blob حذف می‌شود.
 */
export async function disablePasswordProtection(username: string, passphrase: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) throw new Error('Username cannot be empty');
  const record = await loadIdentityRecordV4(norm);
  if (!record || !record.passwordProtected) {
    throw new Error('Password protection is not enabled');
  }
  // رمز عبور را بررسی کن (رمز اشتباه → IdentityLockedError).
  await unlockIdentityWithPassphrase(norm, passphrase);
  const sessionKey = sessionWrappingKeys.get(norm);
  if (!sessionKey) throw new IdentityLockedError();

  const newWrappingKey = await generateNonExtractableWrappingKey();
  const mlkemSecret = await unwrapSecretBytes(sessionKey, norm, 'ML-KEM-768', record.mlkemSecretWrapped);
  const mldsaSecret = await unwrapSecretBytes(sessionKey, norm, 'ML-DSA-65', record.mldsaSecretWrapped);
  let mlkemSecretWrapped: WrappedSecretBlob;
  let mldsaSecretWrapped: WrappedSecretBlob;
  try {
    mlkemSecretWrapped = await wrapSecretBytes(newWrappingKey, norm, 'ML-KEM-768', mlkemSecret);
    mldsaSecretWrapped = await wrapSecretBytes(newWrappingKey, norm, 'ML-DSA-65', mldsaSecret);
  } finally {
    zeroizeBytes(mlkemSecret);
    zeroizeBytes(mldsaSecret);
  }

  // اول رکورد (با کلید تازه)، بعد حذف blob — اگر حذف blob شکست بخورد،
  // رکورد محافظت‌نشده است و blob یتیم بی‌اثر می‌ماند.
  await saveIdentityRecordV4({
    ...record,
    wrappingKey: newWrappingKey,
    passwordProtected: false,
    mlkemSecretWrapped,
    mldsaSecretWrapped,
  });
  await deletePasswordRootBlob(norm);
  sessionWrappingKeys.delete(norm);
  // کلید پوششی عوض شد — ورودی‌های کش تاریخچه زیر کلید تازه بازپیچیده
  // می‌شوند تا تاریخچهٔ قبلی پس از غیرفعال‌کردن محافظت هم خوانا بماند.
  await rewrapDecryptedHistoryForUser(norm, sessionKey, newWrappingKey);
  await rewrapDurableRatchetStateForUser(norm, sessionKey, newWrappingKey);
}

/**
 * باز کردن هویت محافظت‌شده با رمز عبور برای این نشست (L8). رمز اشتباه →
 * IdentityLockedError (خطای AES-GCM auth به بیرون درز نمی‌کند).
 */
export async function unlockIdentityWithPassphrase(username: string, passphrase: string): Promise<void> {
  const norm = normalizeKeystoreUsername(username);
  if (!norm) throw new IdentityLockedError('Username cannot be empty');
  const blob = await loadPasswordRootBlob(norm);
  if (!blob) throw new IdentityLockedError('Password protection is not enabled for this identity');
  let rawBytes: Uint8Array;
  try {
    rawBytes = await unwrapRootKeyWithPassphrase(blob, passphrase);
  } catch {
    throw new IdentityLockedError('Incorrect passphrase');
  }
  try {
    const key = await getWebCrypto().subtle.importKey(
      'raw',
      rawBytes as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    sessionWrappingKeys.set(norm, key);
  } finally {
    zeroizeBytes(rawBytes);
  }
}

/** قفل‌کردن هویت در این نشست (کلید پوششی از حافظه پاک می‌شود). */
export function lockIdentity(username: string): void {
  const norm = normalizeKeystoreUsername(username);
  if (norm) sessionWrappingKeys.delete(norm);
}

/** پاک‌کردن همهٔ کلیدهای پوششی بازشدهٔ نشست — فقط برای شبیه‌سازی رفرش در تست‌ها. */
export function clearAllSessionWrappingKeysForTests(): void {
  sessionWrappingKeys.clear();
}

/**
 * Reset in-memory test store & caches (for isolated unit testing only).
 */
export function resetInMemoryKeyStoreForTests(): void {
  nodeMemoryIdbStore.clear();
  nodeMemoryReplayStore.clear();
  nodeMemoryPasswordRootStore.clear();
  nodeMemoryHistoryStore.clear();
  sessionWrappingKeys.clear();
  publicMetaMemoryCache.clear();
}
