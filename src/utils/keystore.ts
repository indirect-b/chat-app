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
const IDB_VERSION = 1;

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

export interface StoredIdentityRecordV4 {
  v: 4;
  username: string;
  createdAt: number;
  ecdhPublicJwk: JsonWebKey;
  ecdhPrivateKey: CryptoKey; // extractable: false
  wrappingKey: CryptoKey; // AES-GCM 256-bit, extractable: false
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

function hasBrowserIndexedDB(): boolean {
  try {
    return typeof globalThis !== 'undefined' && typeof globalThis.indexedDB !== 'undefined' && globalThis.indexedDB !== null;
  } catch {
    return false;
  }
}

function openKeyStoreDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = globalThis.indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE, { keyPath: 'username' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Failed to open IndexedDB keystore'));
  });
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

  // Enforce version marker v === 4 and non-extractable CryptoKey invariants
  if (
    record.v !== KEY_STORAGE_VERSION ||
    !record.ecdhPrivateKey ||
    record.ecdhPrivateKey.extractable !== false ||
    !record.wrappingKey ||
    record.wrappingKey.extractable !== false ||
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
    normalizedRecord.wrappingKey.extractable !== false
  ) {
    throw new Error('Refusing to store extractable private or wrapping CryptoKey');
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
 * Reset in-memory test store & caches (for isolated unit testing only).
 */
export function resetInMemoryKeyStoreForTests(): void {
  nodeMemoryIdbStore.clear();
  publicMetaMemoryCache.clear();
}
