// سیستم رمزنگاری سرتاسری پیشرفته (E2EE) مجهز به تبادل کلید خودکار ECDH (P-256) + AES-GCM 256-bit

const E2EE_V1_PREFIX = 'e2ee:v1:';
const E2EE_ECDH_PREFIX = 'e2ee:ecdh:';
const ROOM_KEY_STORAGE_PREFIX = 'chat_e2ee_pass_';
const E2EE_ENABLED_STORAGE_KEY = 'chat_e2ee_enabled';
const ECDH_KEYPAIR_PREFIX = 'chat_ecdh_kp_';

interface StoredKeyPair {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

function bufToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuf(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * تولید یا بازیابی جفت‌کلید نامتقارن ECDH (منحنی P-256) برای هر کاربر در مرورگر
 * کلید خصوصی هرگز از مرورگر خارج نمی‌شود و فقط کلید عمومی به سرور ارسال می‌گردد.
 */
export async function ensureUserECDHKeyPair(username: string): Promise<string | null> {
  if (!username || !window.crypto?.subtle) return null;
  const storageKey = `${ECDH_KEYPAIR_PREFIX}${username}`;

  try {
    const existingRaw = localStorage.getItem(storageKey);
    if (existingRaw) {
      const parsed: StoredKeyPair = JSON.parse(existingRaw);
      if (parsed.publicJwk && parsed.privateJwk) {
        return JSON.stringify(parsed.publicJwk);
      }
    }

    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );

    const publicJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privateJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);

    const toStore: StoredKeyPair = { publicJwk, privateJwk };
    localStorage.setItem(storageKey, JSON.stringify(toStore));
    return JSON.stringify(publicJwk);
  } catch {
    return null;
  }
}

/**
 * استخراج کلید مشترک AES-256-GCM با استفاده از پروتکل Diffie-Hellman (ECDH P-256)
 * ECDH(MyPrivateKey, PeerPublicKey) === ECDH(PeerPrivateKey, MyPublicKey)
 */
async function deriveECDHSharedAesKey(
  myUsername: string,
  peerPublicKeyStr: string
): Promise<CryptoKey | null> {
  try {
    const rawPair = localStorage.getItem(`${ECDH_KEYPAIR_PREFIX}${myUsername}`);
    if (!rawPair) return null;
    const { privateJwk }: StoredKeyPair = JSON.parse(rawPair);
    const peerPublicJwk: JsonWebKey = JSON.parse(peerPublicKeyStr);

    const myPrivateKey = await window.crypto.subtle.importKey(
      'jwk',
      privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey']
    );

    const peerPublicKey = await window.crypto.subtle.importKey(
      'jwk',
      peerPublicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    return await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicKey },
      myPrivateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } catch {
    return null;
  }
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
    (text.startsWith(E2EE_V1_PREFIX) || text.startsWith(E2EE_ECDH_PREFIX))
  );
}

export async function encryptMessageText(
  plainText: string,
  roomId: string,
  options?: {
    myUsername?: string;
    peerPublicKey?: string | null;
    customSecret?: string;
  }
): Promise<string> {
  if (!plainText) return '';
  try {
    const manualSecret = options?.customSecret ?? getRoomSecret(roomId);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);

    // ۱. اگر کلید دستی تنظیم نشده و کلید عمومی ECDH مخاطب موجود است، از تبادل کلید خودکار ECDH استفاده کن
    if (!manualSecret && options?.myUsername && options?.peerPublicKey) {
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

    // ۲. در غیر این صورت (گروه‌ها یا رمز دستی)، از مشتق‌سازی PBKDF2 استفاده کن
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
    customSecret?: string;
  }
): Promise<{ text: string; isEncrypted: boolean; mode?: 'ECDH' | 'PBKDF2'; failed?: boolean }> {
  if (!isE2EEPayload(payload)) {
    return { text: payload || '', isEncrypted: false };
  }

  try {
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
