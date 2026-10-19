// سیستم رمزنگاری سرتاسری سمت کلاینت (End-to-End Encryption - AES-GCM 256-bit)

const E2EE_PREFIX = 'e2ee:v1:';
const ROOM_KEY_STORAGE_PREFIX = 'chat_e2ee_pass_';
const E2EE_ENABLED_STORAGE_KEY = 'chat_e2ee_enabled';

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

async function deriveAesKey(roomId: string, customSecret?: string): Promise<CryptoKey> {
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
  return typeof text === 'string' && text.startsWith(E2EE_PREFIX);
}

export async function encryptMessageText(
  plainText: string,
  roomId: string,
  customSecret?: string
): Promise<string> {
  if (!plainText) return '';
  try {
    const key = await deriveAesKey(roomId, customSecret || getRoomSecret(roomId));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plainText);
    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );
    return `${E2EE_PREFIX}${bufToBase64(iv)}:${bufToBase64(cipherBuffer)}`;
  } catch {
    return plainText;
  }
}

export async function decryptMessageText(
  payload: string,
  roomId: string,
  customSecret?: string
): Promise<{ text: string; isEncrypted: boolean; failed?: boolean }> {
  if (!isE2EEPayload(payload)) {
    return { text: payload || '', isEncrypted: false };
  }
  try {
    const raw = payload.slice(E2EE_PREFIX.length);
    const [ivB64, cipherB64] = raw.split(':');
    if (!ivB64 || !cipherB64) {
      return { text: payload, isEncrypted: true, failed: true };
    }
    const key = await deriveAesKey(roomId, customSecret || getRoomSecret(roomId));
    const iv = base64ToBuf(ivB64);
    const cipherBytes = base64ToBuf(cipherB64);
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      key,
      cipherBytes as unknown as BufferSource
    );
    const decoded = new TextDecoder().decode(decryptedBuffer);
    return { text: decoded, isEncrypted: true, failed: false };
  } catch {
    return {
      text: '🔒 [پیام رمزنگاری‌شده - کلید نامعتبر]',
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
