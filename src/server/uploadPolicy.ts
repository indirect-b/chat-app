/**
 * Upload policy — file-type allowlist + magic-bytes sniffing (round 5, H1).
 *
 * Pure, testable helpers: no I/O except readFileHead. The Express route in
 * server.ts is a thin wrapper (multer fileFilter for the extension check,
 * then validateUploadFile on the written temp file before the DB insert).
 *
 * Rules:
 * - Extension must be in the allowlist (images / audio / video only).
 * - Client-encrypted media starts with the 'PQF1' magic (see
 *   FILE_ENCRYPTION_MAGIC in src/utils/crypto.ts). Its inner type is opaque
 *   to the server, so PQF1 files are ALLOWED regardless of inner type.
 * - Any other file must sniff to a magic that matches its extension.
 * - The stored mime is SERVER-VERIFIED: the sniffed mime for raw files, or
 *   the claimed mime for PQF1 files only when it is itself in the allowlist
 *   (else application/octet-stream). A client claim is never stored verbatim.
 */

import fs from 'fs';

export const ALLOWED_UPLOAD_EXTENSIONS: ReadonlyMap<string, string> = new Map([
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.png', 'image/png'],
  ['.gif', 'image/gif'],
  ['.webp', 'image/webp'],
  ['.mp3', 'audio/mpeg'],
  ['.ogg', 'audio/ogg'],
  ['.wav', 'audio/wav'],
  ['.webm', 'audio/webm'],
  ['.m4a', 'audio/mp4'],
  ['.mp4', 'video/mp4'],
  ['.mov', 'video/quicktime'],
  ['.avi', 'video/x-msvideo'],
]);

/** Every mime the server will ever serve for media (allowlist values). */
export const ALLOWED_MEDIA_MIMES: ReadonlySet<string> = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'audio/mpeg',
  'audio/ogg',
  'audio/wav',
  'audio/webm',
  'audio/mp4',
  'video/mp4',
  'video/quicktime',
  'video/x-msvideo',
  'video/webm',
  'application/octet-stream',
]);

export const PQF1_MAGIC = 'PQF1';

/** Sniffed mimes accepted for each extension (raw, non-PQF1 files). */
const SNIFFED_MIME_FOR_EXT: Readonly<Record<string, readonly string[]>> = {
  '.jpg': ['image/jpeg'],
  '.jpeg': ['image/jpeg'],
  '.png': ['image/png'],
  '.gif': ['image/gif'],
  '.webp': ['image/webp'],
  '.mp3': ['audio/mpeg'],
  '.ogg': ['audio/ogg'],
  '.wav': ['audio/wav'],
  // .webm is EBML either way; the sniff reports video/webm.
  '.webm': ['video/webm', 'audio/webm'],
  // .m4a is an ftyp container; the sniff reports video/mp4.
  '.m4a': ['video/mp4', 'audio/mp4'],
  '.mp4': ['video/mp4'],
  // .mov is an ftyp container too (ftypqt); the sniff reports video/mp4.
  '.mov': ['video/mp4'],
  '.avi': ['video/x-msvideo'],
};

/** The mime to STORE for a raw file of this extension (sniff-verified). */
const VERIFIED_MIME_FOR_EXT: Readonly<Record<string, string>> = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.mp3': 'audio/mpeg',
  '.ogg': 'audio/ogg',
  '.wav': 'audio/wav',
  '.webm': 'video/webm',
  '.m4a': 'audio/mp4',
  '.mp4': 'video/mp4',
  '.mov': 'video/quicktime',
  '.avi': 'video/x-msvideo',
};

export function isPqf1(head: Buffer): boolean {
  return head.length >= 4 && head.toString('latin1', 0, 4) === PQF1_MAGIC;
}

/** Identify a raw file from its first bytes. Returns null when unknown. */
export function sniffMime(head: Buffer): string | null {
  if (head.length >= 4 && head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47) {
    return 'image/png';
  }
  if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) {
    return 'image/jpeg';
  }
  if (head.length >= 4 && head.toString('latin1', 0, 4) === 'GIF8') {
    return 'image/gif';
  }
  if (head.length >= 12 && head.toString('latin1', 0, 4) === 'RIFF') {
    const form = head.toString('latin1', 8, 12);
    if (form === 'WEBP') return 'image/webp';
    if (form === 'WAVE') return 'audio/wav';
    if (form === 'AVI ') return 'video/x-msvideo';
    return null;
  }
  if (head.length >= 3 && head.toString('latin1', 0, 3) === 'ID3') return 'audio/mpeg';
  if (head.length >= 2 && head[0] === 0xff && head[1] === 0xfb) return 'audio/mpeg';
  if (head.length >= 4 && head.toString('latin1', 0, 4) === 'OggS') return 'audio/ogg';
  if (head.length >= 8 && head.toString('latin1', 4, 8) === 'ftyp') return 'video/mp4';
  if (head.length >= 4 && head[0] === 0x1a && head[1] === 0x45 && head[2] === 0xdf && head[3] === 0xa3) {
    return 'video/webm';
  }
  return null;
}

/**
 * Flat result type (not a discriminated union): this repo compiles with
 * `strict: false`, under which TS does not narrow `!result.ok` to the
 * failure member, so `reason` must exist on every result.
 */
export interface UploadValidation {
  ok: boolean;
  /** Server-verified mime to store ('' when rejected). */
  verifiedMime: string;
  /** True when the bytes start with the PQF1 magic. */
  isEncrypted: boolean;
  /** Rejection reason ('' when accepted). */
  reason: string;
}

/**
 * Validate an uploaded temp file. `ext` must already be lowercased
 * (including the leading dot). `claimedMime` is the client-sent mimetype —
 * used ONLY for PQF1 files and only when it is in the allowlist.
 */
export function validateUploadFile(
  ext: string,
  head: Buffer,
  claimedMime?: string
): UploadValidation {
  if (!ALLOWED_UPLOAD_EXTENSIONS.has(ext)) {
    return { ok: false, verifiedMime: '', isEncrypted: false, reason: 'نوع فایل مجاز نیست' };
  }
  if (isPqf1(head)) {
    // Client-encrypted media: inner type is opaque to the server.
    const verified =
      claimedMime && ALLOWED_MEDIA_MIMES.has(claimedMime)
        ? claimedMime
        : 'application/octet-stream';
    return { ok: true, verifiedMime: verified, isEncrypted: true, reason: '' };
  }
  const sniffed = sniffMime(head);
  const accepted = SNIFFED_MIME_FOR_EXT[ext] || [];
  if (!sniffed || !accepted.includes(sniffed)) {
    return {
      ok: false,
      verifiedMime: '',
      isEncrypted: false,
      reason: 'محتوای فایل با پسوند آن مطابقت ندارد',
    };
  }
  return { ok: true, verifiedMime: VERIFIED_MIME_FOR_EXT[ext], isEncrypted: false, reason: '' };
}

/**
 * The mime to SERVE for a stored media row. A stored mime outside the
 * allowlist (legacy rows holding a client claim such as text/html) is
 * never served verbatim — it falls back to application/octet-stream.
 */
export function verifyStoredMime(storedMime: string | null | undefined): string {
  if (storedMime && ALLOWED_MEDIA_MIMES.has(storedMime)) return storedMime;
  return 'application/octet-stream';
}

/** Read the first `length` bytes of a file (for magic sniffing). */
export async function readFileHead(filePath: string, length = 16): Promise<Buffer> {
  let fh: fs.promises.FileHandle | null = null;
  try {
    fh = await fs.promises.open(filePath, 'r');
    const buf = Buffer.alloc(length);
    const { bytesRead } = await fh.read(buf, 0, length, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    if (fh) await fh.close().catch(() => undefined);
  }
}
