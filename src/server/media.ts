/**
 * Media access control — pure, testable helpers for chat media.
 *
 * No network, no secrets: every function takes a `query` function with the
 * pool.query signature, so tests pass a fake in-memory store. The Express
 * routes in server.ts are thin wrappers around these helpers.
 *
 * Room model (mirrors the message code — no new membership model):
 * - Group room: `group__<groupId>`, members from `groups.members` (JSON).
 * - DM room: `getRoomId(u1, u2)` = sorted usernames joined with `__`.
 *
 * Backward compatibility (stated plainly): media uploaded BEFORE the E2EE
 * change is RAW — the server never had the key, so it cannot retro-encrypt.
 * Such media is access-controlled (members only, resolved through the
 * message that links it) but NOT encrypted. New media is both encrypted
 * and access-controlled.
 */

export type DbQuery = (
  sql: string,
  params?: any[]
) => Promise<{ rows: any[] }>;

export function getRoomId(u1: string, u2: string): string {
  return [u1, u2].sort().join('__');
}

/** Is `username` a member of `roomId`? Group → members list; DM → the room id must be exactly getRoomId(username, some user). */
export async function isRoomMember(
  username: string,
  roomId: string,
  query: DbQuery
): Promise<boolean> {
  if (!username || !roomId || typeof roomId !== 'string') return false;
  if (roomId.startsWith('group__')) {
    const groupId = roomId.replace('group__', '');
    const { rows } = await query('SELECT members FROM groups WHERE id=$1', [groupId]);
    if (!rows.length) return false;
    let members: unknown;
    try {
      members = JSON.parse(rows[0].members);
    } catch {
      return false;
    }
    return Array.isArray(members) && members.includes(username);
  }
  // DM room: the id is the sorted join of exactly the two members. Compare
  // against every username (exact match — never a prefix test, so a username
  // containing '__' cannot impersonate membership of another room).
  const { rows } = await query('SELECT username FROM users', []);
  return rows.some((r: any) => getRoomId(username, r.username) === roomId);
}

export interface MediaAccess {
  /** 'ok' = serve the bytes; 'forbidden' = 403; 'not-found' = 404. */
  status: 'ok' | 'forbidden' | 'not-found';
  /** Resolved room, or null for avatar media (no room). */
  roomId: string | null;
  /** True when the stored bytes are PQF1-encrypted (new media). */
  isEncrypted: boolean;
  /** The media_blobs row when one exists (null for disk-only legacy files). */
  blob: any | null;
}

function mediaUrlForms(mediaId: string): string[] {
  return [`/api/media/${mediaId}`, `/uploads/${mediaId}`];
}

/**
 * Decide whether `username` (already authenticated) may fetch `mediaId`.
 * Fail closed: anything unresolvable is forbidden — orphan media (no room,
 * no linking message, not a current avatar) is never served.
 */
export async function resolveMediaAccess(
  mediaId: string,
  username: string,
  query: DbQuery
): Promise<MediaAccess> {
  const denied: MediaAccess = { status: 'forbidden', roomId: null, isEncrypted: false, blob: null };
  if (!mediaId || !username) return denied;

  const { rows } = await query('SELECT * FROM media_blobs WHERE id = $1', [mediaId]);
  const blob = rows.length ? rows[0] : null;
  const isEncrypted = !!blob && !!blob.is_encrypted;
  let roomId: string | null = blob && blob.room_id ? String(blob.room_id) : null;

  // 0. The uploader can always fetch their own upload — they already hold
  // the bytes, and upload itself required room membership (or ownership for
  // avatars). This also makes the just-uploaded avatar preview work before
  // the profile is saved.
  if (blob && blob.uploaded_by && blob.uploaded_by === username) {
    return { status: 'ok', roomId, isEncrypted, blob };
  }

  // 1. Room recorded on the blob itself (all media uploaded after the change).
  if (roomId) {
    if (!(await isRoomMember(username, roomId, query))) return denied;
    return { status: 'ok', roomId, isEncrypted, blob };
  }

  // 2. Pre-change media: no room on the blob — resolve it through the
  // message that links this media id. A deleted message denies access too.
  for (const form of mediaUrlForms(mediaId)) {
    const msg = await query(
      'SELECT room_id, is_deleted FROM messages WHERE file_url = $1',
      [form]
    );
    if (msg.rows.length) {
      const m = msg.rows[0];
      if (m.is_deleted) return denied;
      const msgRoom = String(m.room_id);
      if (!(await isRoomMember(username, msgRoom, query))) return denied;
      return { status: 'ok', roomId: msgRoom, isEncrypted, blob };
    }
  }

  // 3. Profile pictures: media with no room that is currently set as some
  // user's avatar. Avatars are public profile pictures by design, so any
  // authenticated user may fetch them — but never anonymously (the route
  // requires a session) and never through the old public /uploads route.
  const forms = mediaUrlForms(mediaId);
  const avatar = await query(
    'SELECT username FROM users WHERE avatar = $1 OR avatar = $2',
    [forms[0], forms[1]]
  );
  if (avatar.rows.length) {
    return { status: 'ok', roomId: null, isEncrypted: false, blob };
  }

  // 4. Nothing resolves to a room or an avatar: orphan media. Fail closed.
  // (A blob row with no room, no message and no avatar is still forbidden —
  // the row alone proves nothing about who may see it.)
  if (!blob) return { status: 'not-found', roomId: null, isEncrypted: false, blob: null };
  return denied;
}

/** May `username` upload chat media into `roomId`? (Avatars skip this — they have no room.) */
export async function canUploadToRoom(
  username: string,
  roomId: string,
  query: DbQuery
): Promise<boolean> {
  if (!username || !roomId) return false;
  return isRoomMember(username, roomId, query);
}
