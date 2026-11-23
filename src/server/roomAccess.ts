/**
 * Room-content access control — pure, testable helpers.
 *
 * No network, no secrets: every function takes an injected `query` function
 * (pool-compatible), so tests pass a fake in-memory store. The Express
 * routes in server.ts are thin wrappers around these helpers.
 *
 * Why 403 for everything denied: a missing/expired session and a non-member
 * get the SAME status, and an unknown room gets the same status as a room
 * the caller is not a member of — so the endpoint never leaks whether a
 * room exists. Message content stays E2EE; this is access control only.
 */

import { isRoomMember, type DbQuery } from './media';

/** 'ok' = serve; 'unauthenticated' = no valid session; 'forbidden' = not a member. */
export type RoomReadAccess = 'ok' | 'unauthenticated' | 'forbidden';

/**
 * May `sessionUsername` (null = no valid session) read the messages of
 * `roomId`? Membership is decided by the shared isRoomMember helper — a DM
 * room is the exact sorted join of its two members, a group room is checked
 * against the group's member list. Unknown rooms fail closed (forbidden).
 */
export async function checkRoomReadAccess(
  sessionUsername: string | null,
  roomId: string,
  query: DbQuery
): Promise<RoomReadAccess> {
  if (!sessionUsername) return 'unauthenticated';
  if (!roomId || typeof roomId !== 'string') return 'forbidden';
  return (await isRoomMember(sessionUsername, roomId, query)) ? 'ok' : 'forbidden';
}

/**
 * May `sessionUsername` (null = no valid session) act on / read the data of
 * `targetUsername`? A user may only touch their own profile, contacts and
 * contact list — the token's username must equal the target username.
 * Same rule as checkOwnGroupsAccess, factored out so the three profile
 * endpoints (POST /api/user/update, POST /api/add-contact,
 * GET /api/contacts/:username) share one implementation.
 */
export function checkOwnUsername(
  sessionUsername: string | null,
  targetUsername: string
): RoomReadAccess {
  if (!sessionUsername) return 'unauthenticated';
  if (!targetUsername || sessionUsername !== targetUsername) return 'forbidden';
  return 'ok';
}

/**
 * May `sessionUsername` (null = no valid session) list the groups of
 * `urlUsername`? A user may only list their own groups — the token's
 * username must equal the username in the URL.
 */
export function checkOwnGroupsAccess(
  sessionUsername: string | null,
  urlUsername: string
): RoomReadAccess {
  return checkOwnUsername(sessionUsername, urlUsername);
}

/**
 * May `username` act on message `msgId` inside `roomId` (pin / react /
 * read / …)? The message must exist, must belong to that room, and the
 * user must be a member of the room. Fails closed on every miss.
 */
export async function canActOnMessage(
  username: string | null,
  msgId: string,
  roomId: string,
  query: DbQuery
): Promise<boolean> {
  if (!username || !msgId || !roomId) return false;
  const { rows } = await query('SELECT * FROM messages WHERE id=$1', [msgId]);
  if (!rows.length) return false;
  if (String(rows[0].room_id) !== roomId) return false;
  return isRoomMember(username, roomId, query);
}
