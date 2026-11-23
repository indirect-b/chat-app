/**
 * Room-member-only emits (round 5, M5).
 *
 * Socket handlers used to broadcast message events with io.emit (every
 * connected socket, even non-members). emitToRoom resolves the room's
 * members and delivers only to them via presence.emitToUser — the same
 * targeted delivery send-message already used.
 *
 * DM rooms are the sorted join `user1__user2`. Splitting on '__' yields
 * exactly 2 parts in the normal case; when it does not (a username
 * containing '__'), we fall back to scanning users for the pair whose
 * getRoomId join equals the room id.
 */

import type { Server as SocketIOServer } from 'socket.io';
import { presence } from './presence';
import { getRoomId, type DbQuery } from './media';
import { safeParseMembers } from './messageParse';

/** Resolve the members of a room id (group → member list; DM → the two users). */
export async function resolveRoomMembers(roomId: string, query: DbQuery): Promise<string[]> {
  if (!roomId || typeof roomId !== 'string') return [];
  if (roomId.startsWith('group__')) {
    const groupId = roomId.replace('group__', '');
    const { rows } = await query('SELECT members FROM groups WHERE id=$1', [groupId]);
    if (!rows.length) return [];
    return safeParseMembers(rows[0].members) ?? [];
  }
  const parts = roomId.split('__');
  if (parts.length === 2 && parts[0] && parts[1]) return parts;
  const { rows } = await query('SELECT username FROM users', []);
  const users = rows.map((r: any) => String(r.username));
  for (const u1 of users) {
    for (const u2 of users) {
      if (u1 < u2 && getRoomId(u1, u2) === roomId) return [u1, u2];
    }
  }
  return [];
}

/** Emit `event` to the members of `roomId` only — never a global broadcast. */
export async function emitToRoom(
  io: SocketIOServer,
  roomId: string,
  event: string,
  payload: any,
  query: DbQuery
): Promise<void> {
  const members = await resolveRoomMembers(roomId, query);
  for (const member of members) {
    presence.emitToUser(io, member, event, payload);
  }
}
