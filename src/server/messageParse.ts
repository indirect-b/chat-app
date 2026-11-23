/**
 * Message parsing helpers — fail-closed JSON handling (round 5, L7(e)).
 *
 * parseMsg used to call JSON.parse on the stored reactions string inline in
 * server.ts: one corrupt row threw inside an async handler, and Express 4
 * does not forward async rejections, so the request hung. These helpers
 * never throw — corrupt JSON degrades to an empty object / null, and the
 * caller decides how to fail closed (skip the item, return {ok:false}).
 *
 * Moved out of server.ts so tests can import them (server.ts binds a port
 * on import and is never imported in tests).
 */

/** Parse a stored reactions JSON string; corrupt → {}. Non-strings pass through. */
export function safeParseReactions(value: unknown): Record<string, string[]> {
  if (typeof value !== 'string') {
    return value && typeof value === 'object' ? (value as Record<string, string[]>) : {};
  }
  try {
    const parsed = JSON.parse(value || '{}');
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Parse a stored group-members JSON value; corrupt / non-array → null.
 * Accepts an already-parsed array too (defensive: some callers pass rows
 * whose driver already decoded the JSON).
 */
export function safeParseMembers(value: unknown): string[] | null {
  if (Array.isArray(value)) {
    return value.filter((m): m is string => typeof m === 'string');
  }
  if (typeof value !== 'string') return null;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed)
      ? parsed.filter((m): m is string => typeof m === 'string')
      : null;
  } catch {
    return null;
  }
}

/** Normalize a message row for the client (reactions + boolean flags). */
export function parseMsg(m: any) {
  return {
    ...m,
    reactions: safeParseReactions(m.reactions),
    is_edited: !!m.is_edited,
    is_deleted: !!m.is_deleted,
    is_pinned: !!m.is_pinned,
    is_read: !!m.is_read,
  };
}
