/**
 * Google profile sync — pure decision logic (no I/O, no network).
 *
 * On Google Sign-In the ID token carries the user's Google display name
 * and profile photo. By default those become the chat profile — but only
 * until the user edits them manually: two flags (name_custom /
 * avatar_custom on the users row) record a manual edit, and once set,
 * later Google logins must NOT overwrite that field.
 *
 * Two entry points:
 *  - resolveGoogleProfileSync: at login, merge the Google profile into
 *    the stored row, respecting the custom flags. Returns the new
 *    { display_name, avatar } or null when nothing would change.
 *  - resolveProfileUpdate: at POST /api/user/update, merge the
 *    submitted profile into the stored row and raise a custom flag
 *    only when the submitted value actually differs from the stored
 *    one (a save that changes nothing must not freeze future sync).
 *
 * The Google photo URL is a public link tied to the Google account;
 * other users see it exactly as they already see the email-based
 * identity. Only the lh3.googleusercontent.com host is accepted (and
 * allowed by the CSP img-src pin) — any other picture host is dropped.
 */

export interface GoogleProfile {
  name: string | null;
  picture: string | null;
}

export interface StoredProfile {
  display_name?: string | null;
  avatar?: string | null;
  name_custom?: number | null;
  avatar_custom?: number | null;
}

/** The only host Google serves profile photos from. */
export const GOOGLE_PHOTO_HOST = 'lh3.googleusercontent.com';

/**
 * Normalize a Google display name: strip control characters, trim,
 * cap at 100 characters. Empty / non-string → null (absent, not an error).
 */
export function normalizeGoogleProfileName(name: unknown): string | null {
  if (typeof name !== 'string') return null;
  const cleaned = name.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (!cleaned) return null;
  return cleaned.slice(0, 100);
}

/**
 * Normalize a Google profile photo URL: it must be an https URL on the
 * Google photo host. Anything else (other hosts, http, unparsable) →
 * null, so a bad value can never be stored or rendered.
 */
export function normalizeGooglePicture(picture: unknown): string | null {
  if (typeof picture !== 'string') return null;
  const url = picture.trim();
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return null;
    if (parsed.hostname !== GOOGLE_PHOTO_HOST) return null;
    return url;
  } catch {
    return null;
  }
}

/**
 * Merge a Google profile into the stored row at login.
 *
 * A field is updated only when its custom flag is 0 AND the Google
 * profile carries a value for it; a missing Google value never clears
 * the stored one. Returns null when nothing would change (caller skips
 * the UPDATE). Values are compared against the stored row with null
 * coalescing so rows created before the profile columns existed
 * (undefined fields) behave like empty ones.
 */
export function resolveGoogleProfileSync(
  stored: StoredProfile,
  profile: GoogleProfile
): { display_name: string | null; avatar: string | null } | null {
  const storedName = stored.display_name ?? null;
  const storedAvatar = stored.avatar ?? null;
  const nameCustom = Number(stored.name_custom) || 0;
  const avatarCustom = Number(stored.avatar_custom) || 0;

  const nextName =
    nameCustom === 0 && profile.name !== null ? profile.name : storedName;
  const nextAvatar =
    avatarCustom === 0 && profile.picture !== null ? profile.picture : storedAvatar;

  if (nextName === storedName && nextAvatar === storedAvatar) return null;
  return { display_name: nextName, avatar: nextAvatar };
}

/**
 * Merge a profile edit (POST /api/user/update) into the stored row.
 *
 * `input` uses presence: a field that is undefined was not submitted
 * and is left untouched; a submitted value (including '' / null, which
 * clear the field) replaces the stored one. A custom flag is raised
 * only when the submitted value actually differs from the stored one.
 */
export function resolveProfileUpdate(
  stored: StoredProfile,
  input: { display_name?: string | null; avatar?: string | null }
): {
  display_name: string | null;
  avatar: string | null;
  name_custom: number;
  avatar_custom: number;
} {
  const storedName = stored.display_name ?? null;
  const storedAvatar = stored.avatar ?? null;

  let nextName = storedName;
  let nameCustom = Number(stored.name_custom) || 0;
  if (input.display_name !== undefined) {
    const submitted =
      typeof input.display_name === 'string'
        ? normalizeGoogleProfileName(input.display_name)
        : null;
    if (submitted !== storedName) nameCustom = 1;
    nextName = submitted;
  }

  let nextAvatar = storedAvatar;
  let avatarCustom = Number(stored.avatar_custom) || 0;
  if (input.avatar !== undefined) {
    const submitted = input.avatar || null;
    if (submitted !== storedAvatar) avatarCustom = 1;
    nextAvatar = submitted;
  }

  return {
    display_name: nextName,
    avatar: nextAvatar,
    name_custom: nameCustom,
    avatar_custom: avatarCustom,
  };
}
