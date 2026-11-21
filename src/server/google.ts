import { OAuth2Client, type TokenPayload } from 'google-auth-library';
import {
  normalizeGooglePicture,
  normalizeGoogleProfileName,
  type GoogleProfile,
} from './profileSync';

/**
 * Strict email validation. Returns the normalized (trimmed, lowercased)
 * address, or null when the input is not a plausible deliverable address.
 * (Moved here from the deleted src/server/email.ts — Google Sign-In
 * needs it to normalize the verified address from the ID token.)
 */
export function validateEmail(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const email = input.trim().toLowerCase();
  if (email.length < 3 || email.length > 254) return null;
  const at = email.indexOf('@');
  if (at <= 0 || at !== email.lastIndexOf('@')) return null;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (!local || !domain) return null;
  if (local.length > 64 || domain.length > 253) return null;
  if (!/^[a-z0-9._%+-]+$/.test(local)) return null;
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return null;
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return null;
  if (domain.startsWith('-') || domain.endsWith('-')) return null;
  const labels = domain.split('.');
  if (labels.length < 2) return null;
  if (labels.some(l => l.length === 0 || l.startsWith('-') || l.endsWith('-'))) return null;
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld)) return null;
  return email;
}

/**
 * Google Sign-In (primary login).
 *
 * The client sends the Google ID token (JWT) issued by Google Identity
 * Services; the server verifies it against Google's keys and only then
 * trusts the email address inside it. No Google client secret is used
 * anywhere in this flow — the Client ID is the OAuth audience and is
 * public by design (it is also embedded in the login page).
 *
 * Env-gated: GOOGLE_CLIENT_ID must be set, otherwise the Google
 * endpoints refuse with a "not enabled" message. Google Sign-In is
 * the only login method — the Bale / email OTP flows were removed.
 */

export const GOOGLE_DISABLED_MSG = 'ورود با گوگل فعلاً فعال نیست';
export const GOOGLE_LOGIN_FAILED_MSG = 'ورود با گوگل ناموفق بود. لطفاً دوباره تلاش کنید.';

/** The Google OAuth Client ID (public audience), or null when unset. */
export function getGoogleClientId(): string | null {
  const id = (process.env.GOOGLE_CLIENT_ID || '').trim();
  return id || null;
}

export function isGoogleConfigured(): boolean {
  return getGoogleClientId() !== null;
}

export interface GoogleIdPayload {
  email: string;
  emailVerified: boolean;
  /** Google display name from the token (absent → null, never an error). */
  name?: string | null;
  /** Google profile photo URL from the token (absent → null). */
  picture?: string | null;
}

type TokenVerifier = (
  idToken: string,
  audience: string
) => Promise<GoogleIdPayload>;

/** Default verifier: Google's own OAuth2Client (network to Google). */
async function defaultVerifier(
  idToken: string,
  audience: string
): Promise<GoogleIdPayload> {
  const client = new OAuth2Client();
  const ticket = await client.verifyIdToken({ idToken, audience });
  const payload: TokenPayload | undefined = ticket.getPayload();
  return {
    email: payload?.email || '',
    emailVerified: payload?.email_verified === true,
    name: normalizeGoogleProfileName(payload?.name),
    picture: normalizeGooglePicture(payload?.picture),
  };
}

/**
 * Verify a Google ID token and return the verified email address
 * (normalized, lowercased) plus the Google profile carried by the token
 * (display name and photo URL, each null when the token does not carry
 * one). Throws on ANY failure — bad signature, wrong audience, expired
 * token, unverified email, missing email — so callers fail closed with
 * a generic message (no details leaked). The `verifier` parameter
 * exists only for tests (a fake that never calls Google); production
 * always uses the default verifier.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  verifier: TokenVerifier = defaultVerifier
): Promise<{ email: string; profile: GoogleProfile }> {
  const audience = getGoogleClientId();
  if (!audience) throw new Error('google_not_configured');
  if (typeof idToken !== 'string' || !idToken.trim()) {
    throw new Error('invalid_token');
  }
  const { email, emailVerified, name, picture } = await verifier(idToken.trim(), audience);
  if (!emailVerified) throw new Error('email_not_verified');
  const normalized = validateEmail(email);
  if (!normalized) throw new Error('invalid_email');
  return {
    email: normalized,
    profile: {
      name: normalizeGoogleProfileName(name),
      picture: normalizeGooglePicture(picture),
    },
  };
}

// ---------------------------------------------------------------------------
// Redirect mode (ux_mode 'redirect'): Google POSTs the credential as a
// form to /api/google-redirect instead of returning it to a popup.
// ---------------------------------------------------------------------------

/**
 * Parse the `g_csrf_token` cookie Google Identity Services sets on the
 * app's own domain. Minimal parsing — no cookie library. Returns null
 * when the cookie is absent.
 */
export function parseGoogleCsrfCookie(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === 'g_csrf_token') {
      const value = part.slice(eq + 1).trim();
      return value || null;
    }
  }
  return null;
}

/** Outcome of the redirect-request gate (decided before any token is issued). */
export type GoogleRedirectGate = 'ok' | 'bad_request' | 'forbidden';

export function getGoogleRedirectUri(env: Record<string, string | undefined> = process.env): string {
  const uri = env.GOOGLE_REDIRECT_URI?.trim();
  return uri || 'https://chatapp-server-1i2a.onrender.com/api/google-redirect';
}

/**
 * Gate a redirect-mode login request. Missing credential is a malformed
 * request (400); a missing or mismatched CSRF token fails closed (403).
 * Pure — the handler maps the result to the HTTP status.
 */
export function checkGoogleRedirectRequest(input: {
  credential: string;
  csrfField: string;
  csrfCookie: string | null;
}): GoogleRedirectGate {
  if (!input.credential.trim()) return 'bad_request';
  if (!input.csrfField || !input.csrfCookie || input.csrfField !== input.csrfCookie) {
    return 'forbidden';
  }
  return 'ok';
}

/**
 * Build the post-login redirect target. The session token rides in the
 * URL only for this one hop (the client stores it and strips it from
 * the address bar at once). The recovery code NEVER appears here — it
 * is fetched once via POST /api/recovery-code-once.
 */
export function buildGoogleRedirectUrl(sessionToken: string, isNew: boolean): string {
  return `/?session=${encodeURIComponent(sessionToken)}${isNew ? '&new=1' : ''}`;
}

/**
 * One-time pending recovery codes for redirect logins. A new redirect
 * login stores its code here keyed by session token; the client fetches
 * it exactly once (take deletes the entry, so a second fetch finds
 * nothing) and expired entries return nothing.
 */
export class PendingRecoveryCodes {
  private readonly codes = new Map<string, { code: string; expire: number }>();

  store(sessionToken: string, code: string, nowMs: number, ttlMs = 10 * 60 * 1000): void {
    this.codes.set(sessionToken, { code, expire: nowMs + ttlMs });
  }

  take(sessionToken: string, nowMs: number): string | undefined {
    const pending = this.codes.get(sessionToken);
    this.codes.delete(sessionToken);
    if (!pending || nowMs > pending.expire) return undefined;
    return pending.code;
  }
}

/**
 * تجزیه کوکی‌های ارسالی کلاینت (L9 - HttpOnly Cookie support)
 */
export function parseCookies(header: string | undefined): Record<string, string> {
  const list: Record<string, string> = {};
  if (!header) return list;
  header.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    if (parts.length >= 2) {
      const rawValue = parts.slice(1).join('=').trim();
      try {
        list[parts[0].trim()] = decodeURIComponent(rawValue);
      } catch {
        // توالی % خراب در کوکی (مثلاً %ZZ) — مقدار خام را نگه دار تا یک
        // کوکی بد، کل درخواست را خراب نکند.
        list[parts[0].trim()] = rawValue;
      }
    }
  });
  return list;
}
