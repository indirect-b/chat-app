import { OAuth2Client, type TokenPayload } from 'google-auth-library';
import { validateEmail } from './email';

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
 * endpoints refuse with a "not enabled" message and the Bale / email
 * flows are completely untouched.
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
  };
}

/**
 * Verify a Google ID token and return the verified email address
 * (normalized, lowercased). Throws on ANY failure — bad signature,
 * wrong audience, expired token, unverified email, missing email —
 * so callers fail closed with a generic message (no details leaked).
 * The `verifier` parameter exists only for tests (a fake that never
 * calls Google); production always uses the default verifier.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  verifier: TokenVerifier = defaultVerifier
): Promise<string> {
  const audience = getGoogleClientId();
  if (!audience) throw new Error('google_not_configured');
  if (typeof idToken !== 'string' || !idToken.trim()) {
    throw new Error('invalid_token');
  }
  const { email, emailVerified } = await verifier(idToken.trim(), audience);
  if (!emailVerified) throw new Error('email_not_verified');
  const normalized = validateEmail(email);
  if (!normalized) throw new Error('invalid_email');
  return normalized;
}
