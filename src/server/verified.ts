/**
 * Verified-ownership marks (registration binding fix).
 *
 * /api/register used to let anyone register ANY Bale ID or email without
 * proving ownership — an attacker could squat an address and take the
 * account with the issued one-time recovery code. Registration now
 * requires a live mark: a successful OTP verification (Bale or email)
 * sets a mark for that identifier, and /api/register consumes it
 * (single-use, 10-minute expiry). /api/google-login does not use
 * /api/register — it creates users atomically after Google itself has
 * verified the email address.
 *
 * Pure in-memory logic (no network, no DB) so the tests exercise the
 * real rules.
 */

export const VERIFIED_MARK_EXPIRE_MS = 10 * 60 * 1000;

export class VerifiedMarks {
  private readonly marks = new Map<string, number>();

  /** Record that `identifier` proved ownership at `now`. */
  public mark(identifier: string, now = Date.now()): void {
    if (!identifier) return;
    this.marks.set(identifier, now + VERIFIED_MARK_EXPIRE_MS);
  }

  /**
   * Consume a live mark for `identifier`. Returns true only when a
   * non-expired mark existed; the mark is deleted either way, so it
   * can never be reused (single-use, fail-closed).
   */
  public consume(identifier: string, now = Date.now()): boolean {
    const expire = this.marks.get(identifier);
    this.marks.delete(identifier);
    if (expire === undefined) return false;
    return now <= expire;
  }

  /** Test helper: how many live (unexpired) marks exist. */
  public liveCount(now = Date.now()): number {
    let count = 0;
    for (const expire of this.marks.values()) {
      if (now <= expire) count += 1;
    }
    return count;
  }
}

/** Process-wide store used by the auth endpoints in server.ts. */
export const verifiedMarks = new VerifiedMarks();
