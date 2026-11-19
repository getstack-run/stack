import { createHash, timingSafeEqual } from 'node:crypto';

// Intentionally UNPEPPERED. This hash never touches the DB: it
// only binds a session to the bearer that initialized it and compares a
// presented key against the session-bound hash of the SAME key in this
// process (see apiKeyMatches). Since it never cross-checks a stored
// operator/member hash, adding the pepper would buy nothing and a mismatch
// with the DB scheme is impossible. Do not "align" this with hashApiKey.
export function hashApiKey(apiKey: string): Buffer {
  return createHash('sha256').update(apiKey).digest();
}

export function apiKeyMatches(presented: string, stored: Buffer): boolean {
  const presentedHash = hashApiKey(presented);
  if (presentedHash.length !== stored.length) return false;
  return timingSafeEqual(presentedHash, stored);
}
