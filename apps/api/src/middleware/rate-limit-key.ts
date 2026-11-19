/**
 * Pick a pre-authentication rate bucket without granting trust to decoded
 * bearer claims or credential-shaped strings. Every bearer value stays on
 * the source-IP bucket until authentication verifies it. `clientIp` is the
 * address the Console's server vouched for, already verified by
 * `verifyForwardedClient`; it takes the place of the source address, and
 * undefined keeps the source address.
 */
export function preAuthRateLimitKey(
  authorization: string | undefined,
  ip: string,
  clientIp?: string,
): string {
  const address = clientIp ?? ip;
  if (authorization?.startsWith('Bearer ')) {
    const token = authorization.slice(7).trim();
    if (token.length > 0 && token.length <= 4_096) {
      // Bearer values cannot use an unverified subject or apparent API-key
      // value as a bucket key. Keep them on
      // one source-IP bucket, with a separate prefix so the server can retain
      // the existing 500/min authenticated headroom while still preventing
      // attacker-controlled token rotation from creating unlimited buckets.
      return `bearer-ip:${address}`;
    }
  }
  return `ip:${address}`;
}
