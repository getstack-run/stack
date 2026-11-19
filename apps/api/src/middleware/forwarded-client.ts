import { createHmac, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';

/**
 * The Console's server says which end-user address a call it forwarded came
 * from, so the global rate limit can count each customer's Console on its own
 * instead of putting every Console on the Console server's one address.
 *
 * The header is `<client-ip>.<unix-seconds>.<hex hmac-sha256>`. The MAC is over
 * `stack-forwarded-client:v1:<client-ip>:<unix-seconds>`, keyed with the
 * dashboard proxy secret the Console already holds, so the secret itself never
 * travels and only a holder of it can produce a header. The Console's server has its
 * own copy of this format, pinned against this one by a shared test vector.
 *
 * The one reader of the verified address is the rate-limit key. An invalid
 * header is ignored (never trusted, never an error).
 */
export const FORWARDED_CLIENT_HEADER = 'x-stack-forwarded-client';
/** How far the header's time may be from ours, in either direction. */
export const FORWARDED_CLIENT_TOLERANCE_SECONDS = 60;
const MAX_HEADER_CHARS = 200;

export function forwardedClientMac(clientIp: string, unixSeconds: string, secret: string): string {
  return createHmac('sha256', secret)
    .update(`stack-forwarded-client:v1:${clientIp}:${unixSeconds}`)
    .digest('hex');
}

/**
 * The client address a valid header asserts, or undefined for anything else:
 * no header, no secret, malformed, an address that is not an IP, a time
 * outside the tolerance, or a MAC that does not verify.
 */
export function verifyForwardedClient(
  header: string | string[] | undefined,
  secret: string | undefined,
  nowMs: number,
): string | undefined {
  if (!secret || typeof header !== 'string' || header.length === 0 || header.length > MAX_HEADER_CHARS) {
    return undefined;
  }
  // An IPv4 address holds dots itself, so the MAC and the time are cut from the right.
  const macAt = header.lastIndexOf('.');
  if (macAt < 0) return undefined;
  const timeAt = header.lastIndexOf('.', macAt - 1);
  if (timeAt < 1) return undefined;
  const clientIp = header.slice(0, timeAt);
  const unixSeconds = header.slice(timeAt + 1, macAt);
  const mac = header.slice(macAt + 1);
  if (isIP(clientIp) === 0) return undefined;
  if (!/^\d{1,12}$/.test(unixSeconds)) return undefined;
  if (!/^[0-9a-f]{64}$/.test(mac)) return undefined;
  if (Math.abs(Number(unixSeconds) - nowMs / 1000) > FORWARDED_CLIENT_TOLERANCE_SECONDS) return undefined;
  const expected = Buffer.from(forwardedClientMac(clientIp, unixSeconds, secret), 'hex');
  const supplied = Buffer.from(mac, 'hex');
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return undefined;
  return clientIp;
}
