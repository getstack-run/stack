import { sha256 } from '@stack/shared';

/**
 * Identical denials are one event with a count, not a card each. A test run that is refused the same way
 * twenty-five times is one thing for the owner to read, not twenty-five.
 */
export const DENIAL_DEDUP_WINDOW_SECONDS = 10 * 60;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PREFIXED_ID = /^[a-z][a-z0-9]{0,11}[_-][A-Za-z0-9_-]{6,}$/;

/** True for a path segment that names one thing among many (a number, a uuid, a long hex or an id with a prefix). */
function looksLikeIdentifier(segment: string): boolean {
  if (/^\d+$/.test(segment)) return true;
  if (UUID.test(segment)) return true;
  if (/^[0-9a-f]{12,}$/i.test(segment)) return true;
  if (PREFIXED_ID.test(segment) && /\d/.test(segment)) return true;
  // A long mixed token (an opaque id) is never a word of the API's own path.
  return segment.length >= 20 && /\d/.test(segment);
}

/** The path of a call's URL, or `/` when it does not parse. Never throws. */
export function pathnameOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return '/';
  }
}

/** The host of a call's URL in lower case, or an empty string when it does not parse. Never throws. */
export function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * The path with each segment that names one thing replaced by `:id`, so `/v1/orders/1001/lines` and
 * `/v1/orders/1002/lines` are the same place. Words stay as they are.
 */
export function pathTemplate(pathname: string): string {
  const template = pathname
    .split('/')
    .slice(0, 16)
    .map((segment) => (segment && looksLikeIdentifier(segment) ? ':id' : segment))
    .join('/');
  return template.slice(0, 256) || '/';
}

/**
 * The dedup gate of one kind of denial: the same agent, the same service, the same method, host and place and the same
 * reason (`op`: what refused it, for example the constraint's path and operator). The host is part of it, so the same
 * refusal to two hosts of one connection is two events, each naming its own. The key is a digest, so it is bounded
 * however long the path is and carries nothing of the call.
 */
export function denialDedup(input: {
  agentId: string;
  service: string;
  method: string;
  /** The destination host; absent is the empty host. */
  host?: string;
  pathname: string;
  op: string;
}): { dedupKey: string; dedupWindowSeconds: number } {
  const digest = sha256(
    JSON.stringify([
      input.agentId,
      input.service,
      input.method.toUpperCase(),
      (input.host ?? '').toLowerCase(),
      pathTemplate(input.pathname),
      input.op,
    ]),
  ).slice(0, 32);
  return { dedupKey: `denial:${digest}`, dedupWindowSeconds: DENIAL_DEDUP_WINDOW_SECONDS };
}
