// What a refusal records about the call it refused.
//
// An operator reading a refusal needs to know WHICH call was stopped and WHY:
// the method, host and path, and the rule and constraint that did not admit
// it. They must never learn the caller's data from it: a security event and a
// signed intent_denial are retained, exported and shown in the console, and
// the request body, its recipients, its headers and its query string are the
// caller's data (frequently PII, sometimes a credential).
//
// So this file records the request's SHAPE and the policy's side of every
// comparison:
//
//   - the path without its query string, with any segment that looks like a
//     secret, a token or an email address replaced by `{redacted}`;
//   - a failing constraint as path + op, and for `eq` / `in` the values the
//     policy ALLOWS. Never the value the request carried: a failing `eq` or
//     `in` cannot contain it, and the ops that could (`not_eq`, `not_in`,
//     whose list is exactly what the request matched) record no values at all.
//     Header constraints record no values either.

import type { Constraint } from '../schemas/passport.js';
import { shannonEntropy } from './shannon-entropy.js';

export const REDACTED_PATH_SEGMENT = '{redacted}';
const MAX_PATH_CHARS = 512;
const MAX_ALLOWED_VALUES = 20;
const MAX_VALUE_CHARS = 256;

/** Prefixes that mark a bearer secret whatever its length. */
const SECRET_PREFIXES = /^(sk|pk|rk)_(live|test)_|^sk-|^xox[abposr]-|^xapp-|^gh[pousr]_|^github_pat_|^glpat-|^AKIA[0-9A-Z]{12}|^AIza[0-9A-Za-z_-]{20}|^ya29\.|^whsec_|^shpat_|^SG\./;
const JWT_SHAPE = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
// ':' included: a Telegram-style bot token is `<digits>:<base64url>`.
const OPAQUE_CHARSET = /^[A-Za-z0-9_\-=+.~:]+$/;

/**
 * Whether one path segment looks like a secret, a token or an email address.
 * Ordinary ids (numbers, prefixed ids, UUIDs, lower-case slugs such as
 * repository names) are kept: they say which resource was addressed, which is
 * what the operator needs.
 */
export function pathSegmentLooksSecret(segment: string): boolean {
  let decoded = segment;
  try { decoded = decodeURIComponent(segment); } catch { /* keep the raw segment */ }
  for (const value of new Set([segment, decoded])) {
    if (value.includes('@')) return true;
    if (SECRET_PREFIXES.test(value) || JWT_SHAPE.test(value)) return true;
    if (value.length < 24 || !OPAQUE_CHARSET.test(value)) continue;
    if (/^[0-9a-f]{32,}$/i.test(value)) return true;
    const upper = /[A-Z]/.test(value);
    const lower = /[a-z]/.test(value);
    const digit = /[0-9]/.test(value);
    // Base64 / base64url secrets mix both cases and digits; slugs and ids do not.
    if (upper && lower && digit && shannonEntropy(value) >= 3.5) return true;
    // A long lower-case-and-digit run with no word separators (a lower-cased key).
    if (value.length >= 32 && digit && !/[-_.]/.test(value) && (value.match(/[0-9]/g)!.length / value.length) >= 0.2) return true;
  }
  return false;
}

/**
 * The request path as a refusal records it: no query string or fragment, any
 * segment that looks like a secret replaced by `{redacted}`, capped at 512
 * characters.
 */
export function redactRequestPath(pathname: string): string {
  const bare = pathname.split(/[?#]/, 1)[0] ?? '';
  const redacted = bare.split('/').map((segment) => (segment && pathSegmentLooksSecret(segment) ? REDACTED_PATH_SEGMENT : segment)).join('/');
  return redacted.length > MAX_PATH_CHARS ? `${redacted.slice(0, MAX_PATH_CHARS)}...` : redacted || '/';
}

/** The policy's side of one failed comparison. Never the request's value. */
export interface ConstraintDescriptor {
  path: string;
  op: Constraint['op'];
  /** For `eq` and `in`: what the policy allows. Absent for every other op and for header paths. */
  allowed?: Array<string | number | boolean>;
  /** Set when `allowed` was cut to its first 20 entries: how many the policy lists. */
  allowed_count?: number;
  /** For `lt`, `lte`, `gt`, `gte`: the policy's bound. */
  bound?: number;
}

function capValue(value: string | number | boolean): string | number | boolean {
  return typeof value === 'string' && value.length > MAX_VALUE_CHARS ? `${value.slice(0, MAX_VALUE_CHARS)}...` : value;
}

export function describeConstraint(constraint: Constraint): ConstraintDescriptor {
  const descriptor: ConstraintDescriptor = { path: constraint.path, op: constraint.op };
  // Header values are credentials as often as not; a header constraint names
  // only its path and op.
  if (constraint.path.toLowerCase().startsWith('headers.')) return descriptor;
  if (constraint.op === 'eq' || constraint.op === 'in') {
    const values = Array.isArray(constraint.value) ? constraint.value : [constraint.value];
    descriptor.allowed = values.slice(0, MAX_ALLOWED_VALUES).map(capValue);
    if (values.length > MAX_ALLOWED_VALUES) descriptor.allowed_count = values.length;
  } else if (['lt', 'lte', 'gt', 'gte'].includes(constraint.op) && typeof constraint.value === 'number') {
    descriptor.bound = constraint.value;
  }
  return descriptor;
}

/** What a refusal records about the HTTP call it refused: method, host and path, nothing the caller sent. */
export function describeRefusedHttpCall(request: { method: string; url: { host: string; pathname: string } }): {
  request_method: string; request_host: string; request_path: string;
} {
  return {
    request_method: request.method.toUpperCase(),
    request_host: request.url.host.toLowerCase(),
    request_path: redactRequestPath(request.url.pathname),
  };
}

/**
 * An absolute request URL as any evidence records it (a signed claim, a
 * security event, an audit row, a log line): origin plus the redacted path.
 * The query string, fragment and userinfo are dropped (they carry the
 * caller's values, a recipient or a key as easily as a search term). An
 * unparseable URL is recorded as null rather than verbatim.
 */
export function evidenceUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${redactRequestPath(parsed.pathname)}`;
  } catch {
    return null;
  }
}

/** `METHOD url` for an intent's `action`, with the URL as `evidenceUrl` records it. */
export function evidenceAction(method: string, url: string): string {
  return `${method} ${evidenceUrl(url) ?? '(unparseable URL)'}`;
}

/**
 * An intent claim as a refusal or a signed record keeps it. An approved
 * intent carries the exact URL its owner approved, query string included, and
 * the call-shape check needs that. A record of a refusal needs only where the
 * call went: the URL in `action` and `parameters.url` becomes `evidenceUrl`,
 * and a `parameters.query` object (the same query string, as pairs) is
 * dropped. The claim passed in is not changed.
 */
export function evidenceIntentClaim<T extends { action: string; parameters: Record<string, unknown> }>(claim: T): T {
  const parameters: Record<string, unknown> = { ...claim.parameters };
  delete parameters['query'];
  const url = parameters['url'];
  if (typeof url === 'string') parameters['url'] = evidenceUrl(url) ?? '(unparseable URL)';
  const action = claim.action.replace(/https?:\/\/\S+/gi, (found) => evidenceUrl(found) ?? '(unparseable URL)');
  return { ...claim, action, parameters };
}
