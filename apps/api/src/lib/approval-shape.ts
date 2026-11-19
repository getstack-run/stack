import { createHash } from 'node:crypto';
import { evidenceUrl, redactRequestPath } from '@stack/shared';

/**
 * Does the live call match the approval that admitted it?
 *
 * The old comparator checked four things and two of them failed OPEN:
 *
 *   target        always
 *   intent_type   always
 *   method        only `if (approvedMethod !== undefined)`
 *   url HOST      only `if (expectedHost !== undefined)` — and host only,
 *                 never the path
 *
 * `IntentClaim.parameters` is an unvalidated `z.record(z.string(),
 * z.unknown())`, so omitting `method` or `url` was legal and silently
 * disabled that dimension. An approval for `POST /v1/customers` admitted
 * `POST /v1/transfers` on the same host. The body was never compared at all.
 *
 * This comparator fails CLOSED. An approval that does not say WHERE cannot
 * authorise a where, and an approval that does not say WHICH METHOD cannot
 * authorise a method. Both are refused with a message naming the field the
 * approval must carry.
 *
 * Lives in its own module so the route and its tests exercise the same
 * function rather than two implementations that drift.
 */

export interface ApprovedIntentShape {
  target: string;
  intent_type: string;
  parameters: Record<string, unknown>;
}

export interface ActualCallShape {
  service: string;
  method: string;
  url: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ShapeMismatch {
  field: string;
  expected: unknown;
  actual: unknown;
}

/**
 * Stable hash of a JSON-ish value. Object keys are sorted at every level so
 * two bodies that differ only in key order compare equal — an agent
 * re-serialising the approved body must not be refused for it.
 */
export function canonicalBodyHash(body: unknown): string {
  const canonical = (value: unknown): unknown => {
    if (value === undefined) return ['absent'];
    if (value === null) return ['null'];
    if (typeof value === 'boolean') return ['boolean', value];
    if (typeof value === 'number') return ['number', value];
    if (typeof value === 'string') return ['string', value];
    if (Array.isArray(value)) return ['array', value.map(canonical)];
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return ['object', entries.map(([k, v]) => [k, canonical(v)])];
  };
  return createHash('sha256').update(JSON.stringify(canonical(body))).digest('hex');
}

function comparableHeaders(value: unknown): Array<[string, string]> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const normalized = new Map<string, string>();
  for (const [rawName, rawValue] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawValue !== 'string') return null;
    const name = rawName.trim().toLowerCase();
    if (!name) return null;
    const prior = normalized.get(name);
    if (prior !== undefined && prior !== rawValue) return null;
    normalized.set(name, rawValue);
  }
  return [...normalized.entries()].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

/**
 * Returns the first mismatch, or null when the call matches the approval.
 */
export function compareApprovedShape(
  approved: ApprovedIntentShape,
  actual: ActualCallShape,
): ShapeMismatch | null {
  if (approved.target !== actual.service) {
    return { field: 'target', expected: approved.target, actual: actual.service };
  }
  if (approved.intent_type !== 'http_call') {
    return { field: 'intent_type', expected: approved.intent_type, actual: 'http_call' };
  }

  const params = approved.parameters ?? {};

  // Method. Absent is a refusal, not a pass.
  const approvedMethod = typeof params['method'] === 'string' ? (params['method'] as string) : undefined;
  if (approvedMethod === undefined) {
    return {
      field: 'method',
      expected: 'declared in the approved intent (parameters.method)',
      actual: actual.method,
    };
  }
  if (approvedMethod.toUpperCase() !== actual.method.toUpperCase()) {
    return { field: 'method', expected: approvedMethod, actual: actual.method };
  }

  // URL. Absent is a refusal. Host AND path are both compared — checking the
  // host alone let an approval for one endpoint admit any other endpoint on
  // the same service.
  const approvedUrl = typeof params['url'] === 'string' ? (params['url'] as string) : undefined;
  if (approvedUrl === undefined) {
    return {
      field: 'url',
      expected: 'declared in the approved intent (parameters.url)',
      actual: evidenceUrl(actual.url) ?? 'an unparseable URL',
    };
  }

  let expected: URL;
  let got: URL;
  try {
    expected = new URL(approvedUrl);
  } catch {
    return { field: 'url', expected: 'a parseable absolute URL', actual: 'an unparseable approved URL' };
  }
  try {
    got = new URL(actual.url);
    for (const [key, value] of Object.entries(actual.query ?? {})) {
      got.searchParams.set(key, value);
    }
  } catch {
    return { field: 'url', expected: evidenceUrl(approvedUrl), actual: 'an unparseable URL' };
  }

  if (expected.protocol.toLowerCase() !== got.protocol.toLowerCase()) {
    return { field: 'url_scheme', expected: expected.protocol, actual: got.protocol };
  }
  if (expected.host.toLowerCase() !== got.host.toLowerCase()) {
    return { field: 'url_host', expected: expected.host, actual: got.host };
  }
  if (expected.pathname !== got.pathname) {
    return { field: 'url_path', expected: redactRequestPath(expected.pathname), actual: redactRequestPath(got.pathname) };
  }
  if (expected.search !== got.search) {
    // A query holds what the call is about (an address, a number, a token): it is not shown, not even as a hash that a
    // guess could be checked against.
    return { field: 'url_query', expected: 'the approved query', actual: 'a different query' };
  }

  // Relevant headers are exact when the approval pins them. Names are
  // case-insensitive; conflicting case-duplicates fail closed. Values are
  // represented only by hashes in mismatches because headers may be sensitive.
  if ('headers' in params && params['headers'] !== undefined) {
    const approvedHeaders = comparableHeaders(params['headers']);
    const actualHeaders = comparableHeaders(actual.headers ?? {});
    if (!approvedHeaders || !actualHeaders) {
      return { field: 'headers', expected: 'valid unambiguous headers', actual: 'invalid or ambiguous headers' };
    }
    const expectedHash = canonicalBodyHash(approvedHeaders);
    const actualHash = canonicalBodyHash(actualHeaders);
    if (expectedHash !== actualHash) {
      return {
        field: 'headers',
        expected: `sha256:${expectedHash.slice(0, 12)}`,
        actual: `sha256:${actualHash.slice(0, 12)}`,
      };
    }
  }

  // Body. Compared only when the approval pinned one. An approval that says
  // nothing about the body does not silently authorise any body — the closed
  // operation policy is what governs body shape — but where the approval DID
  // pin a body, sending a different one is a mismatch.
  if ('body' in params && params['body'] !== undefined) {
    const expectedHash = canonicalBodyHash(params['body']);
    const actualHash = canonicalBodyHash(actual.body);
    if (expectedHash !== actualHash) {
      // Hashes only. The body is caller data and frequently PII, so it must
      // not travel into a denial claim or a security event.
      return { field: 'body', expected: `sha256:${expectedHash.slice(0, 12)}`, actual: `sha256:${actualHash.slice(0, 12)}` };
    }
  }

  return null;
}
