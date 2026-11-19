// The encrypted-envelope vocabulary: lifetimes, safe replay headers, KMS encryption contexts, the
// operation-key and owner-token hashes, and the stored response envelope parser. Every context
// binds the operator and operation so a ciphertext cannot be replayed under another one.

import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalize } from '@stack/shared';
import { type ProxyReplayResult, type ResponseEnvelope } from './types.js';

export const ENVELOPE_VERSION = 1;
export const REPLAY_TTL_MS = 24 * 60 * 60 * 1_000;
export const STRIPE_RETRY_TTL_MS = 23 * 60 * 60 * 1_000;
export const OWNER_LEASE_MS = 2 * 60 * 1_000;

export const PROXY_REPLACEMENT_WARNING_VERSION = 1;
export const PROXY_REPLACEMENT_WARNING =
  'STACK cannot prove whether the original request completed. A replacement may repeat the external action.';
export const PROXY_REPLACEMENT_WARNING_HASH =
  `sha256:${sha256(canonicalize({
    version: PROXY_REPLACEMENT_WARNING_VERSION,
    text: PROXY_REPLACEMENT_WARNING,
  }))}` as const;

export const SAFE_PROXY_REPLAY_HEADERS = new Set([
  'cache-control',
  'content-language',
  'content-type',
  'etag',
  'idempotent-replayed',
  'last-modified',
  'request-id',
  'retry-after',
  'stripe-request-id',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
]);

export function postResponseRetryAt(attempts: number, now = new Date()): Date {
  const exponent = Math.max(0, Math.min(attempts - 1, 10));
  const delayMs = Math.min(15 * 60 * 1_000, 1_000 * (2 ** exponent));
  return new Date(now.getTime() + delayMs);
}

export function proxyAccountingWalletIdentity(
  operatorId: string,
  accountingPeriod: string,
  operationKeyHash: string,
): { holdId: string; transactionId: string } {
  const digest = sha256(canonicalize({
    purpose: 'proxy_accounting_wallet',
    version: 1,
    operator_id: operatorId,
    accounting_period: accountingPeriod,
    operation_key_hash: operationKeyHash,
  }));
  return {
    holdId: `whld_proxy_${digest.slice(0, 40)}`,
    transactionId: `wtxn_proxy_${digest.slice(0, 40)}`,
  };
}

export function hashProxyOperationKey(value: string): string {
  return sha256(value);
}

export function constantTimeHexEqual(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

export function admissionOwnerHashFor(operatorId: string, operationKey: string): string {
  return sha256(canonicalize({
    purpose: 'proxy_admission_owner',
    version: 1,
    operator_id: operatorId,
    operation_key: operationKey,
  }));
}

export function preparedAad(operatorId: string, operationId: string) {
  return {
    operator_id: operatorId,
    proxy_operation_id: operationId,
    envelope_version: String(ENVELOPE_VERSION),
    purpose: 'proxy_prepared_request',
  };
}

export function responseAad(operatorId: string, operationId: string) {
  return {
    operator_id: operatorId,
    proxy_operation_id: operationId,
    envelope_version: String(ENVELOPE_VERSION),
    purpose: 'proxy_final_response',
  };
}

export function scopeAad(operatorId: string, operationId: string) {
  return {
    operator_id: operatorId,
    proxy_operation_id: operationId,
    envelope_version: String(ENVELOPE_VERSION),
    purpose: 'proxy_scope_descriptor',
  };
}

export function postResponseAad(operatorId: string, operationId: string) {
  return {
    operator_id: operatorId,
    proxy_operation_id: operationId,
    envelope_version: String(ENVELOPE_VERSION),
    purpose: 'proxy_post_response_work',
  };
}

export function parseResponseEnvelope(plaintext: string): ProxyReplayResult {
  const value = JSON.parse(plaintext) as Partial<ResponseEnvelope>;
  if (value.v !== ENVELOPE_VERSION || typeof value.status !== 'number'
    || !value.headers || typeof value.headers !== 'object' || Array.isArray(value.headers)) {
    throw new Error('Stored proxy response envelope is invalid');
  }
  const headers: Record<string, string> = {};
  for (const [name, headerValue] of Object.entries(value.headers)) {
    if (!SAFE_PROXY_REPLAY_HEADERS.has(name) || typeof headerValue !== 'string') {
      throw new Error('Stored proxy response envelope contains a forbidden header');
    }
    headers[name] = headerValue;
  }
  return { state: 'available', status: value.status, headers, body: value.body };
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// Kept local so callers never compare raw owner tokens in ordinary string time.
export function proxyOwnerTokenMatches(rawToken: string, storedHash: string): boolean {
  const actual = Buffer.from(sha256(rawToken), 'hex');
  const expected = Buffer.from(storedHash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
