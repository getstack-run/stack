import { canonicalize, sha256, StackError } from '@stack/shared';
import type { ProxyRequestInput } from '@stack/shared';
import type { PreparedProxyRequest } from './prepared-proxy-request.js';

export const STRIPE_RETRY_WINDOW_MS = 23 * 60 * 60 * 1_000;
export const STRIPE_MAX_TRANSPORT_ATTEMPTS = 3;

export interface ProxyProviderAdapter {
  kind: 'generic' | 'stripe';
  headers: Record<string, string>;
  nativeIdempotencyKey: string | null;
  nativeIdempotencyKeyHash: `sha256:${string}` | null;
  providerAccountHash: `sha256:${string}` | null;
  retryDeadline: Date | null;
}

export const STRIPE_OPERATION_METADATA_FIELD = 'stack_operation';

/**
 * Bind a Stripe refund to a provider-visible, one-way operation marker. Stripe
 * cannot retrieve an object by Idempotency-Key, so reconciliation needs a
 * marker on the original resource. The caller cannot set or replace STACK's
 * reserved metadata field.
 */
export function bindStripeRefundCorrelation(input: {
  request: ProxyRequestInput;
  resolvedUrl: string;
  operationKey: string;
}): ProxyRequestInput {
  let pathname: string;
  try { pathname = new URL(input.resolvedUrl).pathname; } catch { return input.request; }
  if (input.request.service !== 'stripe'
    || input.request.method !== 'POST'
    || pathname !== '/v1/refunds') {
    return input.request;
  }

  const marker = `stack_${sha256(input.operationKey)}`;
  if (typeof input.request.body === 'string') {
    const contentType = Object.entries(input.request.headers ?? {}).find(
      ([name]) => name.toLowerCase() === 'content-type',
    )?.[1]?.toLowerCase();
    if (contentType && !contentType.includes('application/x-www-form-urlencoded')) {
      throw new StackError('Stripe refund correlation requires form-urlencoded or object request data', 'INVALID_REQUEST', 400);
    }
    const form = new URLSearchParams(input.request.body);
    const field = `metadata[${STRIPE_OPERATION_METADATA_FIELD}]`;
    if (form.has(field)) throw new StackError(
      `Proxy request cannot set reserved Stripe metadata ${field}`,
      'INVALID_REQUEST',
      400,
    );
    form.set(field, marker);
    return {
      ...input.request,
      headers: stripeFormHeaders(input.request.headers),
      body: form.toString(),
    };
  }

  const body = input.request.body;
  if (body !== undefined && (typeof body !== 'object' || body === null || Array.isArray(body))) {
    throw new StackError('Stripe refund correlation requires form-urlencoded or object request data', 'INVALID_REQUEST', 400);
  }
  const objectBody = (body ?? {}) as Record<string, unknown>;
  const metadata = objectBody.metadata;
  if (metadata !== undefined && (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata))) {
    throw new StackError('Stripe refund metadata must be an object', 'INVALID_REQUEST', 400);
  }
  if (metadata && Object.prototype.hasOwnProperty.call(metadata, STRIPE_OPERATION_METADATA_FIELD)) {
    throw new StackError(
      `Proxy request cannot set reserved Stripe metadata ${STRIPE_OPERATION_METADATA_FIELD}`,
      'INVALID_REQUEST',
      400,
    );
  }
  const encoded = new URLSearchParams();
  appendStripeForm(encoded, '', {
    ...objectBody,
    metadata: {
      ...(metadata as Record<string, unknown> | undefined),
      [STRIPE_OPERATION_METADATA_FIELD]: marker,
    },
  });
  return {
    ...input.request,
    headers: stripeFormHeaders(input.request.headers),
    body: encoded.toString(),
  };
}

function stripeFormHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  return {
    ...Object.fromEntries(Object.entries(headers ?? {}).filter(([name]) => name.toLowerCase() !== 'content-type')),
    'content-type': 'application/x-www-form-urlencoded',
  };
}

function appendStripeForm(form: URLSearchParams, prefix: string, value: unknown): void {
  if (value === undefined) return;
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    if (!prefix) throw new StackError('Stripe refund body must be an object', 'INVALID_REQUEST', 400);
    form.append(prefix, value === null ? '' : String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) appendStripeForm(form, `${prefix}[]`, entry);
    return;
  }
  if (typeof value === 'object') {
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const field = prefix ? `${prefix}[${key}]` : key;
      appendStripeForm(form, field, (value as Record<string, unknown>)[key]);
    }
    return;
  }
  throw new StackError('Stripe refund body contains an unsupported value', 'INVALID_REQUEST', 400);
}

/**
 * Stripe v1 retains POST idempotency keys for at least 24 hours. STACK uses a
 * 23-hour ceiling to leave clock and scheduling margin. V1 starts with the
 * create-refund endpoint only; other providers and Stripe endpoints retain the
 * generic one-transport-attempt rule until independently verified.
 */
export function prepareProxyProviderAdapter(input: {
  prepared: PreparedProxyRequest;
  operationKey: string;
  operatorId: string;
  connectionId: string;
  firstDispatchAt: Date;
}): ProxyProviderAdapter {
  let pathname = '';
  try { pathname = new URL(input.prepared.finalUrl).pathname; } catch { /* validated elsewhere */ }
  const stripeRefund = input.prepared.service === 'stripe'
    && input.prepared.method === 'POST'
    && pathname === '/v1/refunds';
  if (!stripeRefund) {
    return {
      kind: 'generic',
      headers: { ...input.prepared.headers },
      nativeIdempotencyKey: null,
      nativeIdempotencyKeyHash: null,
      providerAccountHash: null,
      retryDeadline: null,
    };
  }

  const account = input.prepared.headers['stripe-account'] ?? 'credential-owner';
  const nativeIdempotencyKey = `stack_${sha256(canonicalize({
    v: 1,
    operation_key: input.operationKey,
    operator_id: input.operatorId,
    service_connection_id: input.connectionId,
    endpoint: pathname,
    request_hash: input.prepared.requestHash,
    stripe_account: account,
  }))}`;
  return {
    kind: 'stripe',
    headers: {
      ...input.prepared.headers,
      'idempotency-key': nativeIdempotencyKey,
    },
    nativeIdempotencyKey,
    nativeIdempotencyKeyHash: `sha256:${sha256(nativeIdempotencyKey)}`,
    providerAccountHash: `sha256:${sha256(account)}`,
    retryDeadline: new Date(input.firstDispatchAt.getTime() + STRIPE_RETRY_WINDOW_MS),
  };
}

export function stripeRetryPermitted(input: {
  transportAttempts: number;
  retryDeadline: Date;
  now: Date;
  deliveryState: string;
  reconciliationState: string;
  liveAuthorizationPassed: boolean;
}): boolean {
  return ['outcome_unknown', 'response_received'].includes(input.deliveryState)
    && ['pending', 'not_found', 'confirmed'].includes(input.reconciliationState)
    && input.liveAuthorizationPassed
    && input.transportAttempts < STRIPE_MAX_TRANSPORT_ATTEMPTS
    && input.now.getTime() < input.retryDeadline.getTime();
}
