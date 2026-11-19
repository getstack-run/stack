import { describe, expect, it } from 'vitest';
import {
  bindStripeRefundCorrelation,
  prepareProxyProviderAdapter,
  stripeRetryPermitted,
} from './proxy-provider-adapter.js';
import { prepareProxyRequest } from './prepared-proxy-request.js';

const binding = {
  operatorId: 'op_1',
  agentId: 'agt_1',
  passportJti: 'jti_1',
  authorityUseId: null,
  approvalId: null,
  connectionId: 'svcconn_1',
  credentialVersion: 1,
  destinationConfigHash: `sha256:${'a'.repeat(64)}` as const,
};

function prepared(overrides: Record<string, unknown> = {}) {
  const request = {
    service: 'stripe',
    url: 'https://api.stripe.com/v1/refunds',
    method: 'POST' as const,
    headers: { 'Idempotency-Key': 'caller-controlled', 'Stripe-Account': 'acct_1' },
    body: { charge: 'ch_1', amount: 100 },
    ...overrides,
  };
  return prepareProxyRequest(request, request.url, binding);
}

describe('prepareProxyProviderAdapter', () => {
  it('adds a stable reserved correlation marker to Stripe refund form data', () => {
    const request = bindStripeRefundCorrelation({
      request: {
        service: 'stripe',
        method: 'POST',
        url: 'https://api.stripe.com/v1/refunds',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'payment_intent=pi_123',
      },
      resolvedUrl: 'https://api.stripe.com/v1/refunds',
      operationKey: 'abcdefghijklmnopqrstuv',
    });
    const form = new URLSearchParams(request.body as string);
    expect(form.get('payment_intent')).toBe('pi_123');
    expect(form.get('metadata[stack_operation]')).toMatch(/^stack_[0-9a-f]{64}$/);
  });

  it('rejects caller control of reserved Stripe correlation metadata', () => {
    expect(() => bindStripeRefundCorrelation({
      request: {
        service: 'stripe',
        method: 'POST',
        url: 'https://api.stripe.com/v1/refunds',
        body: { metadata: { stack_operation: 'caller-value' } },
      },
      resolvedUrl: 'https://api.stripe.com/v1/refunds',
      operationKey: 'abcdefghijklmnopqrstuv',
    })).toThrow(/reserved Stripe metadata/);
  });

  it('serializes object refund data to Stripe form bytes before dispatch', () => {
    const request = bindStripeRefundCorrelation({
      request: {
        service: 'stripe',
        method: 'POST',
        url: 'https://api.stripe.com/v1/refunds',
        body: { payment_intent: 'pi_123', amount: 100, metadata: { reason: 'duplicate' } },
      },
      resolvedUrl: 'https://api.stripe.com/v1/refunds',
      operationKey: 'abcdefghijklmnopqrstuv',
    });
    expect(request.headers?.['content-type']).toBe('application/x-www-form-urlencoded');
    const form = new URLSearchParams(request.body as string);
    expect(form.get('payment_intent')).toBe('pi_123');
    expect(form.get('amount')).toBe('100');
    expect(form.get('metadata[reason]')).toBe('duplicate');
  });

  it('replaces the caller Stripe key with a stable STACK-derived key', () => {
    const first = prepareProxyProviderAdapter({
      prepared: prepared(),
      operationKey: 'operation_abcdefghijklmnopqrstuv',
      operatorId: 'op_1',
      connectionId: 'svcconn_1',
      firstDispatchAt: new Date('2026-09-10T00:00:00Z'),
    });
    const second = prepareProxyProviderAdapter({
      prepared: prepared(),
      operationKey: 'operation_abcdefghijklmnopqrstuv',
      operatorId: 'op_1',
      connectionId: 'svcconn_1',
      firstDispatchAt: new Date('2026-09-10T00:00:00Z'),
    });
    expect(first.kind).toBe('stripe');
    expect(first.headers['idempotency-key']).toBe(first.nativeIdempotencyKey);
    expect(first.nativeIdempotencyKey).not.toContain('caller-controlled');
    expect(first.nativeIdempotencyKey).toBe(second.nativeIdempotencyKey);
    expect(first.retryDeadline?.toISOString()).toBe('2026-09-10T23:00:00.000Z');
  });

  it('binds Stripe account, operation, endpoint and body through the request hash', () => {
    const base = {
      operationKey: 'operation_abcdefghijklmnopqrstuv',
      operatorId: 'op_1',
      connectionId: 'svcconn_1',
      firstDispatchAt: new Date('2026-09-10T00:00:00Z'),
    };
    const key = prepareProxyProviderAdapter({ prepared: prepared(), ...base }).nativeIdempotencyKey;
    expect(prepareProxyProviderAdapter({ prepared: prepared({ headers: { 'Stripe-Account': 'acct_2' } }), ...base }).nativeIdempotencyKey)
      .not.toBe(key);
    expect(prepareProxyProviderAdapter({ prepared: prepared({ body: { charge: 'ch_1', amount: 101 } }), ...base }).nativeIdempotencyKey)
      .not.toBe(key);
    expect(prepareProxyProviderAdapter({ prepared: prepared(), ...base, operationKey: 'operation_bcdefghijklmnopqrstuvw' }).nativeIdempotencyKey)
      .not.toBe(key);
  });

  it('keeps unverified Stripe endpoints on the generic one-attempt path', () => {
    const result = prepareProxyProviderAdapter({
      prepared: prepared({ url: 'https://api.stripe.com/v1/customers' }),
      operationKey: 'operation_abcdefghijklmnopqrstuv',
      operatorId: 'op_1',
      connectionId: 'svcconn_1',
      firstDispatchAt: new Date(),
    });
    expect(result.kind).toBe('generic');
    expect(result.nativeIdempotencyKey).toBeNull();
  });
});

describe('stripeRetryPermitted', () => {
  const base = {
    transportAttempts: 1,
    retryDeadline: new Date('2026-09-10T23:00:00Z'),
    now: new Date('2026-09-10T01:00:00Z'),
    deliveryState: 'outcome_unknown',
    reconciliationState: 'pending',
    liveAuthorizationPassed: true,
  };

  it('allows unresolved or reconciled-response retry only with live authorization and remaining budgets', () => {
    expect(stripeRetryPermitted(base)).toBe(true);
    expect(stripeRetryPermitted({ ...base, deliveryState: 'response_received' })).toBe(true);
    expect(stripeRetryPermitted({ ...base, deliveryState: 'admitted' })).toBe(false);
    expect(stripeRetryPermitted({ ...base, reconciliationState: 'contradictory' })).toBe(false);
    expect(stripeRetryPermitted({ ...base, reconciliationState: 'expired' })).toBe(false);
    expect(stripeRetryPermitted({ ...base, liveAuthorizationPassed: false })).toBe(false);
    expect(stripeRetryPermitted({ ...base, transportAttempts: 3 })).toBe(false);
    expect(stripeRetryPermitted({ ...base, now: base.retryDeadline })).toBe(false);
  });
});
