import { describe, expect, it } from 'vitest';
import { reconcileStripeRefund, StripeReconciliationUnavailableError } from './stripe-proxy-reconciliation.js';

const marker = `stack_${'a'.repeat(64)}`;
const base = {
  credential: 'sk_test_synthetic',
  stripeAccount: 'acct_synthetic',
  providerMarker: marker,
  firstDispatchedAt: new Date('2026-09-10T12:00:00Z'),
};

describe('Stripe refund reconciliation', () => {
  it('derives a confirmed result from provider metadata without accepting browser facts', async () => {
    const result = await reconcileStripeRefund({
      ...base,
      fetcher: async (url, init) => {
        expect(String(url)).toContain('created%5Bgte%5D=');
        expect(init?.method).toBe('GET');
        expect(new Headers(init?.headers).get('stripe-account')).toBe('acct_synthetic');
        return Response.json({
          object: 'list', has_more: false,
          data: [{ id: 're_one', status: 'succeeded', created: 1_789_041_600, metadata: { stack_operation: marker } }],
        });
      },
    });
    expect(result).toMatchObject({ state: 'confirmed', providerStatus: 'succeeded', observedCount: 1 });
    expect(result.resourceHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('uses bounded pagination and reports only a provider-observed absence', async () => {
    let calls = 0;
    const result = await reconcileStripeRefund({
      ...base,
      fetcher: async () => {
        calls += 1;
        return Response.json({ object: 'list', has_more: calls === 1, data: [{ id: `re_${calls}`, metadata: {} }] });
      },
    });
    expect(result.state).toBe('not_found');
    expect(calls).toBe(2);
  });

  it('treats duplicate provider markers as contradictory evidence', async () => {
    const result = await reconcileStripeRefund({
      ...base,
      fetcher: async () => Response.json({
        object: 'list', has_more: false,
        data: [
          { id: 're_one', metadata: { stack_operation: marker } },
          { id: 're_two', metadata: { stack_operation: marker } },
        ],
      }),
    });
    expect(result).toMatchObject({ state: 'contradictory', observedCount: 2 });
  });

  it('preserves a found but nonterminal provider status for later reconciliation', async () => {
    const result = await reconcileStripeRefund({
      ...base,
      fetcher: async () => Response.json({
        object: 'list', has_more: false,
        data: [{ id: 're_pending', status: 'pending', metadata: { stack_operation: marker } }],
      }),
    });
    expect(result).toMatchObject({ state: 'confirmed', providerStatus: 'pending', observedCount: 1 });
  });

  it('fails closed on an unpinned account or provider error', async () => {
    await expect(reconcileStripeRefund({ ...base, stripeAccount: 'evil' })).rejects
      .toBeInstanceOf(StripeReconciliationUnavailableError);
    await expect(reconcileStripeRefund({
      ...base,
      fetcher: async () => Response.json({}, { status: 401 }),
    })).rejects.toThrow(/HTTP 401/);
    await expect(reconcileStripeRefund({
      ...base,
      fetcher: async () => Response.json({
        object: 'list', has_more: false,
        data: [{ id: 're_unknown', status: 'mystery', metadata: { stack_operation: marker } }],
      }),
    })).rejects.toThrow(/status is unavailable/);
  });
});
