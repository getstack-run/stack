import { describe, expect, it } from 'vitest';
import { NetworkIntentDeviationInput } from './network.js';

// An install's checkout is graded however many services, tool calls and actions it holds: only the request's own size
// (the route's body limit) bounds it.

describe('what an install sends to be graded for intent deviation', () => {
  const call = (i: number) => ({ service: `svc${i}`, method: 'get', target: `https://example.com/${i}` });

  it('takes any number of services, tool calls and actions', () => {
    const parsed = NetworkIntentDeviationInput.parse({
      declared: { summary: 'Reconcile the invoices', services: Array.from({ length: 150 }, (_, i) => `svc${i}`) },
      observed: {
        services_used: Array.from({ length: 450 }, (_, i) => `svc${i}`),
        tool_calls: Array.from({ length: 1_200 }, (_, i) => call(i)),
        actions_count: 25_000_000,
      },
    });
    expect(parsed.declared.services).toHaveLength(150);
    expect(parsed.observed.services_used).toHaveLength(450);
    expect(parsed.observed.tool_calls).toHaveLength(1_200);
    expect(parsed.observed.actions_count).toBe(25_000_000);
  });

  it('still wants a summary and whole counts', () => {
    expect(NetworkIntentDeviationInput.safeParse({ declared: { summary: '', services: [] }, observed: { services_used: [], tool_calls: [], actions_count: 0 } }).success).toBe(false);
    expect(NetworkIntentDeviationInput.safeParse({ declared: { summary: 'x', services: [] }, observed: { services_used: [], tool_calls: [], actions_count: -1 } }).success).toBe(false);
    expect(NetworkIntentDeviationInput.safeParse({ declared: { summary: 'x', services: [] }, observed: { services_used: [], tool_calls: [], actions_count: 1.5 } }).success).toBe(false);
  });
});
