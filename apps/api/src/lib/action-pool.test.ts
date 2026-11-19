import { describe, expect, it } from 'vitest';
import { actionPoolSnapshot } from './action-pool.js';
import type { Services } from '../config/services.js';

function services(account: Record<string, unknown>, pool = { limit: 10_000, used: 120 }) {
  return {
    entitlements: { resolve: async () => account },
    actionMeter: { pool: async () => pool },
  } as unknown as Pick<Services, 'actionMeter' | 'entitlements'>;
}

describe('actionPoolSnapshot', () => {
  const now = new Date('2026-11-13T10:00:00.000Z');

  it('reports the plan the account resolves to and never the legacy tier', async () => {
    const snapshot = await actionPoolSnapshot(services({ plan: 'platform', tier: 'free', pooled: false }), 'op_a', now);
    expect(snapshot).toEqual({
      plan: 'platform',
      limit: 10_000,
      used: 120,
      remaining: 9_880,
      period: '2026-11',
    });
    expect(snapshot).not.toHaveProperty('tier');
  });

  it('reads an uncapped contract plan as no limit, and marks a pooled account', async () => {
    const snapshot = await actionPoolSnapshot(
      services({ plan: 'contract', tier: 'enterprise', pooled: true }, { limit: Infinity, used: 5 }),
      'op_b',
      now,
    );
    expect(snapshot).toMatchObject({ plan: 'contract', limit: null, remaining: null, pooled: true });
  });
});
