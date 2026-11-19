import { describe, expect, it, vi } from 'vitest';
import { scoreScopeDrift } from './scope-drift.js';

/**
 * Scope drift batches its Redis work into two pipelined round trips.
 * The scoring, the fire-once guard, the TTLs and the enforced-mode revoke
 * must behave exactly as the sequential version did.
 */

class FakeRedis {
  strings = new Map<string, string>();
  sets = new Map<string, Set<string>>();
  ttls = new Map<string, number>();
  roundTrips = 0;

  private ops() {
    return {
      get: (key: string) => this.strings.get(key) ?? null,
      sadd: (key: string, member: string) => {
        const set = this.sets.get(key) ?? new Set<string>();
        this.sets.set(key, set);
        if (set.has(member)) return 0;
        set.add(member);
        return 1;
      },
      expire: (key: string, seconds: number) => { this.ttls.set(key, seconds); return 1; },
      incrby: (key: string, by: number) => {
        const next = Number(this.strings.get(key) ?? 0) + by;
        this.strings.set(key, String(next));
        return next;
      },
      set: (key: string, value: string) => { this.strings.set(key, value); return 'OK'; },
    };
  }

  pipeline() {
    const queued: Array<() => unknown> = [];
    const ops = this.ops();
    const chain: Record<string, unknown> = {};
    for (const name of Object.keys(ops) as Array<keyof typeof ops>) {
      chain[name] = (...args: unknown[]) => { queued.push(() => (ops[name] as (...a: unknown[]) => unknown)(...args)); return chain; };
    }
    chain['exec'] = async () => { this.roundTrips += 1; return queued.map((run) => [null, run()]); };
    return chain;
  }

  async get(key: string) { this.roundTrips += 1; return this.ops().get(key); }
  async expire(key: string, seconds: number) { this.roundTrips += 1; return this.ops().expire(key, seconds); }
  async set(key: string, value: string) { this.roundTrips += 1; return this.ops().set(key, value); }
}

const input = (overrides: Partial<Parameters<typeof scoreScopeDrift>[0]> = {}) => ({
  jti: 'pas_1', operatorId: 'op_1', agentId: 'agt_1', service: 'slack',
  intentServices: ['slack'], grantedProviders: ['slack', 'github'], noveltyKey: 'slack:/a',
  accountabilityMode: 'standard', ...overrides,
});

describe('scoreScopeDrift', () => {
  it('scores a first-seen path in two round trips and sets both TTLs', async () => {
    const redis = new FakeRedis();
    const record = vi.fn(async () => {});
    await scoreScopeDrift(input(), { redis: redis as never, securityEvent: { record } as never });
    expect(redis.roundTrips).toBe(2);
    expect(redis.strings.get('scope_drift:pas_1')).toBe('50');
    expect(redis.ttls.get('scope_drift_seen:pas_1')).toBe(7200);
    expect(redis.ttls.get('scope_drift:pas_1')).toBe(7200);
    expect(record).not.toHaveBeenCalled();
  });

  it('a repeat call on a declared service is one round trip and scores nothing', async () => {
    const redis = new FakeRedis();
    const deps = { redis: redis as never, securityEvent: { record: vi.fn(async () => {}) } as never };
    await scoreScopeDrift(input(), deps);
    redis.roundTrips = 0;
    await scoreScopeDrift(input(), deps);
    expect(redis.roundTrips).toBe(1);
    expect(redis.strings.get('scope_drift:pas_1')).toBe('50');
  });

  it('fires once on novelty of an undeclared granted service, and revokes in enforced mode', async () => {
    const redis = new FakeRedis();
    const record = vi.fn(async () => {});
    const revoke = vi.fn(async () => ({}));
    const deps = { redis: redis as never, securityEvent: { record } as never, passport: { revoke } as never };
    await scoreScopeDrift(input({ service: 'github', noveltyKey: 'github:/x', accountabilityMode: 'enforced' }), deps);
    expect(record).toHaveBeenCalledTimes(1);
    expect(record).toHaveBeenCalledWith(expect.objectContaining({ signalType: 'scope_drift', severity: 'warning' }));
    expect(revoke).toHaveBeenCalledWith({
      jti: 'pas_1',
      operatorId: 'op_1',
      reason: expect.stringContaining('scope_drift_fire'),
    });
    // Fired: later calls never score or fire again.
    await scoreScopeDrift(input({ service: 'github', noveltyKey: 'github:/y', accountabilityMode: 'enforced' }), deps);
    expect(record).toHaveBeenCalledTimes(1);
    expect(redis.strings.get('scope_drift:pas_1')).toBe('80');
  });

  it('fires on cumulative drift across calls', async () => {
    const redis = new FakeRedis();
    const record = vi.fn(async () => {});
    const deps = { redis: redis as never, securityEvent: { record } as never };
    for (const path of ['/a', '/b', '/c', '/d']) await scoreScopeDrift(input({ noveltyKey: `slack:${path}` }), deps);
    expect(record).toHaveBeenCalledTimes(1);
    expect(record).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Cumulative drift 2.00') }));
  });

  it('surfaces a Redis error exactly as the sequential calls did', async () => {
    const redis = new FakeRedis();
    redis.pipeline = () => ({ get() { return this; }, sadd() { return this; }, exec: async () => [[new Error('redis down'), null], [null, 1]] }) as never;
    await expect(scoreScopeDrift(input(), { redis: redis as never, securityEvent: { record: vi.fn() } as never })).rejects.toThrow('redis down');
  });
});
