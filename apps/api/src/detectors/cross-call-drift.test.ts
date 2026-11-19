import { describe, expect, it } from 'vitest';
import { scoreCrossCallDrift, shannonEntropy, __test__ } from './cross-call-drift.js';

/** In-memory Redis stub covering only the methods the detector uses. */
function makeRedisStub() {
  const store = new Map<string, string>();
  return {
    store,
    async get(key: string) { return store.get(key) ?? null; },
    async set(key: string, value: string) { store.set(key, value); return 'OK'; },
  } as const;
}

interface RecordedEvent {
  signalType: string;
  severity: string;
  message: string;
  metadata: Record<string, unknown>;
}

function makeSecurityEventStub() {
  const events: RecordedEvent[] = [];
  return {
    events,
    async record(input: { signalType: string; severity: string; message: string; metadata: Record<string, unknown> }) {
      events.push({
        signalType: input.signalType,
        severity: input.severity,
        message: input.message,
        metadata: input.metadata,
      });
    },
  };
}

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for single repeated char', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });

  it('is bounded above by log2(byte alphabet)', () => {
    const s = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const h = shannonEntropy(s);
    expect(h).toBeGreaterThan(5);
    expect(h).toBeLessThan(8);
  });

  it('higher entropy for random base64 than for repeated text', () => {
    const text = 'hello hello hello hello hello hello hello hello';
    const random = 'aZx7Yg9Lp3Qk2Md4Vc8WnFpRjEhXTuUyAa==';
    expect(shannonEntropy(random)).toBeGreaterThan(shannonEntropy(text));
  });
});

describe('meanStddev', () => {
  it('returns 0/0 for n<2', () => {
    expect(__test__.meanStddev(0, 0, 0)).toEqual({ mean: 0, stddev: 0 });
    expect(__test__.meanStddev(5, 25, 1)).toEqual({ mean: 5, stddev: 0 });
  });

  it('matches sample stddev formula', () => {
    // Values: 2, 4, 4, 4, 5, 5, 7, 9. n=8, mean=5, sample stddev=2
    const sum = 2 + 4 + 4 + 4 + 5 + 5 + 7 + 9;
    const sumsq = 4 + 16 + 16 + 16 + 25 + 25 + 49 + 81;
    const { mean, stddev } = __test__.meanStddev(sum, sumsq, 8);
    expect(mean).toBeCloseTo(5, 5);
    expect(stddev).toBeCloseTo(2.138, 2);
  });
});

describe('scoreCrossCallDrift', () => {
  const baseInput = {
    jti: 'pst_test_jti',
    operatorId: 'op_test',
    agentId: 'ag_test',
  };

  it('does nothing when body is null', async () => {
    const redis = makeRedisStub();
    const sec = makeSecurityEventStub();
    await scoreCrossCallDrift({ ...baseInput, body: null }, { redis: redis as never, securityEvent: sec as never });
    expect(redis.store.size).toBe(0);
    expect(sec.events.length).toBe(0);
  });

  it('records first observation without firing (cold start)', async () => {
    const redis = makeRedisStub();
    const sec = makeSecurityEventStub();
    await scoreCrossCallDrift({ ...baseInput, body: 'Hello world' }, { redis: redis as never, securityEvent: sec as never });
    expect(redis.store.size).toBe(1);
    expect(sec.events.length).toBe(0);
    const state = JSON.parse(redis.store.get('behavior_drift:pst_test_jti')!);
    expect(state.n).toBe(1);
    expect(state.sum_l).toBe(11);
  });

  it('does not fire while in cold-start window even on outliers', async () => {
    const redis = makeRedisStub();
    const sec = makeSecurityEventStub();
    // Three small bodies + one huge one, all inside the cold-start window
    for (let i = 0; i < 3; i++) {
      await scoreCrossCallDrift({ ...baseInput, body: 'tiny' }, { redis: redis as never, securityEvent: sec as never });
    }
    await scoreCrossCallDrift(
      { ...baseInput, body: 'X'.repeat(100_000) },
      { redis: redis as never, securityEvent: sec as never },
    );
    expect(sec.events.length).toBe(0);
  });

  it('fires on a length outlier after cold-start has passed', async () => {
    const redis = makeRedisStub();
    const sec = makeSecurityEventStub();
    // Build COLD_START_N + small buffer of consistent small calls
    for (let i = 0; i < __test__.COLD_START_N + 2; i++) {
      await scoreCrossCallDrift({ ...baseInput, body: 'small body content here' }, { redis: redis as never, securityEvent: sec as never });
    }
    expect(sec.events.length).toBe(0);
    // Now inject a body that's many σ above baseline length
    await scoreCrossCallDrift(
      { ...baseInput, body: 'X'.repeat(50_000) },
      { redis: redis as never, securityEvent: sec as never },
    );
    expect(sec.events.length).toBe(1);
    expect(sec.events[0]!.signalType).toBe('behavior_drift');
    expect(sec.events[0]!.severity).toBe('warning');
    expect(sec.events[0]!.metadata.dimension).toBe('length');
    expect(sec.events[0]!.metadata.z_score as number).toBeGreaterThanOrEqual(__test__.Z_THRESHOLD);
  });

  it('updates baseline even on a fire so later traffic is graded against the new mean', async () => {
    const redis = makeRedisStub();
    const sec = makeSecurityEventStub();
    for (let i = 0; i < __test__.COLD_START_N + 2; i++) {
      await scoreCrossCallDrift({ ...baseInput, body: 'small body' }, { redis: redis as never, securityEvent: sec as never });
    }
    const before = JSON.parse(redis.store.get('behavior_drift:pst_test_jti')!);
    await scoreCrossCallDrift(
      { ...baseInput, body: 'Y'.repeat(80_000) },
      { redis: redis as never, securityEvent: sec as never },
    );
    const after = JSON.parse(redis.store.get('behavior_drift:pst_test_jti')!);
    expect(after.n).toBe(before.n + 1);
    expect(after.sum_l).toBeGreaterThan(before.sum_l);
  });

  it('serializes object bodies before scoring so JSON shape contributes to length/entropy', async () => {
    const redis = makeRedisStub();
    const sec = makeSecurityEventStub();
    await scoreCrossCallDrift(
      { ...baseInput, body: { a: 1, b: 'hello' } },
      { redis: redis as never, securityEvent: sec as never },
    );
    const state = JSON.parse(redis.store.get('behavior_drift:pst_test_jti')!);
    expect(state.n).toBe(1);
    expect(state.sum_l).toBeGreaterThan(0);
  });

  it('survives a Redis read failure without throwing', async () => {
    const sec = makeSecurityEventStub();
    const brokenRedis = {
      async get() { throw new Error('redis down'); },
      async set() { throw new Error('redis down'); },
    };
    await expect(
      scoreCrossCallDrift({ ...baseInput, body: 'test' }, { redis: brokenRedis as never, securityEvent: sec as never }),
    ).resolves.toBeUndefined();
    expect(sec.events.length).toBe(0);
  });
});
