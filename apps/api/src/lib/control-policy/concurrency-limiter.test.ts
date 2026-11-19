import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ConcurrencyLimiter } from './concurrency-limiter.js';

// Runs against a real Redis when REDIS_URL is set. Every key carries a random
// operator id, so it can never touch a real counter, and only those keys are
// deleted afterwards.
const describeWithRedis = process.env['REDIS_URL'] ? describe : describe.skip;

describeWithRedis('ConcurrencyLimiter against Redis', () => {
  let redis: import('ioredis').Redis;
  let limiter: ConcurrencyLimiter;
  const operatorId = `op_conc_${randomBytes(6).toString('hex')}`;
  const keys = new Set<string>();

  function scope(agent: string) {
    const agentId = `agt_${agent}`;
    keys.add(`stack:control:concurrency:${operatorId}:${agentId}`);
    return { operatorId, agentId };
  }

  beforeAll(async () => {
    const { Redis } = await import('ioredis');
    redis = new Redis(process.env['REDIS_URL']!);
    limiter = new ConcurrencyLimiter(redis);
  });

  afterAll(async () => {
    if (keys.size > 0) await redis.del(...keys);
    await redis.quit();
  });

  it('admits exactly the limit out of 50 parallel acquires', async () => {
    const s = scope('parallel');
    const leases = await Promise.all(Array.from({ length: 50 }, () => limiter.acquire({ ...s, limit: 10 })));
    const admitted = leases.filter((lease) => lease !== null);
    expect(admitted).toHaveLength(10);
    expect(new Set(admitted.map((lease) => lease!.leaseId)).size).toBe(10);
    expect(await limiter.live(s)).toBe(10);
  });

  it('frees a slot when a lease is released', async () => {
    const s = scope('release');
    const first = await limiter.acquire({ ...s, limit: 2 });
    const second = await limiter.acquire({ ...s, limit: 2 });
    expect(first && second).toBeTruthy();
    expect(await limiter.acquire({ ...s, limit: 2 })).toBeNull();
    await limiter.release({ ...s, leaseId: first!.leaseId });
    expect(await limiter.live(s)).toBe(1);
    expect(await limiter.acquire({ ...s, limit: 2 })).not.toBeNull();
    expect(await limiter.acquire({ ...s, limit: 2 })).toBeNull();
  });

  it('lets a lease run out on its own, as after a crash', async () => {
    const s = scope('expiry');
    expect(await limiter.acquire({ ...s, limit: 1, leaseSeconds: 1 })).not.toBeNull();
    expect(await limiter.acquire({ ...s, limit: 1, leaseSeconds: 1 })).toBeNull();
    await new Promise((resolve) => setTimeout(resolve, 1_200));
    expect(await limiter.live(s)).toBe(0);
    expect(await limiter.acquire({ ...s, limit: 1, leaseSeconds: 1 })).not.toBeNull();
  });

  it('keeps the key alive for a long lease when a short one is taken after it', async () => {
    const s = scope('mixed');
    expect(await limiter.acquire({ ...s, limit: 5, leaseSeconds: 300 })).not.toBeNull();
    expect(await limiter.acquire({ ...s, limit: 5, leaseSeconds: 1 })).not.toBeNull();
    const ttl = await redis.pttl(`stack:control:concurrency:${operatorId}:${s.agentId}`);
    expect(ttl).toBeGreaterThan(300_000);
  });

  it('treats releasing an unknown lease as a no-op', async () => {
    const s = scope('unknown');
    const lease = await limiter.acquire({ ...s, limit: 1 });
    await limiter.release({ ...s, leaseId: 'not-a-lease' });
    await limiter.release({ ...scope('never-used'), leaseId: lease!.leaseId });
    expect(await limiter.live(s)).toBe(1);
    await limiter.release({ ...s, leaseId: lease!.leaseId });
    await limiter.release({ ...s, leaseId: lease!.leaseId });
    expect(await limiter.live(s)).toBe(0);
  });

  it('keeps two agents apart', async () => {
    const a = scope('apart_a');
    const b = scope('apart_b');
    expect(await limiter.acquire({ ...a, limit: 1 })).not.toBeNull();
    expect(await limiter.acquire({ ...a, limit: 1 })).toBeNull();
    expect(await limiter.acquire({ ...b, limit: 1 })).not.toBeNull();
    expect(await limiter.live(a)).toBe(1);
    expect(await limiter.live(b)).toBe(1);
  });

  it('keeps one agent id of two customers apart', async () => {
    const other = `${operatorId}_other`;
    const agentId = 'agt_shared_id';
    keys.add(`stack:control:concurrency:${operatorId}:${agentId}`);
    keys.add(`stack:control:concurrency:${other}:${agentId}`);
    expect(await limiter.acquire({ operatorId, agentId, limit: 1 })).not.toBeNull();
    expect(await limiter.acquire({ operatorId: other, agentId, limit: 1 })).not.toBeNull();
  });

  it('follows a caller clock when one is given', async () => {
    let at = 1_000_000;
    const clocked = new ConcurrencyLimiter(redis, { now: () => at });
    const s = scope('clocked');
    expect(await clocked.acquire({ ...s, limit: 1, leaseSeconds: 10 })).not.toBeNull();
    at += 9_999;
    expect(await clocked.acquire({ ...s, limit: 1, leaseSeconds: 10 })).toBeNull();
    at += 2;
    expect(await clocked.live(s)).toBe(0);
    expect(await clocked.acquire({ ...s, limit: 1, leaseSeconds: 10 })).not.toBeNull();
  });

  it('refuses a limit or a lease that is not a positive whole number', async () => {
    const s = scope('invalid');
    await expect(limiter.acquire({ ...s, limit: 0 })).rejects.toThrow(/positive whole number/);
    await expect(limiter.acquire({ ...s, limit: 1.5 })).rejects.toThrow(/positive whole number/);
    await expect(limiter.acquire({ ...s, limit: 1, leaseSeconds: 0 })).rejects.toThrow(/whole number of seconds/);
  });
});
