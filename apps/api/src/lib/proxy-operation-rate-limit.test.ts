import { describe, expect, it } from 'vitest';
import { enforceProxyOperationReadRate } from './proxy-operation-rate-limit.js';

function store(start: number) {
  const seen: string[] = [];
  let count = start;
  const chain = {
    incr(key: string) { seen.push(key); count += 1; return chain; },
    expire() { return chain; },
    async exec() { return [[null, count], [null, 1]] as Array<[Error | null, unknown]>; },
  };
  return { redis: { multi: () => chain }, seen };
}

describe('enforceProxyOperationReadRate', () => {
  it('uses stable principal identity rather than transport-token identity', async () => {
    const fake = store(0);
    const base = {
      redis: fake.redis,
      operatorId: 'op_1',
      principalId: 'agt_1',
      includeResponse: false,
      now: new Date('2026-09-10T12:00:01Z'),
    };
    await enforceProxyOperationReadRate(base);
    await enforceProxyOperationReadRate(base);
    expect(fake.seen[0]).toBe(fake.seen[1]);
    expect(fake.seen[0]).not.toContain('op_1');
    expect(fake.seen[0]).not.toContain('agt_1');
  });

  it('enforces 60 status reads and 10 replay reads per minute', async () => {
    await expect(enforceProxyOperationReadRate({
      redis: store(60).redis,
      operatorId: 'op_1',
      principalId: 'agt_1',
      includeResponse: false,
    })).rejects.toMatchObject({ code: 'RATE_LIMITED', statusCode: 429 });
    await expect(enforceProxyOperationReadRate({
      redis: store(10).redis,
      operatorId: 'op_1',
      principalId: 'agt_1',
      includeResponse: true,
    })).rejects.toMatchObject({ code: 'RATE_LIMITED', statusCode: 429 });
  });

  it('fails closed with a typed service error when Redis is unavailable', async () => {
    const chain = {
      incr() { return chain; },
      expire() { return chain; },
      async exec() { throw new Error('redis offline'); },
    };
    await expect(enforceProxyOperationReadRate({
      redis: { multi: () => chain },
      operatorId: 'op_1',
      principalId: 'agt_1',
      includeResponse: false,
    })).rejects.toMatchObject({ code: 'SERVICE_UNAVAILABLE', statusCode: 503 });
  });
});
