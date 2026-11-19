import { describe, expect, it, vi } from 'vitest';
import { answerHealth, memoiseHealth, probeHealth } from './health-probe.js';

const healthy = () => Promise.resolve();
const down = (message: string) => () => Promise.reject(new Error(message));
const never = () => new Promise<void>(() => {});

describe('probeHealth', () => {
  it('is ok when the database and Redis both answer', async () => {
    await expect(probeHealth({ database: healthy, redis: healthy })).resolves.toEqual({ ok: true });
  });

  it('reports Redis unreachable on its own', async () => {
    await expect(probeHealth({ database: healthy, redis: down('connect ECONNREFUSED 10.0.0.4:6379') }))
      .resolves.toEqual({ ok: false, reason: 'redis_unreachable', failures: [expect.objectContaining({ dependency: 'redis' })] });
  });

  it('reports the database unreachable on its own', async () => {
    const result = await probeHealth({ database: down('connection terminated'), redis: healthy });
    expect(result).toMatchObject({ ok: false, reason: 'database_unreachable' });
  });

  it('reports both when both fail', async () => {
    const result = await probeHealth({ database: down('db'), redis: down('redis') });
    expect(result).toMatchObject({ ok: false, reason: 'database_and_redis_unreachable' });
  });

  it('treats a probe that does not answer within the cap as down', async () => {
    vi.useFakeTimers();
    try {
      const pending = probeHealth({ database: healthy, redis: never }, 2000);
      await vi.advanceTimersByTimeAsync(2001);
      await expect(pending).resolves.toMatchObject({ ok: false, reason: 'redis_unreachable' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps raw error text out of the public reason', async () => {
    const result = await probeHealth({ database: healthy, redis: down('redis://:secret-canary@10.0.0.4:6379 refused') });
    expect(JSON.stringify({ ok: result.ok, reason: 'reason' in result ? result.reason : undefined })).not.toContain('secret-canary');
  });
});

describe('answerHealth', () => {
  it('answers 200 ok while the database and Redis answer', async () => {
    const answer = await answerHealth({ database: healthy, redis: healthy });
    expect(answer.statusCode).toBe(200);
    expect(answer.body.status).toBe('ok');
    expect(answer.failures).toEqual([]);
  });

  it('answers 503 degraded naming Redis when Redis is down, the case that used to read ok', async () => {
    const answer = await answerHealth({ database: healthy, redis: down('redis://:secret-canary@10.0.0.4:6379 refused') });
    expect(answer.statusCode).toBe(503);
    expect(answer.body).toMatchObject({ status: 'degraded', reason: 'redis_unreachable' });
    // The body is all a caller reads; the driver's text stays in `failures` for the log.
    expect(JSON.stringify(answer.body)).not.toContain('secret-canary');
    expect(JSON.stringify(answer.body)).not.toContain('10.0.0.4');
    expect(answer.failures).toHaveLength(1);
  });

  it('answers 503 degraded naming the database when only the database is down', async () => {
    const answer = await answerHealth({ database: down('connection terminated'), redis: healthy });
    expect(answer.statusCode).toBe(503);
    expect(answer.body).toMatchObject({ status: 'degraded', reason: 'database_unreachable' });
  });
});

describe('memoiseHealth', () => {
  function counted(redis: () => Promise<unknown> = healthy) {
    const database = vi.fn(healthy);
    const ping = vi.fn(redis);
    return { database, ping, probes: { database, redis: ping } };
  }

  it('costs one probe for a flood of pings inside the window, and probes again after it', async () => {
    const { database, ping, probes } = counted();
    let clock = 0;
    const health = memoiseHealth(probes, { ttlMs: 1_000, now: () => clock });

    await Promise.all(Array.from({ length: 200 }, () => health()));
    clock = 999;
    await health();
    expect(database).toHaveBeenCalledTimes(1);
    expect(ping).toHaveBeenCalledTimes(1);

    clock = 1_000;
    await health();
    expect(database).toHaveBeenCalledTimes(2);
    expect(ping).toHaveBeenCalledTimes(2);
  });

  it('shares the probe in flight, so callers that arrive while it runs do not start another', async () => {
    let release: () => void = () => {};
    const slow = () => new Promise<void>((resolve) => { release = resolve; });
    const { database, probes } = counted(slow);
    const health = memoiseHealth(probes, { now: () => 0 });

    const first = health();
    const second = health();
    release();
    const [a, b] = await Promise.all([first, second]);
    expect(a).toBe(b);
    expect(database).toHaveBeenCalledTimes(1);
  });

  it('reuses a failure too, and reports it once per probe rather than once per request', async () => {
    const { ping, probes } = counted(down('redis refused'));
    const onDegraded = vi.fn();
    const health = memoiseHealth(probes, { now: () => 0, onDegraded });

    const answers = await Promise.all(Array.from({ length: 50 }, () => health()));
    expect(answers.every((answer) => answer.statusCode === 503 && answer.body.reason === 'redis_unreachable')).toBe(true);
    expect(ping).toHaveBeenCalledTimes(1);
    expect(onDegraded).toHaveBeenCalledTimes(1);
  });

  it('answers 200 again once the dependency is back and the window has passed', async () => {
    let up = false;
    const { probes } = counted(() => (up ? Promise.resolve() : Promise.reject(new Error('down'))));
    let clock = 0;
    const health = memoiseHealth(probes, { ttlMs: 1_000, now: () => clock });

    expect((await health()).statusCode).toBe(503);
    up = true;
    clock = 500;
    expect((await health()).statusCode).toBe(503);
    clock = 1_500;
    expect((await health()).statusCode).toBe(200);
  });

  it('tells the deployment each probe once, whatever it found, and a throwing observer changes nothing', async () => {
    const { probes } = counted(healthy);
    const seen: number[] = [];
    const health = memoiseHealth(probes, { now: () => 0, onProbe: (answer) => { seen.push(answer.statusCode); throw new Error('observer broke'); } });
    const answers = await Promise.all(Array.from({ length: 5 }, () => health()));
    expect(answers.every((answer) => answer.statusCode === 200)).toBe(true);
    expect(seen).toEqual([200]);
  });
});
