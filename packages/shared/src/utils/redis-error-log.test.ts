import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';
import { logRedisErrorsThrottled, observeRedisClient, REDIS_ERROR_LOG_WINDOW_MS } from './redis-error-log.js';

function outage(message: string): Error {
  const err = new Error(message) as Error & { code?: string };
  err.code = 'ECONNREFUSED';
  return err;
}

describe('observeRedisClient', () => {
  class FakeRedis extends EventEmitter {
    readonly overrides: Array<Record<string, unknown> | undefined> = [];
    duplicate(override?: Record<string, unknown>): FakeRedis {
      this.overrides.push(override);
      return new FakeRedis();
    }
  }

  it('gives the client and every duplicate, however deep, the throttled listener', () => {
    const lines: unknown[][] = [];
    const root = observeRedisClient(new FakeRedis(), { now: () => 0, warn: (...args) => lines.push(args) });
    const subscriber = root.duplicate();
    const nested = subscriber.duplicate();
    for (const client of [root, subscriber, nested]) {
      expect(client.listenerCount('error')).toBe(1);
      client.emit('error', outage('connect ECONNREFUSED redis://default:secret-canary@10.0.0.4:6379'));
    }
    // One line per client, each from its own window, none with the address or the credential.
    expect(lines).toHaveLength(3);
    expect(JSON.stringify(lines)).not.toContain('secret-canary');
    expect(JSON.stringify(lines)).not.toContain('10.0.0.4');
  });

  it('builds a duplicate without the request path\'s command timeout, and lets a caller override anything else', () => {
    const root = observeRedisClient(new FakeRedis());
    root.duplicate({ lazyConnect: true });
    expect(root.overrides[0]).toEqual({ commandTimeout: undefined, lazyConnect: true });
  });
});

describe('logRedisErrorsThrottled', () => {
  it('logs the first error, then once per window while the outage lasts', () => {
    const client = new EventEmitter();
    const lines: unknown[][] = [];
    let clock = 1_000_000;
    logRedisErrorsThrottled(client, { now: () => clock, warn: (...args) => lines.push(args) });

    for (let i = 0; i < 10; i += 1) {
      client.emit('error', outage('connect ECONNREFUSED'));
      clock += 3_000; // ten reconnect failures over thirty seconds
    }
    expect(lines).toHaveLength(1);

    clock += REDIS_ERROR_LOG_WINDOW_MS;
    client.emit('error', outage('connect ECONNREFUSED'));
    expect(lines).toHaveLength(2);
  });

  it('never writes a connection string, a credential or the driver text', () => {
    const client = new EventEmitter();
    const lines: unknown[][] = [];
    logRedisErrorsThrottled(client, { now: () => 0, warn: (...args) => lines.push(args) });

    client.emit('error', outage('connect ECONNREFUSED redis://default:secret-canary@10.0.0.4:6379'));

    const written = JSON.stringify(lines);
    expect(written).not.toContain('secret-canary');
    expect(written).not.toContain('redis://');
    expect(written).not.toContain('10.0.0.4');
    expect(written).toContain('ECONNREFUSED');
  });

  it('keeps an error listener on the client, so the library prints nothing of its own', () => {
    const client = new EventEmitter();
    logRedisErrorsThrottled(client, { warn: () => {} });
    expect(client.listenerCount('error')).toBe(1);
  });
});
