import { afterEach, describe, expect, it, vi } from 'vitest';
import { REDIS_COMMAND_TIMEOUT_MS } from '@stack/shared';
import { startSilentRedis } from '../../test/silent-redis.js';
import { connectRedis, createRedis } from './infra.js';

// These tests open real sockets, so each carries its own timeout instead of the 5 s unit default.
const SOCKET_TEST_TIMEOUT_MS = 20_000;

describe('createRedis during an outage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('logs one safe line for a run of connection failures, never the address or the credential', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    // Nothing listens on port 1: every connect attempt is refused (or dropped, and cut by the short connect timeout).
    const redis = await createRedis('redis://default:secret-canary@127.0.0.1:1', {
      retryStrategy: () => 50,
      connectTimeout: 200,
    });
    try {
      let failures = 0;
      redis.on('error', () => {
        failures += 1;
      });
      await vi.waitFor(() => expect(failures).toBeGreaterThanOrEqual(3), { timeout: 10_000, interval: 50 });

      expect(warn).toHaveBeenCalledTimes(1);
      const written = JSON.stringify([...warn.mock.calls, ...error.mock.calls]);
      expect(written).not.toContain('secret-canary');
      expect(written).not.toContain('redis://');
      expect(written).not.toContain('127.0.0.1');
      // ioredis prints "Unhandled error event" only when nothing listens; the helper's listener means it never does.
      expect(written).not.toContain('Unhandled error event');
    } finally {
      redis.disconnect();
    }
  }, SOCKET_TEST_TIMEOUT_MS);

  it('gives every duplicate (the pub/sub subscribers) its own error listener and no command timeout', async () => {
    const redis = await createRedis('redis://127.0.0.1:1', { lazyConnect: true });
    const subscriber = redis.duplicate();
    const nested = subscriber.duplicate();
    try {
      expect(redis.options.commandTimeout).toBe(REDIS_COMMAND_TIMEOUT_MS);
      for (const client of [subscriber, nested]) {
        expect(client.listenerCount('error')).toBeGreaterThan(0);
        // A subscriber is never cut by the request path's cap: it sends a subscribe and a re-subscribe, nothing that waits.
        expect(client.options.commandTimeout).toBeUndefined();
      }
    } finally {
      for (const client of [redis, subscriber, nested]) client.disconnect();
    }
  });
});

describe('connectRedis, the boot\'s wait before the subscribers open', () => {
  it('ends an attempt on a silent Redis inside the cap and tries again, instead of hanging on the first command', async () => {
    const silent = await startSilentRedis();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const sleeps: number[] = [];
      const started = Date.now();
      // The sleep after the first failed attempt ends the test: reaching it proves the attempt returned.
      const outcome = await connectRedis(silent.url, {
        sleep: async (ms) => {
          sleeps.push(ms);
          throw new Error('stop after the first attempt');
        },
      }).catch((err: unknown) => err);
      expect((outcome as Error).message).toBe('stop after the first attempt');
      expect(sleeps).toEqual([1_000]);
      expect(Date.now() - started).toBeLessThan(REDIS_COMMAND_TIMEOUT_MS + 3_000);
      expect(warn.mock.calls.flat().join(' ')).toContain('not reachable yet and retrying: attempt 1');
    } finally {
      warn.mockRestore();
      error.mockRestore();
      await silent.stop();
    }
  }, SOCKET_TEST_TIMEOUT_MS);

  it('gives up, for a one-shot command, after the attempts it was given, and leaves nothing open', async () => {
    const silent = await startSilentRedis();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const sleeps: number[] = [];
      const outcome = await connectRedis(silent.url, { maxAttempts: 2, sleep: async (ms) => { sleeps.push(ms); } }).catch((err: unknown) => err);
      expect((outcome as Error).message).toContain('not reachable after 2 attempts');
      expect(sleeps).toEqual([1_000]);
    } finally {
      warn.mockRestore();
      error.mockRestore();
      await silent.stop();
    }
  }, SOCKET_TEST_TIMEOUT_MS);

  const liveRedis = process.env['STACK_TEST_REDIS_URL'] ?? process.env['REDIS_URL'];
  it.skipIf(!liveRedis)('returns a client that answers once Redis does', async () => {
    const redis = await connectRedis(liveRedis!);
    try {
      await expect(redis.ping()).resolves.toBe('PONG');
    } finally {
      redis.disconnect();
    }
  }, SOCKET_TEST_TIMEOUT_MS);
});

describe('createRedis against a Redis that accepts the socket and never answers', () => {
  it('fails a command with "Command timed out" inside the cap instead of waiting for ever', async () => {
    const silent = await startSilentRedis();
    const redis = await createRedis(silent.url);
    try {
      const started = Date.now();
      const outcome = await redis.get('revoked:jti_silent').catch((err: unknown) => err);
      expect(outcome).toBeInstanceOf(Error);
      expect((outcome as Error).message).toBe('Command timed out');
      expect(Date.now() - started).toBeLessThan(REDIS_COMMAND_TIMEOUT_MS + 3_000);
    } finally {
      redis.disconnect();
      await silent.stop();
    }
  }, SOCKET_TEST_TIMEOUT_MS);
});
