import { describe, expect, it, vi } from 'vitest';
import { redisBackoffMs, waitForRedis } from './redis-wait.js';

describe('waitForRedis', () => {
  it('returns at once when Redis answers', async () => {
    const sleep = vi.fn(async () => {});
    await waitForRedis({ ping: async () => 'PONG' }, sleep);
    expect(sleep).not.toHaveBeenCalled();
  });

  it('retries with a doubling wait, logs each failure without the driver text, and returns when Redis answers', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      let calls = 0;
      const ping = async () => {
        calls += 1;
        if (calls <= 3) throw new Error('connect ECONNREFUSED redis://default:secret-canary@10.0.0.4:6379');
        return 'PONG';
      };
      const waits: number[] = [];
      await waitForRedis({ ping }, async (ms) => {
        waits.push(ms);
      });
      expect(waits).toEqual([1_000, 2_000, 4_000]);
      const written = JSON.stringify(warn.mock.calls);
      expect(written).toContain('"attempt",3');
      expect(written).not.toContain('secret-canary');
      expect(written).not.toContain('10.0.0.4');
    } finally {
      warn.mockRestore();
    }
  });

  it('gives up with an error after the attempts a one-shot command allows, without the driver text', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const ping = vi.fn(async () => { throw new Error('connect ECONNREFUSED redis://default:secret-canary@10.0.0.4:6379'); });
      const waits: number[] = [];
      const outcome = await waitForRedis({ ping }, async (ms) => { waits.push(ms); }, 3).catch((error: unknown) => error);
      expect((outcome as Error).message).toContain('not reachable after 3 attempts');
      expect((outcome as Error).message).not.toContain('secret-canary');
      expect(ping).toHaveBeenCalledTimes(3);
      expect(waits).toEqual([1_000, 2_000]);
    } finally {
      warn.mockRestore();
    }
  });

  it('caps the wait at thirty seconds', () => {
    expect(redisBackoffMs(1)).toBe(1_000);
    expect(redisBackoffMs(6)).toBe(30_000);
    expect(redisBackoffMs(40)).toBe(30_000);
  });
});
