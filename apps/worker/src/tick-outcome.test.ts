import { describe, expect, it, vi } from 'vitest';
import { createPoll, type TickOutcome } from './loop.js';

describe('createPoll tells how each tick ended', () => {
  it('says ok after a clean tick, so the heartbeat is written by the work', async () => {
    const outcomes: TickOutcome[] = [];
    const poll = createPoll({ tick: async () => {}, sentryDsn: undefined, onTick: (o) => outcomes.push(o) });
    await poll();
    expect(outcomes).toEqual([{ ok: true }]);
  });

  it('says what failed: Redis, the database, or something else, and never ok', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const outcomes: TickOutcome[] = [];
    const errors = [
      Object.assign(new Error('Command timed out'), {}),
      Object.assign(new Error('connection terminated'), { code: 'ECONNRESET' }),
      new Error('a job broke'),
    ];
    let clock = 0;
    for (const error of errors) {
      const poll = createPoll({
        tick: async () => {
          throw error;
        },
        sentryDsn: undefined,
        now: () => (clock += 1_000_000),
        onTick: (o) => outcomes.push(o),
      });
      await poll();
    }
    expect(outcomes.every((o) => !o.ok)).toBe(true);
    expect(outcomes).toHaveLength(3);
    expect(outcomes.map((o) => (o.ok ? 'ok' : o.kind))).toEqual(['redis', 'database', 'other']);
  });

  it('is not told of a tick skipped by the Redis backoff, and a throwing observer changes nothing', async () => {
    const onTick = vi.fn(() => {
      throw new Error('observer broke');
    });
    const poll = createPoll({ tick: async () => {}, sentryDsn: undefined, onTick });
    await expect(poll()).resolves.toBeUndefined();
    expect(onTick).toHaveBeenCalledTimes(1);
  });
});
