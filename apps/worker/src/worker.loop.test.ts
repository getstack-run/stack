import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startGuardedInterval } from './worker.js';

describe('startGuardedInterval', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('never runs two ticks concurrently when a tick outlasts the interval', async () => {
    let running = 0;
    let maxRunning = 0;
    let started = 0;
    const task = async () => {
      started += 1;
      running += 1;
      maxRunning = Math.max(maxRunning, running);
      await new Promise((resolve) => setTimeout(resolve, 2_500));
      running -= 1;
    };
    const stop = startGuardedInterval(task, 1_000);

    await vi.advanceTimersByTimeAsync(2_000);
    expect(started).toBe(1);

    await vi.advanceTimersByTimeAsync(1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(maxRunning).toBe(1);
    expect(started).toBeGreaterThanOrEqual(2);
    stop();
  });

  it('keeps ticking after a task rejects', async () => {
    const task = vi.fn(async () => {
      throw new Error('boom');
    });
    const stop = startGuardedInterval(task, 1_000);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(task).toHaveBeenCalledTimes(3);
    stop();
  });

  it('stop prevents further ticks', async () => {
    const task = vi.fn(async () => {});
    const stop = startGuardedInterval(task, 1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(task).toHaveBeenCalledTimes(1);
  });
});
