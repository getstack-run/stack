import type { TickOutcome } from './loop.js';

/**
 * What the worker does when a tick ends: a clean tick writes the `worker:heartbeat` key (the work writes it, not a timer, so a stuck
 * worker stops looking online) and the deployment is told the outcome (its record of its systems, and the heartbeat to the outside
 * watch). A tick that ran every job to the end is clean whatever individual jobs did; only an unreachable database or Redis, or an
 * error the tick itself could not handle, is not.
 */
export function createTickObserver(
  redis: { set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown> },
  ext: { observeTick?: (outcome: TickOutcome) => void } | null,
): (outcome: TickOutcome) => void {
  return (outcome) => {
    if (outcome.ok) void redis.set('worker:heartbeat', new Date().toISOString(), 'EX', 60).catch(() => {});
    ext?.observeTick?.(outcome);
  };
}
