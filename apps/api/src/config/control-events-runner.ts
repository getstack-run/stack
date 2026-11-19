// Streams each customer's record to their events address. Every API machine runs
// it; the sockets that are due are leased one machine at a time on the database
// clock, so delivery stays in order and machines never duplicate a batch. Nothing
// here is on an action's path: the outbox is written inside the audit write and
// this only reads it.
//
// Also, once an hour: trims the control decision log (the stored request of an old
// refusal goes after 30 days, the slim row after 90) and sweeps the events outbox
// for every customer, so retention never depends on a socket being delivered (a
// paused or cleared address is never claimed).

import {
  CONTROL_DECISION_REQUEST_RETENTION_DAYS,
  CONTROL_DECISION_ROW_RETENTION_DAYS,
  runPass,
  safeErrorSummary,
  type JobObserver,
} from '@stack/shared';
import type { Services } from './services.js';

const INTERVAL_MS = 2_000;
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;

type RunnerServices = Pick<Services, 'controlEvents' | 'controlSocketRepo'>;

/** The hourly upkeep: the events outbox retention sweep and the decision log trim. */
export async function runControlUpkeep(services: RunnerServices, observe?: JobObserver): Promise<void> {
  await runPass(
    observe,
    'control_events:sweep',
    () => services.controlEvents.sweep(),
    (error) => console.error('[CONTROL_EVENTS] outbox sweep failed', safeErrorSummary(error)),
  );
  await runPass(
    observe,
    'control_events:decision_trim',
    () => services.controlSocketRepo.pruneDecisions(CONTROL_DECISION_REQUEST_RETENTION_DAYS, CONTROL_DECISION_ROW_RETENTION_DAYS),
    (error) => console.error('[CONTROL] decision log trim failed', safeErrorSummary(error)),
  );
}

/** One delivery pass; the runner's tick, and what tests call. */
export async function runControlEventsPass(services: Pick<Services, 'controlEvents'>, observe?: JobObserver): Promise<void> {
  await runPass(
    observe,
    'control_events:deliver',
    async () => {
      const run = await services.controlEvents.deliverDue();
      if (run.deadLettered + run.failing > 0) {
        console.error('[CONTROL_EVENTS] batches dead-lettered and sockets failing:', run.deadLettered, run.failing);
      }
    },
    (error) => console.error('[CONTROL_EVENTS] delivery pass failed', safeErrorSummary(error)),
  );
}

export function startControlEventsRunner(services: RunnerServices, observe?: JobObserver): () => void {
  let running = false;
  let lastPruneAt = Number.NEGATIVE_INFINITY;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    void (async () => {
      await runControlEventsPass(services, observe);
      const now = Date.now();
      if (now - lastPruneAt >= PRUNE_INTERVAL_MS) {
        lastPruneAt = now;
        await runControlUpkeep(services, observe);
      }
    })().finally(() => {
      running = false;
    });
  }, INTERVAL_MS);
  timer.unref();
  return () => clearInterval(timer);
}
