import type { WorkerRuntime } from '../runtime.js';

/** Retry email-change completion notices, at most every five minutes per worker. */
export async function runEmailChangeRetry(deps: Pick<WorkerRuntime, 'gates'>): Promise<void> {
  const emailDeliveryResult = await deps.gates.emailChangeRetry();
  if (emailDeliveryResult.claimed > 0) {
    console.log(
      `[EMAIL-CHANGE] ${emailDeliveryResult.completed} completion notices sent, ` +
        `${emailDeliveryResult.pending} pending retry.`,
    );
  }
}
