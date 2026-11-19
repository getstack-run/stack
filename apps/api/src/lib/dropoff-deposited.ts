import { safeErrorSummary } from '@stack/shared';
import type { EngineRegistries } from '../config/registries.js';

/**
 * Tell the deployment's hooks that a deposit has committed and its work is there to collect. Called after the deposit's
 * transaction, once per deposit. A hook that throws is logged and never fails or undoes the deposit: the work is
 * already handed over. When every hook ran, the drop-off is marked announced; one whose hooks did not (a hook failed,
 * or the process stopped before this point) stays unmarked, and the deployment's sweep runs them again, so the
 * deposit is never left without its hooks.
 */
export async function announceDeposit(
  services: { registries: Pick<EngineRegistries, 'dropoffDeposited'>; dropoff: { markDepositAnnounced(dropoffId: string): Promise<void> } },
  event: { operatorId: string; dropoffId: string; fromAgentId: string; toAgentIds: readonly string[] },
  log: { error(data: Record<string, unknown>, message: string): void },
): Promise<void> {
  let allRan = true;
  for (const hook of services.registries.dropoffDeposited.list()) {
    try {
      await hook(event);
    } catch (error) {
      allRan = false;
      log.error({ dropoffId: event.dropoffId, error: safeErrorSummary(error) }, '[dropoff] a deposit hook failed');
    }
  }
  if (!allRan) return;
  try {
    await services.dropoff.markDepositAnnounced(event.dropoffId);
  } catch (error) {
    log.error({ dropoffId: event.dropoffId, error: safeErrorSummary(error) }, '[dropoff] a deposit could not be marked announced');
  }
}
