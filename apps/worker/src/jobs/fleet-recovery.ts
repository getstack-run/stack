import type { WorkerRuntime } from '../runtime.js';

/** Release expired fleet reservations and reconcile proxy outcomes recorded against fleets. */
export async function recoverFleets(deps: Pick<WorkerRuntime, 'fleetRepo'>): Promise<void> {
  await deps.fleetRepo.recoverExpiredReservations();
  await deps.fleetRepo.reconcileProxyOutcomes();
}
