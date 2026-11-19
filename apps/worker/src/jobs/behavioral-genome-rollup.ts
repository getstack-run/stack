import { maybeRunBehavioralGenomeRollup } from '@stack/vault';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Daily behavioral_genome rollup. Once per UTC day this emits a signed
 * behavioral_genome claim per passport with audit activity in the previous
 * calendar day, for the accounts with controls on (every account on an install). Crash-safe via per-passport dedupe in
 * `emitForWindow`; the lock TTL only prevents collisions between worker
 * machines and is not the idempotency mechanism.
 */
export async function runBehavioralGenomeRollup(
  deps: Pick<WorkerRuntime, 'behavioralGenome' | 'db' | 'redis' | 'genomeEligible'>,
): Promise<void> {
  await maybeRunBehavioralGenomeRollup(deps.behavioralGenome, deps.db, deps.redis, { eligible: deps.genomeEligible });
}
