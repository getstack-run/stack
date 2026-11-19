import type {
  OperatorErasureClaim,
  OperatorErasureService,
} from '@stack/vault';

const ERASURE_RETRY_INTERVAL_MS = 5 * 60_000;

type ErasureWorker = Pick<OperatorErasureService, 'claimDueJobs' | 'finalizeClaim'>;

export interface OperatorErasureRetryResult {
  claimed: number;
  completed: number;
  pending: number;
}

/** Gate the indexed due-job query to one run every five minutes per worker. */
export function createOperatorErasureRetryGate(
  service: ErasureWorker,
  now: () => number = Date.now,
): () => Promise<OperatorErasureRetryResult> {
  let lastRunAt = Number.NEGATIVE_INFINITY;

  return async () => {
    const current = now();
    if (current - lastRunAt < ERASURE_RETRY_INTERVAL_MS) {
      return { claimed: 0, completed: 0, pending: 0 };
    }
    lastRunAt = current;

    const claims: OperatorErasureClaim[] = await service.claimDueJobs(10);
    let completed = 0;
    let pending = 0;
    for (const claim of claims) {
      const result = await service.finalizeClaim(claim);
      if (result.status === 'completed') completed += 1;
      else pending += 1;
    }
    return { claimed: claims.length, completed, pending };
  };
}
