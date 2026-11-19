import type {
  EmailChangeDeliveryClaim,
  EmailChangeService,
} from '@stack/vault';

const DELIVERY_RETRY_INTERVAL_MS = 5 * 60_000;

type DeliveryWorker = Pick<
  EmailChangeService,
  'claimDueDeliveryJobs' | 'finalizeDeliveryClaim'
>;

export interface EmailChangeDeliveryRetryResult {
  claimed: number;
  completed: number;
  pending: number;
}

/** Gate the indexed due-job query to one run every five minutes per worker. */
export function createEmailChangeDeliveryRetryGate(
  service: DeliveryWorker,
  now: () => number = Date.now,
): () => Promise<EmailChangeDeliveryRetryResult> {
  let lastRunAt = Number.NEGATIVE_INFINITY;

  return async () => {
    const current = now();
    if (current - lastRunAt < DELIVERY_RETRY_INTERVAL_MS) {
      return { claimed: 0, completed: 0, pending: 0 };
    }
    lastRunAt = current;

    const claims: EmailChangeDeliveryClaim[] = await service.claimDueDeliveryJobs(10);
    let completed = 0;
    let pending = 0;
    for (const claim of claims) {
      const result = await service.finalizeDeliveryClaim(claim);
      if (result === 'completed') completed += 1;
      else pending += 1;
    }
    return { claimed: claims.length, completed, pending };
  };
}
