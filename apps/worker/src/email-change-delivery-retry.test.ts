import { describe, expect, it, vi } from 'vitest';
import { createEmailChangeDeliveryRetryGate } from './email-change-delivery-retry.js';

describe('email change delivery retry gate', () => {
  it('claims due jobs once every five minutes and finalizes each claim', async () => {
    let now = 0;
    const claims = [
      { id: 'job_1', claimId: 'claim_1' },
      { id: 'job_2', claimId: 'claim_2' },
    ];
    const service = {
      claimDueDeliveryJobs: vi.fn(async () => claims as never),
      finalizeDeliveryClaim: vi.fn(async () => 'completed' as const),
    };
    const maybeRetry = createEmailChangeDeliveryRetryGate(service as never, () => now);

    await expect(maybeRetry()).resolves.toEqual({ claimed: 2, completed: 2, pending: 0 });
    await expect(maybeRetry()).resolves.toEqual({ claimed: 0, completed: 0, pending: 0 });
    expect(service.claimDueDeliveryJobs).toHaveBeenCalledTimes(1);

    now = 5 * 60_000;
    await maybeRetry();
    expect(service.claimDueDeliveryJobs).toHaveBeenCalledTimes(2);
    expect(service.finalizeDeliveryClaim).toHaveBeenCalledTimes(4);
  });
});
