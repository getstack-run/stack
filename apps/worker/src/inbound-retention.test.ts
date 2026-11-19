import { describe, expect, it, vi } from 'vitest';
import { INBOUND_WEBHOOK_DEDUPE_TTL_SECONDS } from '@stack/shared';
import { runInboundRetention } from './jobs/inbound-retention.js';

function deps(opts: { lock?: 'OK' | null; receiptsFail?: boolean } = {}) {
  const now = new Date('2026-10-19T12:00:00.000Z');
  return {
    now,
    redis: { set: vi.fn().mockResolvedValue(opts.lock === undefined ? 'OK' : opts.lock) },
    inboundReceiptsRepo: {
      sweepOlderThan: opts.receiptsFail ? vi.fn().mockRejectedValue(new Error('db down')) : vi.fn().mockResolvedValue(7),
    },
  };
}

describe('inbound retention', () => {
  it('deletes completed inbound receipts older than the dedupe window', async () => {
    const d = deps();
    await runInboundRetention(d as never, d.now);
    const cutoff = d.inboundReceiptsRepo.sweepOlderThan.mock.calls[0]![0] as Date;
    expect(d.now.getTime() - cutoff.getTime()).toBe(INBOUND_WEBHOOK_DEDUPE_TTL_SECONDS * 1000);
  });

  it('runs once per window across worker machines', async () => {
    const d = deps({ lock: null });
    await runInboundRetention(d as never, d.now);
    expect(d.redis.set).toHaveBeenCalledWith(expect.stringMatching(/^inbound_retention_lock:/), expect.any(String), 'EX', expect.any(Number), 'NX');
    expect(d.inboundReceiptsRepo.sweepOlderThan).not.toHaveBeenCalled();
  });

  it('does not throw into the tick when the sweep fails', async () => {
    const d = deps({ receiptsFail: true });
    await expect(runInboundRetention(d as never, d.now)).resolves.toBeUndefined();
    expect(d.inboundReceiptsRepo.sweepOlderThan).toHaveBeenCalledTimes(1);
  });
});
