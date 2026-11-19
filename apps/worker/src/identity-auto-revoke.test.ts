import { describe, expect, it, vi } from 'vitest';
import { autoRevokeExpiredClaims } from './jobs/identity-auto-revoke.js';

describe('identity claim auto-revocation', () => {
  it('uses the canonical passport revocation path, Redis event, and audit entry', async () => {
    const claim = { id: 'clm_expired', operator_id: 'op_one' };
    const selectQuery = {
      from: vi.fn(),
      innerJoin: vi.fn(),
      where: vi.fn(async () => [claim]),
    };
    selectQuery.from.mockReturnValue(selectQuery);
    selectQuery.innerJoin.mockReturnValue(selectQuery);

    const updateQuery = {
      set: vi.fn(),
      where: vi.fn(),
      returning: vi.fn(async () => [claim]),
    };
    updateQuery.set.mockReturnValue(updateQuery);
    updateQuery.where.mockReturnValue(updateQuery);

    const db = {
      select: vi.fn(() => selectQuery),
      update: vi.fn(() => updateQuery),
    };
    const passportRepo = {
      revokeByCarriedClaim: vi.fn(async () => ({
        rows: [{ jti: 'ppt_one', expires_at: new Date(Date.now() + 60_000) }],
      })),
    };
    const pipeline = {
      set: vi.fn(),
      exec: vi.fn(async () => []),
    };
    pipeline.set.mockReturnValue(pipeline);
    const publish = vi.fn(async () => 1);
    const auditWrite = vi.fn(async () => undefined);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    await autoRevokeExpiredClaims(db as never, {
      passportRepo: passportRepo as never,
      redis: { pipeline: () => pipeline, publish } as never,
      audit: { write: auditWrite } as never,
      now: new Date('2026-08-16T12:00:00Z'),
    });

    expect(passportRepo.revokeByCarriedClaim).toHaveBeenCalledWith(
      'op_one',
      'clm_expired',
      'Claim expired (auto-revoke)',
    );
    expect(pipeline.set).toHaveBeenCalledWith(
      'revoked:ppt_one',
      '1',
      'EX',
      expect.any(Number),
    );
    expect(publish).toHaveBeenCalledWith(
      'stack:revoked',
      expect.stringContaining('"type":"bulk_claim"'),
    );
    expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({
      action: 'identity.claim.auto_revoke',
      outcome: 'success',
      payload_hash: 'clm_expired',
    }));

    log.mockRestore();
  });

  it('does not revoke twice when another worker already claimed the row', async () => {
    const claim = { id: 'clm_expired', operator_id: 'op_one' };
    const selectQuery = {
      from: vi.fn(),
      innerJoin: vi.fn(),
      where: vi.fn(async () => [claim]),
    };
    selectQuery.from.mockReturnValue(selectQuery);
    selectQuery.innerJoin.mockReturnValue(selectQuery);
    const updateQuery = {
      set: vi.fn(),
      where: vi.fn(),
      returning: vi.fn(async () => []),
    };
    updateQuery.set.mockReturnValue(updateQuery);
    updateQuery.where.mockReturnValue(updateQuery);
    const passportRepo = { revokeByCarriedClaim: vi.fn() };

    await autoRevokeExpiredClaims({
      select: vi.fn(() => selectQuery),
      update: vi.fn(() => updateQuery),
    } as never, {
      passportRepo: passportRepo as never,
      redis: {} as never,
      audit: {} as never,
    });

    expect(passportRepo.revokeByCarriedClaim).not.toHaveBeenCalled();
  });
});
