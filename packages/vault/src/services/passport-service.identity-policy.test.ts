import { describe, expect, it, vi } from 'vitest';
import type { PassportClaimRef } from '@stack/shared';
import { IdentityProviderRegistry } from '../identity/provider-registry.js';
import { IdentityVerificationService } from '../identity/identity-verification-service.js';
import {
  identityClaimIdsForRefresh,
  identityClaimIsExpired,
  PassportService,
  preserveIdentityClaimsForDelegation,
  revokePassportsByCarriedClaim,
} from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

function claim(id: string, expiresAt = new Date(Date.now() + 60_000)) {
  return {
    id,
    provider_key: 'stripe_identity',
    layer: 'identity',
    claim_type: 'verified_identity',
    assurance_level: 'high',
    verified_at: new Date('2026-01-01T00:00:00Z'),
    expires_at: expiresAt,
    delegated_scopes: null,
  };
}

describe('passport identity policy', () => {
  it('preserves an explicit empty claim set in automatic mode', async () => {
    const identityRepo = {
      findValidClaims: vi.fn(async () => [claim('clm_should_not_expand')]),
    };
    const service = new IdentityVerificationService(
      {} as never,
      new IdentityProviderRegistry(),
      identityRepo as never,
      {} as never,
    );
    service.setOperatorRepo({
      findById: vi.fn(async () => ({ identity_claim_inheritance: 'auto' })),
    } as never);

    await expect(service.buildPassportClaimRefs('op_one', [])).resolves.toEqual([]);
    expect(identityRepo.findValidClaims).not.toHaveBeenCalled();
  });

  it('keeps a zero-claim passport empty during refresh', () => {
    expect(identityClaimIdsForRefresh([])).toEqual([]);
    expect(identityClaimIdsForRefresh(undefined)).toEqual([]);
  });

  it('keeps the signed and stored claim sets empty through refresh', async () => {
    const create = vi.fn(async () => undefined);
    const sign = vi.fn(async (_jti, payload) => ({
      token: 'refreshed-token',
      expires_at: new Date(Date.now() + 60_000),
      payload,
    }));
    const buildPassportClaimRefs = vi.fn(async () => []);
    const tx = { execute: vi.fn(async () => undefined) };
    // refresh renews a credential for a live Mission only.
    const wiring = passportTestWiring({
      identityVerification: { buildPassportClaimRefs },
      missionLookup: {
        findById: async (missionId) => ({
          mission_id: missionId, operator_id: 'op_one', intent_services: [],
          expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null,
        }),
      },
    });
    const service = new PassportService(
      {
        isRevoked: vi.fn(async () => false), create,
        findByJti: vi.fn(async () => ({
          jti: 'ppt_old', operator_id: 'op_one', agent_id: 'agt_one',
          session_id: 'ses_one', delegation_depth: 0, parent_passport_id: null,
          expires_at: new Date(Date.now() + 60_000), revoked_at: null,
        })),
      } as never,
      { findById: vi.fn(async () => ({ id: 'agt_one', operator_id: 'op_one', name: 'Agent', status: 'active' })) } as never,
      { findGrantsWithConnectionByAgent: vi.fn(async () => []) } as never,
      {
        verify: vi.fn(async () => ({
          jti: 'ppt_old',
          exp: Math.floor(Date.now() / 1000) + 60,
          stk: {
            operator_id: 'op_one',
            agent_id: 'agt_one',
            services: [],
            identity_claims: [],
            delegation_depth: 0,
            session_id: 'ses_one',
            mission_ids: ['ms_one'],
          },
        })),
        sign,
      } as never,
      { get: vi.fn(async () => null) } as never,
      { findById: vi.fn(async () => ({ status: 'active', is_platform_staff: false })) } as never,
      '',
      { transaction: vi.fn(async (work) => work(tx)) } as never,
      wiring.dependencies,
    );

    await service.refresh('op_one', 'old-token');

    expect(buildPassportClaimRefs).toHaveBeenCalledWith('op_one', []);
    expect(sign.mock.calls[0]?.[1]).toMatchObject({ identity_claims: [] });
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ identity_claim_ids: null }),
      tx,
    );
  });

  it('copies parent claims through delegation without adding operator claims', () => {
    const parent = [{
      claim_id: 'clm_one',
      provider: 'stripe_identity',
      layer: 'identity',
      claim_type: 'verified_identity',
      assurance_level: 'high',
      verified_at: 1,
      expires_at: 2,
    }] as PassportClaimRef[];

    expect(preserveIdentityClaimsForDelegation(parent)).toEqual(parent);
    expect(preserveIdentityClaimsForDelegation(undefined)).toEqual([]);
  });

  it('rejects expiry from either the database row or the signed claim', () => {
    const now = Date.parse('2026-08-16T12:00:00Z');
    expect(identityClaimIsExpired(
      { expires_at: new Date(now - 1) },
      { expires_at: Math.floor((now + 60_000) / 1000) },
      now,
    )).toBe(true);
    expect(identityClaimIsExpired(
      { expires_at: new Date(now + 60_000) },
      { expires_at: Math.floor((now - 1) / 1000) },
      now,
    )).toBe(true);
    expect(identityClaimIsExpired(
      { expires_at: new Date(now + 60_000) },
      { expires_at: Math.floor((now + 60_000) / 1000) },
      now,
    )).toBe(false);
  });

  it('writes Redis revocations and publishes the canonical claim event', async () => {
    const set = vi.fn().mockReturnThis();
    const exec = vi.fn(async () => []);
    const publish = vi.fn(async () => 1);
    const repo = {
      revokeByCarriedClaim: vi.fn(async () => ({
        rows: [{ jti: 'ppt_one', expires_at: new Date(Date.now() + 60_000) }],
      })),
    };

    const result = await revokePassportsByCarriedClaim({
      passportRepo: repo as never,
      redis: { pipeline: () => ({ set, exec }), publish } as never,
      operatorId: 'op_one',
      claimId: 'clm_one',
      reason: 'Claim expired (auto-revoke)',
    });

    expect(result).toEqual({ revoked_count: 1 });
    expect(set).toHaveBeenCalledWith('revoked:ppt_one', '1', 'EX', expect.any(Number));
    expect(exec).toHaveBeenCalledOnce();
    expect(publish).toHaveBeenCalledWith(
      'stack:revoked',
      expect.stringContaining('"type":"bulk_claim"'),
    );
  });
});
