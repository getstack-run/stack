import { describe, expect, it, vi } from 'vitest';
import { IdentityRequirementsError, PassportRevokedError } from '@stack/shared';
import { PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

/**
 * the proxy verifies a Passport ONCE per request. `verifyDetailed`
 * must make every check `verify` makes (revocation live, agent, lineage) and
 * hand back the row it read so the caller does not read it again;
 * `assertServiceIdentityRequirements` must be the same gate `verify` runs
 * for a `service_id`.
 */

function rows() {
  const base = { operator_id: 'op_test', session_id: 'ses_test', revoked_at: null, expires_at: new Date(Date.now() + 60_000) };
  return {
    ppt_child: { ...base, jti: 'ppt_child', agent_id: 'agt_child', delegation_depth: 1, parent_passport_id: 'ppt_root', checked_out_at: new Date() },
    ppt_root: { ...base, jti: 'ppt_root', agent_id: 'agt_root', delegation_depth: 0, parent_passport_id: null, checked_out_at: null },
  } as Record<string, Record<string, unknown>>;
}

function makeService(opts: { revokedInRedis?: boolean; requirementsUnmet?: boolean; delegated?: boolean } = {}) {
  const table = rows();
  const passportRepo = {
    findByJti: vi.fn(async (jti: string) => table[jti] ?? null),
    isRevoked: vi.fn(async () => false),
  };
  const agentRepo = {
    findById: vi.fn(async (id: string) => ({ id, operator_id: 'op_test', status: 'active', passport_blocked: false })),
  };
  const delegated = opts.delegated ?? true;
  const signer = {
    verify: vi.fn(async () => ({
      jti: delegated ? 'ppt_child' : 'ppt_root',
      exp: Math.floor(Date.now() / 1000) + 60,
      stk: {
        operator_id: 'op_test',
        agent_id: delegated ? 'agt_child' : 'agt_root',
        session_id: 'ses_test',
        delegation_depth: delegated ? 1 : 0,
        ...(delegated ? { parent_passport_id: 'ppt_root' } : {}),
        services: [],
      },
    })),
  };
  const redis = { get: vi.fn(async () => (opts.revokedInRedis ? '1' : null)) };
  const operatorRepo = { findById: vi.fn(async () => ({ id: 'op_test', status: 'active' })) };
  const identityRepo = {
    findRequirementsByService: vi.fn(async () => [{
      id: 'req_1', service_id: 'svc_bank', layer: 'humanity', requires_claim: 'turnstile',
      minimum_assurance: 'low', accepted_providers: [], required_scopes: [], requires_pii: false, lawful_basis: null,
    }]),
  };
  const claimMatcher = {
    satisfies: vi.fn(() => (opts.requirementsUnmet
      ? { satisfied: false, unmet: [{ layer: 'humanity', requires_claim: 'turnstile' }] }
      : { satisfied: true, unmet: [] })),
  };
  const wiring = passportTestWiring({ claimMatcher, identityRepo });
  const service = new PassportService(
    passportRepo as never,
    agentRepo as never,
    {} as never,
    signer as never,
    redis as never,
    operatorRepo as never,
    '',
    { transaction: async (work: (tx: unknown) => unknown) => work({ execute: async () => undefined }) } as never,
    wiring.dependencies,
  );
  return { service, passportRepo, redis, identityRepo, claimMatcher };
}

describe('PassportService.verifyDetailed', () => {
  it('returns the row read during verification without reading it again', async () => {
    const { service, passportRepo } = makeService();
    const { claims, record } = await service.verifyDetailed('signed');
    expect(claims.jti).toBe('ppt_child');
    expect(record?.jti).toBe('ppt_child');
    expect(record?.checked_out_at).toBeInstanceOf(Date);
    // Lineage: the child and its parent, once each. No third read.
    expect(passportRepo.findByJti.mock.calls.map(([jti]) => jti)).toEqual(['ppt_child', 'ppt_root']);
  });

  it('reads the row once when verification had no reason to', async () => {
    const { service, passportRepo } = makeService({ delegated: false });
    const { record } = await service.verifyDetailed('signed');
    expect(record?.jti).toBe('ppt_root');
    expect(passportRepo.findByJti).toHaveBeenCalledTimes(1);
  });

  it('still checks revocation live', async () => {
    const { service, redis } = makeService({ revokedInRedis: true });
    await expect(service.verifyDetailed('signed')).rejects.toBeInstanceOf(PassportRevokedError);
    expect(redis.get).toHaveBeenCalledWith('revoked:ppt_child');
  });
});

describe('PassportService.assertServiceIdentityRequirements', () => {
  it('is the same gate verify runs for a service_id', async () => {
    const unmet = makeService({ requirementsUnmet: true });
    const { claims } = await unmet.service.verifyDetailed('signed');
    await expect(unmet.service.assertServiceIdentityRequirements(claims, 'svc_bank')).rejects.toBeInstanceOf(IdentityRequirementsError);
    await expect(unmet.service.verify('signed', { service_id: 'svc_bank' })).rejects.toBeInstanceOf(IdentityRequirementsError);
    expect(unmet.identityRepo.findRequirementsByService).toHaveBeenCalledWith('op_test', 'svc_bank');
  });

  it('passes when the requirements are met', async () => {
    const met = makeService();
    const { claims } = await met.service.verifyDetailed('signed');
    await expect(met.service.assertServiceIdentityRequirements(claims, 'svc_bank')).resolves.toBeUndefined();
    expect(met.claimMatcher.satisfies).toHaveBeenCalledTimes(1);
  });
});
