import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError, IdentityRequirementsError, NotFoundError, PassportRevokedError } from '@stack/shared';
import { PassportService } from './passport-service.js';
import { passportTestWiring, type PassportTestWiring } from './passport-service.test-support.js';

/**
 * A Passport service cannot exist without the collaborators its checks run
 * through, so no check can be silently skipped for want of one. A revoke must
 * always name the operator it acts for. Neither may quietly pass.
 */

const NOW_PLUS_MINUTE = () => new Date(Date.now() + 60_000);

function makeService(options: { wiring?: PassportTestWiring } = {}) {
  const wiring = options.wiring ?? passportTestWiring();
  const passportRepo = {
    findByJti: vi.fn(async (jti: string) => (jti === 'ppt_owned'
      ? {
          jti, operator_id: 'op_owner', agent_id: 'agt_one', session_id: 'ses_one',
          delegation_depth: 0, parent_passport_id: null, revoked_at: null, expires_at: NOW_PLUS_MINUTE(),
        }
      : null)),
    isRevoked: vi.fn(async () => false),
    revoke: vi.fn(async () => undefined),
    findActiveChildren: vi.fn(async () => []),
  };
  const agentRepo = {
    findById: vi.fn(async (id: string) => ({ id, operator_id: 'op_owner', status: 'active', passport_blocked: false })),
  };
  const signer = {
    verify: vi.fn(async () => ({
      jti: 'ppt_owned',
      exp: Math.floor(Date.now() / 1000) + 60,
      stk: {
        operator_id: 'op_owner', agent_id: 'agt_one', session_id: 'ses_one', delegation_depth: 0, services: [],
        identity_claims: [{
          claim_id: 'clm_one', provider: 'stripe_identity', layer: 'identity', claim_type: 'verified_identity',
          assurance_level: 'high', verified_at: 1, expires_at: Math.floor(Date.now() / 1000) + 60,
        }],
      },
    })),
  };
  const service = new PassportService(
    passportRepo as never,
    agentRepo as never,
    {} as never,
    signer as never,
    {
      get: vi.fn(async () => null),
      publish: vi.fn(async () => 1),
      pipeline: () => ({ set: vi.fn(), exec: vi.fn(async () => []) }),
    } as never,
    { findById: vi.fn(async () => ({ id: 'op_owner', status: 'active' })) } as never,
    '',
    { transaction: async (work: (tx: unknown) => unknown) => work({ execute: async () => undefined }) } as never,
    wiring.dependencies,
  );
  return { service, passportRepo, signer, wiring };
}

describe('PassportService dependencies', () => {
  const construct = (dependencies: unknown) =>
    new PassportService(
      {} as never, {} as never, {} as never, {} as never, {} as never, {} as never, '', {} as never,
      dependencies as never,
    );
  const complete = passportTestWiring().dependencies;

  it('builds when every dependency is supplied', () => {
    expect(() => construct(complete)).not.toThrow();
  });

  it.each(Object.keys(complete))('cannot be constructed without %s', (key) => {
    const { [key as keyof typeof complete]: _omitted, ...rest } = complete;
    void _omitted;
    expect(() => construct(rest)).toThrow(`requires its ${key} dependency`);
  });

  it('cannot be constructed with no dependencies at all', () => {
    expect(() => construct(undefined)).toThrow(/requires its/);
  });

  it('wiring a dependency as the wrong kind is refused', () => {
    expect(() => construct({ ...complete, missionLookup: {} })).toThrow(/missionLookup/);
    expect(() => construct({ ...complete, identityRepo: null })).toThrow(/identityRepo/);
  });
});

describe('PassportService accessors', () => {
  const issueInput = { agent_id: 'agt_one', mission_ids: ['ms_one'] };

  it('reads the fleet lookup at call time, so a fleet that refuses stops issuance', async () => {
    const { service, wiring } = makeService();
    const assertUnboundIssue = vi.fn(async () => { throw new ForbiddenError(); });
    wiring.fleetLookup = { ...wiring.fleetLookup, assertUnboundIssue };
    await expect(service.issue('op_owner', issueInput)).rejects.toBeInstanceOf(ForbiddenError);
    expect(assertUnboundIssue).toHaveBeenCalledWith('op_owner', 'agt_one');
  });

  it('fails the call, instead of skipping the check, when the collaborator is not there yet', async () => {
    const dependencies = {
      ...passportTestWiring().dependencies,
      fleetLookup: () => { throw new ReferenceError('fleet is not built yet'); },
    };
    const service = new PassportService(
      {} as never, {} as never, {} as never, {} as never, {} as never, {} as never, '', {} as never,
      dependencies,
    );
    await expect(service.issue('op_owner', issueInput)).rejects.toBeInstanceOf(ReferenceError);
  });
});

describe('PassportService identity freshness', () => {
  it('revokes a passport whose carried identity claim no longer exists', async () => {
    const findClaimById = vi.fn(async () => null);
    const wiring = passportTestWiring({
      identityRepo: { findRequirementsByService: vi.fn(async () => []), findClaimById },
    });
    const { service, passportRepo } = makeService({ wiring });
    await expect(service.verify('signed')).rejects.toBeInstanceOf(PassportRevokedError);
    expect(findClaimById).toHaveBeenCalledWith('clm_one');
    expect(passportRepo.revoke).toHaveBeenCalledWith(
      'ppt_owned',
      expect.stringContaining('clm_one'),
      expect.anything(),
    );
  });

  it('applies the per-service identity gate through the identity services it was given', async () => {
    const wiring = passportTestWiring({
      identityRepo: {
        findRequirementsByService: vi.fn(async () => [{
          id: 'req_1', service_id: 'svc_bank', layer: 'identity', requires_claim: 'verified_identity',
          minimum_assurance: 'high', accepted_providers: [], required_scopes: [], requires_pii: false, lawful_basis: null,
        }]),
        findClaimById: vi.fn(async () => null),
      },
      claimMatcher: { satisfies: vi.fn(() => ({ satisfied: false, unmet: [{ layer: 'identity', requires_claim: 'verified_identity' }] })) },
    });
    const { service, signer } = makeService({ wiring });
    const claims = await signer.verify();
    await expect(service.assertServiceIdentityRequirements(claims as never, 'svc_bank'))
      .rejects.toBeInstanceOf(IdentityRequirementsError);
  });

  it('does not consult identity repositories to verify a passport that carries no identity claims', async () => {
    const { service, signer, wiring } = makeService();
    signer.verify.mockResolvedValueOnce({
      jti: 'ppt_owned',
      exp: Math.floor(Date.now() / 1000) + 60,
      stk: { operator_id: 'op_owner', agent_id: 'agt_one', session_id: 'ses_one', delegation_depth: 0, services: [], identity_claims: [] },
    });
    await expect(service.verify('signed')).resolves.toBeDefined();
    expect((wiring.identityRepo as { findClaimById: ReturnType<typeof vi.fn> }).findClaimById).not.toHaveBeenCalled();
  });
});

describe('PassportService.revoke operator scoping', () => {
  it('revokes a passport for the operator that owns it', async () => {
    const { service, passportRepo } = makeService();
    const result = await service.revoke({ jti: 'ppt_owned', operatorId: 'op_owner', reason: 'owner request' });
    expect(passportRepo.findByJti).toHaveBeenCalledWith('ppt_owned');
    expect(passportRepo.revoke).toHaveBeenCalledWith('ppt_owned', 'owner request', expect.anything());
    expect(result.operator_id).toBe('op_owner');
  });

  it('rejects a revoke that names no operator', async () => {
    const { service, passportRepo } = makeService();
    await expect(
      service.revoke({ jti: 'ppt_owned', operatorId: '', reason: 'no operator' }),
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(passportRepo.findByJti).toHaveBeenCalledWith('ppt_owned');
    expect(passportRepo.revoke).not.toHaveBeenCalled();
  });

  it('treats a passport owned by another operator as not found', async () => {
    const { service, passportRepo } = makeService();
    await expect(
      service.revoke({ jti: 'ppt_owned', operatorId: 'op_other', reason: 'cross tenant' }),
    ).rejects.toBeInstanceOf(NotFoundError);
    expect(passportRepo.findByJti).toHaveBeenCalledWith('ppt_owned');
    expect(passportRepo.revoke).not.toHaveBeenCalled();
  });

  it('treats an unknown passport as not found', async () => {
    const { service } = makeService();
    await expect(
      service.revoke({ jti: 'ppt_missing', operatorId: 'op_owner', reason: 'unknown' }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});
