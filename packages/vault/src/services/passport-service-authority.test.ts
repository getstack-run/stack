import { describe, expect, it, vi } from 'vitest';
import type { AuthorityReference } from '@stack/shared';
import { PassportRevokedError } from '@stack/shared';
import { PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

const liveMissionLookup = {
  findById: async (missionId: string) => ({
    mission_id: missionId, operator_id: 'op_one', intent_services: [],
    expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null,
  }),
};

const authorityRefs: AuthorityReference[] = [{
  binding_id: 'abn_test',
  binding_version: 1,
  binding_claim_id: 'pc_test',
  binding_digest: `sha256:${'b'.repeat(64)}`,
  receiver_id: 'rcv_test',
  receiver_profile_version_id: 'apv_test',
  expires_at: Math.floor(Date.now() / 1000) + 300,
}];

function refreshService() {
  const tx = { execute: vi.fn(async () => undefined) };
  const create = vi.fn(async () => undefined);
  const sign = vi.fn(async (_jti, payload) => ({
    token: 'refreshed-token',
    expires_at: new Date(Date.now() + 60_000),
    payload,
  }));
  const verify = vi.fn(async () => ({
    jti: 'ppt_old',
    sub: 'agt_one',
    exp: Math.floor(Date.now() / 1000) + 60,
    iat: Math.floor(Date.now() / 1000),
    stk: {
      operator_id: 'op_one',
      agent_id: 'agt_one',
      services: [],
      identity_claims: [],
      authority_refs: authorityRefs,
      delegation_depth: 0,
      session_id: 'ses_one',
      mission_ids: ['ms_one'],
    },
  }));
  // every agent Passport is bound to exactly one live Mission.
  const wiring = passportTestWiring({ missionLookup: liveMissionLookup });
  const service = new PassportService(
    {
      isRevoked: vi.fn(async () => false), create,
      findByJti: vi.fn(async () => ({
        jti: 'ppt_old', operator_id: 'op_one', agent_id: 'agt_one', session_id: 'ses_one',
        delegation_depth: 0, parent_passport_id: null, revoked_at: null,
        expires_at: new Date(Date.now() + 60_000),
      })),
    } as never,
    { findById: vi.fn(async () => ({ id: 'agt_one', operator_id: 'op_one', name: 'Agent', status: 'active' })) } as never,
    { findGrantsWithConnectionByAgent: vi.fn(async () => []) } as never,
    { verify, sign } as never,
    { get: vi.fn(async () => null) } as never,
    { findById: vi.fn(async () => ({ status: 'active', is_platform_staff: false })) } as never,
    '',
    { transaction: vi.fn(async (work) => work(tx)) } as never,
    wiring.dependencies,
  );
  return { service, wiring, create, sign, tx };
}

describe('PassportService authority lifecycle', () => {
  it('re-verifies and atomically links authority refs on refresh', async () => {
    const { service, wiring, create, sign, tx } = refreshService();
    const verifyPassportRefs = vi.fn(async () => undefined);
    const linkPassportRefs = vi.fn(async () => undefined);
    wiring.authorityLookup = { verifyPassportRefs, linkPassportRefs } as never;

    await service.refresh('op_one', 'old-token');

    expect(verifyPassportRefs).toHaveBeenCalledWith({
      operatorId: 'op_one',
      agentId: 'agt_one',
      refs: authorityRefs,
      missionIds: ['ms_one'],
    });
    expect(sign.mock.calls[0]?.[1]).toMatchObject({
      authority_refs: authorityRefs,
      mission_ids: ['ms_one'],
    });
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ mission_ids: ['ms_one'] }), tx);
    expect(linkPassportRefs).toHaveBeenCalledWith({
      operatorId: 'op_one',
      passportJti: expect.any(String),
      refs: authorityRefs,
    }, tx);
  });

  it('fails closed rather than refreshing authority refs the authority engine no longer accepts', async () => {
    const { service, wiring, create, sign } = refreshService();
    wiring.authorityLookup = {
      verifyPassportRefs: async () => { throw new PassportRevokedError(); },
    } as never;

    await expect(service.refresh('op_one', 'old-token')).rejects.toBeInstanceOf(PassportRevokedError);
    expect(sign).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  });

  it('caches and broadcasts only already-durable authority revocations', async () => {
    const expiresAt = new Date(Date.now() + 60_000);
    const set = vi.fn(async () => 'OK');
    const publish = vi.fn(async () => 1);
    const findByJti = vi.fn(async (jti: string) => ({
      jti,
      operator_id: 'op_one',
      expires_at: expiresAt,
      revoked_at: new Date(),
    }));
    const service = new PassportService(
      { findByJti } as never,
      {} as never,
      {} as never,
      {} as never,
      { set, publish } as never,
      {} as never,
      '',
      {} as never,
      passportTestWiring().dependencies,
    );

    await service.syncAuthorityRevocations(['ppt_one', 'ppt_one'], 'proof revoked');

    expect(findByJti).toHaveBeenCalledTimes(1);
    expect(set).toHaveBeenCalledWith('revoked:ppt_one', '1', 'EX', expect.any(Number));
    expect(publish).toHaveBeenCalledTimes(1);

    findByJti.mockResolvedValueOnce({
      jti: 'ppt_live',
      operator_id: 'op_one',
      expires_at: expiresAt,
      revoked_at: null,
    } as never);
    await expect(service.syncAuthorityRevocations(['ppt_live'], 'proof revoked'))
      .rejects.toThrow('not durable');
  });

  it('preserves the parent Mission set on a narrowed authority delegation', async () => {
    const tx = { execute: vi.fn(async () => undefined) };
    const create = vi.fn(async () => undefined);
    const sign = vi.fn(async (_jti, payload) => ({
      token: 'child-token',
      jti: 'ppt_child',
      expires_at: new Date(Date.now() + 60_000),
      payload,
    }));
    const verify = vi.fn(async () => ({
      jti: 'ppt_parent',
      sub: 'agt_parent',
      exp: Math.floor(Date.now() / 1000) + 300,
      iat: Math.floor(Date.now() / 1000),
      stk: {
        operator_id: 'op_one',
        agent_id: 'agt_parent',
        agent_name: 'Parent',
        services: [],
        identity_claims: [],
        authority_refs: authorityRefs,
        delegation_depth: 0,
        session_id: 'ses_one',
        mission_ids: ['ms_one'],
      },
    }));
    const agents = {
      agt_parent: {
        id: 'agt_parent', operator_id: 'op_one', name: 'Parent', status: 'active',
        passport_blocked: false, accountability_mode: 'standard', pubkey: null,
      },
      agt_child: {
        id: 'agt_child', operator_id: 'op_one', name: 'Child', status: 'active',
        passport_blocked: false, accountability_mode: 'standard',
        pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'child-public-key' },
      },
    } as const;
    // every agent Passport is bound to exactly one live Mission.
    const wiring = passportTestWiring({ missionLookup: liveMissionLookup });
    const service = new PassportService(
      {
        isRevoked: vi.fn(async () => false),
        findByJti: vi.fn(async () => ({
          jti: 'ppt_parent', operator_id: 'op_one', agent_id: 'agt_parent', session_id: 'ses_one',
          delegation_depth: 0, parent_passport_id: null, revoked_at: null,
          expires_at: new Date(Date.now() + 300_000), intent_delegates: true,
        })),
        create,
      } as never,
      { findById: vi.fn(async (id: keyof typeof agents) => agents[id] ?? null) } as never,
      { findConnectionById: vi.fn(async () => null) } as never,
      { verify, sign } as never,
      { get: vi.fn(async () => null) } as never,
      { findById: vi.fn(async () => ({ status: 'active', is_platform_staff: false })) } as never,
      '',
      { transaction: vi.fn(async (work) => work(tx)) } as never,
      wiring.dependencies,
    );
    const childRefs = [{ ...authorityRefs[0]!, binding_id: 'abn_child', binding_claim_id: 'pc_child' }];
    const verifyPassportRefs = vi.fn(async () => undefined);
    const delegatePassportRefs = vi.fn(async () => childRefs);
    const linkPassportRefs = vi.fn(async () => undefined);
    wiring.authorityLookup = { verifyPassportRefs, delegatePassportRefs, linkPassportRefs } as never;

    await service.delegate('op_one', {
      parent_passport_token: 'parent-token',
      child_agent_id: 'agt_child',
      scopes: [],
      ttl_seconds: 60,
    });

    expect(sign.mock.calls[0]?.[1]).toMatchObject({
      authority_refs: childRefs,
      mission_ids: ['ms_one'],
    });
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ mission_ids: ['ms_one'] }), tx);
    expect(linkPassportRefs).toHaveBeenCalledWith({
      operatorId: 'op_one',
      passportJti: expect.any(String),
      refs: childRefs,
    }, tx);
  });
});
