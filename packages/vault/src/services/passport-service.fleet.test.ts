import { beforeAll, describe, expect, it, vi } from 'vitest';
import { ForbiddenError, PassportClaims, PassportRevokedError, ScopeEscalationError } from '@stack/shared';
import { PassportSigner } from '../crypto/passport-signer.js';
import { PassportService, type PassportFleetLookup } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

const binding = { policy_id: 'flp_test', policy_revision: 1, membership_id: 'flm_worker', mission_id: 'ms_test' };
const scope = { service_connection_id: 'scon_slack', scopes: ['chat:write'] };
let signer: PassportSigner;
beforeAll(async () => { signer = new PassportSigner(); await signer.init(); });

function fixture() {
  const rows = new Map<string, Record<string, any>>();
  const signedTokens: string[] = [];
  const deadline = new Date(Date.now() + 120_000);
  let active = true;
  const lookup: PassportFleetLookup = {
    assertUnboundIssue: vi.fn(async () => { throw new ForbiddenError(); }),
    validate: vi.fn(async (claims) => {
      if (!active || !claims.stk.fleet) throw new PassportRevokedError();
    }),
    validateDelegation: vi.fn(async () => ({ ...binding })),
    authorizeIssue: vi.fn(async () => {
      if (!active) throw new PassportRevokedError();
      return { expiresAt: deadline };
    }),
  };
  const repository = {
    create: async (row: Record<string, any>) => { rows.set(row.jti, row); return row; },
    findByJti: async (id: string) => rows.get(id) ?? null,
    isRevoked: async () => false,
  };
  const agentRepo = { findById: async (id: string) => ({ id, operator_id: 'op_test', name: id,
    status: 'active', passport_blocked: false, accountability_mode: 'enforced' }) };
  const serviceRepo = { findGrantsWithConnectionByAgent: async () => [{
    grant: { service_connection_id: 'scon_slack', scopes: ['chat:write'], constraints: [], allow_data_from: [] },
    connection: { id: 'scon_slack', operator_id: 'op_test', service_id: 'svc_slack', provider: 'slack',
      status: 'active', credential_ref: 'ref_slack' },
  }] };
  const capturingSigner = {
    sign: async (...args: Parameters<PassportSigner['sign']>) => {
      const signed = await signer.sign(...args);
      signedTokens.push(signed.token);
      return signed;
    },
    verify: signer.verify.bind(signer),
  };
  const wiring = passportTestWiring({ fleetLookup: lookup, missionLookup: { findById: async () => ({
    mission_id: 'ms_test', operator_id: 'op_test',
    intent_services: ['slack'], expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null,
    // As in production: a fleet Mission is assigned to the worker, while the
    // root Passport is the fleet root's (delegated straight to that worker).
    assigned_agent_id: 'agt_worker' }) } });
  const service = Reflect.construct(PassportService, [repository, agentRepo, serviceRepo, capturingSigner,
    { get: async () => null },
    { findById: async () => ({ id: 'op_test', status: 'active' }) }, '',
    { transaction: async (work: (tx: unknown) => Promise<unknown>) => work({ execute: async () => undefined }) },
    wiring.dependencies,
  ]) as PassportService;
  const issue = (scopes = [scope]) => service.issueFleetMission('op_test', {
    agent_id: 'agt_root', scopes, intent: { summary: 'Support updates', services: ['slack'] },
  }, { child_agent_id: 'agt_worker', scopes }, binding, 'ses_mission');
  return { service, wiring, lookup, issue, rows, signedTokens, deadline, revoke: () => { active = false; } };
}

describe('fleet Passport authority', () => {
  it('resolves separately approved Authority bindings for the worker and exact Mission, never the internal root', async () => {
    const f = fixture();
    const resolvePassportRefs = vi.fn(async () => []);
    f.wiring.authorityLookup = { resolvePassportRefs, linkPassportRefs: vi.fn(async () => {}),
      verifyPassportRefs: vi.fn(async () => {}), delegatePassportRefs: vi.fn(async () => []) };
    await f.service.issueFleetMission('op_test', {
      agent_id: 'agt_root', scopes: [scope], authority_binding_ids: ['abn_worker'], intent: { summary: 'Support', services: ['slack'] },
    }, { child_agent_id: 'agt_worker', scopes: [scope] }, binding, 'ses_mission');
    expect(resolvePassportRefs).toHaveBeenCalledExactlyOnceWith({ operatorId: 'op_test', agentId: 'agt_worker', bindingIds: ['abn_worker'], missionIds: ['ms_test'] });
    expect((await signer.verify(f.signedTokens[0]!)).stk.authority_refs).toBeUndefined();
  });
  it('returns only a worker Passport and keeps the internal root unusable externally', async () => {
    const f = fixture();
    const worker = await f.issue();
    const claims = await f.service.verify(worker.token, { check_freshness: false });
    expect(claims.stk.fleet).toEqual(binding);
    expect(claims.stk.mission_ids).toEqual(['ms_test']);
    expect(claims.stk.agent_id).toBe('agt_worker');
    expect(claims.stk.session_id).toBe('ses_mission');
    expect(worker.expires_at.getTime()).toBeLessThanOrEqual(f.deadline.getTime());
    expect(f.rows.size).toBe(2);
    const rootToken = f.signedTokens[0]!;
    expect((await signer.verify(rootToken)).stk.fleet?.internal_root).toBe(true);
    await expect(f.service.verify(rootToken)).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(f.service.refresh('op_test', rootToken)).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(f.service.delegate('op_test', { parent_passport_token: rootToken,
      child_agent_id: 'agt_worker', scopes: [scope] })).rejects.toBeInstanceOf(PassportRevokedError);
  });

  it('checks live policy even when identity freshness is disabled and on renewal', async () => {
    const f = fixture();
    const worker = await f.issue();
    f.revoke();
    await expect(f.service.verify(worker.token, { check_freshness: false })).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(f.service.refresh('op_test', worker.token)).rejects.toBeInstanceOf(PassportRevokedError);
  });

  it('refuses legacy root issuance for an enrolled member', async () => {
    const f = fixture();
    await expect(f.service.issue('op_test', { agent_id: 'agt_worker' })).rejects.toBeInstanceOf(ForbiddenError);
    expect(f.rows.size).toBe(0);
  });

  it('checks old unbound Passports against membership and refuses missing Mission bindings', async () => {
    const f = fixture();
    const base = { operator_id: 'op_test', agent_id: 'agt_worker', agent_name: 'worker', services: [],
      identity_claims: [], delegation_depth: 0, session_id: 'ses_mission', accountability: 'enforced' as const };
    const old = await signer.sign('ppt_old', base, 60);
    await expect(f.service.verify(old.token, { check_freshness: false })).rejects.toBeInstanceOf(PassportRevokedError);
    const missingMission = await signer.sign('ppt_missing', { ...base, fleet: binding }, 60);
    await expect(f.service.verify(missingMission.token)).rejects.toBeInstanceOf(PassportRevokedError);
  });

  it('renews through a fresh private root while preserving Mission and session', async () => {
    const f = fixture();
    const first = await f.issue();
    const renewed = await f.issue();
    expect(renewed.jti).not.toBe(first.jti);
    const claims = await f.service.verify(renewed.token);
    expect(claims.stk.session_id).toBe('ses_mission');
    expect(claims.stk.fleet).toEqual(binding);
    expect(claims.stk.mission_ids).toEqual(['ms_test']);
  });

  it('refuses partial scope acceptance and delegation into another Mission', async () => {
    const f = fixture();
    await expect(f.issue([{ ...scope, scopes: ['chat:write', 'admin'] }])).rejects.toBeInstanceOf(ScopeEscalationError);
    expect(f.rows.size).toBe(0);
    vi.mocked(f.lookup.validateDelegation).mockResolvedValue({ ...binding, mission_id: 'ms_foreign' });
    await expect(f.issue()).rejects.toBeInstanceOf(PassportRevokedError);
  });

  it('round trips opaque refs and rejects malformed root flags', () => {
    const claims = { operator_id: 'op_test', agent_id: 'agt_worker', agent_name: 'worker', services: [],
      identity_claims: [], delegation_depth: 1, session_id: 'ses_test', fleet: binding };
    expect(PassportClaims.parse(claims).fleet).toEqual(binding);
    expect(PassportClaims.safeParse({ ...claims, fleet: { ...binding, internal_root: false } }).success).toBe(false);
  });
});
