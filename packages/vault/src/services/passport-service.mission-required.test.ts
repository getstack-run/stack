import { describe, it, expect, beforeAll } from 'vitest';
import { decodeProtectedHeader, generateKeyPair, importJWK, jwtVerify } from 'jose';
import { PassportSigner } from '../crypto/passport-signer.js';
import { PassportService, type MissionLookup } from './passport-service.js';
import { passportTestWiring, type PassportTestWiring } from './passport-service.test-support.js';
import { ForbiddenError, IssuePassportInput, NotFoundError } from '@stack/shared';

/**
 * every agent Passport is issued for exactly one live Mission.
 *
 * Schema (route layer, IssuePassportInput):
 *   S1: zero mission ids → rejected with a clear message
 *   S2: two mission ids → rejected
 *   S3: exactly one → accepted
 *   S4: platform_intent without a Mission → accepted (the one exemption)
 *   S5: platform_intent with a Mission → rejected
 *
 * Service (PassportService.issue, defense in depth):
 *   M0: zero missions → ForbiddenError
 *   M0b: two missions → ForbiddenError
 *   M1: a service cannot be constructed without a MissionLookup
 *   M2: unknown mission → NotFoundError
 *   M3: another operator's mission → NotFoundError (existence hidden). This
 *       is the white-label tenant rule: the partner route issues under the
 *       tenant's operator, so a partner-owned or sibling-tenant Mission fails here.
 *   M4: completed mission → ForbiddenError
 *   M5: revoked mission → ForbiddenError
 *   M5b: expired mission → ForbiddenError
 *   M6/M7b: Passport grants do not cover the Mission's services → ForbiddenError
 *   M7: success — the one mission id rides on the JWT and the DB row
 *   M9: the Passport never outlives its Mission (TTL clamped)
 *   P1: platform_intent Passport is issued with no Mission
 *   P2: platform_intent Passport carrying a Mission is refused
 *
 * Revoke direction (an earlier change removed the 5.0.3 orphan cascade):
 *   R1: revoking a Passport never calls into the Mission
 */

const OPERATOR_ID = 'op_mission_test';
const SYSTEM_OP = 'op_stack_system';

const ACTIVE_AGENT = {
  id: 'agt_test',
  operator_id: OPERATOR_ID,
  status: 'active' as const,
  passport_blocked: false,
  accountability_mode: 'standard' as const,
  name: 'agent',
  pubkey: null,
};

interface Stubs {
  passportRepo: ConstructorParameters<typeof PassportService>[0];
  agentRepo: ConstructorParameters<typeof PassportService>[1];
  serviceRepo: ConstructorParameters<typeof PassportService>[2];
  redis: ConstructorParameters<typeof PassportService>[4];
  operatorRepo: ConstructorParameters<typeof PassportService>[5];
  createdRows: Array<Record<string, unknown>>;
}

function grantFor(provider: string) {
  return {
    grant: { service_connection_id: `scon_${provider}`, scopes: ['*'], constraints: [] },
    connection: {
      id: `scon_${provider}`,
      service_id: `svc_${provider}`,
      provider,
      status: 'active',
      credential_ref: `ref_${provider}`,
      operator_id: OPERATOR_ID,
    },
  };
}

function makeStubs(opts?: {
  existingPassport?: { jti: string; operator_id: string; mission_ids: string[] | null; expires_at: Date };
  grants?: ReturnType<typeof grantFor>[];
  platformStaff?: boolean;
}): Stubs {
  const createdRows: Array<Record<string, unknown>> = [];
  const passportRepo = {
    create: async (row: Record<string, unknown>) => {
      createdRows.push(row);
      return row;
    },
    findByJti: async () =>
      opts?.existingPassport ? { ...opts.existingPassport, revoked_at: null, revoked_reason: null } : null,
    findActiveChildren: async () => [],
    revoke: async () => undefined,
    isRevoked: async () => false,
  } as unknown as ConstructorParameters<typeof PassportService>[0];
  const agentRepo = {
    findById: async (id: string) => (id === ACTIVE_AGENT.id ? { ...ACTIVE_AGENT, id } : null),
  } as unknown as ConstructorParameters<typeof PassportService>[1];
  const serviceRepo = {
    findGrantsWithConnectionByAgent: async () => opts?.grants ?? [],
  } as unknown as ConstructorParameters<typeof PassportService>[2];
  const redis = {
    set: async () => 'OK',
    get: async () => null,
    publish: async () => 1,
    pipeline: () => ({ set: () => undefined, exec: async () => [] }),
  } as unknown as ConstructorParameters<typeof PassportService>[4];
  const operatorRepo = {
    findById: async (id: string) =>
      id === OPERATOR_ID ? { id, status: 'active', is_platform_staff: opts?.platformStaff ?? false } : null,
  } as unknown as ConstructorParameters<typeof PassportService>[5];
  return { passportRepo, agentRepo, serviceRepo, redis, operatorRepo, createdRows };
}

type MissionFixture = {
  operator_id: string;
  intent_services: string[];
  expires_at?: Date;
  completed_at?: Date | null;
  revoked_at?: Date | null;
  assigned_agent_id?: string | null;
};

function makeMissionLookup(fixtures: Record<string, MissionFixture>): { lookup: MissionLookup; lookups: string[] } {
  const lookups: string[] = [];
  return {
    lookups,
    lookup: {
      async findById(missionId) {
        lookups.push(missionId);
        const m = fixtures[missionId];
        if (!m) return null;
        return {
          mission_id: missionId,
          operator_id: m.operator_id,
          intent_services: m.intent_services,
          expires_at: m.expires_at ?? new Date(Date.now() + 3_600_000),
          completed_at: m.completed_at ?? null,
          revoked_at: m.revoked_at ?? null,
          assigned_agent_id: m.assigned_agent_id ?? null,
        };
      },
    },
  };
}

const wirings = new WeakMap<PassportService, PassportTestWiring>();

const txDb = {
  transaction: async <T>(work: (tx: { execute: () => Promise<unknown> }) => Promise<T>) =>
    work({ execute: async () => undefined }),
} as unknown as ConstructorParameters<typeof PassportService>[7];

function makeService(stubs: Stubs, signer: PassportSigner): PassportService {
  const wiring = passportTestWiring();
  const service = new PassportService(stubs.passportRepo, stubs.agentRepo, stubs.serviceRepo, signer,
    stubs.redis, stubs.operatorRepo, SYSTEM_OP, txDb, wiring.dependencies);
  wirings.set(service, wiring);
  return service;
}

/** The Mission lookup the service reads on its next call, as the composition root's accessor would. */
function useMissionLookup(service: PassportService, lookup: MissionLookup): void {
  wirings.get(service)!.missionLookup = lookup;
}

const LIVE = { ms_ok: { operator_id: OPERATOR_ID, intent_services: [] as string[] } };

describe('IssuePassportInput — exactly one Mission', () => {
  it('S1: rejects a Passport with no Mission and says how to fix it', () => {
    const parsed = IssuePassportInput.safeParse({ agent_id: 'agt_x' });
    expect(parsed.success).toBe(false);
    expect(parsed.error!.issues[0]!.path).toEqual(['mission_ids']);
    expect(parsed.error!.issues[0]!.message).toMatch(/exactly one Mission/);
    expect(IssuePassportInput.safeParse({ agent_id: 'agt_x', mission_ids: [] }).success).toBe(false);
  });

  it('S2: rejects two Missions', () => {
    expect(IssuePassportInput.safeParse({ agent_id: 'agt_x', mission_ids: ['ms_a', 'ms_b'] }).success).toBe(false);
  });

  it('S3: accepts exactly one Mission', () => {
    expect(IssuePassportInput.parse({ agent_id: 'agt_x', mission_ids: ['ms_a'] }).mission_ids).toEqual(['ms_a']);
  });

  it('S4: exempts a platform Passport, which carries no Mission', () => {
    expect(IssuePassportInput.safeParse({
      agent_id: 'agt_x',
      intent: { summary: 'staff', services: [], platform_intent: 'staff' },
    }).success).toBe(true);
  });

  it('S5: rejects a platform Passport that names a Mission', () => {
    expect(IssuePassportInput.safeParse({
      agent_id: 'agt_x',
      mission_ids: ['ms_a'],
      intent: { summary: 'staff', services: [], platform_intent: 'staff' },
    }).success).toBe(false);
  });
});

describe('PassportService.issue — exactly one live Mission', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  it('M0: no Mission → ForbiddenError, nothing persisted', async () => {
    const stubs = makeStubs();
    const svc = makeService(stubs, signer);
    useMissionLookup(svc, makeMissionLookup(LIVE).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id })).rejects.toBeInstanceOf(ForbiddenError);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: [] }))
      .rejects.toBeInstanceOf(ForbiddenError);
    expect(stubs.createdRows).toHaveLength(0);
  });

  it('M0b: two Missions → ForbiddenError, nothing persisted', async () => {
    const stubs = makeStubs();
    const svc = makeService(stubs, signer);
    useMissionLookup(svc, makeMissionLookup({ ...LIVE, ms_two: { operator_id: OPERATOR_ID, intent_services: [] } }).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_ok', 'ms_two'] }))
      .rejects.toBeInstanceOf(ForbiddenError);
    expect(stubs.createdRows).toHaveLength(0);
  });

  it('M1: a service cannot be constructed without a MissionLookup', () => {
    const stubs = makeStubs();
    const { missionLookup: _omitted, ...rest } = passportTestWiring().dependencies;
    void _omitted;
    expect(() => new PassportService(stubs.passportRepo, stubs.agentRepo, stubs.serviceRepo, signer,
      stubs.redis, stubs.operatorRepo, SYSTEM_OP, txDb, rest as never))
      .toThrow(/requires its missionLookup dependency/);
  });

  it('M2: unknown Mission → NotFoundError', async () => {
    const svc = makeService(makeStubs(), signer);
    useMissionLookup(svc, makeMissionLookup({}).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_unknown'] }))
      .rejects.toBeInstanceOf(NotFoundError);
  });

  it('M3: another operator\'s (or tenant\'s) Mission → NotFoundError, existence hidden', async () => {
    const svc = makeService(makeStubs(), signer);
    useMissionLookup(svc, makeMissionLookup({ ms_other: { operator_id: 'op_partner_parent', intent_services: [] } }).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_other'] }))
      .rejects.toBeInstanceOf(NotFoundError);
  });

  it('M4: completed Mission → ForbiddenError', async () => {
    const svc = makeService(makeStubs(), signer);
    useMissionLookup(svc, makeMissionLookup({
      ms_done: { operator_id: OPERATOR_ID, intent_services: [], completed_at: new Date() },
    }).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_done'] }))
      .rejects.toThrow(/completed/);
  });

  it('M5: revoked Mission → ForbiddenError', async () => {
    const svc = makeService(makeStubs(), signer);
    useMissionLookup(svc, makeMissionLookup({
      ms_killed: { operator_id: OPERATOR_ID, intent_services: [], revoked_at: new Date() },
    }).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_killed'] }))
      .rejects.toThrow(ForbiddenError);
  });

  it('M5b: expired Mission (not yet swept) → ForbiddenError', async () => {
    const svc = makeService(makeStubs(), signer);
    useMissionLookup(svc, makeMissionLookup({
      ms_stale: { operator_id: OPERATOR_ID, intent_services: [], expires_at: new Date(Date.now() - 1000) },
    }).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_stale'] }))
      .rejects.toThrow(/expired/);
  });

  it('M6: Passport grants do not cover the Mission\'s services → ForbiddenError', async () => {
    const svc = makeService(makeStubs(), signer);
    useMissionLookup(svc, makeMissionLookup({ ms_stripe: { operator_id: OPERATOR_ID, intent_services: ['stripe'] } }).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_stripe'] }))
      .rejects.toThrow(/Missing: \[stripe\]/);
  });

  it('M7b: intent cannot stand in for a missing grant → ForbiddenError', async () => {
    const svc = makeService(makeStubs(), signer);
    useMissionLookup(svc, makeMissionLookup({ ms_slack: { operator_id: OPERATOR_ID, intent_services: ['slack'] } }).lookup);
    await expect(svc.issue(OPERATOR_ID, {
      agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_slack'], intent: { summary: 'test', services: ['slack'] },
    })).rejects.toThrow(ForbiddenError);
  });

  it('M7: one live Mission covered by the grants → issued; the Mission rides on the JWT and the row', async () => {
    const stubs = makeStubs({ grants: [grantFor('slack')] });
    const svc = makeService(stubs, signer);
    const { lookup, lookups } = makeMissionLookup({ ms_slack: { operator_id: OPERATOR_ID, intent_services: ['slack'] } });
    useMissionLookup(svc, lookup);
    const result = await svc.issue(OPERATOR_ID, {
      agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_slack'], intent: { summary: 'test', services: ['slack'] },
    });
    const claims = await signer.verify(result.token);
    expect(claims.stk.mission_ids).toEqual(['ms_slack']);
    expect(stubs.createdRows).toHaveLength(1);
    expect(stubs.createdRows[0]!.mission_ids).toEqual(['ms_slack']);
    // Validated before the operator lock and re-read under it.
    expect(lookups).toEqual(['ms_slack', 'ms_slack']);
  });

  it("M10: a tenant's Passport is signed with the deployment key; the tenant's own claim key cannot verify it", async () => {
    // The partner route issues under the tenant's operator. Which key set checks that Passport is the deployment's:
    // the signer has one key and no operator parameter, and a tenant's per-operator keys (kid <operator>:claim:vN)
    // sign claim envelopes. Documentation that sent verifiers to the tenant's JWKS contradicted this.
    const stubs = makeStubs({ grants: [grantFor('slack')] });
    const svc = makeService(stubs, signer);
    useMissionLookup(svc, makeMissionLookup({ ms_slack: { operator_id: OPERATOR_ID, intent_services: ['slack'] } }).lookup);
    const { token } = await svc.issue(OPERATOR_ID, {
      agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_slack'], intent: { summary: 'test', services: ['slack'] },
    });

    const header = decodeProtectedHeader(token);
    expect(header.kid).toBe((await signer.getPublicJwk()).kid);
    expect(header.kid).not.toContain(':claim:');

    const deployment = await jwtVerify(token, await importJWK(await signer.getPublicJwk(), 'EdDSA'),{ audience: 'stack:passport' });
    expect((deployment.payload['stk'] as { operator_id: string }).operator_id).toBe(OPERATOR_ID);

    const tenantClaimKey = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    await expect(jwtVerify(token, tenantClaimKey.publicKey, { audience: 'stack:passport' })).rejects.toThrow();
  });

  it("M8: a Mission opened for another agent binds none of this agent's Passports", async () => {
    const stubs = makeStubs();
    const svc = makeService(stubs, signer);
    useMissionLookup(svc, makeMissionLookup({
      ms_theirs: { operator_id: OPERATOR_ID, intent_services: [], assigned_agent_id: 'agt_someone_else' },
    }).lookup);
    await expect(svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_theirs'] }))
      .rejects.toThrow(/assigned to another agent/);
    expect(stubs.createdRows).toHaveLength(0);
  });

  it('M8b: a Mission opened for this agent binds its Passport', async () => {
    const stubs = makeStubs();
    const svc = makeService(stubs, signer);
    useMissionLookup(svc, makeMissionLookup({
      ms_mine: { operator_id: OPERATOR_ID, intent_services: [], assigned_agent_id: ACTIVE_AGENT.id },
    }).lookup);
    await svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_mine'] });
    expect(stubs.createdRows).toHaveLength(1);
  });

  it('M9: the Passport expires no later than its Mission', async () => {
    const stubs = makeStubs();
    const svc = makeService(stubs, signer);
    const missionEnd = new Date(Date.now() + 120_000);
    useMissionLookup(svc, makeMissionLookup({
      ms_short: { operator_id: OPERATOR_ID, intent_services: [], expires_at: missionEnd },
    }).lookup);
    const result = await svc.issue(OPERATOR_ID, { agent_id: ACTIVE_AGENT.id, mission_ids: ['ms_short'], ttl_seconds: 3600 });
    expect(result.expires_at.getTime()).toBeLessThanOrEqual(missionEnd.getTime());
    expect(result.expires_at.getTime()).toBeGreaterThan(Date.now() + 60_000);
  });

  it('P1: a platform Passport is issued with no Mission', async () => {
    const stubs = makeStubs({ platformStaff: true });
    const svc = makeService(stubs, signer);
    const { lookup, lookups } = makeMissionLookup(LIVE);
    useMissionLookup(svc, lookup);
    const result = await svc.issue(OPERATOR_ID, {
      agent_id: ACTIVE_AGENT.id,
      intent: { summary: 'staff check', services: [], platform_intent: 'staff' },
    });
    const claims = await signer.verify(result.token);
    expect(claims.stk.platform_intent).toBe('staff');
    expect(claims.stk.mission_ids).toBeUndefined();
    expect(lookups).toEqual([]);
  });

  it('P2: a platform Passport that names a Mission is refused', async () => {
    const svc = makeService(makeStubs({ platformStaff: true }), signer);
    useMissionLookup(svc, makeMissionLookup(LIVE).lookup);
    await expect(svc.issue(OPERATOR_ID, {
      agent_id: ACTIVE_AGENT.id,
      mission_ids: ['ms_ok'],
      intent: { summary: 'staff check', services: [], platform_intent: 'staff' },
    })).rejects.toBeInstanceOf(ForbiddenError);
  });
});

describe('PassportService.revoke — never ends the Mission', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  it('R1: revoking the last Passport of a Mission does not look up or touch the Mission', async () => {
    const stubs = makeStubs({
      existingPassport: {
        jti: 'pas_to_revoke', operator_id: OPERATOR_ID, mission_ids: ['ms_ok'], expires_at: new Date(Date.now() + 60_000),
      },
    });
    const svc = makeService(stubs, signer);
    const { lookup, lookups } = makeMissionLookup(LIVE);
    useMissionLookup(svc, lookup);
    await svc.revoke({ jti: 'pas_to_revoke', operatorId: OPERATOR_ID, reason: 'user_initiated' });
    expect(lookups).toEqual([]);
  });
});
