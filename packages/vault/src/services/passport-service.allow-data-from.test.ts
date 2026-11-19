import { describe, it, expect, beforeAll, vi } from 'vitest';
import { PassportSigner } from '../crypto/passport-signer.js';
import { PassportService } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';
import { DelegationAccountabilityError, ForbiddenError, PassportExpiredError, PassportRevokedError, ScopeEscalationError, evaluateDataFlow } from '@stack/shared';

/** every agent Passport is bound to exactly one live Mission. */
const TEST_MISSION_ID = 'ms_test_live';
function liveMissionLookup(operatorId: string) {
  return {
    findById: async (missionId: string) => ({
      mission_id: missionId, operator_id: operatorId, intent_services: [] as string[],
      expires_at: new Date(Date.now() + 3_600_000), completed_at: null, revoked_at: null,
    }),
  };
}

function liveMissionDependencies() {
  return passportTestWiring({ missionLookup: liveMissionLookup(OPERATOR_ID) }).dependencies;
}

/**
 * allow_data_from as a CUSTOMER-SETTABLE control.
 *
 * The scope wall already ENFORCES allow_data_from on the signed ServiceScope
 * (apps/api/src/lib/scope-wall.ts + packages/shared data-flow.ts). What was
 * missing was the input path: a way to SET it. These tests prove that path
 * end to end:
 *
 *   ISSUE
 *     I1  a per-scope subset of the grant lands on the signed ServiceScope
 *     I2  omitting it inherits the grant's baseline ceiling
 *     I3  declaring a flow the grant ceiling does not contain is rejected
 *         (fail closed)
 *     I4  with no standing grant, a Passport cannot introduce a flow
 *     I5  a grant wildcard snapshots the agent's active providers
 *
 *   DELEGATION (the security invariant — a child must never GAIN a flow)
 *     D1  a widening child allow_data_from is REJECTED (ScopeEscalationError)
 *     D2  a narrowing (subset) child is accepted and lands on the child scope
 *     D3  omitting it inherits the parent scope's declaration
 *
 *   END TO END
 *     E1  a call the data-flow rule REFUSES flips to ALLOWED once the flow is
 *         declared via the public issue input — driven through the real
 *         evaluateDataFlow used by the scope wall
 */

const OPERATOR_ID = 'op_adf_test';
const SYSTEM_OP = 'op_stack_system';

const PARENT_AGENT = {
  id: 'agt_parent',
  operator_id: OPERATOR_ID,
  status: 'active' as const,
  passport_blocked: false,
  accountability_mode: 'standard' as const,
  name: 'parent',
  pubkey: null,
};
const CHILD_AGENT = { ...PARENT_AGENT, id: 'agt_child', name: 'child' };

// A granted resend connection. `allowDataFrom` sets the grant-time baseline
// ceiling (grant.allow_data_from column); default none.
function grantResend(allowDataFrom?: string[]) {
  return {
    grant: {
      service_connection_id: 'scon_resend',
      scopes: ['*'],
      constraints: [],
      allow_data_from: allowDataFrom ?? null,
    },
    connection: {
      id: 'scon_resend',
      // Grant freshness binds the connection to the signed tenant. Omitting
      // ownership here would model an unowned/cross-tenant row that production
      // must revoke before delegation or refresh.
      operator_id: OPERATOR_ID,
      service_id: 'svc_resend',
      provider: 'resend',
      status: 'active',
      credential_ref: 'ref_resend',
    },
  };
}

function grantSource(provider: string) {
  return {
    grant: {
      service_connection_id: `scon_${provider}`,
      scopes: ['*'],
      constraints: [],
      allow_data_from: null,
    },
    connection: {
      id: `scon_${provider}`,
      operator_id: OPERATOR_ID,
      service_id: `svc_${provider}`,
      provider,
      status: 'active',
      credential_ref: `ref_${provider}`,
    },
  };
}

function makeStubs(grants: ReturnType<typeof grantResend>[], grantOwner?: string) {
  const createdRows: Array<Record<string, unknown>> = [];
  const connById = new Map(grants.map((g) => [g.connection.id, g.connection]));

  const passportRepo = {
    create: async (row: Record<string, unknown>) => {
      createdRows.push(row);
      return row;
    },
    findByJti: async (jti: string) => createdRows.find((row) => row.jti === jti) ?? null,
    findActiveChildren: async (_jti: string) => [],
    revoke: async () => undefined,
    isRevoked: async () => false,
  } as unknown as ConstructorParameters<typeof PassportService>[0];

  const agentRepo = {
    findById: async (id: string) =>
      id === PARENT_AGENT.id ? PARENT_AGENT : id === CHILD_AGENT.id ? CHILD_AGENT : null,
  } as unknown as ConstructorParameters<typeof PassportService>[1];

  const serviceRepo = {
    findGrantsWithConnectionByAgent: async (agentId: string) => !grantOwner || agentId === grantOwner ? grants : [],
    // delegate()'s verify() freshness check reads this per parent scope.
    findConnectionById: async (id: string) => connById.get(id) ?? null,
  } as unknown as ConstructorParameters<typeof PassportService>[2];

  const redis = {
    set: async () => 'OK',
    get: async () => null,
    publish: async () => 1,
    pipeline: () => ({ set: () => undefined, exec: async () => [] }),
  } as unknown as ConstructorParameters<typeof PassportService>[4];

  const operatorRepo = {
    findById: async (id: string) => (
      id === OPERATOR_ID ? { id, status: 'active', is_platform_staff: false } : null
    ),
  } as unknown as ConstructorParameters<typeof PassportService>[5];

  const db = {
    transaction: async <T>(work: (tx: { execute: () => Promise<unknown> }) => Promise<T>) =>
      work({ execute: async () => undefined }),
  } as unknown as ConstructorParameters<typeof PassportService>[7];

  return { passportRepo, agentRepo, serviceRepo, redis, operatorRepo, createdRows, db };
}

function makeService(grants: ReturnType<typeof grantResend>[], signer: PassportSigner, grantOwner?: string) {
  const stubs = makeStubs(grants, grantOwner);
  const service = new PassportService(
    stubs.passportRepo,
    stubs.agentRepo,
    stubs.serviceRepo,
    signer,
    stubs.redis,
    stubs.operatorRepo,
    SYSTEM_OP,
    stubs.db,
    liveMissionDependencies(),
  );
  return service;
}

/** The resend ServiceScope carried on a signed passport token. */
async function resendScope(signer: PassportSigner, token: string) {
  const claims = await signer.verify(token);
  return claims.stk.services.find((s: { service_name: string }) => s.service_name === 'resend') as
    | { service_name: string; allow_data_from?: string[] }
    | undefined;
}

describe('PassportService.issue — allow_data_from threading', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  it('I1: a per-scope allow_data_from lands on the signed ServiceScope', async () => {
    const svc = makeService([grantResend(['guestbook'])], signer);
    const { token } = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [
        { service_connection_id: 'scon_resend', scopes: ['*'], allow_data_from: ['guestbook'] },
      ],
    });
    expect((await resendScope(signer, token))?.allow_data_from).toEqual(['guestbook']);
  });

  it('I2: omitting it inherits the grant baseline ceiling', async () => {
    const svc = makeService([grantResend(['guestbook'])], signer);
    const { token } = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    expect((await resendScope(signer, token))?.allow_data_from).toEqual(['guestbook']);
  });

  it('I3: declaring a flow beyond the grant ceiling is rejected (fail closed)', async () => {
    const svc = makeService([grantResend(['guestbook'])], signer);
    await expect(
      svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
        agent_id: PARENT_AGENT.id,
        scopes: [
          {
            service_connection_id: 'scon_resend',
            scopes: ['*'],
            allow_data_from: ['guestbook', 'slack'], // slack not in the ceiling
          },
        ],
      }),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('I4: with no standing grant, a Passport cannot introduce a flow', async () => {
    const svc = makeService([grantResend()], signer);
    await expect(
      svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
        agent_id: PARENT_AGENT.id,
        scopes: [
          { service_connection_id: 'scon_resend', scopes: ['*'], allow_data_from: ['guestbook'] },
        ],
      }),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('I5: a grant wildcard snapshots active providers as exact names', async () => {
    const svc = makeService(
      [grantResend(['*']), grantSource('guestbook'), grantSource('slack')],
      signer,
    );
    const { token } = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    expect((await resendScope(signer, token))?.allow_data_from).toEqual(['guestbook', 'slack']);
  });
});

describe('PassportService.delegate — allow_data_from narrowing (SECURITY)', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  // A parent passport whose resend scope permits the guestbook->resend flow.
  async function issueParent(svc: PassportService): Promise<string> {
    const { token } = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [
        { service_connection_id: 'scon_resend', scopes: ['*'], allow_data_from: ['guestbook'] },
      ],
    });
    return token;
  }

  it('D1: a widening child allow_data_from is REJECTED (fail closed)', async () => {
    const svc = makeService([grantResend(['guestbook'])], signer);
    const parentToken = await issueParent(svc);
    await expect(
      svc.delegate(OPERATOR_ID, {
        parent_passport_token: parentToken,
        child_agent_id: CHILD_AGENT.id,
        scopes: [
          {
            service_connection_id: 'scon_resend',
            scopes: ['*'],
            allow_data_from: ['guestbook', 'slack'], // slack: a flow the parent lacked
          },
        ],
      }),
    ).rejects.toBeInstanceOf(ScopeEscalationError);
  });

  it('D2: a narrowing (subset) child is accepted and lands on the child scope', async () => {
    const svc = makeService([grantResend(['guestbook'])], signer);
    const parentToken = await issueParent(svc);
    const { token } = await svc.delegate(OPERATOR_ID, {
      parent_passport_token: parentToken,
      child_agent_id: CHILD_AGENT.id,
      scopes: [
        { service_connection_id: 'scon_resend', scopes: ['*'], allow_data_from: [] }, // narrow to none
      ],
    });
    expect((await resendScope(signer, token))?.allow_data_from).toEqual([]);
  });

  it('D3: omitting it inherits the parent scope declaration', async () => {
    const svc = makeService([grantResend(['guestbook'])], signer);
    const parentToken = await issueParent(svc);
    const { token } = await svc.delegate(OPERATOR_ID, {
      parent_passport_token: parentToken,
      child_agent_id: CHILD_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    expect((await resendScope(signer, token))?.allow_data_from).toEqual(['guestbook']);
  });
});

describe('END TO END — the standing grant controls the scope wall', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  // The scope wall builds exactly this call into evaluateDataFlow: an entity
  // the agent read from "guestbook" is now leaving through a resend call.
  const observed = [{ value: 'alice.johnson@example.com', kind: 'entity' as const, service: 'guestbook' }];
  const dataFlowFor = (allowDataFrom: string[] | undefined) =>
    evaluateDataFlow({
      destinationService: 'resend',
      outboundEntities: ['alice.johnson@example.com'],
      outboundText: [],
      observed,
      declaredFlows: (allowDataFrom ?? []).map((from) => ({ from, to: 'resend' })),
    });

  it('E1: refused without a grant, allowed after the operator grants the source', async () => {
    const withoutFlow = makeService([grantResend()], signer);
    const bare = await withoutFlow.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    const bareScope = await resendScope(signer, bare.token);
    expect(bareScope?.allow_data_from).toBeUndefined();
    const refused = dataFlowFor(bareScope?.allow_data_from);
    expect(refused).not.toBeNull();
    expect(refused?.sourceService).toBe('guestbook');
    expect(refused?.destinationService).toBe('resend');

    // The operator's standing grant is inherited without the agent adding
    // anything to the issue request. The identical movement is now allowed.
    const withFlow = makeService([grantResend(['guestbook'])], signer);
    const declared = await withFlow.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    const declaredScope = await resendScope(signer, declared.token);
    expect(declaredScope?.allow_data_from).toEqual(['guestbook']);
    expect(dataFlowFor(declaredScope?.allow_data_from)).toBeNull();
  });
});

describe('PassportService.refresh — the grant baseline survives refresh', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  it('R1: a grant-declared allow_data_from survives refresh (the agent does not over-block after refresh)', async () => {
    const svc = makeService([grantResend(['guestbook'])], signer);
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    expect((await resendScope(signer, issued.token))?.allow_data_from).toEqual(['guestbook']);

    // Before the fix, refresh re-derived scope from the grant but DROPPED
    // allow_data_from → the refreshed passport refused its own cross-service work.
    const refreshed = await svc.refresh(OPERATOR_ID, issued.token);
    expect((await resendScope(signer, refreshed.token))?.allow_data_from).toEqual(['guestbook']);
  });

  it('R2: a grant constraint survives refresh (no fail-open widening past the parameter guard)', async () => {
    const g = grantResend();
    (g.grant as { constraints: unknown }).constraints = [
      { path: 'body.channel', op: 'eq', value: 'C123' },
    ];
    const svc = makeService([g], signer);
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    // Before the fix, refresh dropped the grant's constraints → the refreshed
    // passport widened past its channel guard.
    const refreshed = await svc.refresh(OPERATOR_ID, issued.token);
    const claims = await signer.verify(refreshed.token);
    const scope = claims.stk.services.find(
      (s: { service_name: string }) => s.service_name === 'resend',
    ) as { constraints?: Array<{ path: string }> } | undefined;
    expect(scope?.constraints?.some((c) => c.path === 'body.channel')).toBe(true);
  });

  it('R3: refresh keeps the signed scope selection, constraints and narrowed data flows', async () => {
    const granted = grantResend(['guestbook', 'github']);
    granted.grant.scopes = ['read', 'write'];
    const svc = makeService([granted, grantSource('github')], signer);
    const restriction = { path: 'body.channel', op: 'eq' as const, value: 'C_PRIVATE' };
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{
        service_connection_id: 'scon_resend',
        scopes: ['read'],
        constraints: [restriction],
        allow_data_from: ['guestbook'],
      }],
    });

    const refreshed = await svc.refresh(OPERATOR_ID, issued.token);
    const claims = await signer.verify(refreshed.token);
    expect(claims.stk.services).toHaveLength(1);
    expect(claims.stk.services[0]).toMatchObject({
      connection_id: 'scon_resend',
      scopes: ['read'],
      constraints: [restriction],
      allow_data_from: ['guestbook'],
    });
  });

  it('R4: delegated refresh cannot extend beyond the parent lifetime', async () => {
    const svc = makeService([grantResend()], signer);
    const parent = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      ttl_seconds: 60,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    const child = await svc.delegate(OPERATOR_ID, {
      parent_passport_token: parent.token,
      child_agent_id: CHILD_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });

    const refreshed = await svc.refresh(OPERATOR_ID, child.token, 3600);
    const claims = await signer.verify(refreshed.token);
    expect(claims.exp).toBeLessThanOrEqual((await signer.verify(parent.token)).exp);
  });

  it('R5: later grant restrictions narrow refresh without erasing earlier restrictions', async () => {
    const granted = grantResend(['guestbook', 'github']);
    granted.grant.scopes = ['read', 'write'];
    const svc = makeService([granted], signer);
    const original = { path: 'body.channel', op: 'eq' as const, value: 'C_PRIVATE' };
    const later = { path: 'method', op: 'eq' as const, value: 'GET' };
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['read', 'write'], constraints: [original], allow_data_from: ['guestbook'] }],
    });
    granted.grant.scopes = ['read'];
    granted.grant.allow_data_from = ['github'];
    (granted.grant as { constraints: unknown }).constraints = [later];
    const first = await svc.refresh(OPERATOR_ID, issued.token);
    const second = await svc.refresh(OPERATOR_ID, first.token);
    expect((await signer.verify(second.token)).stk.services[0]).toMatchObject({
      scopes: ['read'], constraints: [original, later], allow_data_from: [],
    });
  });

  it('R6: a delegated child retains inherited permission without a separate standing grant', async () => {
    const svc = makeService([grantResend()], signer, PARENT_AGENT.id);
    const parent = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: PARENT_AGENT.id });
    const child = await svc.delegate(OPERATOR_ID, {
      parent_passport_token: parent.token, child_agent_id: CHILD_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'], constraints: [{ path: 'method', op: 'eq', value: 'GET' }] }],
    });
    const renewed = await svc.refresh(OPERATOR_ID, child.token);
    expect((await signer.verify(renewed.token)).stk.services).toEqual((await signer.verify(child.token)).stk.services.map((scope) => ({ ...scope, allow_data_from: [] })));
  });

  it('R7: refresh preserves the declared job and delegation permission', async () => {
    const stubs = makeStubs([grantResend()]);
    const svc = new PassportService(stubs.passportRepo, stubs.agentRepo, stubs.serviceRepo, signer,
      stubs.redis, stubs.operatorRepo, SYSTEM_OP, stubs.db, liveMissionDependencies());
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      intent: { summary: 'Read the approved channel', services: ['resend'], will_delegate: true },
    });
    const renewed = await svc.refresh(OPERATOR_ID, issued.token);
    expect((await signer.verify(renewed.token)).stk).toMatchObject({
      accountability: 'standard', intent_summary: 'Read the approved channel', intent_services: ['resend'],
    });
    expect(stubs.createdRows.at(-1)).toMatchObject({ intent_delegates: true, intent_summary: 'Read the approved channel' });
  });

  it('R8: refresh preserves a closed operation policy', async () => {
    const svc = makeService([grantResend()], signer);
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: PARENT_AGENT.id });
    const claims = await signer.verify(issued.token);
    claims.stk.services[0]!.policy = { mode: 'closed', operations: [] };
    const restricted = await signer.sign(issued.jti, claims.stk, 300);
    const renewed = await svc.refresh(OPERATOR_ID, restricted.token);
    expect((await signer.verify(renewed.token)).stk.services[0]!.policy).toEqual({ mode: 'closed', operations: [] });
  });

  it('R9: a slow grant lookup cannot renew a child after its signed deadline', async () => {
    const granted = [grantResend()];
    const stubs = makeStubs(granted);
    const svc = new PassportService(stubs.passportRepo, stubs.agentRepo, stubs.serviceRepo, signer,
      stubs.redis, stubs.operatorRepo, SYSTEM_OP, stubs.db, liveMissionDependencies());
    const parent = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID], agent_id: PARENT_AGENT.id });
    const child = await svc.delegate(OPERATOR_ID, {
      parent_passport_token: parent.token, child_agent_id: CHILD_AGENT.id, scopes: [], ttl_seconds: 60,
    });
    const deadline = (await signer.verify(child.token)).exp * 1000;
    vi.useFakeTimers({ toFake: ['Date'] });
    const lookup = vi.spyOn(stubs.serviceRepo, 'findGrantsWithConnectionByAgent').mockImplementation(async () => {
      vi.setSystemTime(deadline + 1000);
      return granted as never;
    });
    try {
      const denied = await svc.refresh(OPERATOR_ID, child.token).then(
        () => false, (error: unknown) => error instanceof PassportExpiredError,
      );
      expect(denied).toBe(true);
    } finally {
      lookup.mockRestore();
      vi.useRealTimers();
    }
  });

  it('D4: an enforced child retains the declared job and inherited checkpoint interval', async () => {
    const stubs = makeStubs([grantResend()]);
    vi.spyOn(stubs.agentRepo, 'findById').mockImplementation(async (id) => ({
      ...(id === PARENT_AGENT.id ? PARENT_AGENT : CHILD_AGENT), accountability_mode: 'enforced',
    }) as never);
    const svc = new PassportService(stubs.passportRepo, stubs.agentRepo, stubs.serviceRepo, signer,
      stubs.redis, stubs.operatorRepo, SYSTEM_OP, stubs.db, liveMissionDependencies());
    const parent = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id, checkpoint_interval_seconds: 60,
      intent: { summary: 'Read approved records', services: ['resend'], will_delegate: true },
    });
    const child = await svc.delegate(OPERATOR_ID, {
      parent_passport_token: parent.token, child_agent_id: CHILD_AGENT.id, scopes: [],
    });
    expect((await signer.verify(child.token)).stk).toMatchObject({
      accountability: 'enforced', intent_summary: 'Read approved records', checkpoint_interval: 60,
    });
    expect(stubs.createdRows.at(-1)).toMatchObject({
      intent_summary: 'Read approved records', intent_delegates: true, checkpoint_interval_seconds: 60,
    });
  });

  it('D5: a later agent setting cannot lower the signed parent accountability floor', async () => {
    const stubs = makeStubs([grantResend()]);
    let parentMode = 'enforced';
    vi.spyOn(stubs.agentRepo, 'findById').mockImplementation(async (id) => ({
      ...(id === PARENT_AGENT.id ? PARENT_AGENT : CHILD_AGENT),
      accountability_mode: id === PARENT_AGENT.id ? parentMode : 'standard',
    }) as never);
    const svc = new PassportService(stubs.passportRepo, stubs.agentRepo, stubs.serviceRepo, signer,
      stubs.redis, stubs.operatorRepo, SYSTEM_OP, stubs.db, liveMissionDependencies());
    const parent = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      intent: { summary: 'Read approved records', services: ['resend'], will_delegate: true },
    });
    parentMode = 'standard';
    const refused = await svc.delegate(OPERATOR_ID, {
      parent_passport_token: parent.token, child_agent_id: CHILD_AGENT.id, scopes: [],
    }).then(() => false, (error: unknown) => error instanceof DelegationAccountabilityError);
    expect(refused).toBe(true);
  });
});

describe('PassportService.verify — live grant tenant binding (SECURITY)', () => {
  let signer: PassportSigner;
  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init();
  });

  it('revokes a passport when its connection resolves to another tenant', async () => {
    const granted = grantResend(['guestbook']);
    const svc = makeService([granted], signer);
    const issued = await svc.issue(OPERATOR_ID, { mission_ids: [TEST_MISSION_ID],
      agent_id: PARENT_AGENT.id,
      scopes: [{ service_connection_id: 'scon_resend', scopes: ['*'] }],
    });
    granted.connection.operator_id = 'op_other_synthetic';
    await expect(svc.verify(issued.token)).rejects.toBeInstanceOf(PassportRevokedError);
  });
});
