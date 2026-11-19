import Fastify, { type FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError, MissionRefForbidden } from '@stack/shared';
import { beginAgentRuntime, completeFleetDropoff, connectionEligibility, dispatchFleetDropoff, normalizedFleetOperation,
  registerFleetRuntimeLifecycle, requireMissionRef, type AgentRuntimeInput } from './agent-runtime.js';
import type { Services } from '../config/services.js';
import type { FleetAdmission, PassportJWTPayload } from '@stack/vault';

const DENIAL = { intentType: 'a2a_dispatch' as const, namedIntent: 'stack:dropoff:deposit', parameters: {} };

function fixture() {
  const binding = { policy_id: 'flp_one', policy_revision: 1, membership_id: 'fmb_one', mission_id: 'ms_one' };
  const claims = { jti: 'pp_one', stk: { operator_id: 'op_one', agent_id: 'agt_one', services: [{ service_name: 'slack', connection_id: 'scon_one', scopes: ['chat:write'] }], fleet: binding, mission_ids: ['ms_one'], session_id: 'ses_one', accountability: 'enforced' } } as PassportJWTPayload;
  const admission = { state: 'prepared', producer: 'dropoff', authorization: { operatorId: 'op_one', agentId: 'agt_one', passportJti: 'pp_one', binding, intentClaimId: 'clm_one' } } as FleetAdmission;
  const services = {
    passport: { verify: vi.fn(async () => claims) },
    mission: { checkGate: vi.fn(async () => ({ allowed: true, mission: { mission_id: 'ms_one', operator_id: 'op_one' } })) },
    fleetAdmission: { prepare: vi.fn(async () => admission), assertUnboundAgent: vi.fn(async () => {}),
      reserve: vi.fn(async () => { admission.state = 'reserved'; }), dispatch: vi.fn(async () => { admission.state = 'dispatched'; }),
      finish: vi.fn(async () => { admission.state = 'finished'; }), abort: vi.fn(async () => { admission.state = 'finished'; }) },
    authority: { evaluateRuntimeAuthority: vi.fn(async (_input: unknown) => ({ allowed: true, authorityUseId: 'ause_one' })), markRuntimeAuthorityDispatched: vi.fn(async () => {}), completeRuntimeAuthorityUse: vi.fn(async () => {}) },
  };
  const app = Fastify();
  registerFleetRuntimeLifecycle(app);
  app.addHook('preHandler', async request => { request.operatorId = 'op_one'; request.agentId = 'agt_one'; });
  return { app, services, claims, admission };
}
const dropoffInput = (action: 'create' | 'deposit' | 'collect', body: unknown = {}): AgentRuntimeInput => ({
  agentId: 'agt_one', producer: 'dropoff', requestedService: 'stack:dropoff', internal: true, targetId: 'agt_two', action,
  normalizedRequest: normalizedFleetOperation(action, body), denial: DENIAL,
});

describe('fleet producer runtime boundary', () => {
  it('offers a fleet passport the connections its scopes name, several of one provider included', () => {
    const f = fixture();
    const request = {} as unknown as FastifyRequest;
    expect(connectionEligibility(request, 'slack', f.claims)).toEqual({ kind: 'connections', connectionIds: ['scon_one'] });
    f.claims.stk.services.push({ service_id: 'svc_slack', credential_ref: 'cred_test', service_name: 'slack', connection_id: 'scon_two', scopes: ['chat:write'] });
    expect(connectionEligibility(request, 'slack', f.claims)).toEqual({ kind: 'connections', connectionIds: ['scon_one', 'scon_two'] });
    // A provider it holds no scope of has nothing to offer; the pick then finds no connection.
    expect(connectionEligibility(request, 'github', f.claims)).toEqual({ kind: 'connections', connectionIds: [] });
  });
  it('refuses a fleet scope that names no connection', () => {
    const f = fixture();
    f.claims.stk.services.push({ service_id: 'svc_slack', credential_ref: 'cred_test', service_name: 'slack', scopes: ['chat:write'] } as never);
    expect(() => connectionEligibility({} as FastifyRequest, 'slack', f.claims)).toThrow(ForbiddenError);
  });
  it('lets an agent passport without a pinned scope stand for the one shared connection', () => {
    const f = fixture();
    delete (f.claims.stk as { fleet?: unknown }).fleet;
    f.claims.stk.services = [{ service_id: 'svc_slack', credential_ref: 'cred_test', service_name: 'slack', scopes: ['chat:write'] } as never];
    expect(connectionEligibility({} as FastifyRequest, 'slack', f.claims)).toEqual({ kind: 'connections', connectionIds: [], sharedFallback: true });
  });
  it('keeps a team member own-first order and narrows it to the passport grants and the member list', () => {
    const f = fixture();
    f.claims.stk.services.push({ service_id: 'svc_slack', credential_ref: 'cred_test', service_name: 'slack', connection_id: 'scon_two', scopes: ['chat:write'] });
    const member = { memberId: 'mem_a', allowedConnections: ['scon_two', 'scon_other'] } as unknown as FastifyRequest;
    expect(connectionEligibility(member, 'slack', f.claims)).toEqual({ kind: 'member', memberId: 'mem_a', allowedConnections: ['scon_two'] });
    expect(connectionEligibility({ memberId: 'mem_a' } as unknown as FastifyRequest, 'slack', f.claims))
      .toEqual({ kind: 'member', memberId: 'mem_a', allowedConnections: ['scon_one', 'scon_two'] });
  });
  it('is the shared connections for an owner key and the member rule for a member with no passport', () => {
    expect(connectionEligibility({} as FastifyRequest, 'slack')).toEqual({ kind: 'shared' });
    expect(connectionEligibility({ memberId: 'mem_a', allowedConnections: [] } as unknown as FastifyRequest, 'slack'))
      .toEqual({ kind: 'member', memberId: 'mem_a', allowedConnections: [] });
  });
  it.each(['create', 'deposit', 'collect'] as const)('preserves exact Authority checks and completion for dropoff %s', async action => {
    const f = fixture();
    f.app.post('/execute', async request => {
      const a = await beginAgentRuntime(f.services as unknown as Services, request, dropoffInput(action, { dropoff_id: 'dof_one', payload: { value: 1 } }));
      await dispatchFleetDropoff(f.services as unknown as Services, a!.fleet!);
      await completeFleetDropoff(f.services as unknown as Services, a!.fleet, { id: 'dof_one', status: 'ready' });
      return { ok: true };
    });
    const res = await f.app.inject({ method: 'POST', url: '/execute', headers: { 'x-passport-token': 'verified', 'x-stack-authority-request-id': 'abcdefghijklmnopqrstuv' } });
    expect(res.statusCode).toBe(200);
    // Fleet Passports are Mission-gated (lifecycle, scope) before the ledger.
    expect(f.services.mission.checkGate).toHaveBeenCalledWith({ missionId: 'ms_one', requestedService: 'stack:dropoff', internal: true, accounting: 'fleet' });
    expect(f.services.authority.evaluateRuntimeAuthority).toHaveBeenCalledWith(expect.objectContaining({
      agentId: 'agt_one', authenticatedAgentId: 'agt_one', missionId: 'ms_one',
      boundary: { kind: 'dropoff', action, participantAgentId: 'agt_two' }, requestHash: expect.stringMatching(/^sha256:/),
    }));
    expect(f.services.authority.markRuntimeAuthorityDispatched).toHaveBeenCalledOnce();
    expect(f.services.authority.completeRuntimeAuthorityUse).toHaveBeenCalledWith(expect.objectContaining({ outcome: 'succeeded', exactResult: { id: 'dof_one', status: 'ready' }, intentClaimId: 'clm_one' }));
    expect(f.services.fleetAdmission.finish).toHaveBeenCalledWith(f.admission, 0);
    await f.app.close();
  });
  it('never dispatches after Authority denial', async () => {
    const f = fixture();
    f.services.authority.evaluateRuntimeAuthority.mockRejectedValue(new ForbiddenError());
    f.app.post('/execute', async request => {
      const a = await beginAgentRuntime(f.services as unknown as Services, request, dropoffInput('deposit'));
      await dispatchFleetDropoff(f.services as unknown as Services, a!.fleet!);
    });
    const res = await f.app.inject({ method: 'POST', url: '/execute', headers: { 'x-passport-token': 'verified', 'x-stack-authority-request-id': 'abcdefghijklmnopqrstuv' } });
    expect(res.statusCode).toBe(403);
    expect(f.services.fleetAdmission.dispatch).not.toHaveBeenCalled();
    await f.app.close();
  });
  it('never prepares a fleet admission when the Mission refuses', async () => {
    const f = fixture();
    f.services.mission.checkGate.mockResolvedValue({ allowed: false, reason: 'mission_revoked', message: 'mission ms_one is revoked', mission: {} } as never);
    Object.assign(f.services, { claimRegistry: { recordIntentDenial: vi.fn(async () => ({})) }, securityEvent: { record: vi.fn(async () => ({})) } });
    f.app.post('/execute', async request => beginAgentRuntime(f.services as unknown as Services, request, dropoffInput('deposit')));
    const res = await f.app.inject({ method: 'POST', url: '/execute', headers: { 'x-passport-token': 'verified', 'x-stack-authority-request-id': 'abcdefghijklmnopqrstuv' } });
    expect(res.statusCode).toBe(403);
    expect(f.services.fleetAdmission.prepare).not.toHaveBeenCalled();
    await f.app.close();
  });
  it('retains an uncertain dispatched transfer and records failure when response completion fails', async () => {
    const f = fixture();
    f.app.post('/execute', async request => {
      const a = await beginAgentRuntime(f.services as unknown as Services, request, dropoffInput('deposit'));
      await dispatchFleetDropoff(f.services as unknown as Services, a!.fleet!);
      throw new Error('failure');
    });
    expect((await f.app.inject({ method: 'POST', url: '/execute', headers: { 'x-passport-token': 'verified', 'x-stack-authority-request-id': 'abcdefghijklmnopqrstuv' } })).statusCode).toBe(500);
    expect(f.services.fleetAdmission.abort).toHaveBeenCalledWith(f.admission);
    expect(f.services.authority.completeRuntimeAuthorityUse).toHaveBeenCalledWith(expect.objectContaining({ outcome: 'failed' }));
    expect(f.services.fleetAdmission.finish).not.toHaveBeenCalled();
    await f.app.close();
  });
});

// ── Mission admission (non-fleet) ────────────────────────────────────────

type Verdict = { allowed: boolean; reason?: string; message?: string; capBehavior?: string; capService?: string; mission?: Record<string, unknown> };

function admission(opts: {
  claims?: { jti?: string; mission_ids?: string[]; agent_id?: string; operator_id?: string; accountability?: string } | null;
  row?: Record<string, unknown> | null;
  verdict?: Verdict;
  approval?: Record<string, unknown> | null;
  claim?: Record<string, unknown>;
} = {}) {
  const claims = opts.claims === null ? null : {
    jti: opts.claims?.jti ?? 'pas_one',
    stk: { operator_id: opts.claims?.operator_id ?? 'op_one', agent_id: opts.claims?.agent_id ?? 'agt_one',
      mission_ids: opts.claims?.mission_ids ?? ['ms_one'], accountability: opts.claims?.accountability ?? 'standard', services: [] },
  };
  const services = {
    passport: {
      verify: vi.fn(async () => { if (!claims) throw new ForbiddenError('revoked'); return claims; }),
      findByJti: vi.fn(async () => opts.row ?? null),
    },
    mission: {
      checkGate: vi.fn(async () => opts.verdict ?? { allowed: true, mission: { mission_id: 'ms_one', operator_id: 'op_one' } }),
      applyCapBehavior: vi.fn(async () => undefined),
    },
    fleetAdmission: { assertUnboundAgent: vi.fn(async () => {}), prepare: vi.fn() },
    claimRegistry: { recordIntentDenial: vi.fn(async () => ({})), getClaim: vi.fn(async () => opts.claim ?? {}) },
    securityEvent: { record: vi.fn(async () => ({})) },
    intentApproval: { findById: vi.fn(async () => opts.approval ?? null) },
  };
  return services;
}

function req(over: Partial<{ agentId: string; headers: Record<string, string>; passportContext: unknown }> = {}) {
  return { operatorId: 'op_one', headers: over.headers ?? {}, ...(over.agentId ? { agentId: over.agentId } : {}),
    ...(over.passportContext ? { passportContext: over.passportContext } : {}) } as unknown as FastifyRequest;
}

const input = (over: Partial<AgentRuntimeInput> = {}): AgentRuntimeInput => ({
  agentId: 'agt_one', producer: 'proxy', requestedService: 'slack', targetId: 'slack', action: 'POST',
  normalizedRequest: normalizedFleetOperation('POST', {}), denial: { intentType: 'http_call', namedIntent: 'slack:http:proxy', parameters: {} },
  ...over,
});

const liveRow = (over: Record<string, unknown> = {}) => ({ jti: 'pas_row', operator_id: 'op_one', agent_id: 'agt_one', revoked_at: null,
  expires_at: new Date(Date.now() + 60_000), mission_ids: ['ms_one'], ...over });

describe('beginAgentRuntime: one Mission admission for every agent action', () => {
  it('refuses an agent principal that presents no Passport', async () => {
    const s = admission();
    await expect(beginAgentRuntime(s as unknown as Services, req({ agentId: 'agt_one' }), input()))
      .rejects.toThrow(/require a live Passport bound to a Mission/);
    expect(s.mission.checkGate).not.toHaveBeenCalled();
  });

  it('lets a non-agent principal without a Passport through, unbound', async () => {
    const s = admission();
    await expect(beginAgentRuntime(s as unknown as Services, req(), input())).resolves.toBeNull();
    expect(s.mission.checkGate).not.toHaveBeenCalled();
  });

  it('refuses a bare Mission selector without the Passport that carries it', async () => {
    const s = admission();
    await expect(beginAgentRuntime(s as unknown as Services, req(), input({ explicitMissionId: 'ms_one' })))
      .rejects.toBeInstanceOf(ForbiddenError);
  });

  it.each([
    ['no Mission', []],
    ['two Missions and no pick', ['ms_one', 'ms_two']],
  ])('refuses a Passport with %s', async (_label, missionIds) => {
    const s = admission({ claims: { mission_ids: missionIds } });
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .rejects.toThrow(/exactly one Mission/);
    expect(s.mission.checkGate).not.toHaveBeenCalled();
  });

  it('refuses a Mission pick the Passport does not carry', async () => {
    const s = admission();
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input({ explicitMissionId: 'ms_other' })))
      .rejects.toBeInstanceOf(MissionRefForbidden);
  });

  it('admits a live Mission and returns it for attribution', async () => {
    const s = admission();
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .resolves.toEqual({ passportJti: 'pas_one', missionId: 'ms_one', missionIds: ['ms_one'], accountability: 'standard', fleet: null });
    expect(s.mission.checkGate).toHaveBeenCalledWith({ missionId: 'ms_one', requestedService: 'slack' });
  });

  it('checks STACK-internal actions without Mission service scope', async () => {
    const s = admission();
    await beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }),
      input({ producer: 'a2a', requestedService: 'stack:a2a', internal: true }));
    expect(s.mission.checkGate).toHaveBeenCalledWith({ missionId: 'ms_one', requestedService: 'stack:a2a', internal: true });
  });

  it('refuses a Mission that belongs to another operator', async () => {
    const s = admission({ verdict: { allowed: true, mission: { mission_id: 'ms_one', operator_id: 'op_other' } } });
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .rejects.toBeInstanceOf(ForbiddenError);
  });

  it.each([
    ['revoked', { allowed: false, reason: 'mission_revoked', message: 'mission ms_one is revoked', mission: {} }],
    ['completed', { allowed: false, reason: 'mission_completed', message: 'mission ms_one is completed', mission: {} }],
    ['out of scope', { allowed: false, reason: 'mission_scope_mismatch', message: 'service slack not in mission scope', mission: {} }],
  ])('refuses a %s Mission with a signed denial and a security event', async (_label, verdict) => {
    const s = admission({ verdict });
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .rejects.toMatchObject({ statusCode: 403, message: verdict.message });
    expect(s.claimRegistry.recordIntentDenial).toHaveBeenCalledWith(expect.objectContaining({
      passportJti: 'pas_one', denialReason: 'scope_mismatch',
      attemptedIntent: expect.objectContaining({ mission_ref: 'ms_one', target: 'slack' }),
      metadata: expect.objectContaining({ gate_reason: verdict.reason, mission_id: 'ms_one', producer: 'proxy' }),
    }));
    expect(s.securityEvent.record).toHaveBeenCalledWith(expect.objectContaining({ signalType: 'credential_outside_scope', missionIds: ['ms_one'] }));
    expect(s.mission.applyCapBehavior).not.toHaveBeenCalled();
  });

  it.each([
    ['expired', { allowed: false, reason: 'cap_max_duration_seconds', message: 'Forbidden', capBehavior: 'refuse_action', mission: {} }],
    ['at its action cap', { allowed: false, reason: 'cap_max_actions', message: 'mission actions used 3 of cap 3', capBehavior: 'refuse_action', mission: {} }],
  ])('refuses only the action of a %s Mission whose cap refuses it: a signed denial, and no security event', async (_label, verdict) => {
    const s = admission({ verdict });
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN', message: verdict.message });
    expect(s.claimRegistry.recordIntentDenial).toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({ gate_reason: verdict.reason, cap_behavior: 'refuse_action' }),
    }));
    expect(s.securityEvent.record).not.toHaveBeenCalled();
    expect(s.mission.applyCapBehavior).not.toHaveBeenCalled();
  });

  it('pauses the Mission at a cap that pauses it, refuses with MISSION_PAUSED, revokes nothing and records no security event', async () => {
    const s = admission({ verdict: { allowed: false, reason: 'cap_max_actions_per_service', message: 'used 3 of cap 3', capBehavior: 'pause', capService: 'slack', mission: {} } as Verdict });
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .rejects.toMatchObject({ statusCode: 403, code: 'MISSION_PAUSED', details: { mission_id: 'ms_one', cap: 'max_actions_per_service' } });
    expect(s.mission.applyCapBehavior).toHaveBeenCalledWith('ms_one', 'max_actions_per_service', 'pause', 'slack');
    expect(s.securityEvent.record).not.toHaveBeenCalled();
  });

  it('refuses every action of a paused Mission with MISSION_PAUSED, with no denial and no security event', async () => {
    const s = admission({ verdict: { allowed: false, reason: 'mission_paused', message: 'paused', mission: { paused_cap: 'coverage_cap_cents' } } });
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .rejects.toMatchObject({ code: 'MISSION_PAUSED', details: { mission_id: 'ms_one', cap: 'coverage_cap_cents' } });
    expect(s.claimRegistry.recordIntentDenial).not.toHaveBeenCalled();
    expect(s.securityEvent.record).not.toHaveBeenCalled();
    expect(s.mission.applyCapBehavior).not.toHaveBeenCalled();
  });

  it('ends the Mission at a cap that ends it, before refusing, with no security event', async () => {
    const s = admission({ verdict: { allowed: false, reason: 'cap_coverage_cap_cents', message: 'spend exceeds cap', capBehavior: 'end_mission', mission: {} } });
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input()))
      .rejects.toBeInstanceOf(ForbiddenError);
    expect(s.mission.applyCapBehavior).toHaveBeenCalledWith('ms_one', 'coverage_cap_cents', 'end_mission', null);
    expect(s.securityEvent.record).not.toHaveBeenCalled();
  });

  it('resolves a stored Passport JTI and gates its Mission', async () => {
    const s = admission({ claims: null, row: liveRow() });
    await expect(beginAgentRuntime(s as unknown as Services, req({ agentId: 'agt_one' }), input({ passportId: 'pas_row' })))
      .resolves.toMatchObject({ passportJti: 'pas_row', missionId: 'ms_one' });
    expect(s.fleetAdmission.assertUnboundAgent).toHaveBeenCalledWith('op_one', 'agt_one');
  });

  it.each([
    ['missing', null],
    ['foreign operator', liveRow({ operator_id: 'op_other' })],
    ['wrong agent', liveRow({ agent_id: 'agt_other' })],
    ['revoked', liveRow({ revoked_at: new Date() })],
    ['expired', liveRow({ expires_at: new Date(Date.now() - 1) })],
  ])('denies a %s stored Passport with one non-enumerating response', async (_label, row) => {
    const s = admission({ claims: null, row });
    await expect(beginAgentRuntime(s as unknown as Services, req(), input({ passportId: 'pas_row', explicitMissionId: 'ms_one' })))
      .rejects.toMatchObject({ statusCode: 403, message: 'Passport cannot authorize this action' });
    expect(s.mission.checkGate).not.toHaveBeenCalled();
  });

  it('refuses a token whose JTI contradicts the named Passport', async () => {
    const s = admission();
    await expect(beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't' } }), input({ passportId: 'pas_attacker' })))
      .rejects.toBeInstanceOf(ForbiddenError);
  });

  it('refuses a fleet Passport on a producer fleet policy has no rule for', async () => {
    const f = fixture();
    f.app.post('/execute', async request => beginAgentRuntime(f.services as unknown as Services, request,
      { ...dropoffInput('deposit'), producer: 'intent' }));
    const res = await f.app.inject({ method: 'POST', url: '/execute', headers: { 'x-passport-token': 'verified' } });
    expect(res.statusCode).toBe(403);
    expect(f.services.fleetAdmission.prepare).not.toHaveBeenCalled();
    await f.app.close();
  });

  it('discounts the approved intent this call executes, exactly once', async () => {
    const s = admission({
      claims: { accountability: 'enforced' },
      approval: { passport_jti: 'pas_one', status: 'approved', expires_at: new Date(Date.now() + 60_000), intent_claim_id: 'pc_one' },
      claim: { revoked_at: null, body_json: { mission_ref: 'ms_one', target: 'slack' } },
    });
    await beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't', 'x-intent-approval-id': 'iap_one' } }), input());
    expect(s.mission.checkGate).toHaveBeenCalledWith({ missionId: 'ms_one', requestedService: 'slack', alreadyCounted: { target: 'slack' } });
  });

  it.each([
    ['another Passport', { passport_jti: 'pas_other' }, { mission_ref: 'ms_one', target: 'slack' }],
    ['a pending approval', { status: 'pending' }, { mission_ref: 'ms_one', target: 'slack' }],
    ['an intent under no Mission', {}, { mission_ref: null, target: 'slack' }],
  ])('does not discount an approval for %s', async (_label, approvalOver, body) => {
    const s = admission({
      claims: { accountability: 'enforced' },
      approval: { passport_jti: 'pas_one', status: 'approved', expires_at: new Date(Date.now() + 60_000), intent_claim_id: 'pc_one', ...approvalOver },
      claim: { revoked_at: null, body_json: body },
    });
    await beginAgentRuntime(s as unknown as Services, req({ headers: { 'x-passport-token': 't', 'x-intent-approval-id': 'iap_one' } }), input());
    expect(s.mission.checkGate).toHaveBeenCalledWith({ missionId: 'ms_one', requestedService: 'slack' });
  });

  it('requireMissionRef fails closed on zero or ambiguous Missions', () => {
    expect(requireMissionRef(['ms_one'])).toBe('ms_one');
    expect(requireMissionRef(['ms_one', 'ms_two'], 'ms_two')).toBe('ms_two');
    expect(() => requireMissionRef([])).toThrow(/exactly one Mission/);
    expect(() => requireMissionRef(undefined)).toThrow(/exactly one Mission/);
    expect(() => requireMissionRef(['ms_one', 'ms_two'])).toThrow(/exactly one Mission/);
    expect(() => requireMissionRef(['ms_one'], 'ms_two')).toThrow(MissionRefForbidden);
  });
});
