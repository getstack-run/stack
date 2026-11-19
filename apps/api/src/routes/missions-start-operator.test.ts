import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenError, NotFoundError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

/**
 * POST /v1/missions/start, operator path: one call opens a Mission
 * and issues the agent's Passport bound to it, for operator principals,
 * partner-managed account keys (an operator principal on the account). Fleet agents keep the fleet_policy_id path, unchanged.
 */

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const token = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['operatorId'] = token === 'tenant' ? 'op_tenant' : 'op_owner';
    if (token === 'agent' || token === 'fleet') request['agentId'] = token === 'agent' ? 'agt_self' : 'agt_fleet';
    if (token === 'passport') request['passportContext'] = { jti: 'ppt_bearer' };
  },
}));
const meterAction = vi.fn(async () => {});
vi.mock('../middleware/meter.js', () => ({ meterAction: (...args: unknown[]) => meterAction(...(args as [])) }));

const { registerFleetRoutes } = await import('./fleets.js');

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
  meterAction.mockClear();
});

async function makeApp(opts: { issueFails?: boolean } = {}) {
  const missionExpires = new Date(Date.now() + 900_000);
  const open = vi.fn(async () => ({ mission_id: 'ms_new', claim_id: 'pc_open', expires_at: missionExpires }));
  const revoke = vi.fn(async () => ({}));
  const issue = vi.fn(async () => {
    if (opts.issueFails) throw new ForbiddenError('Passport scope does not cover the Mission\'s services');
    return { token: 'jwt', jti: 'ppt_new', expires_at: new Date(Date.now() + 600_000) };
  });
  const fleetStart = vi.fn(async () => ({ mission_id: 'ms_fleet', policy_id: 'flp_1', policy_revision: 1, passport: {} }));
  const assertUnboundIssue = vi.fn(async (_op: string, agentId: string) => {
    if (agentId === 'agt_member') throw new ForbiddenError();
  });
  const getById = vi.fn(async (id: string, operatorId: string) => {
    if (id === 'agt_foreign') throw new NotFoundError('Agent', id);
    return { id, operator_id: operatorId };
  });
  const auditWrite = vi.fn(async () => {});
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerFleetRoutes(app, {
    entitlements: { controlsEnabled: async () => true },
    mission: { open, revoke },
    passport: { issue, findByJti: async () => null },
    fleet: { start: fleetStart, assertUnboundIssue },
    agent: { getById },
    audit: { write: auditWrite },
  } as never);
  await app.ready();
  return { app, open, revoke, issue, fleetStart, assertUnboundIssue, auditWrite };
}

const MISSION = { intent_summary: 'Send the weekly digest', intent_services: ['resend'], max_actions: 20 };

function start(app: ReturnType<typeof Fastify>, token: string, payload: unknown) {
  return app.inject({ method: 'POST', url: '/v1/missions/start', headers: { authorization: `Bearer ${token}` }, payload: payload as object });
}

describe('POST /v1/missions/start — operator path', () => {
  it('opens the Mission and issues a Passport bound to exactly that Mission', async () => {
    const { app, open, issue, auditWrite } = await makeApp();
    const res = await start(app, 'operator', {
      agent_id: 'agt_worker', mission: MISSION, passport: { ttl_seconds: 600 },
    });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({
      mission_id: 'ms_new', claim_id: 'pc_open', passport: { token: 'jwt', jti: 'ppt_new' },
    });
    expect(open).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_owner', assignedAgentId: 'agt_worker', intent_summary: MISSION.intent_summary,
      intent_services: ['resend'], max_actions: 20,
    }));
    expect(issue).toHaveBeenCalledWith('op_owner', {
      ttl_seconds: 600,
      agent_id: 'agt_worker',
      mission_ids: ['ms_new'],
      // Omitted passport intent defaults to the Mission's declared intent.
      intent: { summary: MISSION.intent_summary, services: ['resend'] },
    });
    // Counted once: the Passport issue. Opening the Mission is free.
    expect(meterAction).toHaveBeenCalledTimes(1);
    expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({ action: 'mission.start' }));
  });

  it('a caller cannot choose the Mission id the Passport is bound to', async () => {
    const { app, open, issue } = await makeApp();
    const res = await start(app, 'operator', {
      agent_id: 'agt_worker', mission: MISSION, passport: { mission_ids: ['ms_someone_elses'] },
    });
    expect(res.statusCode).toBe(400);
    expect(open).not.toHaveBeenCalled();
    expect(issue).not.toHaveBeenCalled();
  });

  it('works for a white-label tenant key, under the tenant operator', async () => {
    const { app, open, issue } = await makeApp();
    expect((await start(app, 'tenant', { agent_id: 'agt_tenant', mission: MISSION })).statusCode).toBe(201);
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ operatorId: 'op_tenant' }));
    expect(issue).toHaveBeenCalledWith('op_tenant', expect.objectContaining({ mission_ids: ['ms_new'] }));
  });

  it('lets an agent start only for itself, and refuses a Passport bearer', async () => {
    const { app, open } = await makeApp();
    expect((await start(app, 'agent', { agent_id: 'agt_self', mission: MISSION })).statusCode).toBe(201);
    expect((await start(app, 'agent', { agent_id: 'agt_other', mission: MISSION })).statusCode).toBe(403);
    expect((await start(app, 'passport', { agent_id: 'agt_worker', mission: MISSION })).statusCode).toBe(403);
    expect(open).toHaveBeenCalledTimes(1);
  });

  it('refuses a fleet member before opening anything (fleet agents use their policy)', async () => {
    const { app, open, meter } = { ...(await makeApp()), meter: meterAction };
    expect((await start(app, 'operator', { agent_id: 'agt_member', mission: MISSION })).statusCode).toBe(403);
    expect(open).not.toHaveBeenCalled();
    expect(meter).not.toHaveBeenCalled();
  });

  it('revokes the just-opened Mission when the Passport cannot be issued', async () => {
    const { app, open, revoke } = await makeApp({ issueFails: true });
    const res = await start(app, 'operator', { agent_id: 'agt_worker', mission: MISSION });
    expect(res.statusCode).toBe(403);
    expect(open).toHaveBeenCalledTimes(1);
    expect(revoke).toHaveBeenCalledWith('ms_new', { reason: 'operator_initiated_clean' });
  });

  it('keeps the fleet-agent path unchanged', async () => {
    const { app, fleetStart, open } = await makeApp();
    const res = await start(app, 'fleet', {
      fleet_policy_id: 'flp_1', idempotency_key: 'idem-key-12345', intent_summary: 'x',
      requested_access: [], requested_operations: [], limits: {},
    });
    // A fleet_policy_id body is parsed by FleetMissionStartInput (here it
    // fails on the fleet `limits` fields), never by the operator path, and
    // nothing is opened or issued.
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('max_concurrent_actions');
    expect(open).not.toHaveBeenCalled();
    expect(fleetStart).not.toHaveBeenCalled();
    const operatorKey = await start(app, 'operator', { fleet_policy_id: 'flp_1' });
    expect(operatorKey.statusCode).toBe(400);
    expect(open).not.toHaveBeenCalled();
  });
});
