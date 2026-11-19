import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';
import { EngineRegistries } from '../config/registries.js';

// A drop-off carries what a deployment attaches to it. With none registered (an engine install) the payload is all
// it carries, and files handed over are refused before anything is stored.

const context = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));
const order = vi.hoisted(() => ({ steps: [] as string[] }));
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: object) => Object.assign(request, context.current),
}));
vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn(async () => undefined) }));
vi.mock('../lib/control-decision.js', () => ({ decideControl: vi.fn(async () => undefined) }));
vi.mock('../lib/agent-runtime.js', () => ({
  beginAgentRuntime: vi.fn(async () => ({
    passportJti: 'pas_local', missionId: 'ms_local', missionIds: ['ms_local'], accountability: 'standard', fleet: null,
  })),
  normalizedFleetOperation: (method: string, body: unknown) => ({ method, body }),
  dispatchFleetDropoff: vi.fn(),
  completeFleetDropoff: vi.fn(async () => undefined),
}));
vi.mock('../lib/provenance.js', () => ({
  computeDepositProvenance: vi.fn(async () => ({ v: 1, sources: [] })),
  recordCollectedProvenance: vi.fn(async () => []),
}));
vi.mock('../lib/dropoff-authority.js', () => ({ assertDropoffAgentBinding: vi.fn() }));
import { registerDropoffRoutes } from './dropoffs.js';

const DROPOFF = 'dof_local0000000000001';
const FILE = 'drv_localfile00000001';

function build() {
  const server = Fastify({ logger: false });
  server.setErrorHandler(createErrorHandler());
  const tx = { id: 'tx' };
  // An engine install registers no drop-off attachments: STACK's drive is the deployment's own, covered by its own tests.
  const registries = new EngineRegistries();
  const services = {
    db: { transaction: vi.fn(async (callback: (t: unknown) => unknown) => callback(tx)) },
    audit: { write: vi.fn(async () => { order.steps.push('audit'); return 'aud_1'; }) },
    dropoff: {
      getStatus: vi.fn(async () => ({ to_agent: 'agt_to', to_agents: ['agt_to'], from_agent: 'agt_from', deposited_bytes: 10 })),
      markDepositAnnounced: vi.fn(async () => undefined),
      deposit: vi.fn(async () => { order.steps.push('deposit'); return { id: DROPOFF, status: 'deposited', to_agent_ids: ['agt_to'] }; }),
      collectWithProvenance: vi.fn(async () => { order.steps.push('collect'); return { payload: { note: 'hi' }, provenance: null }; }),
    },
    registries,
  } as unknown as Services;
  registerDropoffRoutes(server, services);
  return { server, services, tx };
}

afterEach(() => {
  order.steps.length = 0;
  context.current = {};
});

describe('a deployment with no drive', () => {
  it('refuses files handed over with a deposit before anything is stored, and deposits an ordinary payload', async () => {
    context.current = { operatorId: 'op_local', agentId: 'agt_from' };
    const { server, services } = build();
    const refused = await server.inject({
      method: 'POST', url: `/v1/dropoffs/${DROPOFF}/deposit`,
      payload: { agent_id: 'agt_from', payload: { note: 'hi' }, drive_files: [FILE] },
    });
    expect(refused.statusCode).toBe(400);
    expect(refused.json().error.code).toBe('NOT_CONFIGURED');
    expect(services.dropoff.deposit).not.toHaveBeenCalled();
    const ordinary = await server.inject({
      method: 'POST', url: `/v1/dropoffs/${DROPOFF}/deposit`,
      payload: { agent_id: 'agt_from', payload: { note: 'hi' } },
    });
    expect(ordinary.statusCode).toBe(200);
  });

  it('hands nothing over at the collect', async () => {
    context.current = { operatorId: 'op_local', agentId: 'agt_to' };
    const { server } = build();
    const response = await server.inject({ method: 'POST', url: `/v1/dropoffs/${DROPOFF}/collect`, payload: { agent_id: 'agt_to' } });
    expect(response.json()).toEqual({ payload: { note: 'hi' } });
  });
});
