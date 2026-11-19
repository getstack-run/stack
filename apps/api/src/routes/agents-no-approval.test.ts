import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';

const context = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));
const stepUp = vi.hoisted(() => ({ inputs: [] as unknown[], refuse: null as Error | null }));
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: object) => Object.assign(request, context.current),
  createEnrollmentAuthMiddleware: () => async (request: object) => Object.assign(request, context.current),
  claimEnrollmentTicket: vi.fn(),
  enrollmentTicketClaimKey: vi.fn(),
  releaseEnrollmentTicketClaim: vi.fn(),
}));
vi.mock('../middleware/governance-stepup.js', () => ({
  enforceGovernanceStepUp: vi.fn(async (_services: unknown, _request: unknown, input: unknown) => {
    stepUp.inputs.push(input);
    if (stepUp.refuse) throw stepUp.refuse;
  }),
}));
import { registerAgentRoutes } from './agents.js';

/**
 * Registering an agent and allowing a skill for one need no person's approval: the owner's own session, key or OAuth
 * sign-in does them directly. An agent's context never reaches either route, and a read-only member may not make
 * them, whatever settings the agent starts with. Both used to be gated by a governance step-up (`agent_register`,
 * `agent_skill_allow`).
 */

const AGENT = { id: 'agt_1', name: 'invoice-bot', operator_id: 'op_1' };

function app() {
  const server = Fastify({ logger: false });
  server.setErrorHandler(createErrorHandler());
  const services = {
    agent: {
      register: vi.fn(async () => AGENT),
      allowSkill: vi.fn(async () => ({ ...AGENT, allowed_skills: ['skl_1'] })),
      getById: vi.fn(async () => ({ ...AGENT, status: 'active', skill_access_mode: 'none', allowed_skills: [], eval_traffic: false })),
      update: vi.fn(async () => AGENT),
    },
    audit: { write: vi.fn(async () => undefined) },
  };
  registerAgentRoutes(server, services as never);
  return { server, services };
}

afterEach(() => {
  stepUp.refuse = null;
  stepUp.inputs.length = 0;
  context.current = {};
});

describe('POST /v1/agents/register', () => {
  it('registers for the owner\'s own key without asking anyone', async () => {
    context.current = { operatorId: 'op_1', operatorTier: 'free' };
    const { server, services } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/register', payload: { name: 'invoice-bot' } });
    expect(response.statusCode).toBe(201);
    expect(stepUp.inputs).toEqual([]);
    expect(services.agent.register).toHaveBeenCalledTimes(1);
    expect(services.audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.register', outcome: 'success' }));
  });

  it('registers for a standard member', async () => {
    context.current = { operatorId: 'op_1', operatorTier: 'free', memberId: 'mem_1', memberRole: 'standard' };
    const { server } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/register', payload: { name: 'invoice-bot' } });
    expect(response.statusCode).toBe(201);
  });

  it('refuses a read-only member, and registers nothing', async () => {
    context.current = { operatorId: 'op_1', operatorTier: 'free', memberId: 'mem_1', memberRole: 'readonly' };
    const { server, services } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/register', payload: { name: 'invoice-bot' } });
    expect(response.statusCode).toBe(403);
    expect(services.agent.register).not.toHaveBeenCalled();
  });

  it('refuses an agent\'s own context, and registers nothing', async () => {
    context.current = { operatorId: 'op_1', operatorTier: 'free', agentId: 'agt_1' };
    const { server, services } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/register', payload: { name: 'invoice-bot' } });
    expect(response.statusCode).toBe(403);
    expect(services.agent.register).not.toHaveBeenCalled();
  });
});

describe('POST /v1/agents/register with settings weaker than the defaults', () => {
  it.each([
    ['test traffic', { eval_traffic: true }],
    ['is_synthetic', { is_synthetic: true }],
    ['PII redaction off', { llm_redact_pii: false }],
    ['the system prompt off', { llm_inject_system_prompt: false }],
    ['weaker accountability', { accountability_mode: 'standard' }],
    ['looser credential access', { credential_access: 'direct' }],
    ['a weaker twin policy', { twin_policy: 'never' }],
    ['several at once', { eval_traffic: true, is_synthetic: true, llm_redact_pii: false, accountability_mode: 'standard' }],
    ['default settings', {}],
    ['skills', { skill_access_mode: 'all', allowed_skills: ['skl_1'] }],
  ])('registers %s without asking anyone', async (_name, extra) => {
    context.current = { operatorId: 'op_1', operatorTier: 'free' };
    stepUp.refuse = new Error('approval required');
    const { server, services } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/register', payload: { name: 'plain-bot', ...extra } });
    expect(response.statusCode).toBe(201);
    expect(stepUp.inputs).toEqual([]);
    expect(services.agent.register).toHaveBeenCalledWith('op_1', 'free', expect.objectContaining({ name: 'plain-bot', ...extra }));
  });
});

describe('DELETE /v1/agents/:id', () => {
  function retiring() {
    const built = app();
    Object.assign(built.services.agent, { delete: vi.fn(async () => ({ ...AGENT, status: 'deleted' })) });
    Object.assign(built.services, {
      agentAccounts: { findOpenAccountByAgent: vi.fn(async () => null) },
      passport: { revokeAllForAgent: vi.fn(async () => undefined) },
    });
    return built;
  }

  it('retires an agent for a standard member', async () => {
    context.current = { operatorId: 'op_1', memberId: 'mem_1', memberRole: 'standard' };
    const { server, services } = retiring();
    const response = await server.inject({ method: 'DELETE', url: '/v1/agents/agt_1' });
    expect(response.statusCode).toBe(200);
    expect((services.agent as unknown as { delete: ReturnType<typeof vi.fn> }).delete).toHaveBeenCalledWith('agt_1', 'op_1');
  });

  it('refuses a read-only member, and retires nothing', async () => {
    context.current = { operatorId: 'op_1', memberId: 'mem_1', memberRole: 'readonly' };
    const { server, services } = retiring();
    const response = await server.inject({ method: 'DELETE', url: '/v1/agents/agt_1' });
    expect(response.statusCode).toBe(403);
    expect((services.agent as unknown as { delete: ReturnType<typeof vi.fn> }).delete).not.toHaveBeenCalled();
  });
});

describe('POST /v1/agents/setup', () => {
  it('refuses a setup that grants nothing and widens no host, and asks no one: to register an agent alone, register it', async () => {
    context.current = { operatorId: 'op_1', operatorTier: 'free' };
    const { server } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/setup', payload: { agent: { name: 'invoice-bot' } } });
    expect(response.statusCode).toBe(400);
    expect(response.body).toContain('to register an agent alone, register it');
    expect(stepUp.inputs).toEqual([]);
  });
});

describe('PATCH /v1/agents/:id and skills', () => {
  it.each([
    ['adds a skill', { allowed_skills: ['skl_1'] }],
    ['widens skill access to all', { skill_access_mode: 'all' }],
    ['widens skill access to a custom list', { skill_access_mode: 'custom', allowed_skills: ['skl_1'] }],
  ])('%s without asking anyone', async (_name, patch) => {
    context.current = { operatorId: 'op_1' };
    const { server, services } = app();
    const response = await server.inject({ method: 'PATCH', url: '/v1/agents/agt_1', payload: patch });
    expect(response.statusCode).toBe(200);
    expect(stepUp.inputs).toEqual([]);
    expect(services.agent.update).toHaveBeenCalledTimes(1);
  });

  it('refuses a read-only member the skill change, and changes nothing', async () => {
    context.current = { operatorId: 'op_1', memberId: 'mem_1', memberRole: 'readonly' };
    const { server, services } = app();
    const response = await server.inject({ method: 'PATCH', url: '/v1/agents/agt_1', payload: { skill_access_mode: 'all' } });
    expect(response.statusCode).toBe(403);
    expect(services.agent.update).not.toHaveBeenCalled();
  });

  it.each([
    ['turns on eval_traffic', { eval_traffic: true }],
    ['weakens accountability', { accountability_mode: 'standard' }],
  ])('still asks when it %s', async (_name, patch) => {
    context.current = { operatorId: 'op_1' };
    const { server, services } = app();
    Object.assign(services.agent, { getById: vi.fn(async () => ({ ...AGENT, status: 'active', accountability_mode: 'logged', eval_traffic: false, skill_access_mode: 'none', allowed_skills: [] })) });
    await server.inject({ method: 'PATCH', url: '/v1/agents/agt_1', payload: patch });
    expect(stepUp.inputs).toEqual([expect.objectContaining({ action: 'agent_authority_expand', resourceId: 'agt_1' })]);
  });
});

describe('POST /v1/agents/:id/allowed-skills', () => {
  it('allows a skill for the owner\'s own key without asking anyone', async () => {
    context.current = { operatorId: 'op_1' };
    const { server, services } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/agt_1/allowed-skills', payload: { skill_id: 'skl_1' } });
    expect(response.statusCode).toBe(200);
    expect(stepUp.inputs).toEqual([]);
    expect(services.agent.allowSkill).toHaveBeenCalledWith('agt_1', 'op_1', 'skl_1');
    expect(services.audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.allowed_skill.add', outcome: 'success' }));
  });

  it('refuses a read-only member, and allows nothing', async () => {
    context.current = { operatorId: 'op_1', memberId: 'mem_1', memberRole: 'readonly' };
    const { server, services } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/agt_1/allowed-skills', payload: { skill_id: 'skl_1' } });
    expect(response.statusCode).toBe(403);
    expect(services.agent.allowSkill).not.toHaveBeenCalled();
  });

  it('refuses an agent\'s own context, so an agent cannot widen its own skills', async () => {
    context.current = { operatorId: 'op_1', agentId: 'agt_1' };
    const { server, services } = app();
    const response = await server.inject({ method: 'POST', url: '/v1/agents/agt_1/allowed-skills', payload: { skill_id: 'skl_1' } });
    expect(response.statusCode).toBe(403);
    expect(services.agent.allowSkill).not.toHaveBeenCalled();
  });
});

describe('the changes that still need a person', () => {
  it('unblocking an agent still asks (agent_unblock)', async () => {
    context.current = { operatorId: 'op_1' };
    const { server, services } = app();
    Object.assign(services.agent, { getById: vi.fn(async () => AGENT) });
    Object.assign(services, { accountability: { unblockAgent: vi.fn(async () => ({ unblocked: true })) } });
    await server.inject({ method: 'POST', url: '/v1/agents/agt_1/unblock' });
    expect(stepUp.inputs).toEqual([expect.objectContaining({ action: 'agent_unblock', resourceId: 'agt_1' })]);
  });
});
