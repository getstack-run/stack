import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError, GovernanceApprovalRequiredError, NotFoundError } from '@stack/shared';
import { registerOperatorReviewRoutes } from './operator-reviews.js';

const PATH = '/v1/agents/:agentId/dismiss-warnings';

function setup(overrides: { dismissed?: Array<{ id: string; signal_type: string; severity: string; mission_id: string | null }>; agentError?: Error } = {}) {
  const dismissOpenForAgent = vi.fn(async () => overrides.dismissed ?? [
    { id: 'sev_1', signal_type: 'credential_outside_scope', severity: 'warning', mission_id: 'ms_a' },
    { id: 'sev_2', signal_type: 'credential_outside_scope', severity: 'warning', mission_id: 'ms_b' },
    { id: 'sev_3', signal_type: 'undeclared_target', severity: 'warning', mission_id: 'ms_b' },
  ]);
  const getById = vi.fn(async () => {
    if (overrides.agentError) throw overrides.agentError;
    return { id: 'agt_one' };
  });
  const write = vi.fn(async () => undefined);
  const requireApproval = vi.fn(async () => { throw new GovernanceApprovalRequiredError('gvr_new', 'https://getstack.run/app/approve/gvr_new', 'operator'); });
  const consume = vi.fn(async () => undefined);
  let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | undefined;
  let options: { preHandler?: unknown[] } | undefined;
  const app = {
    get() {},
    post(path: string, routeOptions: { preHandler?: unknown[] }, routeHandler: typeof handler) {
      if (path === PATH) {
        handler = routeHandler;
        options = routeOptions;
      }
    },
  };
  registerOperatorReviewRoutes(app as never, {
    securityEvent: { dismissOpenForAgent }, agent: { getById }, audit: { write }, governanceApprovals: { requireApproval, consume },
  } as never);
  const reply = { status: vi.fn(() => reply), send: vi.fn((value) => value) };
  // The Console's own session is the person; the other callers (a key, an OAuth token) set isDashboardSession false.
  const call = (request: Record<string, unknown>) =>
    handler!({ id: 'req_one', operatorId: 'op_one', params: { agentId: 'agt_one' }, headers: {}, isDashboardSession: true, ...request }, reply);
  return { call, dismissOpenForAgent, getById, write, requireApproval, consume, options: () => options };
}

describe('POST /v1/agents/:agentId/dismiss-warnings from a key or an OAuth token', () => {
  it('dismisses at once, asking nobody', async () => {
    const { call, dismissOpenForAgent, requireApproval, write } = setup();
    const result = await call({ isDashboardSession: false, oauthClientId: 'client_1' });
    expect(requireApproval).not.toHaveBeenCalled();
    expect(dismissOpenForAgent).toHaveBeenCalledWith('op_one', 'agt_one', 'operator:op_one');
    expect(result).toMatchObject({ agent_id: 'agt_one', dismissed: 3 });
    expect(write).toHaveBeenCalledTimes(1);
  });
});

describe('POST /v1/agents/:agentId/dismiss-warnings', () => {
  it('dismisses the agent\'s open warnings for the owner, and writes one audit row that counts them', async () => {
    const { call, dismissOpenForAgent, write } = setup();
    const result = await call({});
    expect(dismissOpenForAgent).toHaveBeenCalledWith('op_one', 'agt_one', 'operator:op_one');
    expect(result).toEqual({
      agent_id: 'agt_one',
      dismissed: 3,
      by_signal_type: { credential_outside_scope: 2, undeclared_target: 1 },
      repeats_hidden_for_seconds: 86400,
    });
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith(expect.objectContaining({
      action: 'security_events.dismiss_agent',
      outcome: 'success',
      ctx: expect.objectContaining({ operator_id: 'op_one', agent_id: 'agt_one' }),
      payload_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
    }));
  });

  it('records a member as the one who dismissed, and refuses a member who is neither standard nor admin', async () => {
    const { call, dismissOpenForAgent } = setup();
    await call({ memberId: 'mem_one', memberRole: 'standard' });
    expect(dismissOpenForAgent).toHaveBeenCalledWith('op_one', 'agt_one', 'member:mem_one');
    await expect(call({ memberId: 'mem_two', memberRole: 'viewer' })).rejects.toThrow(ForbiddenError);
    expect(dismissOpenForAgent).toHaveBeenCalledTimes(1);
  });

  it('refuses an agent that is not the account\'s, before anything is resolved', async () => {
    const { call, dismissOpenForAgent } = setup({ agentError: new NotFoundError('Agent', 'agt_one') });
    await expect(call({})).rejects.toThrow(NotFoundError);
    expect(dismissOpenForAgent).not.toHaveBeenCalled();
  });

  it('refuses an agent id that is not one', async () => {
    const { call } = setup();
    await expect(call({ params: { agentId: 'ms_nope' } })).rejects.toThrow();
  });

  it('answers zero when there is nothing open, and still writes its row', async () => {
    const { call, write } = setup({ dismissed: [] });
    expect(await call({})).toMatchObject({ dismissed: 0, by_signal_type: {} });
    expect(write).toHaveBeenCalledTimes(1);
  });

  it('is behind authentication and the agent-context denial', () => {
    const { options } = setup();
    expect(options()!.preHandler).toHaveLength(2);
  });
});
