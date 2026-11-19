import { describe, expect, it, vi } from 'vitest';
import { GOVERNANCE_ACTIONS, GOVERNANCE_BROWSER_ONLY_ACTIONS, type GovernanceAction } from '@stack/shared';
import { GOVERNANCE_STEP_UP_WAIVED_ACTION, enforceGovernanceStepUp } from './governance-stepup.js';

/**
 * The trust switch at a governance step-up. With "Trust my agents" the owner's own API key (no member, no OAuth client,
 * no agent) is let through without an approval, and the audit record says the trust setting waived it; with "Ask me
 * first" it asks, as it always did. A browser-only action asks in both.
 */

const OWNER_KEY = { operatorId: 'op_one', isDashboardSession: false, headers: {}, id: 'req_1' };

function services(trusted: boolean | null) {
  const requireApproval = vi.fn(async () => { throw new Error('approval required'); });
  const write = vi.fn(async () => undefined);
  const waives = vi.fn(async () => trusted === true);
  return {
    requireApproval,
    write,
    waives,
    value: {
      governanceApprovals: { requireApproval, consume: vi.fn() },
      audit: { write },
      ...(trusted === null ? {} : { stepUpWaiver: { waives } }),
    } as never,
  };
}

const input = (action: GovernanceAction) => ({ action, resourceId: 'agt_one', payload: { agent_id: 'agt_one' }, summary: 'A change' });

describe('governance step-up and the trust switch', () => {
  it('"Trust my agents": the owner\'s own key sets up an agent without an approval, and the record says why', async () => {
    const s = services(true);
    await expect(enforceGovernanceStepUp(s.value, OWNER_KEY as never, input('agent_setup'))).resolves.toBeUndefined();
    expect(s.requireApproval).not.toHaveBeenCalled();
    expect(s.waives).toHaveBeenCalledWith('op_one');
    expect(s.write).toHaveBeenCalledTimes(1);
    expect((s.write.mock.calls as unknown as Array<[unknown]>)[0]![0]).toMatchObject({ action: GOVERNANCE_STEP_UP_WAIVED_ACTION, outcome: 'success', ctx: { operator_id: 'op_one' } });
    expect(GOVERNANCE_STEP_UP_WAIVED_ACTION).toBe('governance.step_up.waived_by_trust');
  });

  it('"Ask me first": the same call asks for an approval, as today', async () => {
    const s = services(false);
    await expect(enforceGovernanceStepUp(s.value, OWNER_KEY as never, input('agent_setup'))).rejects.toThrow('approval required');
    expect(s.requireApproval).toHaveBeenCalledWith(expect.objectContaining({ operatorId: 'op_one', action: 'agent_setup', requestedVia: 'operator_key' }));
    expect(s.write).not.toHaveBeenCalled();
  });

  it('a deployment with no trust switch (an install) always asks', async () => {
    const s = services(null);
    await expect(enforceGovernanceStepUp(s.value, OWNER_KEY as never, input('agent_setup'))).rejects.toThrow('approval required');
  });

  it('every browser-only action still asks in "Trust my agents", and every other action is let through', async () => {
    for (const action of GOVERNANCE_ACTIONS) {
      const s = services(true);
      const run = enforceGovernanceStepUp(s.value, OWNER_KEY as never, input(action));
      if (GOVERNANCE_BROWSER_ONLY_ACTIONS.has(action)) {
        await expect(run, action).rejects.toThrow('approval required');
        expect(s.waives, action).not.toHaveBeenCalled();
      } else {
        await expect(run, action).resolves.toBeUndefined();
      }
    }
    expect(GOVERNANCE_BROWSER_ONLY_ACTIONS.size).toBe(11);
  });

  it.each([
    ['a member', { memberId: 'mem_one' }],
    ['an OAuth sign-in (a chat)', { oauthClientId: 'client_chat' }],
    ['an agent', { agentId: 'agt_one' }],
    ['an enrollment ticket', { enrollmentTicket: { agent_id: 'agt_one', jti: 'j', machine_label: null, exp: 1 } }],
    ['a platform Passport', { platformPassport: { jti: 'j', operator_id: 'op_one', agent_id: 'agt_one', platform_intent: 'monitor' } }],
    ['an agent Passport', { passportContext: { jti: 'j', operator_id: 'op_one', agent_id: 'agt_one', mission_ids: [], intent_services: [], services: [] } }],
  ])('%s is not the owner\'s own key: it still asks in "Trust my agents"', async (_who, extra) => {
    const s = services(true);
    await expect(enforceGovernanceStepUp(s.value, { ...OWNER_KEY, ...extra } as never, input('agent_setup'))).rejects.toThrow('approval required');
    expect(s.write).not.toHaveBeenCalled();
  });

  it('a retry that carries an approval consumes it as before, trusted or not', async () => {
    const s = services(true);
    const consume = vi.fn(async () => undefined);
    (s.value as unknown as { governanceApprovals: { consume: typeof consume } }).governanceApprovals.consume = consume;
    await enforceGovernanceStepUp(s.value, { ...OWNER_KEY, headers: { 'x-governance-approval': 'gov_one' } } as never, input('agent_unblock'));
    expect(consume).toHaveBeenCalledTimes(1);
    expect(s.write).not.toHaveBeenCalled();
  });

  it('the dashboard human passes free in both modes without the record of a waiver', async () => {
    const s = services(false);
    await expect(enforceGovernanceStepUp(s.value, { ...OWNER_KEY, isDashboardSession: true } as never, input('agent_setup'))).resolves.toBeUndefined();
    expect(s.write).not.toHaveBeenCalled();
  });
});
