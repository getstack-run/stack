import { describe, expect, it } from 'vitest';
import { assertPassportIssueActor, assertPassportContinuationActor } from './passports.js';

const baseInput = {
  agent_id: 'agt_self',
  intent: {
    summary: 'Submit a bounded transaction',
    services: [],
  },
};

describe('Passport authority issuance actor boundary', () => {
  it('allows an agent to request only its own preassigned authority binding', () => {
    expect(() => assertPassportIssueActor(
      { agentId: 'agt_self' },
      { ...baseInput, authority_binding_ids: ['abn_assigned'] },
    )).not.toThrow();
  });

  it('rejects an agent naming another target agent', () => {
    expect(() => assertPassportIssueActor(
      { agentId: 'agt_self' },
      { ...baseInput, agent_id: 'agt_other', authority_binding_ids: ['abn_assigned'] },
    )).toThrowError(expect.objectContaining({ code: 'FORBIDDEN' }));
  });

  it('rejects agent-selected legacy identity claims, including an empty override', () => {
    expect(() => assertPassportIssueActor(
      { agentId: 'agt_self' },
      { ...baseInput, identity_claim_ids: [] },
    )).toThrowError(expect.objectContaining({ code: 'FORBIDDEN' }));
  });

  it('does not change legacy operator issuance', () => {
    expect(() => assertPassportIssueActor({}, baseInput)).not.toThrow();
  });

  it('rejects a narrowed inbound Passport trying to issue an unrestricted root', () => {
    expect(() => assertPassportIssueActor({ agentId: 'agt_self', passportContext: {} }, baseInput))
      .toThrowError(expect.objectContaining({ code: 'FORBIDDEN' }));
  });

  it('allows only the authenticated agent to continue its Passport', () => {
    const claims = { stk: { operator_id: 'op_one', agent_id: 'agt_self' } };
    expect(() => assertPassportContinuationActor({ operatorId: 'op_one', agentId: 'agt_self' }, claims)).not.toThrow();
    expect(() => assertPassportContinuationActor({ operatorId: 'op_one' }, claims)).not.toThrow();
    expect(() => assertPassportContinuationActor({ operatorId: 'op_one', agentId: 'agt_other' }, claims))
      .toThrowError(expect.objectContaining({ code: 'FORBIDDEN' }));
    expect(() => assertPassportContinuationActor({ operatorId: 'op_other' }, claims))
      .toThrowError(expect.objectContaining({ code: 'FORBIDDEN' }));
  });
});
