import { describe, expect, it, vi } from 'vitest';
import { enforceGovernanceStepUp } from './governance-stepup.js';

function request(overrides: Record<string, unknown> = {}) {
  return {
    operatorId: 'op_one', memberId: null, oauthClientId: null,
    isDashboardSession: false,
    headers: { 'x-governance-approval': 'gov_one' },
    ...overrides,
  };
}

describe('authority governance step-up idempotency wiring', () => {
  it('passes the raw mutation key and exact authority operation to idempotent consumption', async () => {
    const consumeAuthorityIdempotently = vi.fn(async () => undefined);
    const consume = vi.fn();
    await enforceGovernanceStepUp({
      governanceApprovals: { consumeAuthorityIdempotently, consume },
    } as never, request() as never, {
      action: 'authority_principal_erase',
      resourceId: 'prn_one',
      payload: {},
      summary: 'Erase principal',
      idempotencyKey: 'Untrimmed-Key-Value',
    });

    expect(consumeAuthorityIdempotently).toHaveBeenCalledWith({
      approvalId: 'gov_one', operatorId: 'op_one', action: 'authority_principal_erase',
      resourceId: 'prn_one', payload: {}, idempotencyKey: 'Untrimmed-Key-Value', memberId: null,
    });
    expect(consume).not.toHaveBeenCalled();
  });

  it('retains single-use consumption for non-authority callers without a mutation key', async () => {
    const consumeAuthorityIdempotently = vi.fn();
    const consume = vi.fn(async () => undefined);
    await enforceGovernanceStepUp({
      governanceApprovals: { consumeAuthorityIdempotently, consume },
    } as never, request() as never, {
      action: 'agent_unblock', resourceId: 'agt_one', payload: {}, summary: 'Unblock agent',
    });

    expect(consume).toHaveBeenCalledWith({
      approvalId: 'gov_one', operatorId: 'op_one', action: 'agent_unblock',
      resourceId: 'agt_one', payload: {}, memberId: null,
    });
    expect(consumeAuthorityIdempotently).not.toHaveBeenCalled();
  });

  it('says which member is retrying, so an approval is only used by the one who asked for it', async () => {
    const consume = vi.fn(async () => undefined);
    const consumeAuthorityIdempotently = vi.fn(async () => undefined);
    await enforceGovernanceStepUp({ governanceApprovals: { consume, consumeAuthorityIdempotently } } as never, request({ memberId: 'mem_two' }) as never, {
      action: 'sso_config_change', resourceId: 'create', payload: {}, summary: 'Set up sign-in',
    });
    expect(consume).toHaveBeenCalledWith(expect.objectContaining({ memberId: 'mem_two' }));
    await enforceGovernanceStepUp({ governanceApprovals: { consume, consumeAuthorityIdempotently } } as never, request({ memberId: 'mem_two' }) as never, {
      action: 'authority_principal_erase', resourceId: 'prn_one', payload: {}, summary: 'Erase', idempotencyKey: 'k',
    });
    expect(consumeAuthorityIdempotently).toHaveBeenCalledWith(expect.objectContaining({ memberId: 'mem_two' }));
  });

  it('keeps a dashboard human ceremony approval-free', async () => {
    const consumeAuthorityIdempotently = vi.fn();
    const consume = vi.fn();
    await enforceGovernanceStepUp({ governanceApprovals: {
      consumeAuthorityIdempotently, consume,
    } } as never, request({ isDashboardSession: true }) as never, {
      action: 'authority_binding_erase', resourceId: 'abn_one', payload: {},
      summary: 'Erase binding', idempotencyKey: 'erase-binding-one',
    });

    expect(consumeAuthorityIdempotently).not.toHaveBeenCalled();
    expect(consume).not.toHaveBeenCalled();
  });
});
