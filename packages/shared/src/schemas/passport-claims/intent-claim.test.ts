import { describe, it, expect } from 'vitest';
import { IntentClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

/**
 * Coverage for the IntentClaim payload schema. Tests assert wire-shape
 * acceptance for each intent_type variant + rejection of malformed
 * shapes. Also pins the schema in PASSPORT_CLAIM_SCHEMAS so the
 * ClaimRegistryService can dispatch by claim_type.
 *
 * Per ADR additive-only versioning rule: these tests pin the v1 wire
 * shape — any breaking change to the schema fails CI loudly.
 */

const baseValid = {
  type: 'intent_claim' as const,
  intent_type: 'http_call' as const,
  agent_id: 'ag_test1',
  named_intent: 'stripe:charges:create',
  target: 'api.stripe.com',
  action: 'POST /v1/charges',
  parameters: { amount: 1000, currency: 'usd' },
  estimated_cost: {
    wallet_cents: 5,
    tokens: null,
    gas_gwei: null,
  },
  accountability: 'standard' as const,
  reason: 'process refund for order #123 per task purpose',
  requires: [],
  user_subject: 'mem_user_a',
  mission_ref: null,
  submitted_at: 1_726_000_000_000,
};

describe('IntentClaim', () => {
  it('accepts a full valid http_call payload', () => {
    expect(() => IntentClaim.parse(baseValid)).not.toThrow();
  });

  it('accepts an mcp_tool intent_type', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        intent_type: 'mcp_tool',
        named_intent: 'slack:messages:send',
        target: 'mcp://slack',
        action: 'send_message',
      }),
    ).not.toThrow();
  });

  it('accepts a skill_invocation intent_type', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        intent_type: 'skill_invocation',
        named_intent: 'skills:invoke:summarise',
        target: 'sk_summarise_v1',
        action: 'invoke',
      }),
    ).not.toThrow();
  });

  it('accepts an onchain_tx intent_type with gas_gwei cost', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        intent_type: 'onchain_tx',
        named_intent: 'evm:erc20:transfer',
        target: '0x1234567890abcdef1234567890abcdef12345678',
        action: 'transfer(address,uint256)',
        estimated_cost: {
          wallet_cents: 1,
          tokens: null,
          gas_gwei: 21000,
        },
      }),
    ).not.toThrow();
  });

  it('accepts an a2a_dispatch intent_type (shared ActionType, added 2026-05-15)', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        intent_type: 'a2a_dispatch',
        named_intent: 'a2a:tasks:send',
        target: 'ag_remote_xyz',
        action: 'tasks/send',
      }),
    ).not.toThrow();
  });

  it('accepts a task_complete intent_type with all-null cost', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        intent_type: 'task_complete',
        named_intent: 'task:complete:milestone',
        target: 'analysis-q4-2026',
        action: 'mark_complete',
        estimated_cost: {
          wallet_cents: null,
          tokens: null,
          gas_gwei: null,
        },
      }),
    ).not.toThrow();
  });

  it('accepts a minimal payload with reason=null and empty requires', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        reason: null,
        requires: [],
        user_subject: null,
        mission_ref: null,
      }),
    ).not.toThrow();
  });

  it('accepts requires array with multiple claim refs', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        requires: ['pc_abc123', 'pc_def456'],
      }),
    ).not.toThrow();
  });

  it('defaults accountability to standard when omitted', () => {
    const { accountability: _omit, ...rest } = baseValid;
    const parsed = IntentClaim.parse(rest);
    expect(parsed.accountability).toBe('standard');
  });

  it('defaults requires to empty array when omitted', () => {
    const { requires: _omit, ...rest } = baseValid;
    const parsed = IntentClaim.parse(rest);
    expect(parsed.requires).toEqual([]);
  });

  it('rejects unknown intent_type', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, intent_type: 'phone_call' as never }),
    ).toThrow();
  });

  it('rejects malformed agent_id', () => {
    expect(() => IntentClaim.parse({ ...baseValid, agent_id: 'not-an-agent' })).toThrow();
  });

  it('rejects named_intent that does not match provider:resource:action', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, named_intent: 'stripe.charges.create' }),
    ).toThrow();
    expect(() =>
      IntentClaim.parse({ ...baseValid, named_intent: 'stripe:charges' }),
    ).toThrow();
    expect(() =>
      IntentClaim.parse({ ...baseValid, named_intent: 'STRIPE:charges:create' }),
    ).toThrow();
  });

  it('rejects empty target', () => {
    expect(() => IntentClaim.parse({ ...baseValid, target: '' })).toThrow();
  });

  it('rejects empty action', () => {
    expect(() => IntentClaim.parse({ ...baseValid, action: '' })).toThrow();
  });

  it('rejects negative wallet_cents', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        estimated_cost: { wallet_cents: -1, tokens: null, gas_gwei: null },
      }),
    ).toThrow();
  });

  it('rejects non-integer tokens', () => {
    expect(() =>
      IntentClaim.parse({
        ...baseValid,
        estimated_cost: { wallet_cents: null, tokens: 1.5, gas_gwei: null },
      }),
    ).toThrow();
  });

  it('rejects reason exceeding 2048 chars', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, reason: 'x'.repeat(2049) }),
    ).toThrow();
  });

  it('accepts reason at exactly 2048 chars', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, reason: 'x'.repeat(2048) }),
    ).not.toThrow();
  });

  it('rejects requires entries that are not claim ids', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, requires: ['not-a-claim'] }),
    ).toThrow();
  });

  it('rejects unknown accountability tier', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, accountability: 'critical' as never }),
    ).toThrow();
  });

  it('rejects malformed mission_ref', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, mission_ref: 'mission_abc' }),
    ).toThrow();
  });

  it('accepts mission_ref as null', () => {
    expect(() => IntentClaim.parse({ ...baseValid, mission_ref: null })).not.toThrow();
  });

  it('accepts mission_ref as a valid mission_id (ms_*)', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, mission_ref: 'ms_mission_2026q4' }),
    ).not.toThrow();
  });

  it('rejects mission_ref with the old pc_* shape (5.0.4 wire-shape change)', () => {
    expect(() =>
      IntentClaim.parse({ ...baseValid, mission_ref: 'pc_old_shape' }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.intent_claim).toBe(IntentClaim);
  });
});
