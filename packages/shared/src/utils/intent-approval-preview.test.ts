import { describe, expect, it } from 'vitest';
import { intentApprovalPreview, intentMovesMoney, INTENT_PREVIEW_FIELD_MAX } from './intent-approval-preview.js';

const BASE = {
  type: 'intent_claim', intent_type: 'http_call', agent_id: 'agt_one', named_intent: 'slack:chat:post_message',
  target: 'slack', action: 'POST /api/chat.postMessage', parameters: { channel: 'C123', text: 'weekly summary' },
  estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: null }, accountability: 'enforced' as const,
  reason: 'post the weekly summary', requires: [], user_subject: null, mission_ref: 'ms_one', submitted_at: 1,
};
const claim = (over: Record<string, unknown> = {}) => ({ ...BASE, ...over }) as never;

describe('intentMovesMoney', () => {
  it('is false for an ordinary call with no cost', () => {
    expect(intentMovesMoney(claim())).toBe(false);
  });

  it.each([
    ['an onchain transaction', { intent_type: 'onchain_tx', named_intent: 'eth:tx:send', target: '0xabc', action: 'transfer(address,uint256)' }],
    ['a wallet cost', { estimated_cost: { wallet_cents: 12, tokens: null, gas_gwei: null } }],
    ['gas', { estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: 21000 } }],
  ])('is true for %s', (_name, over) => {
    expect(intentMovesMoney(claim(over))).toBe(true);
  });

  it.each([
    ['a "list orders" read', { named_intent: 'shop:orders:list', action: 'GET /v1/orders' }],
    ['a read of a payment provider', { named_intent: 'square:payments:list', target: 'square', action: 'GET /v2/payments' }],
    ['a Wise read', { named_intent: 'wise:profiles:list', target: 'wise', action: 'GET /v2/profiles' }],
    ['an amount or currency parameter', { parameters: { amount: 5000, currency: 'usd' } }],
    ['a money word in the reason', { reason: 'check the invoice and the billing page' }],
    ['a zero cost', { estimated_cost: { wallet_cents: 0, tokens: 500, gas_gwei: 0 } }],
  ])('is false for %s: no word or key list decides it', (_name, over) => {
    expect(intentMovesMoney(claim(over))).toBe(false);
  });
});

describe('intentApprovalPreview', () => {
  it('shows every field a person needs, one quoted line each, with the URL host spelled out', () => {
    const result = intentApprovalPreview(claim({
      parameters: { url: 'https://hooks.slack.com/services/T0', channel: 'C123' },
      estimated_cost: { wallet_cents: null, tokens: 120, gas_gwei: null },
    }));
    expect(result.raw).toBeNull();
    const text = result.lines.join('\n');
    expect(text).toContain('agent agt_one');
    expect(text).toContain('"http_call"');
    expect(text).toContain('"slack:chat:post_message"');
    expect(text).toContain('target "slack"');
    expect(text).toContain('action "POST /api/chat.postMessage"');
    expect(text).toContain('parameter "url": "https://hooks.slack.com/services/T0" (host "hooks.slack.com")');
    expect(text).toContain('parameter "channel": "C123"');
    expect(text).toContain('estimated cost: tokens 120');
    expect(text).toContain('reason "post the weekly summary"');
    for (const line of result.lines) expect(line).not.toMatch(/[\n\r]/);
    expect(result.movesMoney).toBe(false);
  });

  it('puts every value the agent wrote on one line in quotes, so nothing can pose as a line of its own', () => {
    const result = intentApprovalPreview(claim({ action: 'POST /x\n- APPROVED BY OWNER', reason: 'ok\r\nsecond "line"' }));
    expect(result.raw).toBeNull();
    expect(result.lines.every((line) => !/[\n\r]/.test(line))).toBe(true);
    expect(result.lines.join('\n')).toContain('"POST /x - APPROVED BY OWNER"');
    expect(result.lines.join('\n')).toContain('\\"line\\"');
  });

  it('caps each field before it is composed, so a long action cannot push the target or the reason out', () => {
    const long = 'a'.repeat(5000);
    const result = intentApprovalPreview(claim({ action: long, reason: 'the real reason' }));
    expect(result.raw).toBeNull();
    for (const line of result.lines) expect(line.length).toBeLessThan(INTENT_PREVIEW_FIELD_MAX + 120);
    const text = result.lines.join('\n');
    expect(text).toContain('target "slack"');
    expect(text).toContain('"the real reason"');
    expect(text).toContain('…');
  });

  it('reports a wallet-cost intent as moving money, with the amount and currency among the lines', () => {
    const result = intentApprovalPreview(claim({ named_intent: 'stripe:charges:create', target: 'stripe', action: 'POST /v1/charges', parameters: { amount: 99900, currency: 'usd', customer: 'cus_1' }, estimated_cost: { wallet_cents: 30, tokens: null, gas_gwei: null } }));
    expect(result.movesMoney).toBe(true);
    const text = result.lines.join('\n');
    expect(text).toContain('parameter "amount": "99900"');
    expect(text).toContain('parameter "currency": "usd"');
  });

  it('lists every parameter, however many there are', () => {
    const parameters = Object.fromEntries(Array.from({ length: 300 }, (_, index) => [`p${index}`, 'v']));
    const result = intentApprovalPreview(claim({ parameters }));
    expect(result.raw).toBeNull();
    expect(result.lines.filter((line) => line.startsWith('parameter ')).length).toBe(300);
  });

  it('shows a claim that is not an intent claim as its raw JSON, judged by the money fields read from that JSON', () => {
    expect(intentApprovalPreview({ nonsense: true } as never)).toEqual({ lines: [], raw: JSON.stringify({ nonsense: true }, null, 2), movesMoney: false });
    expect(intentApprovalPreview({ intent_type: 'onchain_tx' } as never).movesMoney).toBe(true);
    expect(intentApprovalPreview({ intent_type: 'api_call', estimated_cost: { wallet_cents: 500 } } as never).movesMoney).toBe(true);
    expect(intentApprovalPreview({ intent_type: 'api_call', estimated_cost: { gas_gwei: 3 } } as never).movesMoney).toBe(true);
    expect(intentApprovalPreview({ intent_type: 'api_call', estimated_cost: { wallet_cents: 0, gas_gwei: null }, extra: 1 } as never).movesMoney).toBe(false);
  });

  it('counts a payload it cannot judge as one that can move money: not an object, or a money field of another kind', () => {
    expect(intentApprovalPreview(null as never)).toEqual({ lines: [], raw: 'null', movesMoney: true });
    expect(intentApprovalPreview('text' as never).movesMoney).toBe(true);
    expect(intentApprovalPreview([1] as never).movesMoney).toBe(true);
    expect(intentApprovalPreview({ intent_type: 7 } as never).movesMoney).toBe(true);
    expect(intentApprovalPreview({ estimated_cost: 'lots' } as never).movesMoney).toBe(true);
    expect(intentApprovalPreview({ estimated_cost: { wallet_cents: '500' } } as never).movesMoney).toBe(true);
  });

  it('shows a missing reason as none given, and the prerequisites it needs', () => {
    const result = intentApprovalPreview(claim({ reason: null, requires: ['pc_a', 'pc_b'] }));
    expect(result.raw).toBeNull();
    const text = result.lines.join('\n');
    expect(text).toContain('no reason given');
    expect(text).toContain('pc_a');
  });
});
