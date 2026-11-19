import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { GovernanceApprovalRequiredError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({ createAuthMiddleware: () => async (request: Record<string, unknown>) => {
  const headers = request.headers as Record<string, string>;
  request.operatorId = 'op_one';
  request.isDashboardSession = headers.authorization === 'Bearer human';
  if (headers['x-member-role']) {
    request.memberId = 'mem_one';
    request.memberRole = headers['x-member-role'];
  }
} }));
import { registerIntentsRoutes } from './intents.js';

// The owner's key, SDK, CLI or chat decides an intent directly. Only an intent that can move money (an onchain
// transaction, or a wallet or gas cost) is approved in the browser; an intent STACK cannot read counts as one and is shown
// there as its raw JSON. The Console's own session is the person; rejecting needs no approval. A standard member may decide.

const ROW = {
  id: 'ia_one', operator_id: 'op_one', agent_id: 'agt_one', passport_jti: 'ppt_one', intent_claim_id: 'pc_one',
  simulated_claim_id: null, status: 'pending', requested_at: new Date(), expires_at: new Date(Date.now() + 60_000),
  decided_at: null, decided_by_member_id: null, notes: null, block_future: false, fleet_policy_id: null,
};

function claimBody(over: Record<string, unknown> = {}) {
  return {
    type: 'intent_claim', intent_type: 'http_call', agent_id: 'agt_one', named_intent: 'slack:chat:post_message',
    target: 'slack', action: 'POST /chat.postMessage\nAPPROVED BY OWNER', parameters: { channel: 'C123', url: 'https://slack.com/api/chat.postMessage' },
    estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: null },
    accountability: 'enforced', reason: 'post the weekly summary', requires: [], user_subject: null, mission_ref: 'ms_one',
    submitted_at: Date.now(), ...over,
  };
}

function build(options: { row?: Record<string, unknown> | null; body?: unknown } = {}) {
  const row = options.row === undefined ? ROW : options.row;
  const body = options.body === undefined ? claimBody() : options.body;
  const approve = vi.fn(async () => ({ approvalId: 'ia_one', status: 'approved', decidedAt: new Date() }));
  const reject = vi.fn(async () => ({ approvalId: 'ia_one', status: 'rejected', decidedAt: new Date() }));
  const requireApproval = vi.fn(async () => { throw new GovernanceApprovalRequiredError('gvr_new', 'https://getstack.run/app/approve/gvr_new', 'operator'); });
  const consume = vi.fn(async () => undefined);
  const app = Fastify();
  app.setErrorHandler(errorHandler);
  registerIntentsRoutes(app, {
    intentApproval: { findById: async () => row, approve, reject },
    passportClaimsRepo: { findByClaimId: async () => (body === null ? null : { operator_id: 'op_one', passport_id: 'ppt_one', type: 'intent_claim', body_json: body }) },
    governanceApprovals: { requireApproval, consume },
    audit: { write: async () => undefined },
  } as never);
  return { app, approve, reject, requireApproval, consume };
}

type App = ReturnType<typeof build>['app'];
const post = (app: App, action: 'approve' | 'reject', token: string, headers: Record<string, string> = {}, body: unknown = {}) =>
  app.inject({ method: 'POST', url: `/v1/intents/ia_one/${action}`, headers: { authorization: `Bearer ${token}`, ...headers }, payload: body as never });
const asked = (requireApproval: ReturnType<typeof build>['requireApproval']) => (requireApproval.mock.calls[0] as unknown as [Record<string, unknown>])[0];

describe('approving an intent', () => {
  it('approves an intent that moves no money directly for a key or an OAuth token, asking nobody', async () => {
    for (const token of ['operator-key', 'oauth-token']) {
      const { app, approve, requireApproval } = build();
      try {
        const response = await post(app, 'approve', token, {}, { notes: 'ok' });
        expect(response.statusCode).toBe(200);
        expect(requireApproval).not.toHaveBeenCalled();
        expect(approve).toHaveBeenCalledWith(expect.objectContaining({ id: 'ia_one', operatorId: 'op_one', notes: 'ok' }));
      } finally { await app.close(); }
    }
  });

  it.each([
    ['a "list orders" read', claimBody({ named_intent: 'shop:orders:list', action: 'GET /v1/orders' })],
    ['a read of a payment provider', claimBody({ named_intent: 'square:payments:list', target: 'square', action: 'GET /v2/payments' })],
    ['an amount parameter with no cost', claimBody({ parameters: { amount: 99900, currency: 'usd' } })],
    ['an intent with more parameters than any list', claimBody({ parameters: Object.fromEntries(Array.from({ length: 41 }, (_, index) => [`p${index}`, 'v'])) })],
  ])('approves %s directly: no word or parameter count sends it to the browser', async (_name, body) => {
    const { app, approve, requireApproval } = build({ body });
    try {
      expect((await post(app, 'approve', 'oauth-token')).statusCode).toBe(200);
      expect(requireApproval).not.toHaveBeenCalled();
      expect(approve).toHaveBeenCalledTimes(1);
    } finally { await app.close(); }
  });

  it.each([
    ['an onchain transfer', claimBody({ intent_type: 'onchain_tx', named_intent: 'eth:tx:send', target: '0xabc', action: 'transfer(address,uint256)', parameters: {} })],
    ['a wallet cost', claimBody({ estimated_cost: { wallet_cents: 5, tokens: null, gas_gwei: null } })],
    ['gas', claimBody({ estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: 21000 } })],
  ])('sends %s to the browser: intent_approve_payment, with every field on its own quoted line', async (_name, body) => {
    const { app, approve, requireApproval } = build({ body });
    try {
      const response = await post(app, 'approve', 'oauth-token', {}, { notes: 'ok' });
      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ error: { code: 'GOVERNANCE_APPROVAL_REQUIRED', details: { approval_id: 'gvr_new' } } });
      const input = asked(requireApproval);
      expect(input).toMatchObject({
        action: 'intent_approve_payment',
        resourceId: 'ia_one',
        payload: { approval_id: 'ia_one', agent_id: 'agt_one', intent_claim_id: 'pc_one', notes: 'ok' },
      });
      const preview = input['preview'] as { lines: string[]; raw: string | null };
      expect(preview.raw).toBeNull();
      expect(preview.lines.length).toBeGreaterThanOrEqual(5);
      expect(preview.lines.every((line) => !/[\n\r]/.test(line))).toBe(true);
      expect(preview.lines.join('\n')).toContain('action "');
      expect(String(input['summary'])).not.toMatch(/[\n\r]/);
      expect(approve).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });

  it('approves an intent STACK cannot read directly when its JSON shows no money field', async () => {
    for (const body of [{ nonsense: true }, { intent_type: 'http_call', estimated_cost: { wallet_cents: 0 } }]) {
      const { app, approve, requireApproval } = build({ body });
      try {
        expect((await post(app, 'approve', 'operator-key')).statusCode).toBe(200);
        expect(requireApproval).not.toHaveBeenCalled();
        expect(approve).toHaveBeenCalledTimes(1);
      } finally { await app.close(); }
    }
  });

  it('sends an unreadable intent to the browser with its raw JSON when its money fields say so or cannot be read', async () => {
    for (const body of ['not an object', { intent_type: 'onchain_tx' }, { estimated_cost: { wallet_cents: 500 } }, { estimated_cost: { gas_gwei: '1' } }]) {
      const { app, approve, requireApproval } = build({ body });
      try {
        const response = await post(app, 'approve', 'operator-key');
        expect(response.statusCode).toBe(403);
        const input = asked(requireApproval);
        expect(input).toMatchObject({ action: 'intent_approve_payment', resourceId: 'ia_one' });
        expect(input['preview']).toEqual({ lines: [], raw: JSON.stringify(body, null, 2) });
        expect(approve).not.toHaveBeenCalled();
      } finally { await app.close(); }
    }
  });

  it('approves only in the Console an approval whose claim is missing or is another agent\'s intent', async () => {
    for (const body of [null, claimBody({ agent_id: 'agt_other' })]) {
      const { app, approve, requireApproval } = build({ body });
      try {
        const response = await post(app, 'approve', 'operator-key');
        expect(response.statusCode).toBe(403);
        expect(response.json().error.message).toContain('Approve it in the Console.');
        expect(requireApproval).not.toHaveBeenCalled();
        expect(approve).not.toHaveBeenCalled();
      } finally { await app.close(); }
    }
  });

  it('approves a money intent with an approval a person gave to this exact request', async () => {
    const money = build({ body: claimBody({ estimated_cost: { wallet_cents: 1, tokens: null, gas_gwei: null } }) });
    try {
      expect((await post(money.app, 'approve', 'operator-key', { 'x-governance-approval': 'gvr_ok' }, { notes: 'ok' })).statusCode).toBe(200);
      expect(money.consume).toHaveBeenCalledWith(expect.objectContaining({
        approvalId: 'gvr_ok', action: 'intent_approve_payment', resourceId: 'ia_one',
        payload: { approval_id: 'ia_one', agent_id: 'agt_one', intent_claim_id: 'pc_one', notes: 'ok' },
      }));
      expect(money.approve).toHaveBeenCalledTimes(1);
    } finally { await money.app.close(); }
    const refused = build({ body: claimBody({ estimated_cost: { wallet_cents: 1, tokens: null, gas_gwei: null } }) });
    refused.consume.mockRejectedValueOnce(new Error('approval does not match'));
    try {
      expect((await post(refused.app, 'approve', 'operator-key', { 'x-governance-approval': 'gvr_other' })).statusCode).toBe(500);
      expect(refused.approve).not.toHaveBeenCalled();
    } finally { await refused.app.close(); }
  });

  it('lets the Console\'s own session approve a money intent with no further step, because the person is there', async () => {
    const { app, approve, requireApproval, consume } = build({ body: claimBody({ intent_type: 'onchain_tx' }) });
    try {
      expect((await post(app, 'approve', 'human')).statusCode).toBe(200);
      expect(requireApproval).not.toHaveBeenCalled();
      expect(consume).not.toHaveBeenCalled();
      expect(approve).toHaveBeenCalledTimes(1);
    } finally { await app.close(); }
  });

  it('rejects with no approval from anyone', async () => {
    const { app, reject, requireApproval } = build();
    try {
      expect((await post(app, 'reject', 'operator-key', {}, { block_future: true })).statusCode).toBe(200);
      expect(requireApproval).not.toHaveBeenCalled();
      expect(reject).toHaveBeenCalledTimes(1);
    } finally { await app.close(); }
  });

  it('asks nobody about an intent that cannot be decided: it is unknown, or no longer pending', async () => {
    const gone = build({ row: null });
    try {
      expect((await post(gone.app, 'approve', 'operator-key')).statusCode).toBe(404);
      expect(gone.requireApproval).not.toHaveBeenCalled();
    } finally { await gone.app.close(); }
    const decided = build({ row: { ...ROW, status: 'approved' }, body: claimBody({ intent_type: 'onchain_tx' }) });
    try {
      await post(decided.app, 'approve', 'operator-key');
      expect(decided.requireApproval).not.toHaveBeenCalled();
      expect(decided.approve).toHaveBeenCalledTimes(1);
    } finally { await decided.app.close(); }
  });
});

describe('who may decide an intent', () => {
  it('refuses a read-only member to approve or reject, before anything is asked or changed', async () => {
    const { app, approve, reject, requireApproval } = build();
    try {
      for (const action of ['approve', 'reject'] as const) {
        const response = await post(app, action, 'human', { 'x-member-role': 'readonly' });
        expect(response.statusCode, action).toBe(403);
      }
      expect(approve).not.toHaveBeenCalled();
      expect(reject).not.toHaveBeenCalled();
      expect(requireApproval).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });

  it.each(['standard', 'admin'])('lets a %s member decide, and the operator themselves', async (role) => {
    const { app, approve, reject } = build();
    try {
      expect((await post(app, 'approve', 'human', { 'x-member-role': role })).statusCode).toBe(200);
      expect((await post(app, 'reject', 'human', { 'x-member-role': role })).statusCode).toBe(200);
      expect((await post(app, 'reject', 'operator-key')).statusCode).toBe(200);
      expect(approve).toHaveBeenCalledTimes(1);
      expect(reject).toHaveBeenCalledTimes(2);
    } finally { await app.close(); }
  });
});

describe('reviewing an intent', () => {
  const review = (app: App) => app.inject({ method: 'GET', url: '/v1/intents/ia_one?review=1', headers: { authorization: 'Bearer human' } });

  it('shows an intent STACK cannot read as the raw JSON it was stored as', async () => {
    const { app } = build({ body: { nonsense: true } });
    try {
      const response = await review(app);
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ id: 'ia_one', status: 'pending', intent: null, intent_raw: JSON.stringify({ nonsense: true }, null, 2) });
    } finally { await app.close(); }
  });

  it('shows nothing of a claim that reads as another agent\'s intent', async () => {
    const { app } = build({ body: claimBody({ agent_id: 'agt_other' }) });
    try {
      expect((await review(app)).statusCode).toBe(404);
    } finally { await app.close(); }
  });

  it('shows an intent it can read field by field, with no raw JSON', async () => {
    const { app } = build();
    try {
      const response = await review(app);
      expect(response.statusCode).toBe(200);
      expect(response.json().intent).toMatchObject({ named_intent: 'slack:chat:post_message', target: 'slack' });
      expect(response.json().intent_raw).toBeUndefined();
    } finally { await app.close(); }
  });
});
