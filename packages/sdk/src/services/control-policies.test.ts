import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import {
  ControlDeniedError,
  ControlLimitExceededError,
  ControlsNotEnabledError,
  GovernanceApprovalRequiredError,
  StackError,
  UnboundedSendRuleError,
} from '../errors.js';
import { POLICY_RECIPIENTS_PER_MISSION, type PolicyDefinition } from './control-policies.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({
        method: init.method ?? 'GET',
        path: parsed.pathname,
        search: parsed.search,
        body: init.body ? JSON.parse(init.body) : undefined,
        headers: init.headers ?? {},
      });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_control_policies_test', baseUrl: 'http://api.fixture' });
const policies = () => stack().controlPolicies;
const reviews = () => stack().controlReviews;

const AGENT = 'agt_abcdefgh1234';
const definition: PolicyDefinition = { name: 'Support agent', spend: { max_per_action_cents: 500 } };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('controlPolicies reads', () => {
  it('lists every policy and says whether controls are on', async () => {
    const calls = stubFetch({ status: 200, body: { controls_enabled: true, policies: [{ id: 'cpl_1' }] } });
    const result = await policies().list();
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/control-policies' });
    expect(result.controls_enabled).toBe(true);
    expect(result.policies).toHaveLength(1);
  });

  it('reads the default policy and an agent policy from their own paths', async () => {
    const calls = stubFetch({ status: 200, body: {} });
    await policies().get('default');
    await policies().get(AGENT);
    expect(calls.map((call) => [call.method, call.path])).toEqual([
      ['GET', '/v1/control-policies/default'],
      ['GET', `/v1/control-policies/agents/${AGENT}`],
    ]);
  });

  it('answers a missing default with a 404 StackError', async () => {
    stubFetch({ status: 404, body: { error: { code: 'NOT_FOUND', message: 'Control policy default not found' } } });
    const error = await policies().get('default').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({ status: 404, code: 'NOT_FOUND' });
  });

  it('reads the revisions of a policy', async () => {
    const calls = stubFetch({ status: 200, body: { revisions: [] } });
    await policies().revisions('cpl_abc');
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/control-policies/cpl_abc/revisions' });
  });
});

describe('controlPolicies writes', () => {
  it('creates without an expected revision and revises with one', async () => {
    const calls = stubFetch({ status: 200, body: { change: 'create', policy: { id: 'cpl_1' } } });
    await policies().set('default', definition);
    await policies().set(AGENT, definition, { expectedRevision: 3 });
    await policies().set(AGENT, definition, { expectedRevision: 0 });
    expect(calls.map((call) => [call.method, call.path, call.body])).toEqual([
      ['PUT', '/v1/control-policies/default', { definition }],
      ['PUT', `/v1/control-policies/agents/${AGENT}`, { definition, expected_revision: 3 }],
      ['PUT', `/v1/control-policies/agents/${AGENT}`, { definition, expected_revision: 0 }],
    ]);
  });

  it('deletes with the expected revision in the query only when given, and no body', async () => {
    const calls = stubFetch({ status: 200, body: { change: 'delete', policy: null } });
    await policies().delete('default');
    await policies().delete(AGENT, { expectedRevision: 2 });
    expect(calls.map((call) => [call.method, call.path, call.search, call.body])).toEqual([
      ['DELETE', '/v1/control-policies/default', '', undefined],
      ['DELETE', `/v1/control-policies/agents/${AGENT}`, '?expected_revision=2', undefined],
    ]);
  });

  it('starts from current access with a POST and no body', async () => {
    const calls = stubFetch({ status: 201, body: { change: 'start_from_access', policy: { id: 'cpl_1' } } });
    const result = await policies().startFromCurrentAccess(AGENT);
    expect(calls[0]).toMatchObject({ method: 'POST', path: `/v1/control-policies/agents/${AGENT}/start-from-current-access`, body: undefined });
    expect(result.change).toBe('start_from_access');
  });

  it('simulates a call against an agent or a draft and sends the input as given', async () => {
    const calls = stubFetch({ status: 200, body: { verdict: 'deny' } });
    await policies().simulate({ agent_id: AGENT, call: { action: 'card.checkout', amount_cents: 900 } });
    await policies().simulate({ definition, call: { action: 'email.send', target: { to: 'a@example.com' } } });
    expect(calls.map((call) => [call.method, call.path, call.body])).toEqual([
      ['POST', '/v1/control-policies/simulate', { agent_id: AGENT, call: { action: 'card.checkout', amount_cents: 900 } }],
      ['POST', '/v1/control-policies/simulate', { definition, call: { action: 'email.send', target: { to: 'a@example.com' } } }],
    ]);
  });

  it('encodes ids that are not path safe', async () => {
    const calls = stubFetch();
    await policies().get('agt_a/../b');
    expect(calls[0]!.path).toBe('/v1/control-policies/agents/agt_a%2F..%2Fb');
  });
});

describe('controlPolicies approvals', () => {
  type Approval = { governanceApprovalId: string } | undefined;
  const cases: Array<[string, (approval: Approval) => Promise<unknown>, string, string]> = [
    ['set', (a) => policies().set('default', definition, { expectedRevision: 1, ...a }), 'PUT', '/v1/control-policies/default'],
    ['delete', (a) => policies().delete(AGENT, { expectedRevision: 1, ...a }), 'DELETE', `/v1/control-policies/agents/${AGENT}`],
    ['startFromCurrentAccess', (a) => policies().startFromCurrentAccess(AGENT, a), 'POST', `/v1/control-policies/agents/${AGENT}/start-from-current-access`],
  ];

  it.each(cases)('%s sends X-Governance-Approval only when given', async (_name, call, method, path) => {
    const calls = stubFetch();
    await call(undefined);
    await call({ governanceApprovalId: 'gvr_approved' });
    expect(calls.map((sent) => [sent.method, sent.path])).toEqual([[method, path], [method, path]]);
    expect(calls[0]!.headers['X-Governance-Approval']).toBeUndefined();
    expect(calls[1]!.headers['X-Governance-Approval']).toBe('gvr_approved');
  });

  it('throws GovernanceApprovalRequiredError with the approval link for a loosening', async () => {
    stubFetch({
      status: 403,
      body: {
        error: {
          code: 'GOVERNANCE_APPROVAL_REQUIRED',
          message: 'A person must approve this',
          details: { approval_id: 'gvr_1', approval_url: 'https://getstack.run/app/approvals/gvr_1' },
        },
      },
    });
    const error = await policies().set('default', definition, { expectedRevision: 1 }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(GovernanceApprovalRequiredError);
    expect(error).toMatchObject({ approvalId: 'gvr_1', approvalUrl: 'https://getstack.run/app/approvals/gvr_1' });
  });

  it('simulate and the reads never send an approval header', async () => {
    const calls = stubFetch();
    await policies().simulate({ agent_id: AGENT, call: { action: 'model.call' } });
    await policies().list();
    expect(calls.every((sent) => sent.headers['X-Governance-Approval'] === undefined)).toBe(true);
  });
});

describe('recipients set per job', () => {
  const perJob: PolicyDefinition = {
    name: 'Per job',
    connections: {
      mode: 'listed',
      rules: [{
        id: 'mail-per-job',
        effect: 'allow',
        recipients: POLICY_RECIPIENTS_PER_MISSION,
        access: { connection_id: 'scon_abcdefgh', intents: [{ name: 'resend.send_email', params: {} }] },
      }],
    },
    recipients: { email: ['@example.com'], sms: ['+14155550100'], call: ['+442071838750'] },
  };

  it('sends a rule as per_mission and the account lists as lists, unchanged', async () => {
    const calls = stubFetch({ status: 200, body: { change: 'create', policy: { id: 'cpl_1' } } });
    await policies().set('default', perJob);
    expect(POLICY_RECIPIENTS_PER_MISSION).toBe('per_mission');
    expect(calls[0]).toMatchObject({ method: 'PUT', path: '/v1/control-policies/default', body: { definition: perJob } });
  });

  it('sends the account email, text and call recipients as per_mission, unchanged', async () => {
    const calls = stubFetch({ status: 200, body: { change: 'create', policy: { id: 'cpl_1' } } });
    const accountPerJob: PolicyDefinition = {
      name: 'Account per job',
      recipients: { email: POLICY_RECIPIENTS_PER_MISSION, sms: 'per_mission', call: 'per_mission' },
    };
    await policies().set('default', accountPerJob);
    expect(calls[0]).toMatchObject({
      method: 'PUT',
      path: '/v1/control-policies/default',
      body: { definition: { recipients: { email: 'per_mission', sms: 'per_mission', call: 'per_mission' } } },
    });
  });

  it('sends a list for one account channel and per_mission for another in one policy', async () => {
    const calls = stubFetch({ status: 200, body: { change: 'create', policy: { id: 'cpl_1' } } });
    const mixed: PolicyDefinition = { name: 'Mixed', recipients: { email: 'per_mission', sms: ['+14155550100'] } };
    await policies().set('default', mixed);
    expect(calls[0]).toMatchObject({ body: { definition: { recipients: { email: 'per_mission', sms: ['+14155550100'] } } } });
  });

  it('tries a call inside a Mission with its mission_id', async () => {
    const calls = stubFetch({ status: 200, body: { verdict: 'deny' } });
    await policies().simulate({
      agent_id: AGENT,
      call: { action: 'email.send', mission_id: 'ms_abcdefgh1234', target: { to: 'ana@example.com' } },
    });
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: '/v1/control-policies/simulate',
      body: { agent_id: AGENT, call: { action: 'email.send', mission_id: 'ms_abcdefgh1234', target: { to: 'ana@example.com' } } },
    });
  });

  it('carries recipients_not_pinned and recipient_not_allowed on a refusal', async () => {
    for (const code of ['recipients_not_pinned', 'recipient_not_allowed'] as const) {
      stubFetch({
        status: 403,
        body: {
          error: {
            code: 'CONTROL_DENIED',
            message: 'refused',
            details: {
              decision_id: 'dec_abcdefghijklmnop',
              reason_code: code,
              rule: { policy_id: 'cpl_1', policy_revision: 2, section: 'connections', rule: 'mail-per-job', code },
            },
          },
        },
      });
      const error = await stack().accounts.get('acct_1').catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ControlDeniedError);
      expect(error).toMatchObject({ reasonCode: code, rule: { code, section: 'connections' } });
    }
  });
});

describe('controlPolicies errors', () => {
  it('maps UNBOUNDED_SEND_RULE on a set to its typed error', async () => {
    stubFetch({
      status: 400,
      body: {
        error: {
          code: 'UNBOUNDED_SEND_RULE',
          message: 'A rule allows a send without naming who receives it',
          details: { rules: [{ rule_id: 'mail', connection_id: 'scon_x', provider: 'resend', reason: 'unbound_recipient', intents: ['resend.send_email'], unbound_paths: ['body.to'] }] },
        },
      },
    });
    const error = await policies().set('default', definition).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(UnboundedSendRuleError);
    expect(error).toMatchObject({ rules: [{ ruleId: 'mail', unboundPaths: ['body.to'] }] });
  });

  it('maps CONTROLS_NOT_ENABLED on a set to its typed error', async () => {
    stubFetch({ status: 409, body: { error: { code: 'CONTROLS_NOT_ENABLED', message: 'Hosted controls are not on' } } });
    const error = await policies().set('default', definition).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlsNotEnabledError);
    expect(error).toMatchObject({ code: 'CONTROLS_NOT_ENABLED', status: 409 });
  });
});

describe('controlReviews', () => {
  it('lists pending reviews by default and sends only the filters given', async () => {
    const calls = stubFetch({ status: 200, body: { reviews: [] } });
    await reviews().list();
    await reviews().list({ status: 'all', limit: 10 });
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/control-reviews', search: '' });
    expect(Object.fromEntries(new URLSearchParams(calls[1]!.search))).toEqual({ status: 'all', limit: '10' });
  });

  it('reads one review, with where a person decides it', async () => {
    const calls = stubFetch({ status: 200, body: { id: 'crv_1', approval_url: 'https://getstack.run/app/approvals/gvr_1' } });
    const review = await reviews().get('crv_1');
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/control-reviews/crv_1' });
    expect(review.approval_url).toBe('https://getstack.run/app/approvals/gvr_1');
  });

  it('has no decide call: a person decides through the governance approval', () => {
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(reviews()))).toEqual(['constructor', 'list', 'get']);
  });
});

describe('refusal errors', () => {
  async function thrown(code: string, status: number, details: unknown): Promise<unknown> {
    stubFetch({ status, body: { error: { code, message: 'refused', details } } });
    return stack().accounts.get('acct_1').catch((e: unknown) => e);
  }

  it('maps CONTROL_DENIED with the rule that refused', async () => {
    const error = await thrown('CONTROL_DENIED', 403, {
      decision_id: 'dec_abcdefghijklmnop',
      reason_code: 'recipient_not_allowed',
      rule: { policy_id: 'cpl_1', policy_revision: 4, section: 'recipients', rule: 'recipients.email', code: 'recipient_not_allowed', detail: { allowed_entries: 3 } },
    });
    expect(error).toBeInstanceOf(ControlDeniedError);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({
      code: 'CONTROL_DENIED',
      status: 403,
      decisionId: 'dec_abcdefghijklmnop',
      reasonCode: 'recipient_not_allowed',
      retry: null,
      rule: { policyId: 'cpl_1', policyRevision: 4, section: 'recipients', rule: 'recipients.email', code: 'recipient_not_allowed', detail: { allowed_entries: 3 } },
    });
  });

  it('carries the retry reference of an action held for a person', async () => {
    const error = (await thrown('CONTROL_DENIED', 403, {
      decision_id: 'dec_abcdefghijklmnop',
      reason_code: 'review_required',
      retry: { ref: 'crv_abc', after_seconds: 30 },
      rule: { policy_id: 'cpl_1', policy_revision: 4, section: 'review', rule: 'review.over_cents', code: 'review_required' },
    })) as ControlDeniedError;
    expect(error.retry).toEqual({ ref: 'crv_abc', afterSeconds: 30 });
    expect(error.rule).toMatchObject({ code: 'review_required', detail: null });
  });

  it('tells an agent whose connection the policy does not list that a person must add it, and which revision', async () => {
    const message = "Your controls do not list this connection. A person must add it to this agent's policy, a loosening they approve in their browser.";
    stubFetch({
      status: 403,
      body: {
        error: {
          code: 'CONTROL_DENIED',
          message,
          details: {
            decision_id: 'dec_abcdefghijklmnop',
            reason_code: 'connection_not_listed',
            rule: { policy_id: 'cpl_1', policy_revision: 4, section: 'connections', rule: 'mode', code: 'connection_not_listed', detail: { connection_id: 'scon_late', revision_needed: 5 } },
          },
        },
      },
    });
    const error = (await stack().accounts.get('acct_1').catch((e: unknown) => e)) as ControlDeniedError;
    expect(error).toBeInstanceOf(ControlDeniedError);
    expect(error.message).toBe(message);
    expect(error.reasonCode).toBe('connection_not_listed');
    expect(error.rule).toMatchObject({ policyId: 'cpl_1', policyRevision: 4, detail: { connection_id: 'scon_late', revision_needed: 5 } });
  });

  it('maps a refusal from your own server, which has no rule', async () => {
    const error = (await thrown('CONTROL_DENIED', 403, { decision_id: 'dec_abcdefghijklmnop', reason_code: 'card_not_allowed' })) as ControlDeniedError;
    expect(error).toBeInstanceOf(ControlDeniedError);
    expect(error.rule).toBeNull();
    expect(error.retry).toBeNull();
    expect(error.reasonCode).toBe('card_not_allowed');
  });

  it('maps CONTROL_LIMIT_EXCEEDED for a counter and for the most one action may cost', async () => {
    const counter = await thrown('CONTROL_LIMIT_EXCEEDED', 403, { limit: { window: 'day', unit: 'cents' }, remaining: 120 });
    expect(counter).toBeInstanceOf(ControlLimitExceededError);
    expect(counter).toMatchObject({ code: 'CONTROL_LIMIT_EXCEEDED', limit: { window: 'day', unit: 'cents' }, remaining: 120, maxPerActionCents: null });
    const perAction = await thrown('CONTROL_LIMIT_EXCEEDED', 403, { limit: { window: 'action', unit: 'cents' }, remaining: 0, max_per_action_cents: 500 });
    expect(perAction).toMatchObject({ limit: { window: 'action', unit: 'cents' }, maxPerActionCents: 500 });
  });
});

describe('a connection grant under controls', () => {
  const grant = { agent_id: AGENT, service_connection_id: 'scon_late', scopes: ['read'] };

  it('returns what the policy of the agent still needs, typed', async () => {
    const notice = {
      policy_id: 'cpl_1', policy_revision: 3, source: 'agent', agent_id: AGENT, connection_id: 'scon_late',
      action_needed: 'list_connection', revision_needed: 4, message: 'The grant is made, but this agent cannot call the connection until a revision lists it.',
    };
    const calls = stubFetch({ status: 201, body: { id: 'grant_1', control_policy: notice } });
    const result = await stack().services.grantAgentAccess(grant);
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/services/grant', body: grant });
    expect(result.control_policy).toEqual(notice);
    expect(result.control_policy?.revision_needed).toBe(4);
  });

  it('adds nothing when the policy needs nothing', async () => {
    stubFetch({ status: 201, body: { id: 'grant_1' } });
    expect((await stack().services.grantAgentAccess(grant)).control_policy).toBeUndefined();
  });
});
