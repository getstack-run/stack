import { describe, expect, it } from 'vitest';
import { UnboundedSendRuleError } from '../errors/index.js';
import { PolicyDefinition, type PolicyDefinitionInput } from '../schemas/control-policy.js';
import { normalizeRequest } from './constraints.js';
import {
  NOT_LISTED_MESSAGE,
  assertPolicyBounded,
  classifyPolicyRevision,
  connectionNeedsListing,
  evaluatePolicy,
  limitWindowKey,
  normalizePolicy,
  policyDigest,
  policyFindings,
  policyNarrows,
  refusalEvidence,
  startingPolicyFromGrants,
  type PolicyCall,
} from './control-policy.js';

/** A policy as a test writes it: every section optional, the name too. */
type Sections = Omit<PolicyDefinitionInput, 'name'> & { name?: string };
const policy = (input: Sections = {}) => normalizePolicy({ name: 'p', ...input });
const slackRequest = (channel: string) =>
  normalizeRequest({
    service: 'slack',
    url: 'https://slack.com/api/chat.postMessage',
    method: 'POST',
    body: { channel, text: 'hello' },
  });
const proxyCall = (connection: string, request = slackRequest('C123')): PolicyCall => ({
  action: 'proxy.call',
  target: { service: 'slack', connection_id: connection, method: 'POST', host: 'slack.com', path: '/api/chat.postMessage' },
  amountCents: null,
  request,
});
const call = (action: PolicyCall['action'], target: Record<string, unknown> = {}, amountCents: number | null = null): PolicyCall => ({ action, target, amountCents });

describe('a policy that says nothing', () => {
  it('has no objection to any action', () => {
    const empty = policy();
    expect(evaluatePolicy(empty, proxyCall('scon_a')).verdict).toBe('allow');
    expect(evaluatePolicy(empty, call('email.send', { recipients: [{ address: 'x@y.com', domain: 'y.com' }] })).verdict).toBe('allow');
    expect(evaluatePolicy(empty, call('card.checkout', { merchant_origin: 'https://shop.example' }, 5_000_000)).verdict).toBe('allow');
  });

  it('parses with every section defaulted', () => {
    const parsed = PolicyDefinition.parse({ name: 'x' });
    expect(parsed.connections).toEqual({ mode: 'any', rules: [] });
    expect(parsed.spend.limits).toEqual([]);
    expect(PolicyDefinition.safeParse({ name: 'x', extra: 1 }).success).toBe(false);
  });
});

describe('connection rules', () => {
  const deny = policy({ connections: { mode: 'any', rules: [{ id: 'no-slack', effect: 'deny', access: { connection_id: 'scon_slack' } }] } });

  it('refuses a call on a denied connection and names the rule, never the call', () => {
    const verdict = evaluatePolicy(deny, proxyCall('scon_slack'));
    expect(verdict).toMatchObject({ verdict: 'deny', section: 'connections', rule: 'no-slack', code: 'connection_denied' });
    const evidence = refusalEvidence({ id: 'cpl_1', revision: 3 }, verdict as Exclude<typeof verdict, { verdict: 'allow' }>);
    expect(evidence).toMatchObject({ policy_id: 'cpl_1', policy_revision: 3, section: 'connections', rule: 'no-slack' });
    const text = JSON.stringify(evidence);
    expect(text).not.toContain('hello');
    expect(text).not.toContain('C123');
    expect(evidence.detail).toMatchObject({ request_method: 'POST', request_host: 'slack.com', request_path: '/api/chat.postMessage' });
  });

  it('leaves other connections alone', () => {
    expect(evaluatePolicy(deny, proxyCall('scon_other')).verdict).toBe('allow');
  });

  it('holds a call for review, and a refusal outranks a hold', () => {
    const review = policy({ connections: { mode: 'any', rules: [{ id: 'ask', effect: 'review', access: { connection_id: 'scon_slack' } }] } });
    expect(evaluatePolicy(review, proxyCall('scon_slack'))).toMatchObject({ verdict: 'review', rule: 'ask', code: 'review_required' });
    const both = policy({
      connections: {
        mode: 'any',
        rules: [
          { id: 'ask', effect: 'review', access: { connection_id: 'scon_slack' } },
          { id: 'never', effect: 'deny', access: { connection_id: 'scon_slack' } },
        ],
      },
    });
    expect(evaluatePolicy(both, proxyCall('scon_slack'))).toMatchObject({ verdict: 'deny', rule: 'never' });
  });

  it('in listed mode only a connection an allow rule names may be called', () => {
    const listed = policy({ connections: { mode: 'listed', rules: [{ id: 'slack', effect: 'allow', access: { connection_id: 'scon_slack' } }] } });
    expect(evaluatePolicy(listed, proxyCall('scon_slack')).verdict).toBe('allow');
    expect(evaluatePolicy(listed, proxyCall('scon_github'))).toMatchObject({ verdict: 'deny', code: 'connection_not_listed' });
  });

  it('tells an agent whose connection is not listed that a person must add it, and which revision lists it', () => {
    const listed = policy({ connections: { mode: 'listed', rules: [{ id: 'slack', effect: 'allow', access: { connection_id: 'scon_slack' } }] } });
    const refusal = evaluatePolicy(listed, proxyCall('scon_granted_later'));
    expect(refusal).toMatchObject({ verdict: 'deny', section: 'connections', rule: 'mode', code: 'connection_not_listed', message: NOT_LISTED_MESSAGE });
    expect(NOT_LISTED_MESSAGE).toMatch(/person must add it to this agent's policy.*loosening.*browser/);
    expect(NOT_LISTED_MESSAGE.length).toBeLessThanOrEqual(200);
    if (refusal.verdict === 'allow') throw new Error('unreachable');
    expect(refusalEvidence({ id: 'cpl_1', revision: 3 }, refusal)).toEqual({
      policy_id: 'cpl_1',
      policy_revision: 3,
      section: 'connections',
      rule: 'mode',
      code: 'connection_not_listed',
      detail: { connection_id: 'scon_granted_later', revision_needed: 4 },
    });
    // A draft has no revision to name, and any other refusal carries no such field.
    expect(refusalEvidence({ id: 'draft', revision: 0 }, refusal).detail).toEqual({ connection_id: 'scon_granted_later' });
    const denied = evaluatePolicy(policy({ connections: { mode: 'any', rules: [{ id: 'no', effect: 'deny', access: { connection_id: 'scon_slack' } }] } }), proxyCall('scon_slack'));
    if (denied.verdict === 'allow') throw new Error('unreachable');
    expect(refusalEvidence({ id: 'cpl_1', revision: 3 }, denied).detail).not.toHaveProperty('revision_needed');
  });

  it('knows which connections a listed policy still has to list', () => {
    const listed = policy({
      connections: {
        mode: 'listed',
        rules: [
          { id: 'slack', effect: 'allow', access: { connection_id: 'scon_slack' } },
          { id: 'no-github', effect: 'deny', access: { connection_id: 'scon_github' } },
        ],
      },
    });
    expect(connectionNeedsListing(listed, 'scon_new')).toBe(true);
    // Named by a rule, whatever its effect: that is the customer's own choice.
    expect(connectionNeedsListing(listed, 'scon_slack')).toBe(false);
    expect(connectionNeedsListing(listed, 'scon_github')).toBe(false);
    // Any mode never needs listing.
    expect(connectionNeedsListing(policy({ connections: { mode: 'any' } }), 'scon_new')).toBe(false);
    expect(connectionNeedsListing(policy(), 'scon_new')).toBe(false);
  });

  it('pins a recipient: a listed connection admits only the calls its rule describes', () => {
    const pinned = policy({
      connections: {
        mode: 'listed',
        rules: [
          {
            id: 'post-to-c123',
            effect: 'allow',
            access: { connection_id: 'scon_slack', intents: [{ name: 'slack.post_to_channel', params: { channel: ['C123'] } }] },
          },
        ],
      },
    });
    expect(evaluatePolicy(pinned, proxyCall('scon_slack', slackRequest('C123'))).verdict).toBe('allow');
    const refused = evaluatePolicy(pinned, proxyCall('scon_slack', slackRequest('C999')));
    expect(refused).toMatchObject({ verdict: 'deny', section: 'connections', code: 'call_outside_rules', rule: 'post-to-c123' });
    expect(JSON.stringify(refused)).not.toContain('C999');
  });

  it('judges against the caller what it cannot judge: no request to try a constraint on', () => {
    const noRequest = (connection: string): PolicyCall => ({ ...proxyCall(connection), request: null });
    const allowRule = policy({
      connections: {
        mode: 'listed',
        rules: [{ id: 'a', effect: 'allow', access: { connection_id: 'scon_slack', constraints: [{ path: 'method', op: 'eq', value: 'POST' }] } }],
      },
    });
    expect(evaluatePolicy(allowRule, noRequest('scon_slack')).verdict).toBe('deny');
    const denyRule = policy({
      connections: {
        mode: 'any',
        rules: [{ id: 'd', effect: 'deny', access: { connection_id: 'scon_slack', constraints: [{ path: 'method', op: 'eq', value: 'DELETE' }] } }],
      },
    });
    expect(evaluatePolicy(denyRule, noRequest('scon_slack'))).toMatchObject({ verdict: 'deny', rule: 'd' });
  });

  it('a rule naming an intent that does not exist can never allow, and always applies when it refuses', () => {
    const allowUnknown = policy({
      connections: { mode: 'listed', rules: [{ id: 'a', effect: 'allow', access: { connection_id: 'scon_slack', intents: [{ name: 'slack.no_such_thing', params: {} }] } }] },
    });
    expect(evaluatePolicy(allowUnknown, proxyCall('scon_slack')).verdict).toBe('deny');
    const denyUnknown = policy({
      connections: { mode: 'any', rules: [{ id: 'd', effect: 'deny', access: { connection_id: 'scon_slack', intents: [{ name: 'slack.no_such_thing', params: {} }] } }] },
    });
    expect(evaluatePolicy(denyUnknown, proxyCall('scon_slack')).verdict).toBe('deny');
  });

  it('only a proxy call is judged by the connection rules', () => {
    expect(evaluatePolicy(deny, call('model.call', { provider: 'openai', model: 'gpt-4o' })).verdict).toBe('allow');
  });
});

describe('action stances', () => {
  it('refuses or holds a whole kind of action', () => {
    const p = policy({ actions: { kinds: { 'sms.send': 'deny', 'call.start': 'review' } } });
    expect(evaluatePolicy(p, call('sms.send', { recipients: [{ number: '+46701740605' }] }))).toMatchObject({ verdict: 'deny', section: 'actions', code: 'action_denied' });
    expect(evaluatePolicy(p, call('call.start', { recipients: [{ number: '+46701740605' }] }))).toMatchObject({ verdict: 'review', section: 'actions' });
    expect(evaluatePolicy(p, call('model.call', {})).verdict).toBe('allow');
  });
});

describe('recipients', () => {
  const p = policy({ recipients: { email: ['@acme.com', 'boss@other.org'], sms: ['+46701740605'], call: ['+46701740605'] } });
  const mail = (...addresses: string[]) => call('email.send', { recipients: addresses.map((address) => ({ address, domain: address.split('@')[1] })) });

  it('lets an address through by exact match or by domain', () => {
    expect(evaluatePolicy(p, mail('anyone@acme.com')).verdict).toBe('allow');
    expect(evaluatePolicy(p, mail('Boss@Other.org')).verdict).toBe('allow');
  });

  it('refuses the first recipient off the list and does not echo it', () => {
    const refused = evaluatePolicy(p, mail('anyone@acme.com', 'stranger@evil.test'));
    expect(refused).toMatchObject({ verdict: 'deny', section: 'recipients', rule: 'email', code: 'recipient_not_allowed' });
    expect(JSON.stringify(refused)).not.toContain('stranger');
    expect(evaluatePolicy(p, mail('sub@mail.acme.com')).verdict).toBe('deny');
  });

  it('texts and calls match numbers exactly', () => {
    expect(evaluatePolicy(p, call('sms.send', { recipients: [{ number: '+46701740605' }] })).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('sms.send', { recipients: [{ number: '+46701740699' }] }))).toMatchObject({ verdict: 'deny', rule: 'sms' });
    expect(evaluatePolicy(p, call('call.start', { recipients: [{ number: '+46701740699' }] }))).toMatchObject({ verdict: 'deny', rule: 'call' });
  });

  it('an empty list refuses everyone, and a send with no readable recipient is refused', () => {
    const none = policy({ recipients: { email: [] } });
    expect(evaluatePolicy(none, mail('a@b.com')).verdict).toBe('deny');
    expect(evaluatePolicy(p, call('email.send', {}))).toMatchObject({ verdict: 'deny', code: 'policy_unevaluable' });
  });
});

describe('spend and review thresholds', () => {
  it('refuses an action over the per-action ceiling and holds one over the review amount', () => {
    const p = policy({ spend: { max_per_action_cents: 10_000, limits: [] }, review: { over_cents: 2_000 } });
    expect(evaluatePolicy(p, call('card.checkout', { merchant_origin: 'https://s.example' }, 500)).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('card.checkout', { merchant_origin: 'https://s.example' }, 2_500))).toMatchObject({ verdict: 'review', section: 'review', rule: 'over_cents' });
    expect(evaluatePolicy(p, call('card.checkout', { merchant_origin: 'https://s.example' }, 12_000))).toMatchObject({ verdict: 'deny', section: 'spend', code: 'amount_over_limit' });
  });
});

describe('the account surfaces', () => {
  it('models: an allowlist with prefixes, matched on the bare or the provider-qualified name', () => {
    const p = policy({ surfaces: { models: { allowed: ['openai/*', 'claude-sonnet-4'] } } });
    expect(evaluatePolicy(p, call('model.call', { provider: 'openai', model: 'gpt-4o' })).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('model.call', { provider: 'anthropic', model: 'claude-sonnet-4' })).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('model.call', { provider: 'mistral', model: 'large' }))).toMatchObject({ verdict: 'deny', section: 'models', code: 'model_not_allowed' });
  });

  it('browser: exact hosts and wildcard subdomains, by the visited origin', () => {
    const p = policy({ surfaces: { browser: { hosts: ['docs.example.com', '*.shop.test'] } } });
    expect(evaluatePolicy(p, call('browser.navigate', { origin: 'https://docs.example.com', path: '/' })).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('browser.navigate', { origin: 'https://a.shop.test', path: '/' })).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('browser.navigate', { origin: 'https://shop.test', path: '/' })).verdict).toBe('deny');
    expect(evaluatePolicy(p, call('browser.navigate', { origin: 'https://evil.example', path: '/' }))).toMatchObject({ section: 'browser', code: 'host_not_allowed' });
    expect(evaluatePolicy(p, call('browser.session.start', {})).verdict).toBe('allow');
  });

  it('card: merchants and an amount cap, and a non-USD amount cannot be capped', () => {
    const p = policy({ surfaces: { card: { merchants: ['*.shop.test'], max_amount_cents: 5_000 } } });
    const ok = call('card.checkout', { merchant_origin: 'https://a.shop.test' }, 4_000);
    expect(evaluatePolicy(p, ok).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('card.checkout', { merchant_origin: 'https://x.test' }, 100))).toMatchObject({ code: 'merchant_not_allowed' });
    expect(evaluatePolicy(p, call('card.checkout', { merchant_origin: 'https://a.shop.test' }, 6_000))).toMatchObject({ code: 'amount_over_limit' });
    expect(evaluatePolicy(p, call('card.checkout', { merchant_origin: 'https://a.shop.test' }, null))).toMatchObject({ code: 'policy_unevaluable' });
  });

  it('wallet: payees and an amount cap', () => {
    const payee = `0x${'a'.repeat(40)}`;
    const p = policy({ surfaces: { wallet: { payees: [payee], max_amount_cents: 1_000 } } });
    expect(evaluatePolicy(p, call('wallet.payment', { payee: payee.toUpperCase().replace('0X', '0x') }, 500)).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('wallet.payment', { payee: `0x${'b'.repeat(40)}` }, 500))).toMatchObject({ code: 'payee_not_allowed' });
    expect(evaluatePolicy(p, call('wallet.payment', { payee }, 2_000))).toMatchObject({ code: 'amount_over_limit' });
  });

  it('workspace: a ceiling on how long one command may run', () => {
    const p = policy({ surfaces: { workspace: { max_timeout_seconds: 60 } } });
    const exec = (timeout: unknown) => call('workspace.exec', { new_workspace: false, timeout_seconds: timeout, stack_access: false, command_bytes: 10 });
    expect(evaluatePolicy(p, exec(30)).verdict).toBe('allow');
    expect(evaluatePolicy(p, exec(60)).verdict).toBe('allow');
    expect(evaluatePolicy(p, exec(600))).toMatchObject({ code: 'timeout_over_limit' });
    // A limit it cannot read is refused, not guessed.
    expect(evaluatePolicy(p, exec(null))).toMatchObject({ code: 'policy_unevaluable' });
    // With no ceiling set nothing is asked of the command.
    expect(evaluatePolicy(policy({}), exec(600)).verdict).toBe('allow');
  });

  it('tools: a provider, or provider and endpoint', () => {
    const p = policy({ surfaces: { tools: { allowed: ['monid/search*', 'weather'] } } });
    expect(evaluatePolicy(p, call('tool.run', { provider: 'weather', endpoint: 'forecast' })).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('tool.run', { provider: 'monid', endpoint: 'search-web' })).verdict).toBe('allow');
    expect(evaluatePolicy(p, call('tool.run', { provider: 'monid', endpoint: 'scrape' }))).toMatchObject({ section: 'tools', code: 'tool_not_allowed' });
  });
});

describe('limit windows', () => {
  const at = new Date('2026-10-21T23:59:59.900Z');
  it('keys a day, a month and a Mission', () => {
    expect(limitWindowKey('day', at, null)).toBe('2026-10-21');
    expect(limitWindowKey('month', at, null)).toBe('2026-10');
    expect(limitWindowKey('mission', at, 'msn_1')).toBe('msn_1');
    expect(limitWindowKey('mission', at, null)).toBe('no_mission');
  });
});

describe('revisions: only a provable tightening applies at once', () => {
  const base = policy({
    connections: { mode: 'any', rules: [{ id: 'no-slack', effect: 'deny', access: { connection_id: 'scon_slack' } }] },
    recipients: { email: ['@acme.com'] },
    spend: { max_per_action_cents: 5_000, limits: [{ kind: 'day', unit: 'actions', limit: 100 }], max_concurrent: 4 },
    review: { over_cents: 2_000 },
    surfaces: { models: { allowed: ['openai/*'] }, browser: { hosts: ['*.example.com'] } },
  });
  const revise = (change: Sections) => policy({ ...(base as unknown as Sections), ...change });

  it('unchanged, and no policy is the widest of all', () => {
    expect(classifyPolicyRevision(base, base)).toBe('unchanged');
    expect(policyNarrows(base, null)).toBe(true);
    expect(policyNarrows(null, base)).toBe(false);
    expect(classifyPolicyRevision(null, base)).toBe('loosen');
    expect(classifyPolicyRevision(base, null)).toBe('tighten');
  });

  it('adding a rule, a refusal or a smaller list tightens', () => {
    const more = revise({
      connections: {
        mode: 'any',
        rules: [
          { id: 'no-slack', effect: 'deny', access: { connection_id: 'scon_slack' } },
          { id: 'ask-github', effect: 'review', access: { connection_id: 'scon_github' } },
        ],
      },
    });
    expect(classifyPolicyRevision(more, base)).toBe('tighten');
    expect(classifyPolicyRevision(revise({ recipients: { email: ['ceo@acme.com'] } }), base)).toBe('tighten');
    expect(classifyPolicyRevision(revise({ actions: { kinds: { 'sms.send': 'deny' } } }), base)).toBe('tighten');
    expect(classifyPolicyRevision(revise({ surfaces: { models: { allowed: ['openai/gpt-4o'] }, browser: { hosts: ['a.example.com'] } } }), base)).toBe('tighten');
  });

  it('removing or weakening a refusal loosens', () => {
    expect(classifyPolicyRevision(revise({ connections: { mode: 'any', rules: [] } }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ connections: { mode: 'any', rules: [{ id: 'no-slack', effect: 'review', access: { connection_id: 'scon_slack' } }] } }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ connections: { mode: 'any', rules: [{ id: 'renamed', effect: 'deny', access: { connection_id: 'scon_slack' } }] } }), base)).toBe('tighten');
  });

  it('a refusal made stricter covers the one it replaces', () => {
    const held = policy({ connections: { mode: 'any', rules: [{ id: 'ask', effect: 'review', access: { connection_id: 'scon_slack' } }] } });
    const refused = policy({ connections: { mode: 'any', rules: [{ id: 'never', effect: 'deny', access: { connection_id: 'scon_slack' } }] } });
    expect(classifyPolicyRevision(refused, held)).toBe('tighten');
    expect(classifyPolicyRevision(held, refused)).toBe('loosen');
  });

  it('raising a ceiling, dropping a limit or growing a list loosens', () => {
    expect(classifyPolicyRevision(revise({ spend: { max_per_action_cents: 9_000, limits: [{ kind: 'day', unit: 'actions', limit: 100 }], max_concurrent: 4 } }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ spend: { max_per_action_cents: 5_000, limits: [], max_concurrent: 4 } }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ spend: { max_per_action_cents: 5_000, limits: [{ kind: 'day', unit: 'actions', limit: 500 }], max_concurrent: 4 } }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ recipients: { email: ['@acme.com', '@other.org'] } }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ recipients: {} }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ review: { over_cents: 9_000 } }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ review: {} }), base)).toBe('loosen');
    expect(classifyPolicyRevision(revise({ surfaces: { models: { allowed: ['openai/*', 'anthropic/*'] }, browser: { hosts: ['*.example.com'] } } }), base)).toBe('loosen');
  });

  it('a new limit tightens, and mixed changes are loosening', () => {
    expect(classifyPolicyRevision(revise({ spend: { max_per_action_cents: 5_000, limits: [{ kind: 'day', unit: 'actions', limit: 100 }, { kind: 'month', unit: 'cents', limit: 50_000 }], max_concurrent: 4 } }), base)).toBe('tighten');
    expect(
      classifyPolicyRevision(
        revise({
          recipients: { email: ['ceo@acme.com'] },
          spend: { max_per_action_cents: 9_000, limits: [{ kind: 'day', unit: 'actions', limit: 100 }], max_concurrent: 4 },
        }),
        base,
      ),
    ).toBe('loosen');
  });

  it('a domain entry covers its addresses and a wildcard covers its subdomains, not the other way round', () => {
    const wide = policy({ recipients: { email: ['@acme.com'] }, surfaces: { browser: { hosts: ['*.example.com'] } } });
    expect(policyNarrows(policy({ recipients: { email: ['a@acme.com'] }, surfaces: { browser: { hosts: ['x.example.com', '*.y.example.com'] } } }), wide)).toBe(true);
    expect(policyNarrows(wide, policy({ recipients: { email: ['a@acme.com'] }, surfaces: { browser: { hosts: ['x.example.com'] } } }))).toBe(false);
    expect(policyNarrows(policy({ recipients: { email: ['a@acme.com'] }, surfaces: { browser: { hosts: ['example.com'] } } }), wide)).toBe(false);
  });

  describe('connections mode', () => {
    const listed = policy({
      connections: {
        mode: 'listed',
        rules: [
          { id: 'slack', effect: 'allow', access: { connection_id: 'scon_slack' } },
          { id: 'github', effect: 'allow', access: { connection_id: 'scon_github' } },
        ],
      },
    });
    it('any to listed tightens, listed to any loosens', () => {
      expect(classifyPolicyRevision(listed, policy())).toBe('tighten');
      expect(classifyPolicyRevision(policy(), listed)).toBe('loosen');
    });
    it('dropping a listed connection tightens; listing one more, or widening a listed rule, loosens', () => {
      const fewer = policy({ connections: { mode: 'listed', rules: [{ id: 'slack', effect: 'allow', access: { connection_id: 'scon_slack' } }] } });
      expect(classifyPolicyRevision(fewer, listed)).toBe('tighten');
      expect(classifyPolicyRevision(listed, fewer)).toBe('loosen');
      const pinned = policy({
        connections: {
          mode: 'listed',
          rules: [{ id: 'slack', effect: 'allow', access: { connection_id: 'scon_slack', constraints: [{ path: 'body.channel', op: 'eq', value: 'C1' }] } }],
        },
      });
      expect(classifyPolicyRevision(pinned, fewer)).toBe('tighten');
      expect(classifyPolicyRevision(fewer, pinned)).toBe('loosen');
    });
    it('an allow rule cannot be upgraded from review', () => {
      const held = policy({ connections: { mode: 'listed', rules: [{ id: 'slack', effect: 'review', access: { connection_id: 'scon_slack' } }] } });
      const open = policy({ connections: { mode: 'listed', rules: [{ id: 'slack', effect: 'allow', access: { connection_id: 'scon_slack' } }] } });
      expect(classifyPolicyRevision(open, held)).toBe('loosen');
      expect(classifyPolicyRevision(held, open)).toBe('tighten');
    });
  });

  it('a digest is the same for the same policy however it was written', () => {
    expect(policyDigest(policy({ recipients: { email: ['@acme.com'] } }))).toBe(policyDigest(normalizePolicy({ recipients: { email: ['@acme.com'] }, name: 'p' })));
    expect(policyDigest(policy({ recipients: { email: ['@acme.com'] } }))).not.toBe(policyDigest(policy({ recipients: { email: ['@other.org'] } })));
  });
});

describe('start from current access', () => {
  const grants = [
    { connection_id: 'scon_slack', constraints: [{ path: 'method', op: 'eq' as const, value: 'POST' }] },
    { connection_id: 'scon_github', constraints: null },
  ];

  it('lists exactly the granted connections, each within the grant', () => {
    const started = startingPolicyFromGrants('Current access', grants);
    expect(started.connections.mode).toBe('listed');
    expect(started.connections.rules.map((r) => [r.access.connection_id, r.effect])).toEqual([
      ['scon_github', 'allow'],
      ['scon_slack', 'allow'],
    ]);
    expect(started.connections.rules.find((r) => r.access.connection_id === 'scon_slack')?.access.constraints).toEqual(grants[0]!.constraints);
  });

  it('admits every call the grant admits, so it changes no outcome', () => {
    const started = startingPolicyFromGrants('Current access', grants);
    expect(evaluatePolicy(started, proxyCall('scon_slack')).verdict).toBe('allow');
    expect(evaluatePolicy(started, proxyCall('scon_github')).verdict).toBe('allow');
    // A call the grant itself refuses (a DELETE on a POST-only grant) never reaches the policy; the policy's rule mirrors the grant.
    const deleteCall = proxyCall('scon_slack', normalizeRequest({ service: 'slack', url: 'https://slack.com/api/x', method: 'DELETE' }));
    expect(evaluatePolicy(started, deleteCall).verdict).toBe('deny');
  });

  it('is a tightening of "no policy" and refuses a connection granted later', () => {
    const started = startingPolicyFromGrants('Current access', grants);
    expect(classifyPolicyRevision(started, null)).toBe('tighten');
    expect(evaluatePolicy(started, proxyCall('scon_granted_later'))).toMatchObject({ verdict: 'deny', code: 'connection_not_listed' });
  });
});

describe('send bounds', () => {
  const gmailRule = (effect: 'allow' | 'review') =>
    policy({ connections: { mode: 'listed', rules: [{ id: 'mail', effect, access: { connection_id: 'scon_gmail', intents: [{ name: 'gmail.send_email', params: {} }] } }] } });
  const providerOf = (id: string) => (id === 'scon_gmail' ? 'gmail' : undefined);

  it('refuses a policy that allows an unbounded send, and accepts it as a review or when pinned', () => {
    expect(() => assertPolicyBounded(gmailRule('allow'), providerOf)).toThrow(UnboundedSendRuleError);
    expect(() => assertPolicyBounded(gmailRule('review'), providerOf)).not.toThrow();
    const pinned = policy({
      connections: {
        mode: 'listed',
        rules: [{ id: 'mail', effect: 'allow', access: { connection_id: 'scon_gmail', intents: [{ name: 'gmail.send_email_to', params: { to: ['cfo@acme.com'] } }] } }],
      },
    });
    expect(() => assertPolicyBounded(pinned, providerOf)).not.toThrow();
  });

  it('reports a stored policy that allows one as a finding', () => {
    const findings = policyFindings(gmailRule('allow'), providerOf);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ kind: 'unbound_send', rule_id: 'mail' });
    expect(policyFindings(gmailRule('review'), providerOf)).toEqual([]);
  });
});
