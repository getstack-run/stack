import { describe, expect, it } from 'vitest';
import { MAX_SUBSET_COMPARISONS, compareConstraintSets, constraintsAreSubset, findFailingConstraint, normalizeRequest } from './constraints.js';
import { expandGrantRules, expandIntents, grantIntentRefs } from '../intents/index.js';
import { Constraint, MAX_ANY_OF_PER_SCOPE, ServiceScope, type Constraint as ConstraintType } from '../schemas/passport.js';
import { GrantAgentAccessInput } from '../schemas/service.js';
import { approvalScopeLines } from './approval-scope-lines.js';

// A grant that carries a read rule and a post rule on one connection: each
// rule allows its own calls, and a call that fits neither is refused.

const call = (method: string, path: string, extra: { query?: Record<string, string>; body?: unknown } = {}) =>
  normalizeRequest({ service: 'slack', method, url: `https://slack.com${path}`, body: extra.body, query: extra.query } as never);

const READ = { intents: [{ name: 'slack.list_channels', params: {} }] };
const POST = { intents: [{ name: 'slack.post_to_channel', params: { channel: ['C1'] } }] };

describe('a grant with a read rule and a post rule', () => {
  const constraints = expandGrantRules({ alternatives: [READ, POST] });
  const allowed = (request: ReturnType<typeof call>) => findFailingConstraint(constraints, request) === null;

  it('keeps one any_of constraint of both rules', () => {
    expect(constraints).toHaveLength(1);
    expect(constraints[0]).toMatchObject({ path: 'any_of', op: 'any_of' });
    expect(Constraint.safeParse(constraints[0]).success).toBe(true);
  });

  it('allows the read rule its own call', () => {
    expect(allowed(call('GET', '/api/conversations.list'))).toBe(true);
  });

  it('allows the post rule its own call', () => {
    expect(allowed(call('POST', '/api/chat.postMessage', { body: { channel: 'C1', text: 'hi' } }))).toBe(true);
  });

  it('allows nothing else', () => {
    expect(allowed(call('POST', '/api/chat.postMessage', { body: { channel: 'C2', text: 'hi' } }))).toBe(false);
    expect(allowed(call('POST', '/api/conversations.list'))).toBe(false);
    expect(allowed(call('GET', '/api/chat.postMessage'))).toBe(false);
    expect(allowed(call('POST', '/api/chat.delete', { body: { channel: 'C1' } }))).toBe(false);
    expect(allowed(call('GET', '/api/users.list'))).toBe(false);
  });

  it('is what the same intents cancel out to when they are listed flat', () => {
    const flat = expandIntents([...READ.intents, ...POST.intents]);
    expect(findFailingConstraint(flat, call('GET', '/api/conversations.list'))).not.toBeNull();
    expect(findFailingConstraint(flat, call('POST', '/api/chat.postMessage', { body: { channel: 'C1' } }))).not.toBeNull();
  });

  it('applies the grant\'s own constraints to every rule', () => {
    const shared = expandGrantRules({
      constraints: [{ path: 'url.host', op: 'eq', value: 'slack.com' }],
      alternatives: [READ, POST],
    });
    expect(findFailingConstraint(shared, call('GET', '/api/conversations.list'))).toBeNull();
    const elsewhere = normalizeRequest({ service: 'slack', method: 'GET', url: 'https://evil.example/api/conversations.list' } as never);
    expect(findFailingConstraint(shared, elsewhere)).not.toBeNull();
  });

  it('holds raw constraints inside a rule in full', () => {
    const rules = expandGrantRules({
      alternatives: [
        { constraints: [{ path: 'method', op: 'eq', value: 'GET' }, { path: 'url.pathname', op: 'starts_with', value: '/api/conversations.' }] },
        POST,
      ],
    });
    expect(findFailingConstraint(rules, call('GET', '/api/conversations.history'))).toBeNull();
    expect(findFailingConstraint(rules, call('POST', '/api/conversations.history'))).not.toBeNull();
  });

  it('names every intent of every rule in the readable record', () => {
    expect(grantIntentRefs({ intents: [{ name: 'slack.get_user_info', params: {} }], alternatives: [READ, POST] }).map((r) => r.name))
      .toEqual(['slack.get_user_info', 'slack.list_channels', 'slack.post_to_channel']);
  });
});

describe('expandGrantRules', () => {
  it('spreads a single rule into the list as it is', () => {
    expect(expandGrantRules({ alternatives: [READ] })).toEqual(expandIntents(READ.intents));
  });

  it('is the flat list when there are no rules', () => {
    expect(expandGrantRules({ intents: READ.intents, constraints: [{ path: 'method', op: 'eq', value: 'GET' }] }))
      .toEqual([...expandIntents(READ.intents), { path: 'method', op: 'eq', value: 'GET' }]);
  });

  it('accepts a rule with no limits: it allows every call the grant\'s own constraints allow', () => {
    const method = { path: 'method', op: 'eq', value: 'GET' } as const;
    expect(expandGrantRules({ constraints: [method], alternatives: [READ, { intents: [] }] })).toEqual([method]);
    expect(expandGrantRules({ alternatives: [{}] })).toEqual([]);
    expect(GrantAgentAccessInput.safeParse({
      agent_id: 'agt_1', service_connection_id: 'scon_1', scopes: ['*'], alternatives: [READ, {}],
    }).success).toBe(true);
  });

  it('accepts the grant input with rules', () => {
    expect(GrantAgentAccessInput.safeParse({
      agent_id: 'agt_1', service_connection_id: 'scon_1', scopes: ['*'], alternatives: [READ, POST],
    }).success).toBe(true);
  });
});

describe('any_of in the schema', () => {
  it('needs at least two groups, each with a constraint', () => {
    const one: ConstraintType = { path: 'any_of', op: 'any_of', value: [[{ path: 'method', op: 'eq', value: 'GET' }]] } as never;
    expect(Constraint.safeParse(one).success).toBe(false);
    const empty = { path: 'any_of', op: 'any_of', value: [[{ path: 'method', op: 'eq', value: 'GET' }], []] };
    expect(Constraint.safeParse(empty).success).toBe(false);
  });

  it('does not nest', () => {
    const inner = { path: 'any_of', op: 'any_of', value: [[{ path: 'method', op: 'eq', value: 'GET' }], [{ path: 'method', op: 'eq', value: 'PUT' }]] };
    const nested = { path: 'any_of', op: 'any_of', value: [[inner], [{ path: 'method', op: 'eq', value: 'POST' }]] };
    expect(Constraint.safeParse(nested).success).toBe(false);
  });
});

describe('narrowing a grant with rules', () => {
  const both = expandGrantRules({ alternatives: [READ, POST] });
  const readOnly = expandGrantRules({ alternatives: [READ] });
  const postOnly = expandGrantRules({ alternatives: [POST] });
  const none = expandGrantRules({});

  it('is within itself', () => {
    expect(constraintsAreSubset(both, both)).toBe(true);
  });

  it('keeping only one rule is narrower', () => {
    expect(constraintsAreSubset(readOnly, both)).toBe(true);
    expect(constraintsAreSubset(postOnly, both)).toBe(true);
  });

  it('adding a rule is wider', () => {
    expect(constraintsAreSubset(both, readOnly)).toBe(false);
    expect(constraintsAreSubset(both, postOnly)).toBe(false);
  });

  it('dropping the rules is wider', () => {
    expect(constraintsAreSubset(none, both)).toBe(false);
    expect(constraintsAreSubset(both, none)).toBe(true);
  });

  it('a tighter rule is narrower, a different one is not', () => {
    const tighter = expandGrantRules({
      alternatives: [READ, { intents: [{ name: 'slack.post_to_channel', params: { channel: ['C1'] } }], constraints: [{ path: 'body.text', op: 'starts_with', value: 'ok' }] }],
    });
    expect(constraintsAreSubset(tighter, both)).toBe(true);
    const other = expandGrantRules({ alternatives: [READ, { intents: [{ name: 'slack.post_to_channel', params: { channel: ['C9'] } }] }] });
    expect(constraintsAreSubset(other, both)).toBe(false);
  });

  it('tightening with a plain constraint keeps every rule inside', () => {
    expect(constraintsAreSubset([...both, { path: 'url.host', op: 'eq', value: 'slack.com' }], both)).toBe(true);
  });
});

describe('what an approval shows of a grant with rules', () => {
  it('lists every rule in full', () => {
    const lines = approvalScopeLines({
      action: 'service_grant_expand',
      grant_preview: {
        agent_id: 'agt_1', service: 'slack', scopes: ['*'], constraints: [], intents: [], allow_data_from: [],
        alternatives: [
          { intents: ['slack.list_channels'], constraints: [{ path: 'method', op: 'eq', value: 'GET' }] },
          { intents: ['slack.post_to_channel'], constraints: [{ path: 'body.channel', op: 'in', value: ['C1', 'C2'] }] },
        ],
      },
    });
    expect(lines).toContain('  a call may match any one of these rules:');
    expect(lines).toContain('    rule 1: the named action slack.list_channels; method must be "GET"');
    expect(lines).toContain('    rule 2: the named action slack.post_to_channel; body.channel must be one of "C1", "C2"');
    expect(lines.join('\n')).not.toContain('with no limits');
  });

  it('shows a choice of rules inside a constraint', () => {
    const lines = approvalScopeLines({
      action: 'service_grant_expand',
      grant_preview: {
        agent_id: 'agt_1', service: 'slack', scopes: ['*'], intents: [], allow_data_from: [],
        constraints: expandGrantRules({ alternatives: [READ, POST] }),
      },
    });
    expect(lines.join('\n')).toContain('a call may match any one of these rules: (');
    expect(lines.join('\n')).not.toContain('[object Object]');
  });
});

describe('the subset check is cheap whatever it is given', () => {
  const big = Array.from({ length: 256 }, (_, i) => `v${i}`);
  const plain = Array.from({ length: 29 }, (_, i) => ({ path: `body.p${i}`, op: 'in' as const, value: big }));
  const anyOf = (groups: number, per: number, tag: string) => ({
    path: 'any_of' as const, op: 'any_of' as const,
    value: Array.from({ length: groups }, (_, g) => Array.from({ length: per }, (_, l) => ({ path: `body.${tag}${g}_${l}`, op: 'eq' as const, value: `x${g}` }))),
  });
  const heavy = [...plain, anyOf(16, 8, 'a'), anyOf(16, 8, 'b'), anyOf(4, 32, 'c')] as ConstraintType[];

  it('answers yes at once when every parent constraint is in the child as it stands (what delegation always does)', () => {
    const started = Date.now();
    expect(constraintsAreSubset(heavy, heavy)).toBe(true);
    expect(Date.now() - started).toBeLessThan(500);
    const started2 = Date.now();
    expect(constraintsAreSubset([...heavy, { path: 'method', op: 'eq', value: 'GET' }], heavy)).toBe(true);
    expect(Date.now() - started2).toBeLessThan(500);
  });

  it('does not mind the order of a list, or of the rules in a choice', () => {
    const a = anyOf(3, 2, 'z');
    const reordered = { ...a, value: [...a.value].reverse().map((g) => [...g].reverse()) } as ConstraintType;
    expect(constraintsAreSubset([reordered], [a as ConstraintType])).toBe(true);
    expect(constraintsAreSubset([{ path: 'body.t', op: 'in', value: ['b', 'a'] }], [{ path: 'body.t', op: 'in', value: ['a', 'b'] }])).toBe(true);
  });

  it('refuses plainly, and at once, what it would take more than the budget of comparisons to judge', () => {
    const tighter = [...plain, anyOf(16, 8, 'a'), anyOf(16, 8, 'b'), { path: 'method', op: 'eq', value: 'GET' }] as ConstraintType[];
    const parent = [...plain, anyOf(16, 8, 'a'), anyOf(16, 7, 'b')] as ConstraintType[];
    const started = Date.now();
    expect(compareConstraintSets(tighter, parent)).toBe('too_many_to_compare');
    expect(constraintsAreSubset(tighter, parent)).toBe(false);
    expect(Date.now() - started).toBeLessThan(500);
    expect(MAX_SUBSET_COMPARISONS).toBe(4096);
  });

  it('still judges what fits the budget, one choice against one', () => {
    expect(compareConstraintSets([anyOf(2, 1, 'k') as ConstraintType], [anyOf(3, 1, 'k') as ConstraintType])).toBe('within');
    expect(compareConstraintSets([anyOf(3, 1, 'k') as ConstraintType], [anyOf(2, 1, 'k') as ConstraintType])).toBe('wider');
  });

  it('a scope holds at most eight choices of rules', () => {
    expect(MAX_ANY_OF_PER_SCOPE).toBe(8);
    const list = 'abcdefghi'.split('').map((key) => anyOf(2, 1, key));
    expect(ServiceScope.safeParse({ service_id: 's', service_name: 'slack', scopes: ['*'], credential_ref: 'c', constraints: list }).success).toBe(false);
    expect(ServiceScope.safeParse({ service_id: 's', service_name: 'slack', scopes: ['*'], credential_ref: 'c', constraints: list.slice(0, 8) }).success).toBe(true);
    expect(GrantAgentAccessInput.safeParse({ agent_id: 'a', service_connection_id: 'c', scopes: ['*'], constraints: list }).success).toBe(false);
  });
});
