import { describe, it, expect } from 'vitest';
import { normalizeRequest, evaluateConstraint } from './constraints.js';
import type { PlainConstraint as Constraint } from '../schemas/passport.js';
import type { ProxyRequestInput } from '../schemas/proxy.js';

/**
 * The constraint language could not express the policies its own catalogue
 * recommended. `stripe.create_charge` and four siblings tell operators to
 * "add an amount cap via raw constraint on body.amount" — with only
 * eq/not_eq/in/not_in/matches/starts_with, that was unwritable. A deny-list
 * was unusable because a missing field failed every operator, including the
 * negative ones. And an array-valued field failed unconditionally, so the
 * tightest email intent we ship broke on an ordinary request.
 */

function req(body: unknown, extra: Partial<ProxyRequestInput> = {}) {
  return normalizeRequest({
    service: 'test',
    url: 'https://api.example.com/v1/things',
    method: 'POST',
    body,
    ...extra,
  } as ProxyRequestInput);
}

const c = (path: string, op: Constraint['op'], value?: Constraint['value']): Constraint =>
  ({ path, op, value: value as Constraint['value'] });

describe('numeric comparison', () => {
  it('caps a spend amount', () => {
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: 5000 }))).toBe(true);
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: 5001 }))).toBe(false);
  });

  it('supports the other three comparisons', () => {
    expect(evaluateConstraint(c('body.n', 'lt', 10), req({ n: 9 }))).toBe(true);
    expect(evaluateConstraint(c('body.n', 'lt', 10), req({ n: 10 }))).toBe(false);
    expect(evaluateConstraint(c('body.n', 'gt', 10), req({ n: 11 }))).toBe(true);
    expect(evaluateConstraint(c('body.n', 'gte', 10), req({ n: 10 }))).toBe(true);
  });

  it('caps a numeric STRING, because form bodies and query params are strings', () => {
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: '4999' }))).toBe(true);
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: '5001' }))).toBe(false);
    const q = req({}, { query: { amount: '4999' } } as Partial<ProxyRequestInput>);
    expect(evaluateConstraint(c('query.amount', 'lte', 5000), q)).toBe(true);
  });

  it('refuses a non-numeric target rather than letting it through', () => {
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: 'lots' }))).toBe(false);
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: '' }))).toBe(false);
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: null }))).toBe(false);
  });

  it('does NOT let a boolean satisfy a cap by coercing to 1', () => {
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({ amount: true }))).toBe(false);
  });

  it('fails a missing field, like every other value operator', () => {
    expect(evaluateConstraint(c('body.amount', 'lte', 5000), req({}))).toBe(false);
  });
});

describe('presence', () => {
  it('exists passes only when the field is there', () => {
    expect(evaluateConstraint(c('body.x', 'exists', true), req({ x: 1 }))).toBe(true);
    expect(evaluateConstraint(c('body.x', 'exists', true), req({}))).toBe(false);
  });

  it('not_exists is what makes a deny-list usable', () => {
    // The old behaviour: every operator failed on a missing field, so
    // "this field must not be present" was unexpressible.
    expect(evaluateConstraint(c('body.bcc', 'not_exists', true), req({ to: 'a@b.com' }))).toBe(true);
    expect(evaluateConstraint(c('body.bcc', 'not_exists', true), req({ bcc: 'x@evil.com' }))).toBe(false);
  });

  it('treats an explicit null as present', () => {
    expect(evaluateConstraint(c('body.x', 'exists', true), req({ x: null }))).toBe(true);
  });
});

describe('array-valued fields', () => {
  it('accepts a pinned recipient sent as a one-element list', () => {
    // Resend accepts `to` as a string OR an array. This used to deny.
    expect(evaluateConstraint(c('body.to', 'eq', 'alice@corp.com'), req({ to: ['alice@corp.com'] }))).toBe(true);
  });

  it('REJECTS an extra recipient smuggled into the list', () => {
    expect(
      evaluateConstraint(
        c('body.to', 'eq', 'alice@corp.com'),
        req({ to: ['alice@corp.com', 'attacker@evil.com'] }),
      ),
    ).toBe(false);
  });

  it('quantifies `in` over every element', () => {
    const allow = c('body.to', 'in', ['alice@corp.com', 'bob@corp.com']);
    expect(evaluateConstraint(allow, req({ to: ['alice@corp.com', 'bob@corp.com'] }))).toBe(true);
    expect(evaluateConstraint(allow, req({ to: ['alice@corp.com', 'attacker@evil.com'] }))).toBe(false);
  });

  it('quantifies a negative op over every element', () => {
    const deny = c('body.to', 'not_in', ['attacker@evil.com']);
    expect(evaluateConstraint(deny, req({ to: ['alice@corp.com', 'bob@corp.com'] }))).toBe(true);
    expect(evaluateConstraint(deny, req({ to: ['alice@corp.com', 'attacker@evil.com'] }))).toBe(false);
  });

  it('quantifies a regex over every element', () => {
    const corpOnly = c('body.to', 'matches', '^[^@]+@corp\\.com$');
    expect(evaluateConstraint(corpOnly, req({ to: ['a@corp.com', 'b@corp.com'] }))).toBe(true);
    expect(evaluateConstraint(corpOnly, req({ to: ['a@corp.com', 'x@evil.com'] }))).toBe(false);
  });

  it('caps every element of a numeric list', () => {
    expect(evaluateConstraint(c('body.amounts', 'lte', 100), req({ amounts: [10, 20] }))).toBe(true);
    expect(evaluateConstraint(c('body.amounts', 'lte', 100), req({ amounts: [10, 900] }))).toBe(false);
  });

  it('fails an empty list on a positive op and passes it on a negative one', () => {
    // Claiming a pinned value while supplying none is not a match. "None of
    // these are forbidden" is trivially true of nothing.
    expect(evaluateConstraint(c('body.to', 'eq', 'alice@corp.com'), req({ to: [] }))).toBe(false);
    expect(evaluateConstraint(c('body.to', 'not_in', ['x@evil.com']), req({ to: [] }))).toBe(true);
  });

  it('rejects a list of non-primitives rather than guessing', () => {
    expect(
      evaluateConstraint(c('body.to', 'eq', 'alice@corp.com'), req({ to: [{ email: 'alice@corp.com' }] })),
    ).toBe(false);
  });
});
