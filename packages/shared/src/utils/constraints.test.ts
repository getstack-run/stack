import { describe, it, expect } from 'vitest';
import {
  normalizeRequest,
  resolvePath,
  evaluateConstraint,
  findFailingConstraint,
  constraintsAreSubset,
  allowDataFromIsSubset,
  allowDataFromGrantWidens,
  resolveAllowDataFromGrant,
  isResolvablePath,
  FAN_OUT_LIMIT,
} from './constraints.js';
import type { PlainConstraint as Constraint } from '../schemas/passport.js';
import { IssuePassportInput, DelegatePassportInput } from '../schemas/passport.js';
import { flowServiceKey } from './data-flow.js';

const baseRequest = {
  service: 'slack',
  url: 'https://slack.com/api/chat.postMessage',
  method: 'POST' as const,
  headers: { 'Content-Type': 'application/json', 'X-Trace-Id': 'abc123' },
  body: { channel: 'C0123', text: 'hello' },
  query: { team: 'T001' },
};

describe('normalizeRequest', () => {
  it('lowercases headers', () => {
    const r = normalizeRequest(baseRequest);
    expect(r.headers['content-type']).toBe('application/json');
    expect(r.headers['x-trace-id']).toBe('abc123');
  });

  it('uppercases method', () => {
    const r = normalizeRequest({ ...baseRequest, method: 'POST' });
    expect(r.method).toBe('POST');
  });

  it('strips trailing slash from pathname', () => {
    const r = normalizeRequest({ ...baseRequest, url: 'https://slack.com/api/chat/' });
    expect(r.url.pathname).toBe('/api/chat');
  });

  it('keeps lone-root slash', () => {
    const r = normalizeRequest({ ...baseRequest, url: 'https://slack.com/' });
    expect(r.url.pathname).toBe('/');
  });

  it('lowercases host', () => {
    const r = normalizeRequest({ ...baseRequest, url: 'https://Slack.com/api/x' });
    expect(r.url.host).toBe('slack.com');
  });

  it('defaults missing query/headers to empty', () => {
    const r = normalizeRequest({ ...baseRequest, headers: undefined, query: undefined });
    expect(r.headers).toEqual({});
    expect(r.query).toEqual({});
  });
});

describe('resolvePath', () => {
  const req = normalizeRequest(baseRequest);

  it('resolves method + url paths', () => {
    expect(resolvePath(req, 'method')).toBe('POST');
    expect(resolvePath(req, 'url.pathname')).toBe('/api/chat.postMessage');
    expect(resolvePath(req, 'url.host')).toBe('slack.com');
    expect(resolvePath(req, 'url.origin')).toBe('https://slack.com');
  });

  it('resolves headers case-insensitively', () => {
    expect(resolvePath(req, 'headers.content-type')).toBe('application/json');
    expect(resolvePath(req, 'headers.Content-Type')).toBe('application/json');
    expect(resolvePath(req, 'headers.X-TRACE-ID')).toBe('abc123');
  });

  it('resolves query', () => {
    expect(resolvePath(req, 'query.team')).toBe('T001');
  });

  it('resolves body via dot path', () => {
    expect(resolvePath(req, 'body.channel')).toBe('C0123');
    expect(resolvePath(req, 'body.text')).toBe('hello');
  });

  it('resolves the whole body', () => {
    expect(resolvePath(req, 'body')).toEqual({ channel: 'C0123', text: 'hello' });
  });

  it('returns undefined for missing paths', () => {
    expect(resolvePath(req, 'body.nonexistent')).toBeUndefined();
    expect(resolvePath(req, 'headers.nope')).toBeUndefined();
    expect(resolvePath(req, 'query.nope')).toBeUndefined();
  });

  it('returns undefined for nested missing in body', () => {
    expect(resolvePath(req, 'body.user.id')).toBeUndefined();
  });
});

describe('evaluateConstraint', () => {
  const req = normalizeRequest(baseRequest);

  it('eq: matches when equal, fails when not', () => {
    expect(evaluateConstraint({ path: 'method', op: 'eq', value: 'POST' }, req)).toBe(true);
    expect(evaluateConstraint({ path: 'method', op: 'eq', value: 'GET' }, req)).toBe(false);
  });

  it('not_eq: inverse of eq', () => {
    expect(evaluateConstraint({ path: 'method', op: 'not_eq', value: 'GET' }, req)).toBe(true);
    expect(evaluateConstraint({ path: 'method', op: 'not_eq', value: 'POST' }, req)).toBe(false);
  });

  it('in: matches allowlist', () => {
    expect(
      evaluateConstraint({ path: 'body.channel', op: 'in', value: ['C0123', 'C0456'] }, req),
    ).toBe(true);
    expect(
      evaluateConstraint({ path: 'body.channel', op: 'in', value: ['C0456'] }, req),
    ).toBe(false);
  });

  it('not_in: inverse of in', () => {
    expect(
      evaluateConstraint({ path: 'body.channel', op: 'not_in', value: ['C0456'] }, req),
    ).toBe(true);
    expect(
      evaluateConstraint({ path: 'body.channel', op: 'not_in', value: ['C0123'] }, req),
    ).toBe(false);
  });

  it('starts_with: string prefix match', () => {
    expect(
      evaluateConstraint({ path: 'url.pathname', op: 'starts_with', value: '/api/' }, req),
    ).toBe(true);
    expect(
      evaluateConstraint({ path: 'url.pathname', op: 'starts_with', value: '/v1/' }, req),
    ).toBe(false);
  });

  it('matches: regex via RE2', () => {
    expect(
      evaluateConstraint(
        { path: 'url.pathname', op: 'matches', value: '^/api/chat\\.[a-zA-Z]+$' },
        req,
      ),
    ).toBe(true);
    expect(
      evaluateConstraint({ path: 'url.pathname', op: 'matches', value: '^/v1/' }, req),
    ).toBe(false);
  });

  it('unresolved path always fails (deny-by-default)', () => {
    expect(
      evaluateConstraint({ path: 'body.missing', op: 'eq', value: 'anything' }, req),
    ).toBe(false);
    expect(
      evaluateConstraint({ path: 'body.missing', op: 'not_eq', value: 'anything' }, req),
    ).toBe(false);
  });

  it('type mismatch (matches on non-string) fails safely', () => {
    const numReq = normalizeRequest({ ...baseRequest, body: { n: 42 } });
    expect(
      evaluateConstraint({ path: 'body.n', op: 'matches', value: '^42$' }, numReq),
    ).toBe(false);
  });
});

describe('findFailingConstraint', () => {
  const req = normalizeRequest(baseRequest);

  it('returns null when all pass', () => {
    const cs: Constraint[] = [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'body.channel', op: 'in', value: ['C0123'] },
    ];
    expect(findFailingConstraint(cs, req)).toBeNull();
  });

  it('returns first failing constraint (AND semantics)', () => {
    const cs: Constraint[] = [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'body.channel', op: 'eq', value: 'C0456' }, // fails
      { path: 'body.text', op: 'eq', value: 'wrong' }, // would also fail
    ];
    const failed = findFailingConstraint(cs, req);
    expect(failed?.path).toBe('body.channel');
    expect(failed?.value).toBe('C0456');
  });

  it('empty constraint array passes', () => {
    expect(findFailingConstraint([], req)).toBeNull();
  });
});

describe('constraintsAreSubset', () => {
  const parent: Constraint[] = [
    { path: 'method', op: 'eq', value: 'POST' },
    { path: 'body.channel', op: 'in', value: ['C0123', 'C0456'] },
  ];

  it('child with identical constraints is a valid subset', () => {
    expect(constraintsAreSubset(parent, parent)).toBe(true);
  });

  it('child with additional constraint is a valid subset (tightening)', () => {
    const child: Constraint[] = [
      ...parent,
      { path: 'body.text', op: 'starts_with', value: '[alert]' },
    ];
    expect(constraintsAreSubset(child, parent)).toBe(true);
  });

  it('child missing a parent constraint is NOT a subset (loosening)', () => {
    const child: Constraint[] = [{ path: 'method', op: 'eq', value: 'POST' }];
    expect(constraintsAreSubset(child, parent)).toBe(false);
  });

  it('child with different value for same path is NOT a subset', () => {
    const child: Constraint[] = [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'body.channel', op: 'in', value: ['C0123'] }, // narrower value
    ];
    expect(constraintsAreSubset(child, parent)).toBe(false);
  });

  it('array value equality is order-independent', () => {
    const p: Constraint[] = [{ path: 'x', op: 'in', value: ['a', 'b'] }];
    const c: Constraint[] = [{ path: 'x', op: 'in', value: ['b', 'a'] }];
    expect(constraintsAreSubset(c, p)).toBe(true);
  });
});

// allow_data_from narrows the OPPOSITE way to constraints — it GRANTS a flow,
// so a child/issued set may only SHRINK relative to the parent/grant ceiling.
describe('allowDataFromIsSubset', () => {
  it('a child equal to the parent is a subset', () => {
    expect(allowDataFromIsSubset(['guestbook'], ['guestbook'])).toBe(true);
  });

  it('a child that drops a parent flow is a subset (narrowing)', () => {
    expect(allowDataFromIsSubset(['guestbook'], ['guestbook', 'crm'])).toBe(true);
  });

  it('an empty child is a subset of anything (declares no flows)', () => {
    expect(allowDataFromIsSubset([], ['guestbook'])).toBe(true);
  });

  it('a child flow the parent lacks is NOT a subset (widening)', () => {
    expect(allowDataFromIsSubset(['guestbook', 'slack'], ['guestbook'])).toBe(false);
  });

  it('any non-empty child against an empty parent is a widening', () => {
    expect(allowDataFromIsSubset(['guestbook'], [])).toBe(false);
  });
});

describe('standing allow_data_from grants', () => {
  it('classifies only added sources or a new wildcard as widening', () => {
    expect(allowDataFromGrantWidens(['guestbook'], [])).toBe(true);
    expect(allowDataFromGrantWidens(['guestbook'], ['guestbook', 'slack'])).toBe(false);
    expect(allowDataFromGrantWidens(['*'], ['guestbook'])).toBe(true);
    expect(allowDataFromGrantWidens(['guestbook'], ['*'])).toBe(false);
  });

  it('resolves a wildcard to an exact, stable, destination-free snapshot', () => {
    expect(resolveAllowDataFromGrant(['*'], ['slack', 'resend', 'guestbook', 'slack'], 'resend'))
      .toEqual(['guestbook', 'slack']);
  });

  it('keeps a named flow from the destination service itself or one of its connections, which a wildcard never adds', () => {
    expect(resolveAllowDataFromGrant(['cal_com'], ['cal_com', 'slack'], 'cal_com')).toEqual(['cal_com']);
    expect(resolveAllowDataFromGrant(['cal_com@scon_a'], ['cal_com'], 'cal_com')).toEqual(['cal_com@scon_a']);
    expect(resolveAllowDataFromGrant(['*'], ['cal_com', 'slack'], 'cal_com')).toEqual(['slack']);
  });

  it('reads a flow from one connection as narrower than a flow from its service', () => {
    expect(allowDataFromIsSubset(['cal_com@scon_a'], ['cal_com'])).toBe(true);
    expect(allowDataFromIsSubset(['cal_com'], ['cal_com@scon_a'])).toBe(false);
    expect(allowDataFromIsSubset(['cal_com@scon_b'], ['cal_com@scon_a'])).toBe(false);
  });

  it('reads a long custom service by its name or its key, so a parent naming it either way covers a connection of it', () => {
    const long = `custom_${'a1b2c3d4e5'.repeat(10)}`;
    const key = flowServiceKey(long);
    expect(allowDataFromIsSubset([`${key}@scon_a`], [long])).toBe(true);
    expect(allowDataFromIsSubset([`${long}@scon_a`], [key])).toBe(true);
    expect(allowDataFromIsSubset([long], [key])).toBe(true);
    expect(allowDataFromIsSubset([key], [`${key}@scon_a`])).toBe(false);
    expect(allowDataFromIsSubset([`${key}@scon_a`], [`custom_${'z'.repeat(110)}`])).toBe(false);
  });

  it('resolves a wildcard to the key of a long custom service, within the 128 characters a Passport allows', () => {
    const long = `custom_${'a1b2c3d4e5'.repeat(20)}`;
    const [entry] = resolveAllowDataFromGrant(['*'], [long, 'resend'], 'resend');
    expect(entry).toBe(flowServiceKey(long));
    expect(entry!.length).toBeLessThanOrEqual(128);
  });
});

describe('IssuePassportInput / DelegatePassportInput accept allow_data_from', () => {
  it('parses a per-scope allow_data_from on an issue call', () => {
    const parsed = IssuePassportInput.parse({
      agent_id: 'agt_x',
      mission_ids: ['ms_test'],
      scopes: [
        {
          service_connection_id: 'scon_resend',
          scopes: ['email:send'],
          allow_data_from: ['guestbook'],
        },
      ],
    });
    expect(parsed.scopes?.[0]?.allow_data_from).toEqual(['guestbook']);
  });

  it('parses a per-scope allow_data_from on a delegate call', () => {
    const parsed = DelegatePassportInput.parse({
      parent_passport_token: 'tok',
      child_agent_id: 'agt_child',
      scopes: [
        {
          service_connection_id: 'scon_resend',
          scopes: ['email:send'],
          allow_data_from: ['guestbook'],
        },
      ],
    });
    expect(parsed.scopes[0]?.allow_data_from).toEqual(['guestbook']);
  });

  it('rejects more than 32 declared flows', () => {
    const tooMany = Array.from({ length: 33 }, (_, i) => `svc_${i}`);
    expect(() =>
      IssuePassportInput.parse({
        agent_id: 'agt_x',
        mission_ids: ['ms_test'],
        scopes: [{ service_connection_id: 'scon_x', scopes: ['*'], allow_data_from: tooMany }],
      }),
    ).toThrow();
  });
});

describe('query parameters already in the URL', () => {
  const req = (url: string, query?: Record<string, string>) =>
    normalizeRequest({ method: 'POST', url, query, headers: {} } as never);
  const qbo = 'https://quickbooks.api.intuit.com/v3/company/1/invoice/9/send';

  it('are visible to constraints, so not_exists cannot be smuggled past', () => {
    const absent: Constraint = { path: 'query.sendTo', op: 'not_exists', value: true };
    expect(evaluateConstraint(absent, req(qbo))).toBe(true);
    expect(evaluateConstraint(absent, req(`${qbo}?sendTo=attacker@evil.com`))).toBe(false);
  });

  it('are overridden by the explicit query, as the proxy does', () => {
    expect(resolvePath(req(`${qbo}?sendTo=attacker@evil.com`, { sendTo: 'ap@acme.com' }), 'query.sendTo')).toBe('ap@acme.com');
  });

  it('become a list when repeated, so every value must pass', () => {
    const pinned: Constraint = { path: 'query.sendTo', op: 'eq', value: 'ap@acme.com' };
    expect(evaluateConstraint(pinned, req(`${qbo}?sendTo=ap@acme.com&sendTo=attacker@evil.com`))).toBe(false);
    expect(evaluateConstraint({ path: 'query.sendTo', op: 'not_eq', value: 'attacker@evil.com' }, req(`${qbo}?sendTo=ap@acme.com&sendTo=attacker@evil.com`))).toBe(false);
    expect(evaluateConstraint(pinned, req(`${qbo}?sendTo=ap@acme.com`))).toBe(true);
  });

  it('cannot reach Object.prototype', () => {
    expect(resolvePath(req(`${qbo}?__proto__=x`), 'query.constructor')).toBeUndefined();
    expect(resolvePath(req(`${qbo}?__proto__=x`), 'query.__proto__')).toBe('x');
    expect(resolvePath(req(qbo, {}), 'query.toString')).toBeUndefined();
  });
});

describe('array fan-out paths', () => {
  const req = (body: unknown) => normalizeRequest({ method: 'POST', url: 'https://api.sendgrid.com/v3/mail/send', body, headers: {}, query: {} } as never);
  const body = { personalizations: [{ to: [{ email: 'a@acme.com' }] }, { to: [{ email: 'b@evil.com' }], bcc: [{ email: 'c@evil.com' }] }] };
  const to = (op: Constraint['op'], value: Constraint['value']): Constraint => ({ path: 'body.personalizations[].to[].email', op, value });
  const bcc = (op: Constraint['op'], value?: Constraint['value']): Constraint => ({ path: 'body.personalizations[].bcc[].email', op, value: value ?? true });

  it('collects every element, so a second recipient cannot slip past an index-0 pin', () => {
    expect(resolvePath(req(body), 'body.personalizations[].to[].email')).toEqual(['a@acme.com', 'b@evil.com']);
    expect(evaluateConstraint(to('in', ['a@acme.com']), req(body))).toBe(false);
    expect(evaluateConstraint(to('in', ['a@acme.com', 'b@evil.com']), req(body))).toBe(true);
    expect(evaluateConstraint({ path: 'body.personalizations.0.to.0.email', op: 'eq', value: 'a@acme.com' }, req(body))).toBe(true);
  });

  it('refuses when any one element is off the pin, whichever position it is in', () => {
    const at = (emails: string[]) => req({ personalizations: [{ to: emails.map(email => ({ email })) }] });
    const pin = to('in', ['a@acme.com', 'b@acme.com']);
    expect(evaluateConstraint(pin, at(['a@acme.com', 'b@acme.com']))).toBe(true);
    for (const emails of [['x@evil.com', 'a@acme.com'], ['a@acme.com', 'x@evil.com'], ['a@acme.com', 'b@acme.com', 'x@evil.com'], ['A@acme.com']]) {
      expect(evaluateConstraint(pin, at(emails))).toBe(false);
    }
  });

  it('treats a field absent from every element as absent', () => {
    expect(resolvePath(req({ personalizations: [{ to: [] }] }), 'body.personalizations[].bcc[].email')).toBeUndefined();
    expect(evaluateConstraint(bcc('not_exists'), req({ personalizations: [{ to: [] }] }))).toBe(true);
    expect(evaluateConstraint(bcc('not_exists'), req(body))).toBe(false);
  });

  it('fans out over a root array body', () => {
    expect(resolvePath(req([{ to: 'a@acme.com' }, { to: ['b@x.com', 'c@x.com'] }]), 'body[].to')).toEqual(['a@acme.com', 'b@x.com', 'c@x.com']);
  });

  it('flattens a list-valued field once, so each address in it is judged', () => {
    expect(evaluateConstraint({ path: 'body[].to', op: 'in', value: ['a@acme.com', 'b@x.com'] }, req([{ to: 'a@acme.com' }, { to: ['b@x.com', 'c@x.com'] }]))).toBe(false);
  });

  it('refuses a shape it cannot read, for every operator and for not_exists', () => {
    const unreadable: Record<string, unknown> = {
      'to is an object, not a list': { personalizations: [{ to: { email: 'x@evil.com' } }] },
      'to is a string': { personalizations: [{ to: 'x@evil.com' }] },
      'to is null': { personalizations: [{ to: null }] },
      'personalizations is an object': { personalizations: { to: [{ email: 'x@evil.com' }] } },
      'a recipient is a bare string': { personalizations: [{ to: ['x@evil.com'] }] },
      'a recipient is null': { personalizations: [{ to: [null] }] },
      'one good and one bare string': { personalizations: [{ to: [{ email: 'a@acme.com' }, 'x@evil.com'] }] },
      'a recipient is a number': { personalizations: [{ to: [{ email: 'a@acme.com' }, 7] }] },
      'an email that is an object': { personalizations: [{ to: [{ email: { address: 'x@evil.com' } }] }] },
    };
    for (const [label, shape] of Object.entries(unreadable)) {
      const r = req(shape);
      for (const c of [to('eq', 'a@acme.com'), to('in', ['a@acme.com']), to('not_eq', 'x@evil.com'), to('not_in', ['x@evil.com']), to('matches', '^.*@acme\\.com$'), to('not_exists', true)]) {
        expect(evaluateConstraint(c, r), `${label}: ${c.op}`).toBe(false);
      }
    }
  });

  it('does not let a malformed sibling hide behind not_exists on a container', () => {
    const cc = (shape: unknown) => evaluateConstraint({ path: 'body.personalizations[].cc', op: 'not_exists', value: true }, req(shape));
    expect(cc({ personalizations: [{ to: [] }] })).toBe(true);
    expect(cc({ personalizations: [{ cc: [] }] })).toBe(true);
    expect(cc({ personalizations: [{ cc: [{ email: 'x@evil.com' }] }] })).toBe(false);
    expect(cc({ personalizations: [{ cc: 'x@evil.com' }] })).toBe(false);
  });

  it('refuses a list longer than the fan-out limit', () => {
    const many = (n: number) => req({ personalizations: Array.from({ length: n }, () => ({ to: [{ email: 'a@acme.com' }] })) });
    expect(evaluateConstraint(to('eq', 'a@acme.com'), many(FAN_OUT_LIMIT / 2 - 1))).toBe(true);
    expect(evaluateConstraint(to('eq', 'a@acme.com'), many(FAN_OUT_LIMIT))).toBe(false);
    expect(evaluateConstraint(to('not_exists', true), many(FAN_OUT_LIMIT))).toBe(false);
  });

  it('keeps an empty list failing a positive pin and passing a negative one', () => {
    const empty = req({ personalizations: [] });
    expect(resolvePath(empty, 'body.personalizations[].to[].email')).toEqual([]);
    expect(evaluateConstraint(to('in', ['a@acme.com']), empty)).toBe(false);
    expect(evaluateConstraint(to('not_in', ['x@evil.com']), empty)).toBe(true);
  });

  it('does not walk the prototype chain', () => {
    expect(resolvePath(req({ personalizations: [{}] }), 'body.personalizations[].constructor')).toBeUndefined();
  });
});

describe('isResolvablePath', () => {
  it('accepts exactly the notation resolvePath reads', () => {
    for (const path of ['method', 'body', 'url.pathname', 'url.host', 'url.origin', 'headers.x-a', 'query.sendTo', 'body.a', 'body.a.b', 'body.a.0.b',
      'body.to[].email', 'body.a[].b[].c', 'body.a[]', 'body[].to', 'body[].a[].b', 'derived.email.recipients', 'derived.email.text']) {
      expect(isResolvablePath(path), path).toBe(true);
    }
    for (const path of ['', 'body.', 'body..a', 'body.a[0].b', 'body.a[*].b', 'body.[].a', 'body.a.[]', 'body[]', 'body[].', 'body.a[][]', 'derived.email', 'derived.email.nope',
      'derived.sms.to', 'query.', 'query.a.b', 'url.path', 'cookies.a', 'Body.a']) {
      expect(isResolvablePath(path), path).toBe(false);
    }
  });
});
