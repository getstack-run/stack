import { describe, it, expect } from 'vitest';
import { normalizeRequest } from './constraints.js';
import {
  evaluateScopePolicy,
  enumerateRequestFields,
  isFieldDeclared,
  type ScopePolicy,
} from './operation-policy.js';
import type { ProxyRequestInput } from '../schemas/proxy.js';

/**
 * The scenario this exists for: an agent is allowed to send one email to one
 * recipient. `resend.send_email_to` pins body.to and nothing else, so an
 * injected agent keeps the approved recipient and adds a second one in a
 * field the intent never mentions. Under a closed policy the extra field is
 * refused because nobody declared it — not because someone forbade it.
 */

function req(body: unknown, opts: Partial<ProxyRequestInput> = {}) {
  return normalizeRequest({
    service: 'resend',
    url: 'https://api.resend.com/emails',
    method: 'POST',
    body,
    ...opts,
  } as ProxyRequestInput);
}

const SEND_ONE_EMAIL: ScopePolicy = {
  mode: 'closed',
  operations: [
    {
      id: 'resend.send_email_to_alice',
      methods: ['POST'],
      path: { kind: 'exact', value: '/emails' },
      allow_fields: ['body.from', 'body.to', 'body.subject', 'body.text'],
      constraints: [{ path: 'body.to', op: 'eq', value: 'alice@corp.com' }],
    },
  ],
};

const OK_BODY = {
  from: 'bot@corp.com',
  to: 'alice@corp.com',
  subject: 'hello',
  text: 'hi',
};

describe('closed operation policy', () => {
  it('permits the declared call', () => {
    expect(evaluateScopePolicy(SEND_ONE_EMAIL, req(OK_BODY))).toBeNull();
  });

  it('refuses a field nobody declared', () => {
    const d = evaluateScopePolicy(SEND_ONE_EMAIL, req({ ...OK_BODY, bcc: 'attacker@evil.com' }));
    expect(d?.reason).toBe('undeclared_field');
    expect(d && 'field' in d && d.field).toBe('body.bcc');
  });

  it.each(['cc', 'bcc', 'reply_to', 'attachments', 'headers', 'tags'])(
    'refuses body.%s, which no intent in the catalogue thought to forbid',
    (field) => {
      const d = evaluateScopePolicy(SEND_ONE_EMAIL, req({ ...OK_BODY, [field]: 'x@evil.com' }));
      expect(d?.reason).toBe('undeclared_field');
    },
  );

  it('still enforces the value rule on a declared field', () => {
    const d = evaluateScopePolicy(SEND_ONE_EMAIL, req({ ...OK_BODY, to: 'attacker@evil.com' }));
    expect(d?.reason).toBe('constraint_violation');
  });

  it('refuses an extra recipient smuggled into the declared field as a list', () => {
    const d = evaluateScopePolicy(
      SEND_ONE_EMAIL,
      req({ ...OK_BODY, to: ['alice@corp.com', 'attacker@evil.com'] }),
    );
    expect(d?.reason).toBe('constraint_violation');
  });

  it('accepts the pinned recipient sent as a one-element list', () => {
    expect(evaluateScopePolicy(SEND_ONE_EMAIL, req({ ...OK_BODY, to: ['alice@corp.com'] }))).toBeNull();
  });

  it('refuses an undeclared method', () => {
    const d = evaluateScopePolicy(SEND_ONE_EMAIL, req(OK_BODY, { method: 'DELETE' } as Partial<ProxyRequestInput>));
    expect(d?.reason).toBe('no_matching_operation');
  });

  it('refuses an undeclared path on a declared host', () => {
    const d = evaluateScopePolicy(
      SEND_ONE_EMAIL,
      req(OK_BODY, { url: 'https://api.resend.com/domains' } as Partial<ProxyRequestInput>),
    );
    expect(d?.reason).toBe('no_matching_operation');
  });

  it('refuses an undeclared query parameter', () => {
    const d = evaluateScopePolicy(
      SEND_ONE_EMAIL,
      req(OK_BODY, { query: { redirect: 'https://evil.com' } } as Partial<ProxyRequestInput>),
    );
    expect(d?.reason).toBe('undeclared_field');
  });

  it('open mode changes nothing, so existing passports keep working', () => {
    const open: ScopePolicy = { ...SEND_ONE_EMAIL, mode: 'open' };
    expect(evaluateScopePolicy(open, req({ ...OK_BODY, bcc: 'attacker@evil.com' }))).toBeNull();
  });

  it('an absent policy changes nothing', () => {
    expect(evaluateScopePolicy(undefined, req({ anything: true }))).toBeNull();
  });

  it('admits a request when any one of several overlapping operations allows it', () => {
    const policy: ScopePolicy = {
      mode: 'closed',
      operations: [
        {
          id: 'narrow',
          methods: ['POST'],
          path: { kind: 'exact', value: '/emails' },
          allow_fields: ['body.to'],
        },
        {
          id: 'wide',
          methods: ['POST'],
          path: { kind: 'exact', value: '/emails' },
          allow_fields: ['body.to', 'body.subject', 'body.text', 'body.from'],
        },
      ],
    };
    expect(evaluateScopePolicy(policy, req(OK_BODY))).toBeNull();
  });
});

describe('enumerateRequestFields', () => {
  // found by the AgentDojo benchmark, not by review.
  it('an empty body carries no fields, so a no-argument call is declarable', () => {
    const req = normalizeRequest({ service: 's', method: 'POST', url: 'https://x.test/c', body: {} });
    expect(enumerateRequestFields(req)).toEqual([]);
  });

  it('an empty object BELOW the root is still a field the caller sent', () => {
    const req = normalizeRequest({
      service: 's',
      method: 'POST',
      url: 'https://x.test/c',
      body: { metadata: {} },
    });
    expect(enumerateRequestFields(req)).toEqual(['body.metadata']);
  });

  it('a no-argument operation admits an empty body under a closed policy', () => {
    // Before the fix this was refused for want of a field named "body", which
    // no operator could ever declare. It refused get_channels(), list_files()
    // and every other call that carries nothing.
    const policy = {
      mode: 'closed' as const,
      operations: [
        { id: 'get_channels', methods: ['POST'], path: { kind: 'exact' as const, value: '/c' }, allow_fields: [] },
      ],
    };
    const req = normalizeRequest({ service: 's', method: 'POST', url: 'https://x.test/c', body: {} });
    expect(evaluateScopePolicy(policy, req)).toBeNull();
  });

  it('walks nested objects', () => {
    const fields = enumerateRequestFields(req({ a: { b: { c: 1 } } }));
    expect(fields).toContain('body.a.b.c');
  });

  it('collapses array indices so a policy never enumerates them', () => {
    const fields = enumerateRequestFields(req({ attachments: [{ url: 'x' }, { url: 'y' }] }));
    expect(fields).toContain('body.attachments[].url');
    expect(fields.some((f) => /\.\d+\./.test(f))).toBe(false);
  });

  it('reports query parameters', () => {
    const fields = enumerateRequestFields(
      req({}, { query: { limit: '10' } } as Partial<ProxyRequestInput>),
    );
    expect(fields).toContain('query.limit');
  });

  it('reports a null-valued field as present, so it cannot hide', () => {
    expect(enumerateRequestFields(req({ bcc: null }))).toContain('body.bcc');
  });
});

describe('isFieldDeclared', () => {
  it('permits the declared path itself', () => {
    expect(isFieldDeclared('body.to', ['body.to'])).toBe(true);
  });

  it('permits a subtree, for the free-form blobs real APIs accept', () => {
    expect(isFieldDeclared('body.metadata.anything.deep', ['body.metadata'])).toBe(true);
  });

  it('does not permit a sibling that merely shares a prefix', () => {
    expect(isFieldDeclared('body.tokens', ['body.to'])).toBe(false);
  });

  it('matches array declarations regardless of index', () => {
    expect(isFieldDeclared('body.attachments.0.url', ['body.attachments[].url'])).toBe(true);
    expect(isFieldDeclared('body.attachments.7.url', ['body.attachments[].url'])).toBe(true);
  });

  it('refuses an undeclared leaf under a declared array', () => {
    expect(isFieldDeclared('body.attachments[].path', ['body.attachments[].url'])).toBe(false);
  });

  it('refuses everything against an empty declaration', () => {
    expect(isFieldDeclared('body.to', [])).toBe(false);
  });
});
