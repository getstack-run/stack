import { describe, expect, it } from 'vitest';
import { describeConstraint, describeRefusedHttpCall, pathSegmentLooksSecret, redactRequestPath, evidenceUrl, evidenceAction, evidenceIntentClaim } from './refusal-evidence.js';

// A refusal names the call it refused (method, host, path) and the
// policy's side of the failed comparison, never the caller's data.

describe('redactRequestPath', () => {
  it('keeps ordinary resource paths readable', () => {
    for (const path of [
      '/api/chat.postMessage',
      '/repos/stack-fixture/boundary-example/issues',
      '/repos/acme/my-really-long-repository-name-2024/issues/12345',
      '/v1/customers/cus_Nffrfeqx/charges',
      '/v1/items/3f2b8c4e-1d2a-4b6c-9e7f-0a1b2c3d4e5f',
      '/gmail/v1/users/me/messages/send',
    ]) expect(redactRequestPath(path)).toBe(path);
  });

  it('drops the query string and fragment', () => {
    expect(redactRequestPath('/api/conversations.history?channel=C_EXEC&token=abc#x')).toBe('/api/conversations.history');
  });

  it('redacts segments that look like secrets, tokens or email addresses', () => {
    // Built from parts so the repository holds no token-shaped literal.
    const jwt = ['eyJ' + 'hbGciOiJFZERTQSJ9', 'eyJ' + 'zdWIiOiJhZ3RfMSJ9', 'c2lnbmF0dXJl'].join('.');
    expect(redactRequestPath(`/v1/keys/sk_live_abc123/rotate`)).toBe('/v1/keys/{redacted}/rotate');
    expect(redactRequestPath(`/hooks/xoxb-1234-5678-abcdef`)).toBe('/hooks/{redacted}');
    expect(redactRequestPath(`/verify/${jwt}`)).toBe('/verify/{redacted}');
    expect(redactRequestPath('/users/cfo@acme.com/messages')).toBe('/users/{redacted}/messages');
    expect(redactRequestPath('/users/cfo%40acme.com/messages')).toBe('/users/{redacted}/messages');
    expect(redactRequestPath('/blobs/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')).toBe('/blobs/{redacted}');
    expect(redactRequestPath('/t/Zx8Qm2Lk9Vb4Np7Rt1Ws6Yh3Jd5Gf0Ca')).toBe('/t/{redacted}');
    expect(redactRequestPath('/k/a8f3k29d0q7m4z1x6c5v8b2n3m9l0p7o')).toBe('/k/{redacted}');
  });

  it('caps a very long path', () => {
    expect(redactRequestPath(`/${'a/'.repeat(400)}`).length).toBeLessThanOrEqual(515);
  });

  it('classifies single segments', () => {
    expect(pathSegmentLooksSecret('issues')).toBe(false);
    expect(pathSegmentLooksSecret('12345')).toBe(false);
    expect(pathSegmentLooksSecret('ghp_abcdefghijklmnop')).toBe(true);
  });
});

describe('describeConstraint', () => {
  it('records the values the policy allows for eq and in', () => {
    expect(describeConstraint({ path: 'body.channel', op: 'in', value: ['D_OWNER', 'C_SUPPORT'] }))
      .toEqual({ path: 'body.channel', op: 'in', allowed: ['D_OWNER', 'C_SUPPORT'] });
    expect(describeConstraint({ path: 'method', op: 'eq', value: 'GET' })).toEqual({ path: 'method', op: 'eq', allowed: ['GET'] });
  });

  it('records no value for a deny-list op, whose list is what the request matched', () => {
    expect(describeConstraint({ path: 'body.to', op: 'not_in', value: ['attacker@evil.com'] })).toEqual({ path: 'body.to', op: 'not_in' });
    expect(describeConstraint({ path: 'body.to', op: 'not_eq', value: 'attacker@evil.com' })).toEqual({ path: 'body.to', op: 'not_eq' });
  });

  it('records no value for a header constraint', () => {
    expect(describeConstraint({ path: 'headers.x-api-key', op: 'eq', value: 'secret-value' })).toEqual({ path: 'headers.x-api-key', op: 'eq' });
  });

  it('records the bound of a numeric cap, and caps long allowed lists', () => {
    expect(describeConstraint({ path: 'body.amount', op: 'lte', value: 5000 })).toEqual({ path: 'body.amount', op: 'lte', bound: 5000 });
    const many = Array.from({ length: 30 }, (_, i) => `C${i}`);
    const described = describeConstraint({ path: 'body.channel', op: 'in', value: many });
    expect(described.allowed).toHaveLength(20);
    expect(described.allowed_count).toBe(30);
  });
});

describe('describeRefusedHttpCall and evidenceUrl', () => {
  it('names method, host and redacted path only', () => {
    expect(describeRefusedHttpCall({ method: 'post', url: { host: 'Slack.com', pathname: '/api/chat.postMessage' } }))
      .toEqual({ request_method: 'POST', request_host: 'slack.com', request_path: '/api/chat.postMessage' });
  });

  it('drops the query string, fragment and credentials from an absolute URL', () => {
    expect(evidenceUrl('https://user:pw@slack.com/api/conversations.history?channel=C_EXEC#frag')).toBe('https://slack.com/api/conversations.history');
    expect(evidenceUrl('https://api.example.com/v1/keys/sk_live_abc123')).toBe('https://api.example.com/v1/keys/{redacted}');
    expect(evidenceUrl('not a url')).toBeNull();
  });
});

describe('evidenceIntentClaim', () => {
  const secret = ['planted', 'query', 'secret', '42'].join('-');
  const approved = {
    action: `GET https://slack.com/api/conversations.list?token=${secret}`,
    parameters: { service: 'slack', method: 'GET', url: `https://slack.com/api/conversations.list?token=${secret}`, query: { access_token: secret } },
  };

  it('keeps where the call went and drops the query string, in the action and the parameters', () => {
    const shown = evidenceIntentClaim(approved);
    expect(shown.action).toBe('GET https://slack.com/api/conversations.list');
    expect(shown.parameters).toEqual({ service: 'slack', method: 'GET', url: 'https://slack.com/api/conversations.list' });
    expect(JSON.stringify(shown)).not.toContain(secret);
  });

  it('does not change the claim it is given', () => {
    evidenceIntentClaim(approved);
    expect(approved.parameters.url).toContain(secret);
  });

  it('records an unparseable URL as such, never verbatim', () => {
    const shown = evidenceIntentClaim({ action: 'GET nonsense', parameters: { url: `nonsense?token=${secret}` } });
    expect(shown.parameters['url']).toBe('(unparseable URL)');
    expect(evidenceAction('GET', `nonsense?token=${secret}`)).toBe('GET (unparseable URL)');
  });
});
