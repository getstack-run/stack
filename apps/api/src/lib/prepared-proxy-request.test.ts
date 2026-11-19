import { describe, expect, it } from 'vitest';
import { prepareProxyRequest, resolveProxyDestination } from './prepared-proxy-request.js';

const binding = {
  operatorId: 'op_1',
  agentId: 'agt_1',
  passportJti: 'jti_1',
  authorityUseId: 'ause_1',
  approvalId: 'iap_1',
  connectionId: 'svcconn_1',
  credentialVersion: 4,
  destinationConfigHash: `sha256:${'a'.repeat(64)}` as const,
};

function prepare(overrides: Record<string, unknown> = {}) {
  const input = {
    service: 'stripe',
    url: 'https://api.stripe.com/v1/refunds?expand[]=charge&expand[]=balance_transaction',
    method: 'POST' as const,
    headers: { 'X-Trace': 'abc' },
    body: { amount: 1 },
    ...overrides,
  };
  return prepareProxyRequest(input, input.url, binding);
}

describe('prepareProxyRequest', () => {
  it('preserves duplicate embedded query order in the operation identity', () => {
    const first = prepare();
    const reversed = prepare({
      url: 'https://api.stripe.com/v1/refunds?expand[]=balance_transaction&expand[]=charge',
    });
    expect(first.requestHash).not.toBe(reversed.requestHash);
  });

  it('binds appended query values and the exact pathname', () => {
    expect(prepare({ query: { amount: '1' } }).requestHash)
      .not.toBe(prepare({ query: { amount: '999' } }).requestHash);
    expect(prepare({ url: 'https://api.stripe.com/v1/refunds/' }).requestHash)
      .not.toBe(prepare({ url: 'https://api.stripe.com/v1/refunds' }).requestHash);
  });

  it('keeps object and array JSON bodies distinct while ignoring object key order', () => {
    const object = prepare({ body: { x: 1, y: true } });
    const reordered = prepare({ body: { y: true, x: 1 } });
    const array = prepare({ body: [['x', 1], ['y', true]] });
    expect(object.requestHash).toBe(reordered.requestHash);
    expect(object.requestHash).not.toBe(array.requestHash);
  });

  it('treats case-only header names as equivalent and rejects ambiguous duplicates', () => {
    expect(prepare({ headers: { 'X-Trace': 'abc' } }).requestHash)
      .toBe(prepare({ headers: { 'x-trace': 'abc' } }).requestHash);
    expect(() => prepare({ headers: { 'X-Trace': 'abc', 'x-trace': 'changed' } }))
      .toThrow(/conflicting duplicate header x-trace/);
  });

  it('binds the connection, credential revision, passport, authority and approval', () => {
    for (const changed of [
      { connectionId: 'svcconn_2' },
      { credentialVersion: 5 },
      { destinationConfigHash: `sha256:${'b'.repeat(64)}` as const },
      { passportJti: 'jti_2' },
      { authorityUseId: 'ause_2' },
      { approvalId: 'iap_2' },
      { agentId: 'agt_2' },
      { operatorId: 'op_2' },
    ]) {
      const other = prepareProxyRequest(
        {
          service: 'stripe',
          url: 'https://api.stripe.com/v1/refunds?expand[]=charge&expand[]=balance_transaction',
          method: 'POST',
          headers: { 'X-Trace': 'abc' },
          body: { amount: 1 },
        },
        'https://api.stripe.com/v1/refunds?expand[]=charge&expand[]=balance_transaction',
        { ...binding, ...changed },
      );
      expect(other.requestHash).not.toBe(prepare().requestHash);
    }
  });

  it('keeps body and header values out of the persistence descriptor', () => {
    const prepared = prepare({
      headers: { 'X-Customer': 'private-value' },
      body: { email: 'person@example.com' },
    });
    const persisted = JSON.stringify(prepared.persistence);
    expect(persisted).not.toContain('private-value');
    expect(persisted).not.toContain('person@example.com');
  });
});

describe('resolveProxyDestination', () => {
  it('allows declared non-secret destination fields', () => {
    const credential = JSON.stringify({ instance_url: 'https://acme.my.salesforce.com', access_token: 'secret' });
    expect(resolveProxyDestination('salesforce', '{{instance_url}}/services/data/v59.0', credential))
      .toBe('https://acme.my.salesforce.com/services/data/v59.0');
  });

  it('rejects secret, unknown and query-string credential interpolation', () => {
    const credential = JSON.stringify({ instance_url: 'https://example.com', access_token: 'secret' });
    expect(() => resolveProxyDestination('salesforce', 'https://example.com?q={{access_token}}', credential))
      .toThrow(/cannot be interpolated/);
    expect(() => resolveProxyDestination('salesforce', 'https://example.com/{{unknown}}', credential))
      .toThrow(/cannot be interpolated/);
  });
});
