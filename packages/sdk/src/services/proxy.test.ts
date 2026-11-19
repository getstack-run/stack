import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import type { ProxyRequest } from '../types.js';
import { ProxyService } from './proxy.js';

function clientStub(): HttpClient {
  return {
    post: vi.fn(async () => ({ status: 200, headers: {}, body: { ok: true } })),
  } as unknown as HttpClient;
}

describe('ProxyService request selector compatibility', () => {
  it('accepts the legacy provider field and sends only service on the wire', async () => {
    const client = clientStub();
    const input: ProxyRequest = {
      provider: 'slack',
      method: 'GET',
      url: 'https://slack.com/api/auth.test',
    };

    await new ProxyService(client).request(input, { passportToken: 'passport' });

    expect(client.post).toHaveBeenCalledWith(
      '/v1/proxy',
      {
        service: 'slack',
        method: 'GET',
        url: 'https://slack.com/api/auth.test',
      },
      { headers: { 'X-Passport-Token': 'passport' } },
    );
    expect(input).toEqual({
      provider: 'slack',
      method: 'GET',
      url: 'https://slack.com/api/auth.test',
    });
  });

  it('accepts service and preserves it as the sole wire selector', async () => {
    const client = clientStub();
    const input: ProxyRequest = {
      service: 'stripe',
      method: 'GET',
      url: 'https://api.stripe.com/v1/customers',
    };

    await new ProxyService(client).request(input);

    expect(client.post).toHaveBeenCalledWith(
      '/v1/proxy',
      {
        service: 'stripe',
        method: 'GET',
        url: 'https://api.stripe.com/v1/customers',
      },
      undefined,
    );
  });

  it('rejects conflicting selectors before persistence or network I/O', async () => {
    const client = clientStub();
    const onOperationId = vi.fn();
    const conflictingInput = {
      service: 'stripe',
      provider: 'slack',
      method: 'POST',
      url: 'https://api.stripe.com/v1/refunds',
    } as unknown as ProxyRequest;

    await expect(new ProxyService(client).request(conflictingInput, { onOperationId }))
      .rejects.toThrow('ProxyRequest must include exactly one of service or provider');
    expect(onOperationId).not.toHaveBeenCalled();
    expect(client.post).not.toHaveBeenCalled();
  });

  it('makes conflicting selectors unassignable in TypeScript', () => {
    type ConflictingRequest = {
      service: string;
      provider: string;
      method: string;
      url: string;
    };
    type ConflictIsAssignable = ConflictingRequest extends ProxyRequest ? true : false;
    const conflictIsAssignable: ConflictIsAssignable = false;

    expect(conflictIsAssignable).toBe(false);
  });
});
