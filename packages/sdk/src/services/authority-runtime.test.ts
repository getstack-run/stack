import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import { ProxyService } from './proxy.js';
import { SkillService } from './skills.js';

const AUTHORITY_REQUEST_ID = 'authority_request_abc123';

function clientStub(): HttpClient {
  return { post: vi.fn(async () => ({ status: 200, headers: {}, body: { ok: true } })) } as unknown as HttpClient;
}

describe('runtime authority request threading', () => {
  it('sends a proxy authority request id only as a header', async () => {
    const client = clientStub();
    const service = new ProxyService(client);
    const input = { service: 'slack', method: 'POST', url: 'https://slack.com/api/chat.postMessage' };

    await service.request(input, { passportToken: 'passport', authorityRequestId: AUTHORITY_REQUEST_ID });

    expect(client.post).toHaveBeenCalledWith('/v1/proxy', input, {
      headers: {
        'X-Passport-Token': 'passport',
        'X-STACK-Authority-Request-Id': AUTHORITY_REQUEST_ID,
      },
    });
    expect(input).not.toHaveProperty('authority_request_id');
  });

  it('generates and exposes a stable operation id for non-GET calls', async () => {
    const client = clientStub();
    const service = new ProxyService(client);

    const response = await service.request(
      { service: 'slack', method: 'POST', url: 'https://slack.com/api/chat.postMessage' },
      { passportToken: 'passport' },
    );

    expect(response.operationId).toMatch(/^[A-Za-z0-9_-]{22,256}$/);
    expect(client.post).toHaveBeenCalledWith('/v1/proxy', expect.anything(), {
      headers: {
        'X-Passport-Token': 'passport',
        'X-STACK-Authority-Request-Id': response.operationId,
      },
    });
  });

  it('awaits durable operation-id persistence before starting network I/O', async () => {
    let persisted: string | undefined;
    const client = {
      post: vi.fn(async () => {
        expect(persisted).toMatch(/^[A-Za-z0-9_-]{22,256}$/);
        return { status: 200, headers: {}, body: { ok: true } };
      }),
    } as unknown as HttpClient;

    const response = await new ProxyService(client).request(
      { service: 'stripe', method: 'POST', url: 'https://api.stripe.com/v1/refunds' },
      {
        passportToken: 'passport',
        onOperationId: async (operationId) => {
          await Promise.resolve();
          persisted = operationId;
        },
      },
    );
    expect(response.operationId).toBe(persisted);
  });

  it('preserves the generated operation id on API and network errors', async () => {
    const apiError = new Error('response lost');
    const client = { post: vi.fn(async () => { throw apiError; }) } as unknown as HttpClient;

    await expect(new ProxyService(client).request(
      { service: 'stripe', method: 'POST', url: 'https://api.stripe.com/v1/refunds' },
      { passportToken: 'passport' },
    )).rejects.toMatchObject({ operationId: expect.stringMatching(/^[A-Za-z0-9_-]{22,256}$/) });
  });

  it('leaves GET calls without a generated operation id', async () => {
    const client = clientStub();
    const response = await new ProxyService(client).request(
      { service: 'slack', method: 'GET', url: 'https://slack.com/api/auth.test' },
      { passportToken: 'passport' },
    );
    expect(response.operationId).toBeUndefined();
    expect(client.post).toHaveBeenCalledWith('/v1/proxy', expect.anything(), {
      headers: { 'X-Passport-Token': 'passport' },
    });
  });

  it('reads operation state with body-based identity and live Passport auth', async () => {
    const client = clientStub();
    await new ProxyService(client).getOperation(AUTHORITY_REQUEST_ID, {
      passportToken: 'passport',
      includeResponse: true,
    });
    expect(client.post).toHaveBeenCalledWith(
      '/v1/proxy/operations/get',
      { operation_id: AUTHORITY_REQUEST_ID, include_response: true },
      { headers: { 'X-Passport-Token': 'passport' } },
    );
  });

  it('sends a skill authority request id only as a header', async () => {
    const client = clientStub();
    const service = new SkillService(client);
    const input = { agent_id: 'agt_x', input: { value: 1 }, passport_id: 'pas_x' };

    await service.invoke('sk_x', input, { authorityRequestId: AUTHORITY_REQUEST_ID });

    expect(client.post).toHaveBeenCalledWith('/v1/skills/sk_x/invoke', input, {
      headers: { 'X-STACK-Authority-Request-Id': AUTHORITY_REQUEST_ID },
    });
    expect(input).not.toHaveProperty('authority_request_id');
  });

  it('fails closed on malformed authority request ids', async () => {
    const client = clientStub();
    const service = new ProxyService(client);
    await expect(service.request(
      { service: 'slack', method: 'GET', url: 'https://slack.com/api/auth.test' },
      { authorityRequestId: 'short' },
    )).rejects.toThrow(/authorityRequestId/);
    expect(client.post).not.toHaveBeenCalled();
  });
});
