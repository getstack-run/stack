import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import { AuthorityService } from './authority.js';

function clientStub(): HttpClient {
  return {
    get: vi.fn(async () => ({})),
    post: vi.fn(async () => ({})),
  } as unknown as HttpClient;
}

describe('AuthorityService', () => {
  it('creates a human-approved OIDC Authority request without granting access', async () => {
    const client = clientStub();
    const service = new AuthorityService(client);
    const expiresAt = new Date('2026-08-26T12:30:00.000Z');

    await service.createEnterpriseOidcRequest({
      organisation_name: 'Example AB',
      role_name: 'CFO',
      role_claim_path: 'roles',
      role_claim_value: 'cfo',
      agent_id: 'agt_finance',
      service_connection_id: 'scon_stripe',
      provider: 'stripe',
      purpose: 'Send one approved payment',
      http_method: 'POST',
      resource_path: '/v1/payments',
      expires_at: expiresAt,
    }, { idempotencyKey: 'authority-request-1' });

    expect(client.post).toHaveBeenCalledWith(
      '/v1/authority/enterprise-oidc/requests',
      expect.objectContaining({ expires_at: expiresAt.toISOString() }),
      { headers: { 'Idempotency-Key': 'authority-request-1' } },
    );
  });

  it('threads mandatory idempotency and governance headers on protected mutations', async () => {
    const client = clientStub();
    const service = new AuthorityService(client);

    await service.eraseBinding('abn_x', {
      idempotencyKey: 'authority-exact-retry-1',
      governanceApprovalId: 'gov_x',
    });

    expect(client.post).toHaveBeenCalledWith(
      '/v1/authority/bindings/abn_x/erase',
      {},
      { headers: {
        'Idempotency-Key': 'authority-exact-retry-1',
        'X-Governance-Approval': 'gov_x',
      } },
    );
  });

  it('rejects malformed idempotency keys before making a request', async () => {
    const client = clientStub();
    const service = new AuthorityService(client);

    expect(() => service.createPrincipal(
      { kind: 'person' },
      { idempotencyKey: 'contains a space' },
    )).toThrow(/idempotencyKey/);
    expect(client.post).not.toHaveBeenCalled();
  });

  it('uses versioned safe-read routes without accepting an operator id', async () => {
    const client = clientStub();
    const service = new AuthorityService(client);

    await service.getBinding('abn_x', 3);

    expect(client.get).toHaveBeenCalledWith(
      '/v1/authority/bindings/abn_x',
      { version: '3' },
    );
  });
});
