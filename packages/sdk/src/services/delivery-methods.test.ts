import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import { DeliveryMethodService } from './delivery-methods.js';

function clientStub(): HttpClient {
  return {
    get: vi.fn(async () => []),
    post: vi.fn(async () => ({})),
    delete: vi.fn(async () => ({})),
  } as unknown as HttpClient;
}

describe('DeliveryMethodService', () => {
  it('sends the canonical REST shape and governance approval on creation', async () => {
    const client = clientStub();
    const service = new DeliveryMethodService(client);

    await service.add(
      { channel_type: 'webhook', destination: 'https://hooks.example.test/stack' },
      { governanceApprovalId: 'gvr_1' },
    );

    expect(client.post).toHaveBeenCalledWith(
      '/v1/notifications/destinations',
      { channel_type: 'webhook', destination: 'https://hooks.example.test/stack' },
      { headers: { 'X-Governance-Approval': 'gvr_1' } },
    );
  });

  it('threads governance approval through one-time secret rotation', async () => {
    const client = clientStub();
    const service = new DeliveryMethodService(client);

    await service.rotateSecret('ndst_1', { governanceApprovalId: 'gvr_2' });

    expect(client.post).toHaveBeenCalledWith(
      '/v1/notifications/destinations/ndst_1/rotate-secret',
      undefined,
      { headers: { 'X-Governance-Approval': 'gvr_2' } },
    );
  });
});
