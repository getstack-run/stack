import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import { NetworkSubscriptionsService } from './network.js';

describe('network subscription signing secret', () => {
  it('returns the signing secret from create, once, and sends only the address and installs', async () => {
    const post = vi.fn().mockResolvedValue({ id: 'nsub_1', signed: true, signing_secret: 'whsec_once' });
    const service = new NetworkSubscriptionsService({ post } as unknown as HttpClient);
    const created = await service.create({ url: 'https://counterparty.example/hook', installs: ['ins_1'] });
    expect(created.signing_secret).toBe('whsec_once');
    expect(post).toHaveBeenCalledWith('/v1/network/subscriptions', { url: 'https://counterparty.example/hook', installs: ['ins_1'] });
  });

  it('rotates through the rotation route and escapes the id', async () => {
    const post = vi.fn().mockResolvedValue({ signing_secret: 'whsec_new', previous_valid_until: '2026-10-25T00:00:00.000Z' });
    const service = new NetworkSubscriptionsService({ post } as unknown as HttpClient);
    expect(await service.rotateSecret('nsub 1')).toEqual({ signing_secret: 'whsec_new', previous_valid_until: '2026-10-25T00:00:00.000Z' });
    expect(post).toHaveBeenCalledWith('/v1/network/subscriptions/nsub%201/rotate-secret', {});
  });
});
