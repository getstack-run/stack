import { describe, expect, it, vi } from 'vitest';
import type { HttpClient } from '../client.js';
import { InboundWebhookService } from './inbound-webhooks.js';

describe('inbound provider signing setup', () => {
  it('sends the key only in the request body and returns configuration status', async () => {
    const put = vi.fn().mockResolvedValue({ configured: true, webhook_secret: 'synthetic-generated-downstream' });
    const service = new InboundWebhookService({ put } as unknown as HttpClient);
    expect(await service.setProviderSigningSecret('iwh fixture', 'synthetic-key')).toEqual({
      configured: true,
      webhook_secret: 'synthetic-generated-downstream',
    });
    expect(put).toHaveBeenCalledWith('/v1/operator/inbound-webhooks/iwh%20fixture/provider-signing-secret', { signing_secret: 'synthetic-key' });
    await service.setProviderSigningSecret('iwh fixture', 'synthetic-provider', 'synthetic-downstream');
    expect(put).toHaveBeenLastCalledWith('/v1/operator/inbound-webhooks/iwh%20fixture/provider-signing-secret', {
      signing_secret: 'synthetic-provider', downstream_signing_secret: 'synthetic-downstream',
    });
  });
});

describe('inbound downstream secret rotation', () => {
  it('posts to the rotation route and returns the new secret once', async () => {
    const post = vi.fn().mockResolvedValue({ webhook_secret: 'whsec_x', previous_valid_until: '2026-10-25T00:00:00.000Z' });
    const service = new InboundWebhookService({ post } as unknown as HttpClient);
    expect(await service.rotateSecret('iwh fixture')).toEqual({ webhook_secret: 'whsec_x', previous_valid_until: '2026-10-25T00:00:00.000Z' });
    expect(post).toHaveBeenCalledWith('/v1/operator/inbound-webhooks/iwh%20fixture/rotate-secret', {});
  });
});
