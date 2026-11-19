import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import type { Services } from '../config/services.js';
const context = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));
vi.mock('../middleware/auth.js', () => ({ createAuthMiddleware: () => async (request: object) => Object.assign(request, context.current) }));
import { registerInboundReceiverRoute } from './inbound.js';
import { registerInboundWebhookRoutes } from './inbound-webhooks.js';

describe('public inbound HTTP boundary', () => {
  it('preserves signed bytes and returns a retry response for unfinished delivery', async () => {
    const receive = vi.fn().mockResolvedValue({ status: 503, body: { error: 'delivery_in_progress' } });
    const app = Fastify();
    await registerInboundReceiverRoute(app, { inboundWebhooks: { receive } } as unknown as Services);
    try {
      const raw = '{ "id": "fixture", "text": "é" }';
      const result = await app.inject({ method: 'POST', url: '/v1/inbound/generic/fixture',
        headers: { 'content-type': 'application/json', 'x-webhook-signature': 'fixture-signature' }, payload: raw });
      expect(result.statusCode).toBe(503);
      expect(result.headers['retry-after']).toBe('5');
      expect(receive.mock.calls[0]![0].rawBody.equals(Buffer.from(raw))).toBe(true);
      expect(receive.mock.calls[0]![0].parsedBody).toEqual({ id: 'fixture', text: 'é' });
    } finally { await app.close(); }
  });
  it.each([{ body: '{broken', status: 400 }, { body: JSON.stringify({ text: 'x'.repeat(1024 * 1024) }), status: 413 }])(
    'rejects invalid or oversized bodies before service effects ($status)', async ({ body, status }) => {
      const receive = vi.fn(); const app = Fastify();
      await registerInboundReceiverRoute(app, { inboundWebhooks: { receive } } as unknown as Services);
      try {
        const result = await app.inject({ method: 'POST', url: '/v1/inbound/generic/fixture',
          headers: { 'content-type': 'application/json' }, payload: body });
        expect(result.statusCode).toBe(status); expect(receive).not.toHaveBeenCalled();
      } finally { await app.close(); }
    },
  );
});

describe('provider signing-secret governance', () => {
  it.each([
    { name: 'readonly', principal: { memberId: 'mem_fixture', memberRole: 'readonly' }, status: 403 },
    { name: 'standard', principal: { memberId: 'mem_fixture', memberRole: 'standard' }, status: 403 },
    { name: 'agent', principal: { agentId: 'agt_fixture' }, status: 403 },
    { name: 'OAuth', principal: { oauthScope: 'inbound-webhooks:write' }, status: 403 },
    { name: 'owner', principal: {}, status: 200 },
    { name: 'admin', principal: { memberId: 'mem_fixture', memberRole: 'admin' }, status: 200 },
  ])('enforces $name authority before changing the key', async ({ principal, status }) => {
    context.current = { operatorId: 'op_fixture', ...principal };
    const generatedDownstream = 'synthetic-generated-downstream-key';
    const setProviderSigningSecret = vi.fn().mockResolvedValue({ configured: true, webhook_secret: generatedDownstream });
    const write = vi.fn().mockResolvedValue(undefined); const app = Fastify();
    app.setErrorHandler((error, _request, reply) => reply.code((error as { statusCode?: number; httpStatus?: number }).statusCode ??
      (error as { httpStatus?: number }).httpStatus ?? 500).send({ error: 'rejected' }));
    registerInboundWebhookRoutes(app, { inboundWebhooks: { setProviderSigningSecret }, audit: { write } } as unknown as Services);
    try {
      const fixtureSecret = 'whsec_' + Buffer.alloc(24, 7).toString('base64');
      const response = await app.inject({ method: 'PUT', url: '/v1/operator/inbound-webhooks/iwh_fixture/provider-signing-secret',
        payload: { signing_secret: fixtureSecret } });
      expect(response.statusCode).toBe(status);
      expect(setProviderSigningSecret).toHaveBeenCalledTimes(status === 200 ? 1 : 0);
      expect(response.body).not.toContain(fixtureSecret);
      expect(JSON.stringify(write.mock.calls)).not.toContain(fixtureSecret);
      if (status === 200) {
        expect(response.headers['cache-control']).toBe('no-store');
        expect(response.json()).toMatchObject({ configured: true, webhook_secret: generatedDownstream });
        expect(JSON.stringify(write.mock.calls)).not.toContain(generatedDownstream);
      }
    } finally { await app.close(); }
  });

  it('marks the create response containing both one-time generic keys as non-cacheable', async () => {
    context.current = { operatorId: 'op_fixture' };
    const result = {
      id: 'iwh_fixture', provider: 'generic', slug: 'synthetic-slug',
      webhook_url: 'https://api.example.test/v1/inbound/generic/synthetic-slug',
      webhook_secret: 'synthetic-downstream-once',
      incoming_signing_secret: 'synthetic-incoming-once',
      signing_configured: true, agent_id: 'agt_fixture', forward_url: null,
      created_at: new Date(0).toISOString(),
    };
    const create = vi.fn().mockResolvedValue(result);
    const write = vi.fn().mockResolvedValue(undefined);
    const app = Fastify();
    registerInboundWebhookRoutes(app, { inboundWebhooks: { create }, audit: { write } } as unknown as Services);
    try {
      const response = await app.inject({ method: 'POST', url: '/v1/operator/inbound-webhooks',
        payload: { provider: 'generic', agent_id: 'agt_fixture' } });
      expect(response.statusCode).toBe(201);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.json()).toMatchObject({
        webhook_secret: result.webhook_secret,
        incoming_signing_secret: result.incoming_signing_secret,
      });
      expect(JSON.stringify(write.mock.calls)).not.toContain(result.webhook_secret);
      expect(JSON.stringify(write.mock.calls)).not.toContain(result.incoming_signing_secret);
    } finally { await app.close(); }
  });
});

describe('downstream signing-secret rotation governance', () => {
  it.each([
    { name: 'readonly', principal: { memberId: 'mem_fixture', memberRole: 'readonly' }, status: 403 },
    { name: 'standard', principal: { memberId: 'mem_fixture', memberRole: 'standard' }, status: 403 },
    { name: 'agent', principal: { agentId: 'agt_fixture' }, status: 403 },
    { name: 'OAuth', principal: { oauthScope: 'inbound-webhooks:write' }, status: 403 },
    { name: 'owner', principal: {}, status: 200 },
    { name: 'admin', principal: { memberId: 'mem_fixture', memberRole: 'admin' }, status: 200 },
  ])('enforces $name authority before issuing a secret', async ({ principal, status }) => {
    context.current = { operatorId: 'op_fixture', ...principal };
    const issued = 'whsec_synthetic-issued-once';
    const rotateDownstreamSecret = vi.fn().mockResolvedValue({ webhook_secret: issued, previous_valid_until: new Date(0).toISOString() });
    const write = vi.fn().mockResolvedValue(undefined); const app = Fastify();
    app.setErrorHandler((error, _request, reply) => reply.code((error as { statusCode?: number; httpStatus?: number }).statusCode ??
      (error as { httpStatus?: number }).httpStatus ?? 500).send({ error: 'rejected' }));
    registerInboundWebhookRoutes(app, { inboundWebhooks: { rotateDownstreamSecret }, audit: { write } } as unknown as Services);
    try {
      const response = await app.inject({ method: 'POST', url: '/v1/operator/inbound-webhooks/iwh_fixture/rotate-secret', payload: {} });
      expect(response.statusCode).toBe(status);
      expect(rotateDownstreamSecret).toHaveBeenCalledTimes(status === 200 ? 1 : 0);
      expect(JSON.stringify(write.mock.calls)).not.toContain(issued);
      if (status === 200) {
        expect(response.headers['cache-control']).toBe('no-store');
        expect(response.json()).toMatchObject({ webhook_secret: issued });
        expect(rotateDownstreamSecret).toHaveBeenCalledWith('iwh_fixture', 'op_fixture');
      } else {
        expect(response.body).not.toContain(issued);
      }
    } finally { await app.close(); }
  });
});
