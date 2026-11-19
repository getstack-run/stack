import { describe, it, expect, vi } from 'vitest';
import { NotFoundError } from '@stack/shared';
import { InboundWebhookService } from './inbound-webhook-service.js';
import { genericExtractor } from './inbound-webhook-extractors/generic.js';
import type { InboundDeliveryHandler, InboundExtractorSource } from './inbound-webhook-extractors/index.js';
import { PARTNER_OP, SLUG, buildPayload, makeDeps } from './inbound-webhook-service.test-support.js';

// A provider the deployment takes the deliveries of itself: its rows belong to no agent, a handler decides what an event does, and the
// owner sees them marked as managed, and revoking one ends the provider's side first.

const extractors: InboundExtractorSource = { get: (provider) => (provider === 'managed' ? genericExtractor : undefined) };

function build(handler: InboundDeliveryHandler) {
  const made = makeDeps({}, extractors);
  const row = made.state.rows[0]!;
  row.provider = 'managed';
  row.agent_id = null;
  row.forward_url = null;
  const service = new InboundWebhookService({ ...made.deps, deliveries: { get: (provider) => (provider === 'managed' ? handler : undefined) } });
  const delivery = (messageId = 'msg_managed') => {
    const { raw, parsed, sig } = buildPayload(messageId);
    return { provider: 'managed', slug: SLUG, rawBody: raw, parsedBody: parsed, requestPath: '/v1/inbound/managed/' + SLUG, headers: { 'x-webhook-signature': `sha256=${sig}` } };
  };
  return { ...made, service, delivery };
}

describe('a provider the deployment takes the deliveries of', () => {
  it('hands a verified delivery to its handler with the ids of the row and the delivery, forwards nothing and runs no agent check', async () => {
    const handler = vi.fn(async () => undefined);
    const { service, delivery, state } = build(handler);
    const result = await service.receive(delivery());
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ decision: 'clean', forwarded: false });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(expect.objectContaining({ operatorId: PARTNER_OP, webhookId: 'iwh_test', provider: 'managed', deliveryId: expect.stringMatching(/^body:[0-9a-f]{64}$/) }));
    expect(state.forwardCalls).toEqual([]);
    expect(state.detectorCalls).toEqual([]);
  });

  it('handles one delivery once: a redelivery is answered from the receipt and the handler is not called again', async () => {
    const handler = vi.fn(async () => undefined);
    const { service, delivery } = build(handler);
    expect((await service.receive(delivery())).status).toBe(200);
    expect((await service.receive(delivery())).status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('refuses a delivery for a row that has no provider secret yet, and never calls the handler', async () => {
    const handler = vi.fn(async () => undefined);
    const { service, delivery, state } = build(handler);
    state.rows[0]!.provider_signing_secret_encrypted = null;
    const result = await service.receive(delivery());
    expect(result.status).toBe(503);
    expect(result.body).toMatchObject({ error: 'provider_signing_secret_unconfigured', forwarded: false });
    expect(handler).not.toHaveBeenCalled();
  });

  it('refuses a delivery with a wrong signature before the handler', async () => {
    const handler = vi.fn(async () => undefined);
    const { service, delivery } = build(handler);
    const result = await service.receive({ ...delivery(), headers: { 'x-webhook-signature': 'sha256=deadbeef' } });
    expect(result.status).toBe(400);
    expect(handler).not.toHaveBeenCalled();
  });

  it('answers 502 when the handler throws, so the provider delivers it again, and the retry is handled', async () => {
    let fail = true;
    const handler = vi.fn(async () => { if (fail) throw new Error('the wake could not be recorded'); });
    const { service, delivery } = build(handler);
    const first = await service.receive(delivery());
    expect(first.status).toBe(502);
    expect(first.body).toMatchObject({ error: 'delivery_failed', forwarded: false });
    fail = false;
    expect((await service.receive(delivery())).status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('answers a revoked row 404 and never calls the handler', async () => {
    const handler = vi.fn(async () => undefined);
    const { service, delivery, state } = build(handler);
    state.rows[0]!.revoked_at = new Date();
    expect((await service.receive(delivery())).status).toBe(404);
    expect(handler).not.toHaveBeenCalled();
  });

  it('is listed and read by the owner marked as managed, and a plain webhook is not', async () => {
    const { service, state } = build(async () => undefined);
    const listed = await service.list(PARTNER_OP);
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({ id: 'iwh_test', provider: 'managed', managed: true, agent_id: null, forward_url: null });
    expect(await service.get('iwh_test', PARTNER_OP)).toMatchObject({ managed: true });
    state.rows[0]!.provider = 'generic';
    expect(await service.get('iwh_test', PARTNER_OP)).toMatchObject({ managed: false });
  });

  it('ends the side of the provider first when the owner revokes a managed row, and keeps the row when it cannot be ended', async () => {
    const calls: string[] = [];
    const made = makeDeps({}, extractors);
    made.state.rows[0]!.provider = 'managed';
    made.state.rows[0]!.agent_id = null;
    made.state.rows[0]!.forward_url = null;
    let fail = true;
    const end = vi.fn(async (operatorId: string, webhookId: string) => {
      calls.push(`end ${operatorId} ${webhookId} revoked=${made.state.rows[0]!.revoked_at !== null}`);
      if (fail) throw new Error('RentAHuman did not answer');
    });
    const service = new InboundWebhookService({
      ...made.deps,
      deliveries: { get: () => async () => undefined },
      managedEnds: { get: (provider) => (provider === 'managed' ? end : undefined) },
    });
    await expect(service.revoke('iwh_test', PARTNER_OP)).rejects.toThrow('did not answer');
    expect(made.state.rows[0]!.revoked_at).toBeNull();
    fail = false;
    expect(await service.revoke('iwh_test', PARTNER_OP)).toEqual({ transitioned: true });
    expect(made.state.rows[0]!.revoked_at).not.toBeNull();
    // The provider's side was ended before the row was, both times.
    expect(calls).toEqual(['end op_partner iwh_test revoked=false', 'end op_partner iwh_test revoked=false']);
    // A webhook that is already ended does not ask the provider again.
    await service.revoke('iwh_test', PARTNER_OP);
    expect(end).toHaveBeenCalledTimes(2);
  });

  it('still refuses a webhook of another account as not found', async () => {
    const { service } = build(async () => undefined);
    await expect(service.get('iwh_test', 'op_other')).rejects.toBeInstanceOf(NotFoundError);
    await expect(service.revoke('iwh_test', 'op_other')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('makes a row with no agent, no forward address and no provider secret, then keeps the secret sealed and ends the row on request', async () => {
    const { service, deps, state } = build(async () => undefined);
    state.rows.length = 0;
    const encrypt = vi.spyOn(deps.kms, 'encryptDirect');
    const made = await service.createManaged(PARTNER_OP, 'managed');
    expect(made.webhook_url).toBe(`https://api.getstack.run/v1/inbound/managed/${made.slug}`);
    expect(state.rows[0]).toMatchObject({ id: made.id, provider: 'managed', agent_id: null, forward_url: null, provider_signing_secret_encrypted: null });

    await service.setManagedSecret(made.id, PARTNER_OP, 'whsec_provider_gave_this');
    expect(state.rows[0]!.provider_signing_secret_encrypted).not.toContain('whsec_provider_gave_this');
    expect(encrypt.mock.calls.map((call) => call[1]?.context?.purpose)).toEqual(['inbound_webhook_downstream_secret', 'inbound_provider_signing_secret']);

    await service.revokeManaged(made.id, PARTNER_OP);
    expect(state.rows[0]!.revoked_at).not.toBeNull();
  });

  it('makes no row for a provider no deployment manages, and sets no secret on an ordinary webhook', async () => {
    const { service, deps } = build(async () => undefined);
    await expect(service.createManaged(PARTNER_OP, 'generic')).rejects.toBeInstanceOf(NotFoundError);
    const ordinary = makeDeps();
    const plain = new InboundWebhookService(ordinary.deps);
    await expect(plain.setManagedSecret('iwh_test', PARTNER_OP, 'whsec_x')).rejects.toBeInstanceOf(NotFoundError);
    expect(deps).toBeDefined();
  });
});
