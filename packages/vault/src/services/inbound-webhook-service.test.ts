import { describe, it, expect, vi } from 'vitest';
import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { generateWebhookSecret, InvalidRequestError, signStandardWebhook, UnsafeUrlError, verifyStandardWebhook } from '@stack/shared';
import { InboundWebhookService } from './inbound-webhook-service.js';
import {
  AGENT_ID,
  DOWNSTREAM_SECRET,
  PARTNER_OP,
  SECRET,
  SLUG,
  buildPayload,
  hmacBody,
  makeDeps,
  receiveInput,
} from './inbound-webhook-service.test-support.js';

/**
 * InboundWebhookService invariants — hardening.
 *
 *   I1: create — returns plaintext secret + KMS-encrypts at rest
 *   I2: HMAC verify failure → 400, not 401 (slug existence not leaked)
 *   I3: detector block → 200 decision=blocked + counters bumped + no forward
 *   I4: clean → forwards with X-Stack-* headers + Standard Webhooks signature
 *   I5: idempotency dedupe short-circuits before detector runs
 *   I6: revoke-mid-flight returns 410 + does NOT forward
 *   I7: KMS decrypt failure → 404 (timing leak documented)
 *   I8: missing slug → 404
 *   I9: metering — one recorded action per accepted delivery, none for an
 *       unsigned or deduplicated one, and a refused delivery releases its
 *       dedupe key so the provider's retry is not answered 'already seen'
 */

describe('inbound delivery recovery', () => {
  it('fails closed for legacy generic rows until distinct keys are configured', async () => {
    const { deps, state } = makeDeps();
    state.rows[0]!.provider_signing_secret_encrypted = null;
    const decrypt = vi.spyOn(deps.kms, 'decryptDirect');

    const result = await new InboundWebhookService(deps).receive(receiveInput());

    expect(result).toEqual({ status: 503, body: {
      error: 'signing_key_separation_required',
      forwarded: false,
    } });
    expect(decrypt).not.toHaveBeenCalled();
    expect(state.meterCalls).toHaveLength(0);
    expect(state.forwardCalls).toHaveLength(0);
  });

  it('cannot forge an inbound request with the downstream verification key', async () => {
    const { deps, state } = makeDeps();
    const input = receiveInput('msg_directional_forgery');
    input.headers['x-webhook-signature'] = `sha256=${hmacBody(input.rawBody.toString(), DOWNSTREAM_SECRET)}`;

    const result = await new InboundWebhookService(deps).receive(input);

    expect(result.status).toBe(400);
    expect(state.meterCalls).toHaveLength(0);
    expect(state.forwardCalls).toHaveLength(0);
  });

  it('refuses a row whose decrypted incoming and downstream keys are equal', async () => {
    const { deps, state } = makeDeps();
    vi.spyOn(deps.kms, 'decryptDirect').mockResolvedValue(Buffer.from(SECRET));

    const result = await new InboundWebhookService(deps).receive(receiveInput('msg_equal_keys'));

    expect(result).toEqual({ status: 503, body: {
      error: 'signing_key_separation_required',
      forwarded: false,
    } });
    expect(state.meterCalls).toHaveLength(0);
    expect(state.forwardCalls).toHaveLength(0);
  });

  it('does not charge or scan deliveries for a suspended agent', async () => {
    const { deps, state } = makeDeps();
    vi.spyOn(deps.agentRepo, 'findById').mockResolvedValue({ id: AGENT_ID, operator_id: PARTNER_OP,
      status: 'suspended', passport_blocked: true } as never);
    expect((await new InboundWebhookService(deps).receive(receiveInput())).status).toBe(410);
    expect(state.meterCalls).toHaveLength(0);
    expect(state.detectorCalls).toHaveLength(0);
    expect(state.forwardCalls).toHaveLength(0);
  });
  it('uses persisted generic header, algorithm, content and delivery ID settings', async () => {
    const { deps, state } = makeDeps();
    state.rows[0]!.generic_config = { signature_header: 'X-Custom-Signature', signature_algorithm: 'hmac-sha1',
      dedupe_key_path: 'data.event_id', content_paths: ['data.text'] };
    const parsedBody = { data: { event_id: 'configured-event', text: 'selected content' }, ignored: 'not selected' };
    const rawBody = Buffer.from(JSON.stringify(parsedBody));
    const input = { ...receiveInput(), parsedBody, rawBody, headers: {
      'x-custom-signature': createHmac('sha1', SECRET).update(rawBody).digest('hex'),
    } };
    const result = await new InboundWebhookService(deps).receive(input);
    expect(result.body.message_id).toBe('configured-event');
    expect(result.body.forwarded).toBe(true);
    expect(state.detectorCalls[0]!.content).toBe('data.text: selected content');
  });

  it('retains one metering identity across a crash before the receipt marker', async () => {
    const { deps, state } = makeDeps();
    const identities: string[] = [];
    const dates: number[] = [];
    deps.meterAction = async (_operator, eventKey, date) => { identities.push(eventKey); dates.push(date.getTime()); };
    vi.spyOn(deps.receiptsRepo, 'markMetered').mockRejectedValueOnce(new Error('fixture database interruption'));
    const service = new InboundWebhookService(deps);
    expect((await service.receive(receiveInput())).status).toBe(500);
    expect((await service.receive(receiveInput())).status).toBe(200);
    expect(identities).toHaveLength(2);
    expect(new Set(identities).size).toBe(1);
    expect(new Set(dates).size).toBe(1);
    expect(state.forwardCalls).toHaveLength(1);
  });

  it('never forwards after losing its receipt lease', async () => {
    const { deps, state } = makeDeps();
    vi.spyOn(deps.receiptsRepo, 'renew').mockResolvedValue(false);
    const result = await new InboundWebhookService(deps).receive(receiveInput());
    expect(result.status).toBe(503);
    expect(state.forwardCalls).toHaveLength(0);
    expect(state.receipts.size).toBe(0);
  });

  it('blocks oversized scan content without forwarding unscanned tails', async () => {
    const { deps, state } = makeDeps();
    const parsedBody = { message_id: 'large', text: 'x'.repeat(70_000) };
    const rawBody = Buffer.from(JSON.stringify(parsedBody));
    const result = await new InboundWebhookService(deps).receive({ ...receiveInput(), parsedBody, rawBody,
      headers: { 'x-webhook-signature': hmacBody(rawBody.toString(), SECRET) } });
    expect(result.body).toMatchObject({ decision: 'blocked', reason: 'scan_content_too_large', forwarded: false });
    expect(state.forwardCalls).toHaveLength(0);
    expect(state.detectorCalls).toHaveLength(0);
  });

  it('knows only the generic provider until a deployment registers its own', async () => {
    const { deps, state } = makeDeps();
    const engineOnly = new InboundWebhookService({ ...deps, extractors: undefined });
    state.rows[0]!.provider = 'agentmail';
    expect((await engineOnly.receive({ ...receiveInput(), provider: 'agentmail' })).status).toBe(404);
    await expect(engineOnly.create(PARTNER_OP, { provider: 'agentmail', agent_id: AGENT_ID })).rejects.toThrow(/inbound_webhook_provider/);
  });

  it('refuses a forward address that is not public as a 400 that names the field, not an unhandled error', async () => {
    const { deps } = makeDeps();
    const guarded = new InboundWebhookService({ ...deps, urlGuard: () => { throw new UnsafeUrlError('Destination resolves to a non-public address'); } });
    const refused = await guarded.create(PARTNER_OP, { provider: 'generic', agent_id: AGENT_ID, forward_url: 'http://127.0.0.1/forward' }).catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(InvalidRequestError);
    expect(refused).toMatchObject({ statusCode: 400, code: 'INVALID_REQUEST', message: 'forward_url must be a public address' });
  });

  it('rotates both generic trust directions without exposing supplied values in reads', async () => {
    const { deps, state } = makeDeps();
    const service = new InboundWebhookService(deps);
    const secret = 'synthetic-human-selected-generic-key-32bytes';
    const downstreamSecret = 'synthetic-distinct-downstream-key-32bytes';
    await expect(service.setProviderSigningSecret('iwh_test', PARTNER_OP, 'too-short')).rejects.toThrow();
    await expect(service.setProviderSigningSecret('iwh_test', PARTNER_OP, ' '.repeat(32))).rejects.toThrow();
    await expect(service.setProviderSigningSecret('iwh_test', PARTNER_OP, 'x'.repeat(257))).rejects.toThrow();
    const encrypt = vi.spyOn(deps.kms, 'encryptDirect').mockResolvedValue(Buffer.from('synthetic-new-ciphertext'));
    await expect(service.setProviderSigningSecret('iwh_test', PARTNER_OP, secret, secret))
      .rejects.toThrow('must be different');
    expect(await service.setProviderSigningSecret('iwh_test', PARTNER_OP, secret, downstreamSecret)).toEqual({ configured: true });
    expect(encrypt.mock.calls[0]![1]).toMatchObject({ operatorId: PARTNER_OP, context: {
      operator_id: PARTNER_OP, webhook_id: 'iwh_test', purpose: 'inbound_provider_signing_secret',
    } });
    expect(encrypt.mock.calls[1]![1]).toMatchObject({ operatorId: PARTNER_OP, context: {
      operator_id: PARTNER_OP, webhook_id: 'iwh_test', purpose: 'inbound_webhook_downstream_secret',
    } });
    expect(state.rows[0]!.provider_signing_secret_encrypted).toBe(Buffer.from('synthetic-new-ciphertext').toString('base64'));
    vi.spyOn(deps.kms, 'decryptDirect').mockImplementation(async (_buffer, options) => Buffer.from(
      options?.expectedContext?.purpose === 'inbound_provider_signing_secret' ? secret : downstreamSecret));
    expect((await service.receive(receiveInput())).status).toBe(400);
    const input = receiveInput();
    input.headers['x-webhook-signature'] = hmacBody(input.rawBody.toString(), secret);
    expect((await service.receive(input)).body.forwarded).toBe(true);
    const forwarded = state.forwardCalls[0]!;
    expect(verifyStandardWebhook({ headers: forwarded.headers, body: forwarded.body, secrets: [downstreamSecret], toleranceSeconds: 300 }).ok).toBe(true);
    expect(JSON.stringify(await service.get('iwh_test', PARTNER_OP))).not.toContain(secret);
  });

  it('returns a generated generic downstream replacement exactly once', async () => {
    const { deps } = makeDeps();
    const service = new InboundWebhookService(deps);
    const incomingSecret = 'synthetic-incoming-key-for-one-time-response';
    vi.spyOn(deps.kms, 'encryptDirect').mockImplementation(async (value) => Buffer.from(`wrapped:${value.length}`));

    const result = await service.setProviderSigningSecret('iwh_test', PARTNER_OP, incomingSecret);

    expect(result.configured).toBe(true);
    expect(result.webhook_secret).toBeTruthy();
    expect(result.webhook_secret).not.toBe(incomingSecret);
    expect(JSON.stringify(await service.get('iwh_test', PARTNER_OP))).not.toContain(result.webhook_secret!);
  });

  it('retries a failed scan without dropping the event or charging again', async () => {
    const { deps, state } = makeDeps();
    vi.spyOn(deps.detector, 'scanInput').mockRejectedValueOnce(new Error('fixture scan unavailable'));
    const service = new InboundWebhookService(deps);
    expect((await service.receive(receiveInput())).status).toBe(500);
    const retry = await service.receive(receiveInput());
    expect(retry.body.decision).toBe('clean');
    expect(retry.body.forwarded).toBe(true);
    expect(state.meterCalls).toHaveLength(1);
  });

  it('does not acknowledge an event while another request is still processing it', async () => {
    const { deps } = makeDeps();
    let started!: () => void;
    const entered = new Promise<void>((resolve) => { started = resolve; });
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    const scan = deps.detector.scanInput.bind(deps.detector);
    vi.spyOn(deps.detector, 'scanInput').mockImplementationOnce(async (input) => { started(); await pending; return scan(input); });
    const service = new InboundWebhookService(deps);
    const first = service.receive(receiveInput());
    await entered;
    try { expect((await service.receive(receiveInput())).status).toBe(503); }
    finally { finish(); await first; }
  });

  it('does not call a downstream rejection successful, and retries use one stable key', async () => {
    const { deps, state } = makeDeps({ forwardStatus: 503 });
    const service = new InboundWebhookService(deps);
    const first = await service.receive(receiveInput());
    expect(first.status).toBe(502);
    expect(first.body.forwarded).toBe(false);
    state.forwardStatus = 200;
    expect((await service.receive(receiveInput())).body.forwarded).toBe(true);
    expect(state.forwardCalls[0]!.headers['idempotency-key']).toBeTruthy();
    expect(state.forwardCalls[1]!.headers['idempotency-key']).toBe(state.forwardCalls[0]!.headers['idempotency-key']);
    expect(state.meterCalls).toHaveLength(1);
  });

  it('persists the accepted generic extractor configuration', async () => {
    const { deps, state } = makeDeps({ rows: [] });
    const config = { signature_header: 'X-Custom-Signature', signature_algorithm: 'hmac-sha256' as const,
      dedupe_key_path: 'data.event_id', content_paths: ['data.text'] };
    await new InboundWebhookService(deps).create(PARTNER_OP, { provider: 'generic', agent_id: AGENT_ID, generic_config: config });
    expect(state.rows[0]).toMatchObject({ generic_config: config });
  });

  it('refuses reuse of one event ID for different signed content', async () => {
    const { deps } = makeDeps();
    const service = new InboundWebhookService(deps);
    await service.receive(receiveInput());
    const changed = receiveInput();
    changed.parsedBody = { message_id: 'msg_retry', text: 'different fixture body' };
    changed.rawBody = Buffer.from(JSON.stringify(changed.parsedBody));
    changed.headers['x-webhook-signature'] = `sha256=${hmacBody(changed.rawBody.toString(), SECRET)}`;
    expect((await service.receive(changed)).status).toBe(409);
  });
});

describe('InboundWebhookService hardening', () => {
  it('I1 create returns distinct one-time secrets + KMS-encrypts both at rest', async () => {
    const { deps, state } = makeDeps({ rows: [] });
    const svc = new InboundWebhookService(deps);
    const encrypt = vi.spyOn(deps.kms, 'encryptDirect');
    const result = await svc.create(PARTNER_OP, {
      provider: 'generic',
      agent_id: AGENT_ID,
      forward_url: 'https://downstream.example.com/inbound',
    });
    expect(result.webhook_secret).toBeTruthy();
    expect(result.incoming_signing_secret).toBeTruthy();
    expect(result.incoming_signing_secret).not.toBe(result.webhook_secret);
    expect(result.webhook_secret.length).toBeGreaterThanOrEqual(32);
    expect(result.webhook_url).toMatch(/^https:\/\/api\.getstack\.run\/v1\/inbound\/generic\//);
    expect(state.rows).toHaveLength(1);
    // Plaintext secret NEVER stored on the row
    expect(state.rows[0]!.webhook_secret_encrypted).not.toContain(result.webhook_secret);
    expect(state.rows[0]!.provider_signing_secret_encrypted).not.toContain(result.incoming_signing_secret!);
    expect(encrypt.mock.calls.map((call) => call[1]?.context?.purpose)).toEqual([
      'inbound_webhook_downstream_secret',
      'inbound_provider_signing_secret',
    ]);
  });

  it('I2 HMAC verify failure → 400 (not 401)', async () => {
    const { deps } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed } = buildPayload();
    const result = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': 'sha256=deadbeef' }, // wrong sig
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toMatch(/signature/);
  });

  it('I3 detector critical → blocked + no forward + counters bumped', async () => {
    const { deps, state } = makeDeps({ detectorVerdict: 'critical' });
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload();
    const result = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });
    expect(result.status).toBe(200);
    expect(result.body.decision).toBe('blocked');
    expect(result.body.forwarded).toBe(false);
    expect(state.forwardCalls).toHaveLength(0);
    expect(state.rows[0]!.total_blocked).toBe(1);
    expect(state.rows[0]!.total_calls).toBe(1);
    expect(state.detectorCalls).toHaveLength(1);
  });

  it('I4 clean → forwards with the Standard Webhooks signature + headers', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload();
    const result = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });
    expect(result.status).toBe(200);
    expect(result.body.decision).toBe('clean');
    expect(result.body.forwarded).toBe(true);
    expect(state.forwardCalls).toHaveLength(1);
    const fwd = state.forwardCalls[0]!;
    expect(fwd.url).toBe('https://downstream.example.com/inbound');
    expect(fwd.headers['x-stack-scan-verdict']).toBe('clean');
    expect(fwd.headers['x-stack-inbound-webhook-id']).toBe('iwh_test');
    expect(fwd.headers['x-stack-provider']).toBe('generic');
    expect(fwd.headers['webhook-signature']).toMatch(/^v1,/);
    // The outbound signature uses a distinct key from inbound authentication, and no other signature header is sent.
    expect(verifyStandardWebhook({ headers: fwd.headers, body: fwd.body, secrets: [DOWNSTREAM_SECRET], toleranceSeconds: 300 }).ok).toBe(true);
    expect(fwd.headers['x-stack-signature']).toBeUndefined();
  });

  it('I4b forwards signed as Standard Webhooks, the event key as the message id, and no other signature header', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const input = receiveInput('msg_signed');
    expect((await svc.receive(input)).body.forwarded).toBe(true);
    const fwd = state.forwardCalls[0]!;
    const headers = fwd.headers;
    expect(headers['webhook-id']).toBe(headers['x-stack-event-id']);
    expect(headers['webhook-id']).toBe(headers['idempotency-key']);
    expect(headers['webhook-id']).toMatch(/^iwh_[a-f0-9]{64}$/);
    const check = (over: Partial<Parameters<typeof verifyStandardWebhook>[0]> = {}) =>
      verifyStandardWebhook({ headers, body: fwd.body, secrets: [DOWNSTREAM_SECRET], toleranceSeconds: 300, ...over });
    expect(check()).toMatchObject({ ok: true, id: headers['webhook-id'] });
    // A captured forward replayed after the tolerance, a changed body and the inbound key are all refused.
    const issuedAt = Number(headers['webhook-timestamp']);
    expect(check({ now: issuedAt + 301 })).toEqual({ ok: false, reason: 'stale' });
    expect(check({ body: fwd.body.replace('Quarterly', 'Annual') })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(check({ secrets: [SECRET] })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(headers['x-stack-signature']).toBeUndefined();
  });

  it('I4c repeats the same message id on a redelivery of one event, with a fresh timestamp', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    state.forwardStatus = 500;
    expect((await svc.receive(receiveInput('msg_retry_id'))).status).toBe(502);
    state.forwardStatus = 200;
    expect((await svc.receive(receiveInput('msg_retry_id'))).status).toBe(200);
    expect(state.forwardCalls).toHaveLength(2);
    expect(state.forwardCalls[1]!.headers['webhook-id']).toBe(state.forwardCalls[0]!.headers['webhook-id']);
  });

  describe('rotating the downstream secret', () => {
    function withSealedSecrets(deps: ReturnType<typeof makeDeps>['deps']) {
      // A reversible stand-in: the ciphertext is the plaintext behind a marker.
      vi.spyOn(deps.kms, 'encryptDirect').mockImplementation(async (plain) => Buffer.from(`enc:${plain.toString('utf8')}`));
      vi.spyOn(deps.kms, 'decryptDirect').mockImplementation(async (blob, options) => {
        const text = blob.toString('utf8');
        if (text.startsWith('enc:')) return Buffer.from(text.slice(4));
        return Buffer.from(options?.expectedContext?.purpose === 'inbound_provider_signing_secret' ? SECRET : DOWNSTREAM_SECRET);
      });
    }

    it('returns the new secret once, and signs with both for 24 hours, then with the new one only', async () => {
      const { deps, state } = makeDeps();
      withSealedSecrets(deps);
      const svc = new InboundWebhookService(deps);
      const rotation = await svc.rotateDownstreamSecret('iwh_test', PARTNER_OP);
      expect(rotation.webhook_secret).toMatch(/^whsec_/);
      expect(Date.parse(rotation.previous_valid_until) - Date.now()).toBeGreaterThan(23 * 3_600_000);
      expect(JSON.stringify(await svc.get('iwh_test', PARTNER_OP))).not.toContain(rotation.webhook_secret);

      expect((await svc.receive(receiveInput('msg_rot_1'))).body.forwarded).toBe(true);
      const during = state.forwardCalls[0]!;
      expect(during.headers['webhook-signature']!.split(' ')).toHaveLength(2);
      for (const secret of [rotation.webhook_secret, DOWNSTREAM_SECRET]) {
        expect(verifyStandardWebhook({ headers: during.headers, body: during.body, secrets: [secret], toleranceSeconds: 300 }).ok).toBe(true);
      }

      state.rows[0]!.webhook_secret_rotated_at = new Date(Date.now() - 25 * 3_600_000);
      expect((await svc.receive(receiveInput('msg_rot_2'))).body.forwarded).toBe(true);
      const after = state.forwardCalls[1]!;
      expect(after.headers['webhook-signature']!.split(' ')).toHaveLength(1);
      expect(verifyStandardWebhook({ headers: after.headers, body: after.body, secrets: [DOWNSTREAM_SECRET], toleranceSeconds: 300 }).ok).toBe(false);
      expect(verifyStandardWebhook({ headers: after.headers, body: after.body, secrets: [rotation.webhook_secret], toleranceSeconds: 300 }).ok).toBe(true);
    });

    it('does not stop a delivery when the previous secret cannot be read', async () => {
      const { deps, state } = makeDeps();
      withSealedSecrets(deps);
      const svc = new InboundWebhookService(deps);
      await svc.rotateDownstreamSecret('iwh_test', PARTNER_OP);
      state.rows[0]!.webhook_secret_previous_encrypted = Buffer.from('enc:x').toString('base64');
      vi.spyOn(deps.kms, 'decryptDirect').mockImplementation(async (blob, options) => {
        const text = blob.toString('utf8');
        if (text === 'enc:x') throw new Error('unreadable');
        if (text.startsWith('enc:')) return Buffer.from(text.slice(4));
        return Buffer.from(options?.expectedContext?.purpose === 'inbound_provider_signing_secret' ? SECRET : DOWNSTREAM_SECRET);
      });
      vi.spyOn(console, 'error').mockImplementation(() => {});
      expect((await svc.receive(receiveInput('msg_rot_3'))).body.forwarded).toBe(true);
      expect(state.forwardCalls[0]!.headers['webhook-signature']!.split(' ')).toHaveLength(1);
    });

    it('is refused for another owner, a revoked webhook and an unknown one', async () => {
      const { deps } = makeDeps();
      withSealedSecrets(deps);
      const svc = new InboundWebhookService(deps);
      await expect(svc.rotateDownstreamSecret('iwh_test', 'op_stranger')).rejects.toThrow(/inbound_webhook/);
      await expect(svc.rotateDownstreamSecret('iwh_nope', PARTNER_OP)).rejects.toThrow(/inbound_webhook/);
      await svc.revoke('iwh_test', PARTNER_OP);
      await expect(svc.rotateDownstreamSecret('iwh_test', PARTNER_OP)).rejects.toThrow(/inbound_webhook/);
    });
  });

  it('I4d new webhooks are created with a whsec_ downstream secret that verifies a forward', async () => {
    const secret = generateWebhookSecret();
    const headers = signStandardWebhook({ id: 'iwh_x', body: '{}', secrets: [secret], timestamp: 1_790_000_000 });
    expect(verifyStandardWebhook({ headers, body: '{}', secrets: [secret], toleranceSeconds: 300, now: 1_790_000_000 }).ok).toBe(true);
  });

  it('I5 idempotency dedupe → second receive short-circuits without invoking detector', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload('msg_dedupe');

    // First call: should pass through + invoke detector
    const first = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });
    expect(first.body.decision).toBe('clean');
    expect(state.detectorCalls).toHaveLength(1);

    // Second call same message_id: dedupe short-circuit
    const second = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });
    expect(second.status).toBe(200);
    expect(second.body.decision).toBe('deduplicated');
    expect(second.body.forwarded).toBe(false);
    expect(state.detectorCalls).toHaveLength(1); // detector NOT re-invoked
  });

  it('I6 revoke-mid-flight → 410 Gone + does NOT forward', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload();

    // Hack: revoke the row BEFORE detector returns by overriding the
    // detector. The service re-reads revoked_at after detector — so we
    // mutate the row mid-flight.
    const detectorOrig = deps.detector.scanInput.bind(deps.detector);
    deps.detector.scanInput = async (args) => {
      // Mid-detector: simulate concurrent revoke
      state.rows[0]!.revoked_at = new Date();
      return detectorOrig(args);
    };

    const result = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });
    expect(result.status).toBe(410);
    expect(result.body.decision).toBe('revoked_during_flight');
    expect(result.body.forwarded).toBe(false);
    expect(state.forwardCalls).toHaveLength(0);
  });

  it('I7 KMS decrypt failure → 404 (fail-closed, no leak of slug existence)', async () => {
    const { deps } = makeDeps({ kmsShouldFailDecrypt: true });
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload();
    const result = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });
    expect(result.status).toBe(404);
  });

  it('I8 missing slug → 404', async () => {
    const { deps } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload();
    const result = await svc.receive({
      provider: 'generic',
      slug: 's_does_not_exist',
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/s_does_not_exist',
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });
    expect(result.status).toBe(404);
  });

  it('I9 metering — an accepted delivery counts exactly one recorded action', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload('msg_metered');

    const result = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': `sha256=${sig}` },
    });

    expect(result.body.decision).toBe('clean');
    expect(state.meterCalls).toEqual([PARTNER_OP]);
  });

  it('I9 metering — an unsigned delivery cannot spend an allowance', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed } = buildPayload('msg_forged');

    const result = await svc.receive({
      provider: 'generic',
      slug: SLUG,
      rawBody: raw,
      parsedBody: parsed,
      requestPath: '/v1/inbound/generic/' + SLUG,
      headers: { 'x-webhook-signature': 'sha256=deadbeef' },
    });

    expect(result.status).toBe(400);
    expect(state.meterCalls).toEqual([]);
  });

  it('I9 metering — a provider retry of a handled message is not charged twice', async () => {
    const { deps, state } = makeDeps();
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload('msg_at_least_once');
    const call = () =>
      svc.receive({
        provider: 'generic',
        slug: SLUG,
        rawBody: raw,
        parsedBody: parsed,
        requestPath: '/v1/inbound/generic/' + SLUG,
        headers: { 'x-webhook-signature': `sha256=${sig}` },
      });

    await call();
    const second = await call();

    expect(second.body.decision).toBe('deduplicated');
    expect(state.meterCalls).toEqual([PARTNER_OP]);
  });

  it('I9 metering — a refused delivery is retryable, not silently deduplicated', async () => {
    // The failure this guards: record the dedupe key, then refuse on payment.
    // The provider retries, we answer 'already seen', and the event is gone
    // for good — lost data as a side effect of a billing decision.
    const { deps, state } = makeDeps({ meterShouldRefuse: true });
    const svc = new InboundWebhookService(deps);
    const { raw, parsed, sig } = buildPayload('msg_refused');
    const call = () =>
      svc.receive({
        provider: 'generic',
        slug: SLUG,
        rawBody: raw,
        parsedBody: parsed,
        requestPath: '/v1/inbound/generic/' + SLUG,
        headers: { 'x-webhook-signature': `sha256=${sig}` },
      });

    await expect(call()).rejects.toMatchObject({ statusCode: 402 });
    expect(state.detectorCalls, 'refused before the work is done').toHaveLength(0);
    expect(state.receipts.size, 'dedupe key released').toBe(0);

    // Allowance restored (top-up); the provider's retry now lands properly.
    state.meterShouldRefuse = false;
    const retry = await call();
    expect(retry.body.decision).toBe('clean');
    expect(state.detectorCalls).toHaveLength(1);
  });
});
