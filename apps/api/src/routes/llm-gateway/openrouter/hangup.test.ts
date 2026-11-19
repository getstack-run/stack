// A passed-through answer hijacks its reply, so Fastify's response hooks never describe how it ended. Over a real socket:
// a caller that stays to the last byte, and one that hangs up in the middle of a stream, both end the request once, when
// the call is really over (the charge settled), with the status the answer had. A caller that hangs up stops the call to
// OpenRouter, and the charge is what OpenRouter billed for the generation.

import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LlmGatewayService, PiiRedactor } from '@stack/vault';
import type { Services } from '../../../config/services.js';
import { registerControlSettle } from '../../../middleware/control-settle.js';
import { registerMeterRefund } from '../../../middleware/meter.js';
import { registerApprovalRelease } from '../../../middleware/request-cleanup.js';
import { createErrorHandler } from '../../../middleware/error-handler.js';
import { listen, pause } from '../../../test/http-hangup.js';

vi.mock('../../../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: { operatorId?: string; operatorTier?: string }) => {
    request.operatorId = 'op_1';
    request.operatorTier = 'pro';
  },
}));
vi.mock('../../../lib/agent-runtime.js', async (original) => ({
  ...(await original<typeof import('../../../lib/agent-runtime.js')>()),
  beginAgentRuntime: vi.fn(async () => ({ passportJti: 'pas_1', missionId: 'msn_1', fleet: null })),
}));
vi.mock('../approval-gate.js', () => ({ enforceApprovalGate: vi.fn(async () => ({ gate: { skipped: true }, approvalIdHeader: undefined })) }));
vi.mock('../scope-wall.js', () => ({ enforceProviderScope: vi.fn(async () => ({ intentServices: [], carriedSources: [] })) }));
vi.mock('../../../lib/control-decision.js', () => ({ decideControl: vi.fn(async () => undefined) }));

const { registerLlmRoutes } = await import('../../llm.js');

const CHAT_MODEL = { id: 'acme/chat-1', modalities: { input: ['text'], output: ['text'] }, context_length: 8_000, max_completion_tokens: 1_000, price: { unit: 'token', provider_cost: { input_per_million_tokens_usd_micros: 1_000_000, output_per_million_tokens_usd_micros: 1_000_000 } } };
const LISTINGS = { find: (id: string) => (id === CHAT_MODEL.id ? CHAT_MODEL : null), all: () => [CHAT_MODEL] };
const BODY = { model: 'acme/chat-1', stream: true, messages: [{ role: 'user', content: 'hello' }], max_tokens: 50 };
const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function serve(options: { upstreamStatus?: number; noId?: boolean; silent?: boolean; json?: boolean; usageEarly?: boolean } = {}) {
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerMeterRefund(app);
  registerControlSettle(app);
  registerApprovalRelease(app);

  let open!: () => void;
  const gate = new Promise<void>((resolve) => { open = resolve; });
  const calls = {
    rollback: vi.fn(async () => undefined),
    controlSettle: vi.fn(async (_outcome: { ok: boolean; handedBack: boolean }) => undefined),
  };
  const services = {
    passport: { verify: vi.fn(async () => ({ jti: 'pas_1', stk: { agent_id: 'agt_1', operator_id: 'op_1', accountability: 'standard', mission_ids: ['msn_1'], services: [], intent_services: [] } })) },
    modelAccessPolicy: {
      resolve: vi.fn(async () => ({ kind: 'account', accountId: 'acct_1' })),
      stackKey: vi.fn(() => 'sk-or-stack'),
      hold: vi.fn(async () => ({ internal: false, billingMode: 'wallet', bounded: true, denyReason: null, walletHoldId: 'whld_1', heldCents: 100, pricing: null })),
      listings: vi.fn(async () => LISTINGS),
      release: vi.fn(async () => undefined),
      ownsJob: vi.fn(async () => false),
    },
    serviceConnection: { findActiveByProvider: vi.fn() },
    authority: { evaluateRuntimeAuthority: vi.fn(async () => ({ enforced: false })), markRuntimeAuthorityDispatched: vi.fn(), completeRuntimeAuthorityUse: vi.fn() },
    actionMeter: {
      meterAction: vi.fn(async (request: { meterRollback?: unknown; controlSettle?: unknown }) => {
        request.meterRollback = calls.rollback;
        request.controlSettle = [calls.controlSettle];
      }),
    },
    accountModelBilling: { settleCall: vi.fn(async () => ({ outcome: 'charged', cost: null })), retrySettlement: vi.fn(async () => 'retrying') },
    llmUsage: { record: vi.fn(), authorizeGateway: vi.fn() },
    audit: { write: vi.fn(async () => undefined) },
    // Redaction: the owner has controls and the agent's flag is on, and these calls carry nothing to redact.
    entitlements: { controlsEnabled: vi.fn(async () => true) },
    agent: { getById: vi.fn(async () => ({ id: 'agt_1', llm_redact_pii: true })) },
    operatorPiiConfig: { resolveScanOptions: vi.fn(async () => ({})) },
    llmGateway: new LlmGatewayService(),
    piiRedactor: new PiiRedactor(),
    claimRegistry: { registerClaim: vi.fn() },
    approvalGate: { markConsumed: vi.fn() },
    fleetAdmission: {},
  } as unknown as Services;

  const encoder = new TextEncoder();
  const upstream = { aborted: false };
  const answer = (init: RequestInit) => new Response(new ReadableStream({
    async start(controller) {
      // What the network does when the call is aborted: the answer's body fails.
      init.signal?.addEventListener('abort', () => {
        upstream.aborted = true;
        try { controller.error(new DOMException('aborted', 'AbortError')); } catch { /* already closed */ }
      });
      if (options.json) {
        // An answer that is not streamed: one JSON body, once the gate opens.
        await gate;
        try {
          controller.enqueue(encoder.encode(JSON.stringify({ id: 'gen-1', choices: [], usage: { prompt_tokens: 3, completion_tokens: 2, cost: 0.001 } })));
          controller.close();
        } catch { /* the call was aborted */ }
        return;
      }
      const early = options.usageEarly ? ',"usage":{"prompt_tokens":3,"completion_tokens":2}' : '';
      controller.enqueue(encoder.encode('data: {' + (options.noId ? '' : '"id":"gen-1",') + '"choices":[{"delta":{"content":"hi"}}]' + early + '}\n\n'));
      await gate;
      try {
        controller.enqueue(encoder.encode('data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"cost":0.001}}\n\ndata: [DONE]\n\n'));
        controller.close();
      } catch { /* the call was aborted */ }
    },
  }), { status: options.upstreamStatus ?? 200, headers: { 'content-type': options.json ? 'application/json' : 'text/event-stream' } });
  // OpenRouter that has not answered yet: nothing comes back until the call is aborted, which fails it.
  const silent = (init: RequestInit) => new Promise<Response>((_resolve, reject) => {
    init.signal?.addEventListener('abort', () => {
      upstream.aborted = true;
      reject(new DOMException('aborted', 'AbortError'));
    });
  });
  const fetchImpl = vi.fn(async (_url: string, init: RequestInit): Promise<Response> => (options.silent ? silent(init) : answer(init)));
  registerLlmRoutes(app, services, { fetchImpl: fetchImpl as never });
  const client = await listen(app);
  return { ...client, calls, services, upstream, open: () => open() };
}

const URL_PATH = '/v1/llm/openrouter/chat/completions';
const POST = { method: 'POST', body: BODY, headers: { 'x-passport-token': 'passport.jwt' } } as const;

const POST_JSON = { method: 'POST', body: { ...BODY, stream: false }, headers: { 'x-passport-token': 'passport.jwt' } } as const;

describe('a passed-through stream and the end of its request', () => {
  it('settles the charge before the answer ends, then ends once', async () => {
    const t = await serve();
    const done = t.call(URL_PATH, POST);
    await pause(100);
    expect(t.services.accountModelBilling.settleCall).not.toHaveBeenCalled();
    expect(t.calls.controlSettle).not.toHaveBeenCalled();
    t.open();
    expect(await done).toBe(200);
    await pause(100);
    expect(t.services.accountModelBilling.settleCall).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledWith({ ok: true, handedBack: false });
    expect(t.calls.rollback).not.toHaveBeenCalled();
    expect(t.services.modelAccessPolicy.release).not.toHaveBeenCalled();
  });

  it('stops the call to OpenRouter when the caller hangs up, and charges what OpenRouter billed for the generation', async () => {
    const t = await serve();
    await t.hangUp(URL_PATH, 100, POST);
    await pause(200);
    // The upstream was aborted without waiting for the rest of the answer, which never came.
    expect(t.upstream.aborted).toBe(true);
    expect(t.services.accountModelBilling.settleCall).toHaveBeenCalledTimes(1);
    // The cost was not in what had been read: the charge goes to the generation's own record through the retry.
    const settled = vi.mocked(t.services.accountModelBilling.settleCall).mock.calls[0]![0];
    expect(settled).toMatchObject({ generationId: 'gen-1', status: 200, releaseIfUnresolved: true });
    expect(settled.usage).toBeNull();
    expect(t.calls.controlSettle).toHaveBeenCalledTimes(1);
    expect(t.calls.rollback).not.toHaveBeenCalled();
    t.open();
  });

  it('reads a call that is not streamed to its end when the caller hangs up, and charges its real cost', async () => {
    const t = await serve({ json: true });
    await t.hangUp(URL_PATH, 100, POST_JSON);
    // The caller is gone and OpenRouter is still working on the answer: the call is not stopped.
    expect(t.upstream.aborted).toBe(false);
    expect(t.services.accountModelBilling.settleCall).not.toHaveBeenCalled();
    t.open();
    await pause(300);
    expect(t.upstream.aborted).toBe(false);
    expect(t.services.accountModelBilling.settleCall).toHaveBeenCalledTimes(1);
    const settled = vi.mocked(t.services.accountModelBilling.settleCall).mock.calls[0]![0];
    expect(settled).toMatchObject({ generationId: 'gen-1', status: 200, usage: { provider_cost_usd: 0.001 } });
    expect(settled).not.toHaveProperty('releaseIfUnresolved');
    expect(t.services.accountModelBilling.retrySettlement).not.toHaveBeenCalled();
    expect(t.calls.controlSettle).toHaveBeenCalledTimes(1);
  });

  it('charges the tokens the answer showed, not the hold, when the caller hangs up before any generation id or cost is known', async () => {
    const t = await serve({ noId: true, usageEarly: true });
    await t.hangUp(URL_PATH, 100, POST);
    await pause(200);
    expect(t.upstream.aborted).toBe(true);
    expect(t.services.accountModelBilling.retrySettlement).toHaveBeenCalledTimes(1);
    expect(t.services.accountModelBilling.retrySettlement).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_1', agentId: 'agt_1', model: 'acme/chat-1', generationId: null,
      usage: expect.objectContaining({ prompt_tokens: 3, completion_tokens: 2 }),
    }));
    t.open();
  });

  it('releases the hold, charging nothing, when the caller hangs up before any generation id, cost or usage is known', async () => {
    const t = await serve({ noId: true });
    await t.hangUp(URL_PATH, 100, POST);
    await pause(200);
    expect(t.upstream.aborted).toBe(true);
    expect(t.services.accountModelBilling.settleCall).not.toHaveBeenCalled();
    expect(t.services.accountModelBilling.retrySettlement).toHaveBeenCalledTimes(1);
    expect(t.services.accountModelBilling.retrySettlement).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_1', agentId: 'agt_1', model: 'acme/chat-1', generationId: null, usage: null, hold: expect.objectContaining({ walletHoldId: 'whld_1' }),
    }));
    t.open();
  });

  it('aborts the call and charges nothing when the caller hangs up before OpenRouter has answered', async () => {
    const t = await serve({ silent: true });
    await t.hangUp(URL_PATH, 100, POST);
    await pause(200);
    // The call to OpenRouter was stopped while it waited for a first byte, and the hold was given back: nothing is charged.
    expect(t.upstream.aborted).toBe(true);
    expect(t.services.modelAccessPolicy.release).toHaveBeenCalledTimes(1);
    expect(t.services.accountModelBilling.settleCall).not.toHaveBeenCalled();
    expect(t.services.accountModelBilling.retrySettlement).not.toHaveBeenCalled();
  });

  it('hands the action back for an upstream refusal the caller never read', async () => {
    const t = await serve({ upstreamStatus: 429 });
    await t.hangUp(URL_PATH, 100, POST);
    t.open();
    await pause(200);
    expect(t.calls.rollback).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledWith({ ok: false, handedBack: true });
  });
});
