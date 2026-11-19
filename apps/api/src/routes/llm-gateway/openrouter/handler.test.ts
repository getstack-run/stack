// The OpenRouter passthrough, over a real socket: every endpoint and method goes to OpenRouter's one host with the body
// and the answer as they are, an agent account's call is held and charged at the cost OpenRouter reports, and the gates
// run in their order. OpenRouter is a fake `fetch`; nothing leaves the process.

import http from 'node:http';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  NotFoundError,
  OPENROUTER_ENDPOINTS,
  OPENROUTER_GATEWAY_PREFIX,
  OPENROUTER_REQUEST_MAX_BYTES,
  UNPRICED_CALL_HOLD_USD_MICROS,
  openRouterWorstCase,
  type WorstCaseListing,
} from '@stack/shared';
import { LlmGatewayService, PiiRedactor } from '@stack/vault';
import type { Services } from '../../../config/services.js';
import { createErrorHandler } from '../../../middleware/error-handler.js';

const order = vi.hoisted(() => [] as string[]);
const controls = vi.hoisted(() => ({ on: true, agentFlag: true }));

vi.mock('../../../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: { operatorId?: string; operatorTier?: string }) => {
    request.operatorId = 'op_1';
    request.operatorTier = 'pro';
  },
}));
vi.mock('../../../lib/agent-runtime.js', async (original) => ({
  ...(await original<typeof import('../../../lib/agent-runtime.js')>()),
  beginAgentRuntime: vi.fn(async () => { order.push('mission'); return { passportJti: 'pas_1', missionId: 'msn_1', fleet: null }; }),
}));
vi.mock('../approval-gate.js', () => ({
  enforceApprovalGate: vi.fn(async () => { order.push('approval'); return { gate: { skipped: true }, approvalIdHeader: undefined }; }),
}));
vi.mock('../scope-wall.js', () => ({
  enforceProviderScope: vi.fn(async () => { order.push('wall'); return { intentServices: [], carriedSources: [] }; }),
}));
vi.mock('../../../lib/control-decision.js', () => ({
  decideControl: vi.fn(async () => { order.push('decider'); }),
}));

const { registerLlmRoutes } = await import('../../llm.js');
const { decideControl } = await import('../../../lib/control-decision.js');

const JSON_HEADERS = { 'content-type': 'application/json' };
const CHAT = { model: 'acme/chat-1', messages: [{ role: 'user', content: 'hello' }], max_tokens: 50 };
// What the catalogue lists: a chat model priced per million tokens, a voice priced by the character, a video priced by the second.
const LISTINGS: WorstCaseListing[] = [
  { id: 'acme/chat-1', modalities: { input: ['text'], output: ['text'] }, context_length: 200_000, max_completion_tokens: 8_000, price: { unit: 'token', provider_cost: { input_per_million_tokens_usd_micros: 3_000_000, output_per_million_tokens_usd_micros: 15_000_000 } } },
  { id: 'acme/long-1', modalities: { input: ['text'], output: ['text'] }, context_length: 1_000_000, max_completion_tokens: 128_000, price: { unit: 'token', provider_cost: { input_per_million_tokens_usd_micros: 1_000_000, output_per_million_tokens_usd_micros: 10_000_000 } } },
  { id: 'acme/x', modalities: { input: ['text'], output: ['text'] }, context_length: 8_000, max_completion_tokens: 1_000, price: { unit: 'token', provider_cost: { input_per_million_tokens_usd_micros: 1_000_000, output_per_million_tokens_usd_micros: 1_000_000 } } },
  { id: 'acme/voice-1', modalities: { input: ['text'], output: ['speech'] }, price: { unit: 'lines', provider_cost: { lines: [{ item: 'prompt', per: 'character', per_count: 1, cost_usd_micros: 15 }] } } },
  { id: 'acme/video-1', modalities: { input: ['text'], output: ['video'] }, price: { unit: 'lines', provider_cost: { lines: [{ item: 'cents_per_video_output_second_720p', per: 'second', per_count: 1, cost_usd_micros: 10_000 }] } } },
  { id: 'acme/audio-1', modalities: { input: ['text'], output: ['speech'] }, price: { unit: 'lines', provider_cost: { lines: [{ item: 'completion', per: 'audio_unit', per_count: 1, cost_usd_micros: 2_500 }] } } },
];
const byId = new Map(LISTINGS.map((l) => [l.id, l]));
const CATALOGUE = { find: (id: string) => byId.get(id) ?? null, all: () => LISTINGS };
/** The hold the gateway must take for a body: the same worst case, worked out from the same listings. */
function worstCents(body: unknown): number {
  const raw = JSON.stringify(body);
  const worst = openRouterWorstCase({ body: JSON.parse(raw) as Record<string, unknown>, bodyBytes: Buffer.byteLength(raw), listings: CATALOGUE });
  return worst.cents;
}

const HOLD_AUTH = { internal: false, billingMode: 'wallet', bounded: true, denyReason: null, walletHoldId: 'whld_1', heldCents: 100, pricing: null };

interface Setup {
  app: FastifyInstance;
  base: string;
  services: ReturnType<typeof makeServices>;
  fetchImpl: ReturnType<typeof vi.fn>;
}

function makeServices(kind: 'account' | 'customer', over: Record<string, unknown> = {}) {
  const services = {
    passport: {
      verify: vi.fn(async () => ({
        jti: 'pas_1',
        stk: { agent_id: 'agt_1', operator_id: 'op_1', accountability: 'standard', mission_ids: ['msn_1'], services: [{ service_name: 'openrouter', service_id: 'svc_or', connection_id: 'conn_customer', scopes: [] }], intent_services: [] },
      })),
    },
    modelAccessPolicy: {
      resolve: vi.fn(async () => (kind === 'account' ? { kind: 'account', accountId: 'acct_1' } : { kind: 'customer' })),
      stackKey: vi.fn(() => 'sk-or-stack'),
      hold: vi.fn(async (input: { heldCents: number }) => ({ ...HOLD_AUTH, heldCents: input.heldCents })),
      listings: vi.fn(async () => CATALOGUE),
      release: vi.fn(async () => undefined),
      ownsJob: vi.fn(async (_op: string, _account: string, jobId: string) => jobId === 'gen-vid-mine'),
    },
    serviceConnection: {
      resolveProxyConnection: vi.fn(async () => ({ connection_id: 'conn_customer', credential_version: 1 })),
      getConnectionScoped: vi.fn(),
      retrieveCredential: vi.fn(async () => ({ credential: 'sk-or-customer' })),
      retrieveCredentialByConnectionId: vi.fn(async () => ({ credential: 'sk-or-customer' })),
    },
    authority: {
      evaluateRuntimeAuthority: vi.fn(async () => { order.push('authority'); return { enforced: false }; }),
      markRuntimeAuthorityDispatched: vi.fn(),
      completeRuntimeAuthorityUse: vi.fn(),
    },
    actionMeter: { meterAction: vi.fn(async () => { order.push('meter'); }) },
    accountModelBilling: { settleCall: vi.fn(async () => ({ outcome: 'charged', cost: null })), retrySettlement: vi.fn(async () => 'retrying') },
    llmUsage: {
      authorizeGateway: vi.fn(async () => ({ bounded: false, denyReason: null, heldCents: 0, pricing: null, internal: false, feeFree: true, walletHoldId: null })),
      record: vi.fn(async () => ({ llmUsageId: 'usg_1', walletDebited: false, cost: null })),
    },
    audit: { write: vi.fn(async () => undefined) },
    // Redaction: with the owner's controls on it reads the agent's flag and the account's switch.
    entitlements: { controlsEnabled: vi.fn(async () => controls.on) },
    agent: { getById: vi.fn(async () => ({ id: 'agt_1', llm_redact_pii: controls.agentFlag })) },
    operatorPiiConfig: { resolveScanOptions: vi.fn(async () => ({})) },
    llmGateway: new LlmGatewayService(),
    piiRedactor: new PiiRedactor(),
    claimRegistry: { registerClaim: vi.fn() },
    approvalGate: { markConsumed: vi.fn() },
    fleetAdmission: { reserve: vi.fn(), dispatch: vi.fn(), finish: vi.fn() },
    ...over,
  };
  return services;
}

const apps: FastifyInstance[] = [];
async function serve(kind: 'account' | 'customer', answer: (url: string, init: RequestInit) => Response | Promise<Response>, over: Record<string, unknown> = {}): Promise<Setup> {
  const services = makeServices(kind, over);
  const fetchImpl = vi.fn(async (url: string, init: RequestInit) => answer(url, init));
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerLlmRoutes(app, services as unknown as Services, { fetchImpl: fetchImpl as never });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  return { app, base, services, fetchImpl };
}

function call(setup: Setup, path: string, init: RequestInit = {}) {
  return fetch(`${setup.base}${OPENROUTER_GATEWAY_PREFIX}${path}`, {
    ...init,
    headers: { 'x-passport-token': 'passport.jwt', authorization: 'Bearer sk_live_caller', ...(init.headers as Record<string, string> | undefined) },
  });
}

const post = (body: unknown, headers: Record<string, string> = {}): RequestInit => ({
  method: 'POST',
  headers: { ...JSON_HEADERS, ...headers },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

beforeEach(() => {
  order.length = 0;
  vi.mocked(decideControl).mockClear();
});
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe('an agent account\'s call on STACK\'s key', () => {
  it('holds the default amount, sends the body and the key as they are, passes the answer on and charges what OpenRouter reported', async () => {
    const upstreamBody = JSON.stringify({ id: 'gen-abc', choices: [{ message: { content: 'hi' } }], usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7, cost: 0.0012 } });
    const s = await serve('account', () => new Response(upstreamBody, { status: 200, headers: { ...JSON_HEADERS, 'x-generation-id': 'gen-abc', 'set-cookie': '__cf_bm=1', 'access-control-allow-origin': '*' } }));
    const sent = JSON.stringify(CHAT);
    const res = await call(s, '/chat/completions', post(sent, { 'x-title': 'my agent', 'x-openrouter-cache': 'true' }));

    expect(res.status).toBe(200);
    expect(await res.text()).toBe(upstreamBody);
    expect(res.headers.get('x-generation-id')).toBe('gen-abc');
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
    expect(res.headers.get('cache-control')).toBe('private, no-store');

    expect(s.fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = s.fetchImpl.mock.calls[0]! as [string, RequestInit & { headers: Record<string, string> }];
    expect(url).toBe('https://openrouter.ai/api/v1/chat/completions');
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('manual');
    expect(Buffer.from(init.body as Uint8Array).toString('utf8')).toBe(sent);
    expect(init.headers['authorization']).toBe('Bearer sk-or-stack');
    // The caller's own headers go on, on STACK's key as on the customer's.
    expect(init.headers['x-title']).toBe('my agent');
    expect(init.headers['x-openrouter-cache']).toBe('true');
    // Nothing of the caller's own credentials goes to OpenRouter.
    expect(JSON.stringify(init.headers)).not.toContain('sk_live_caller');
    expect(init.headers).not.toHaveProperty('x-passport-token');

    expect(s.services.modelAccessPolicy.hold).toHaveBeenCalledWith(expect.objectContaining({ accountId: 'acct_1', heldCents: worstCents(CHAT), model: 'acme/chat-1' }));
    expect(s.services.accountModelBilling.settleCall).toHaveBeenCalledWith(expect.objectContaining({
      status: 200, model: 'acme/chat-1', generationId: 'gen-abc', streaming: false,
      usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7, provider_cost_usd: 0.0012 },
      authorization: expect.objectContaining({ walletHoldId: 'whld_1', heldCents: worstCents(CHAT) }),
    }));
    expect(s.services.modelAccessPolicy.release).not.toHaveBeenCalled();
    expect(s.services.serviceConnection.retrieveCredentialByConnectionId).not.toHaveBeenCalled();
    expect(s.services.audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'llm.openrouter.chat.completions', outcome: 'success' }));
  });

  it('runs the gates in their order, meters once, and asks the customer\'s decider with the held amount', async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    await call(s, '/chat/completions', post(CHAT, { 'x-max-cost-cents': '250' }));
    // The header is a ceiling: the call holds its own worst case, which is below it.
    expect(order).toEqual(['authority', 'meter', 'mission', 'approval', 'wall', 'decider']);
    expect(s.services.actionMeter.meterAction).toHaveBeenCalledTimes(1);
    expect(decideControl).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      action: 'model.call', scope: 'agent', agentId: 'agt_1',
      target: { provider: 'openrouter', model: 'acme/chat-1', stream: false, max_output_tokens: 50 },
      amount: { max_cents: worstCents(CHAT), currency: 'USD' },
    }));
    expect(s.services.modelAccessPolicy.hold).toHaveBeenCalledWith(expect.objectContaining({ heldCents: worstCents(CHAT) }));
  });

  it("holds a call at the caller's cap when that is below its worst case, and shows the decider the hold", async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    const big = { model: 'acme/chat-1', messages: [{ role: 'user', content: 'hello' }], max_tokens: 8_000 };
    expect(worstCents(big)).toBeGreaterThan(5);
    const res = await call(s, '/chat/completions', post(big, { 'x-max-cost-cents': '5' }));
    expect(res.status).toBe(200);
    expect(s.services.modelAccessPolicy.hold).toHaveBeenCalledWith(expect.objectContaining({ heldCents: 5 }));
    expect(decideControl).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      amount: { max_cents: 5, currency: 'USD' },
    }));
  });

  it('holds a call with no output limit on a model that lists a large maximum at 8,192 output tokens', async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    const noLimit = { model: 'acme/long-1', messages: [{ role: 'user', content: 'hello' }] };
    expect((await call(s, '/chat/completions', post(noLimit))).status).toBe(200);
    const bytes = Buffer.byteLength(JSON.stringify(noLimit));
    const micros = (bytes + 1_024) * 1 + 8_192 * 10;
    expect(s.services.modelAccessPolicy.hold).toHaveBeenCalledWith(expect.objectContaining({ heldCents: Math.ceil(micros / 10_000) }));
    expect(decideControl).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      amount: { max_cents: Math.ceil(micros / 10_000), currency: 'USD' },
    }));
  });

  it('holds a call with no output limit at the model\'s listed maximum, not at an amount of STACK\'s own', async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    const noLimit = { model: 'acme/chat-1', messages: [{ role: 'user', content: 'hello' }] };
    const res = await call(s, '/chat/completions', post(noLimit));
    expect(res.status).toBe(200);
    expect(worstCents(noLimit)).toBeGreaterThan(worstCents(CHAT));
    expect(s.services.modelAccessPolicy.hold).toHaveBeenCalledWith(expect.objectContaining({ heldCents: worstCents(noLimit) }));
  });

  it('holds a call its listing cannot price exactly at an estimate, never a refusal, lowered to the cap when one is named', async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    // A voice priced per audio unit, held from the seconds of speech its input makes.
    const speech = { model: 'acme/audio-1', input: 'hello', voice: 'a' };
    expect((await call(s, '/audio/speech', post(speech))).status).toBe(200);
    expect(s.services.modelAccessPolicy.hold).toHaveBeenLastCalledWith(expect.objectContaining({ heldCents: worstCents(speech), model: 'acme/audio-1' }));
    // A tool OpenRouter runs itself, held at its price a use.
    const coded = { ...CHAT, tools: [{ type: 'code_interpreter' }] };
    expect((await call(s, '/chat/completions', post(coded))).status).toBe(200);
    expect(s.services.modelAccessPolicy.hold).toHaveBeenLastCalledWith(expect.objectContaining({ heldCents: worstCents(coded) }));
    expect(worstCents(coded)).toBeGreaterThan(worstCents(CHAT));
    expect((await call(s, '/chat/completions', post(coded, { 'x-max-cost-cents': '1' }))).status).toBe(200);
    expect(s.services.modelAccessPolicy.hold).toHaveBeenLastCalledWith(expect.objectContaining({ heldCents: 1 }));
    // A model the catalogue does not list, held at the unpriced allowance.
    expect((await call(s, '/chat/completions', post({ ...CHAT, model: 'acme/brand-new' }))).status).toBe(200);
    expect(s.services.modelAccessPolicy.hold).toHaveBeenLastCalledWith(expect.objectContaining({ heldCents: UNPRICED_CALL_HOLD_USD_MICROS / 10_000 }));
  });

  it("sends the caller's own headers with STACK's key, a long one whole, and none of its credentials or STACK's headers", async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    const long = 'v'.repeat(6_000);
    await call(s, '/chat/completions', post(CHAT, {
      'anthropic-beta': 'context-1m-2025-08-07', 'x-anthropic-beta': 'x', 'http-referer': 'https://app.example', 'x-title': 'App', accept: 'application/json',
      'x-long': long, 'x-stack-save-output': 'ftp', cookie: 'a=b',
    }));
    const [, init] = s.fetchImpl.mock.calls[0]! as [string, RequestInit & { headers: Record<string, string> }];
    expect(init.headers['x-long']).toBe(long);
    expect(init.headers['anthropic-beta']).toBe('context-1m-2025-08-07');
    expect(init.headers['http-referer']).toBe('https://app.example');
    expect(init.headers['authorization']).toBe('Bearer sk-or-stack');
    for (const name of ['x-passport-token', 'cookie', 'x-stack-save-output', 'host', 'connection']) expect(init.headers, name).not.toHaveProperty(name);
  });

  it("keeps OpenRouter's refusal of STACK's key for its own limit from the agent, and passes a refusal of the request on", async () => {
    const limit = JSON.stringify({ error: { code: 403, message: 'Key limit exceeded', metadata: { limit_source: 'openrouter_key_limit' } } });
    const s = await serve('account', () => new Response(limit, { status: 403, headers: JSON_HEADERS }));
    const res = await call(s, '/chat/completions', post(CHAT));
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: unknown }).error).toMatchObject({ code: 'PROVIDER_CAPACITY_UNAVAILABLE' });
    expect(s.services.modelAccessPolicy.release).toHaveBeenCalledTimes(1);
    const flagged = JSON.stringify({ error: { code: 403, message: 'Your input was flagged', metadata: { reasons: ['violence'], flagged_input: 'x' } } });
    const t = await serve('account', () => new Response(flagged, { status: 403, headers: JSON_HEADERS }));
    const passed = await call(t, '/chat/completions', post(CHAT));
    expect(passed.status).toBe(403);
    expect(await passed.text()).toBe(flagged);
  });

  it('sends a call whose charge cannot be recorded to the retry that reads its cost from OpenRouter, never charging the hold', async () => {
    const s = await serve('account', () => new Response('{"id":"gen-lost","usage":{"cost":0.001}}', { status: 200, headers: { ...JSON_HEADERS, 'x-generation-id': 'gen-lost' } }));
    s.services.accountModelBilling.settleCall.mockRejectedValueOnce(new Error('database went away'));
    const res = await call(s, '/chat/completions', post(CHAT));
    expect(res.status).toBe(200);
    // The one settlement that failed is not repeated at the hold: the call goes to the retry, by its generation.
    expect(s.services.accountModelBilling.settleCall).toHaveBeenCalledTimes(1);
    expect(s.services.accountModelBilling.retrySettlement).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_1', generationId: 'gen-lost', job: null, hold: expect.objectContaining({ walletHoldId: 'whld_1' }),
    }));
    expect(s.services.modelAccessPolicy.release).not.toHaveBeenCalled();
  });

  it('answers as it would have when the retry gives the hold back because the call has nothing to look up', async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    s.services.accountModelBilling.settleCall.mockRejectedValueOnce(new Error('database went away'));
    s.services.accountModelBilling.retrySettlement.mockResolvedValueOnce('released');
    expect((await call(s, '/chat/completions', post(CHAT))).status).toBe(200);
    expect(s.services.accountModelBilling.retrySettlement).toHaveBeenCalledWith(expect.objectContaining({ generationId: null }));
  });

  it('leaves the answer already on its way as it is when neither the charge nor the retry could be recorded', async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    s.services.accountModelBilling.settleCall.mockRejectedValueOnce(new Error('database went away'));
    s.services.accountModelBilling.retrySettlement.mockRejectedValueOnce(new Error('still down'));
    expect((await call(s, '/chat/completions', post(CHAT))).status).toBe(200);
    expect(s.services.accountModelBilling.settleCall).toHaveBeenCalledTimes(1);
    expect(s.services.accountModelBilling.retrySettlement).toHaveBeenCalledTimes(1);
    // The hold is not charged in place of the retry that failed.
    expect(s.services.modelAccessPolicy.release).not.toHaveBeenCalled();
  });

  it('takes a cap of any size, however large, and holds the worst case of the call itself when that is below it', async () => {
    const s = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    for (const cap of ['100001', '5000000', '99999999999']) {
      const res = await call(s, '/chat/completions', post(CHAT, { 'x-max-cost-cents': cap }));
      expect(res.status, cap).toBe(200);
    }
    expect(s.services.modelAccessPolicy.hold).toHaveBeenCalledWith(expect.objectContaining({ heldCents: worstCents(CHAT) }));
  });

  it('refuses a cap that is not a whole number of cents of at least 1, before anything is counted', async () => {
    const s = await serve('account', () => new Response('{}'));
    for (const cap of ['0', '1.5', 'many']) {
      const res = await call(s, '/chat/completions', post(CHAT, { 'x-max-cost-cents': cap }));
      expect(res.status, cap).toBe(400);
    }
    expect(s.services.actionMeter.meterAction).not.toHaveBeenCalled();
    expect(s.fetchImpl).not.toHaveBeenCalled();
  });

  it('passes an event stream through byte for byte and charges the cost in its last event', async () => {
    const events = [
      'data: {"id":"gen-s1","choices":[{"delta":{"content":"he"}}]}\n\n',
      ': OPENROUTER PROCESSING\n\n',
      'data: {"id":"gen-s1","choices":[{"delta":{"content":"llo"}}]}\n\n',
      'data: {"id":"gen-s1","choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"cost":0.0007,"cost_details":{"upstream_inference_cost":0.0007}}}\n\n',
      'data: [DONE]\n\n',
    ];
    const s = await serve('account', () => new Response(
      new ReadableStream({ start(controller) { for (const event of events) controller.enqueue(new TextEncoder().encode(event)); controller.close(); } }),
      { status: 200, headers: { 'content-type': 'text/event-stream' } },
    ));
    const sent = { ...CHAT, stream: true };
    const res = await call(s, '/chat/completions', post(sent));
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    expect(await res.text()).toBe(events.join(''));
    // The body is the agent's own: no stream option was added.
    expect(JSON.parse(Buffer.from((s.fetchImpl.mock.calls[0]![1] as RequestInit).body as Uint8Array).toString('utf8'))).toEqual(sent);
    expect(s.services.accountModelBilling.settleCall).toHaveBeenCalledWith(expect.objectContaining({
      status: 200, streaming: true, generationId: 'gen-s1',
      usage: expect.objectContaining({ provider_cost_usd: 0.0007, prompt_tokens: 4, completion_tokens: 2 }),
    }));
  });

  it('passes audio bytes as they are and hands the generation id to the billing, since the answer carries no cost', async () => {
    const audio = Buffer.from([0xff, 0xfb, 0x90, 0x00, 1, 2, 3, 4, 5]);
    const s = await serve('account', () => new Response(audio, { status: 200, headers: { 'content-type': 'audio/mpeg', 'x-generation-id': 'gen-tts-1' } }));
    const res = await call(s, '/audio/speech', post({ model: 'acme/voice-1', input: 'hello', voice: 'a' }));
    expect(res.headers.get('content-type')).toBe('audio/mpeg');
    expect(Buffer.from(await res.arrayBuffer()).equals(audio)).toBe(true);
    expect(s.services.accountModelBilling.settleCall).toHaveBeenCalledWith(expect.objectContaining({
      status: 200, usage: null, generationId: 'gen-tts-1', model: 'acme/voice-1',
    }));
  });

  it('hands a started video job to the billing, which keeps the hold until the job ends', async () => {
    // The id in the shape OpenRouter documents for a video job: not a `gen-` generation id.
    const s = await serve('account', () => new Response(JSON.stringify({ id: 'y34x1YREG4Pkdcj7f02v', polling_url: 'https://openrouter.ai/api/v1/videos/y34x1YREG4Pkdcj7f02v', status: 'pending' }), { status: 202, headers: JSON_HEADERS }));
    const res = await call(s, '/videos', post({ model: 'acme/video-1', prompt: 'a cat', duration: 5 }));
    expect(res.status).toBe(202);
    expect(s.services.accountModelBilling.settleCall).toHaveBeenCalledWith(expect.objectContaining({
      status: 202, usage: null, job: { kind: 'video_job', id: 'y34x1YREG4Pkdcj7f02v' },
    }));
  });

  it('hands an upstream refusal to the billing, which gives the hold back, and passes the refusal on as it is', async () => {
    const refusal = JSON.stringify({ error: { code: 400, message: 'bad request' } });
    const s = await serve('account', () => new Response(refusal, { status: 400, headers: JSON_HEADERS }));
    const res = await call(s, '/chat/completions', post(CHAT));
    expect(res.status).toBe(400);
    expect(await res.text()).toBe(refusal);
    expect(s.services.accountModelBilling.settleCall).toHaveBeenCalledWith(expect.objectContaining({ status: 400, usage: null }));
  });

  it('keeps STACK\'s own key trouble from the agent, gives the hold back and hands the action back', async () => {
    for (const status of [401, 402]) {
      const s = await serve('account', () => new Response(JSON.stringify({ error: { message: 'insufficient credits on key sk-or-stack', metadata: { limit_source: 'openrouter_credits' } } }), { status, headers: JSON_HEADERS }));
      const res = await call(s, '/chat/completions', post(CHAT));
      const text = await res.text();
      expect(res.status, String(status)).toBe(503);
      expect(JSON.parse(text).error).toMatchObject({ code: 'PROVIDER_CAPACITY_UNAVAILABLE' });
      expect(text).not.toContain('credits');
      expect(s.services.modelAccessPolicy.release).toHaveBeenCalledTimes(1);
      expect(s.services.accountModelBilling.settleCall).not.toHaveBeenCalled();
    }
  });

  it('gives the hold back when OpenRouter cannot be reached, and says nothing of why', async () => {
    const s = await serve('account', () => { throw new Error('connect ECONNREFUSED sk-or-stack'); });
    const res = await call(s, '/chat/completions', post(CHAT));
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain('ECONNREFUSED');
    expect(s.services.modelAccessPolicy.release).toHaveBeenCalledTimes(1);
  });

  it('gives the hold back when the key is not configured', async () => {
    const s = await serve('account', () => new Response('{}'));
    s.services.modelAccessPolicy.stackKey.mockImplementation(() => { throw new Error('no key'); });
    const res = await call(s, '/chat/completions', post(CHAT));
    expect(res.status).toBe(500);
    expect(s.services.modelAccessPolicy.release).toHaveBeenCalledTimes(1);
    expect(s.fetchImpl).not.toHaveBeenCalled();
  });

  it('holds nothing for a read: the public lists are free', async () => {
    const s = await serve('account', () => new Response(JSON.stringify({ data: [{ id: 'acme/chat-1' }] }), { status: 200, headers: JSON_HEADERS }));
    const res = await call(s, '/models?output_modalities=all');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ data: [{ id: 'acme/chat-1' }] });
    expect(s.fetchImpl.mock.calls[0]![0]).toBe('https://openrouter.ai/api/v1/models?output_modalities=all');
    expect(s.services.modelAccessPolicy.hold).not.toHaveBeenCalled();
    expect(s.services.accountModelBilling.settleCall).not.toHaveBeenCalled();
    expect(decideControl).not.toHaveBeenCalled();
    // A read is still one action on the meter.
    expect(s.services.actionMeter.meterAction).toHaveBeenCalledTimes(1);
  });

  it('refuses the endpoints of the OpenRouter account that holds STACK\'s key, before anything is counted', async () => {
    const s = await serve('account', () => new Response('{}'));
    for (const [method, path] of [['GET', '/key'], ['GET', '/credits'], ['POST', '/keys'], ['GET', '/files'], ['POST', '/batches'], ['GET', '/generation?id=gen-x'], ['GET', '/models/user'], ['DELETE', '/guardrails/g1']] as const) {
      const res = await call(s, path, { method, ...(method === 'POST' ? post({}) : {}) });
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(((await res.json()) as { error: unknown }).error).toMatchObject({ code: 'OPENROUTER_ENDPOINT_REFUSED' });
    }
    expect(s.fetchImpl).not.toHaveBeenCalled();
    expect(s.services.actionMeter.meterAction).not.toHaveBeenCalled();
    expect(s.services.modelAccessPolicy.hold).not.toHaveBeenCalled();
  });

  it('refuses an endpoint the table does not list, on STACK\'s key only', async () => {
    const s = await serve('account', () => new Response('{}'));
    const res = await call(s, '/vector_stores', post({}));
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: unknown }).error).toMatchObject({ code: 'OPENROUTER_ENDPOINT_REFUSED', details: { reason: 'not_listed' } });
  });

  it('lets an account read its own video job and its file, and nobody else\'s', async () => {
    const s = await serve('account', () => new Response('{"status":"completed"}', { status: 200, headers: JSON_HEADERS }));
    expect((await call(s, '/videos/gen-vid-mine')).status).toBe(200);
    const other = await call(s, '/videos/gen-vid-theirs/content');
    expect(other.status).toBe(404);
    expect(s.fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('refuses a path that could leave the API base', async () => {
    const s = await serve('account', () => new Response('{}'));
    // Sent as written: a URL parser would fold `..` away before the request left, which is not what an attacker sends.
    const status = (path: string) => new Promise<number>((resolve, reject) => {
      const port = Number(new URL(s.base).port);
      const request = http.request({ host: '127.0.0.1', port, path: `${OPENROUTER_GATEWAY_PREFIX}${path}`, headers: { 'x-passport-token': 'p.jwt' } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      request.on('error', reject);
      request.end();
    });
    for (const path of ['/models/../key', '/models//count', '/models/%2e%2e/key', '/models/a%2fb', '/']) {
      expect(await status(path), path).toBe(400);
    }
    expect(s.fetchImpl).not.toHaveBeenCalled();
  });

  it('refuses a body that is not a JSON object when it says it is JSON', async () => {
    const s = await serve('account', () => new Response('{}'));
    expect((await call(s, '/chat/completions', post('{not json'))).status).toBe(400);
    expect((await call(s, '/chat/completions', post('[1,2]'))).status).toBe(400);
    expect(s.fetchImpl).not.toHaveBeenCalled();
  });

  it('does not follow a redirect and points a redirect at this gateway', async () => {
    const s = await serve('account', () => new Response(null, { status: 308, headers: { location: '/api/v1/tools/web_search' } }));
    const res = await fetch(`${s.base}${OPENROUTER_GATEWAY_PREFIX}/tools/web_search`, {
      redirect: 'manual', headers: { 'x-passport-token': 'passport.jwt', authorization: 'Bearer sk_live_caller' },
    });
    expect(res.status).toBe(308);
    expect(res.headers.get('location')).toBe('/v1/llm/openrouter/tools/web_search');
    expect(s.fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('forwards a multipart body byte for byte with its boundary', async () => {
    const boundary = '----stackboundary';
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\nacme/stt-1\r\n--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.wav"\r\nContent-Type: audio/wav\r\n\r\n`),
      Buffer.from([0, 255, 1, 254, 2, 253]),
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    // On the customer's own key the form goes on as it is.
    const s = await serve('customer', () => new Response('{"text":"hi","usage":{"cost":0.001,"seconds":1}}', { status: 200, headers: JSON_HEADERS }));
    const res = await call(s, '/audio/transcriptions', { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, body });
    expect(res.status).toBe(200);
    const [, init] = s.fetchImpl.mock.calls[0]! as [string, RequestInit & { headers: Record<string, string> }];
    expect(Buffer.from(init.body as Uint8Array).equals(body)).toBe(true);
    expect(init.headers['content-type']).toBe(`multipart/form-data; boundary=${boundary}`);
    // On STACK's key the form is held from its model field and the size of its file (the model is unlisted here: the allowance).
    const stack = await serve('account', () => new Response('{}'));
    const held = await call(stack, '/audio/transcriptions', { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, body });
    expect(held.status).toBe(200);
    expect(stack.services.modelAccessPolicy.hold).toHaveBeenCalledWith(expect.objectContaining({ heldCents: UNPRICED_CALL_HOLD_USD_MICROS / 10_000 }));
  });
});

describe('PII redaction on the passthrough: a controls feature', () => {
  const PII = { model: 'acme/chat-1', messages: [{ role: 'system', content: 'ada@example.com is the system line' }, { role: 'user', content: 'mail ada@example.com please' }], max_tokens: 50 };
  const sent = (setup: Setup) => Buffer.from((setup.fetchImpl.mock.calls[0]![1] as RequestInit).body as Uint8Array).toString('utf8');

  beforeEach(() => { controls.on = true; controls.agentFlag = true; });

  it('redacts the user and tool messages with controls on, and nothing else of the body', async () => {
    const setup = await serve('account', () => Response.json({ id: 'gen-1', usage: { cost: 0.0001 } }));
    const res = await call(setup, '/chat/completions', post(PII));
    expect(res.status).toBe(200);
    const body = JSON.parse(sent(setup)) as { messages: Array<{ role: string; content: string }>; model: string };
    expect(body.messages[1]!.content).not.toContain('ada@example.com');
    expect(body.messages[1]!.content).toContain('[REDACTED:');
    // The system message is never touched, and the rest of the body is as it was.
    expect(body.messages[0]!.content).toBe('ada@example.com is the system line');
    expect(body.model).toBe('acme/chat-1');
  });

  it('redacts on the customer\'s own key too', async () => {
    const setup = await serve('customer', () => Response.json({ id: 'gen-1' }));
    await call(setup, '/chat/completions', post(PII));
    expect(sent(setup)).not.toContain('mail ada@example.com');
  });

  it('redacts nothing without controls, whatever the agent flag says, and the body goes as it came', async () => {
    controls.on = false;
    const setup = await serve('account', () => Response.json({ id: 'gen-1', usage: { cost: 0.0001 } }));
    const raw = JSON.stringify(PII);
    await call(setup, '/chat/completions', post(raw));
    expect(sent(setup)).toBe(raw);
  });

  it('redacts nothing when the agent\'s flag is off, even with controls on', async () => {
    controls.agentFlag = false;
    const setup = await serve('account', () => Response.json({ id: 'gen-1', usage: { cost: 0.0001 } }));
    const raw = JSON.stringify(PII);
    await call(setup, '/chat/completions', post(raw));
    expect(sent(setup)).toBe(raw);
  });

  it('redacts nothing when the account switched redaction off', async () => {
    const setup = await serve('account', () => Response.json({ id: 'gen-1', usage: { cost: 0.0001 } }), {
      operatorPiiConfig: { resolveScanOptions: vi.fn(async () => null) },
    });
    const raw = JSON.stringify(PII);
    await call(setup, '/chat/completions', post(raw));
    expect(sent(setup)).toBe(raw);
  });

  it('forwards a body with no personal data byte for byte', async () => {
    const setup = await serve('account', () => Response.json({ id: 'gen-1', usage: { cost: 0.0001 } }));
    const raw = '{ "model" : "acme/chat-1",  "messages":[{"role":"user","content":"hello"}], "max_tokens": 50 }';
    await call(setup, '/chat/completions', post(raw));
    expect(sent(setup)).toBe(raw);
  });
});

describe('a call on the customer\'s own OpenRouter key', () => {
  it('passes every method to OpenRouter on the customer\'s key, holds and charges nothing, and counts one action', async () => {
    const s = await serve('customer', () => new Response('{"data":{"label":"mine"}}', { status: 200, headers: JSON_HEADERS }));
    for (const [method, path] of [['GET', '/key'], ['GET', '/credits'], ['POST', '/keys'], ['PATCH', '/keys/abc'], ['PUT', '/workspaces/w1/budgets/daily'], ['DELETE', '/files/f1'], ['POST', '/vector_stores']] as const) {
      const res = await call(s, path, { method, ...(method === 'GET' || method === 'DELETE' ? {} : post({ x: 1 })) });
      expect(res.status, `${method} ${path}`).toBe(200);
    }
    expect(s.fetchImpl).toHaveBeenCalledTimes(7);
    const [, init] = s.fetchImpl.mock.calls[0]! as [string, RequestInit & { headers: Record<string, string> }];
    expect(init.headers['authorization']).toBe('Bearer sk-or-customer');
    expect(s.services.modelAccessPolicy.hold).not.toHaveBeenCalled();
    expect(s.services.accountModelBilling.settleCall).not.toHaveBeenCalled();
    expect(s.services.actionMeter.meterAction).toHaveBeenCalledTimes(7);
  });

  it('records the usage of a call for the usage list and takes no hold', async () => {
    const usage = { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7, cost: 0.002 };
    const s = await serve('customer', () => new Response(JSON.stringify({ id: 'gen-c', choices: [], usage }), { status: 200, headers: JSON_HEADERS }));
    await call(s, '/chat/completions', post(CHAT));
    expect(s.services.llmUsage.record).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'openrouter', model: 'acme/chat-1', streaming: false,
      usage: { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7, provider_cost_usd: 0.002 },
    }));
    expect(s.services.modelAccessPolicy.hold).not.toHaveBeenCalled();
  });

  it('ignores a cost cap, which has no hold to size on a key STACK does not pay for', async () => {
    const s = await serve('customer', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    expect((await call(s, '/chat/completions', post(CHAT, { 'x-max-cost-cents': '5' }))).status).toBe(200);
    // Not a refusal either when the value is not a number of cents: the header is not read.
    expect((await call(s, '/chat/completions', post(CHAT, { 'x-max-cost-cents': 'abc' }))).status).toBe(200);
    expect(s.services.actionMeter.meterAction).toHaveBeenCalledTimes(2);
    expect(s.fetchImpl).toHaveBeenCalledTimes(2);
    expect(s.services.modelAccessPolicy.hold).not.toHaveBeenCalled();
  });

  it('sends nothing when the customer has no OpenRouter connection', async () => {
    const s = await serve('customer', () => new Response('{}'), {
      serviceConnection: {
        resolveProxyConnection: vi.fn(async () => { throw new NotFoundError('ServiceConnection', 'openrouter'); }),
        getConnectionScoped: vi.fn(),
        retrieveCredentialByConnectionId: vi.fn(),
      },
    });
    const res = await call(s, '/chat/completions', post(CHAT));
    expect(res.status).toBe(403);
    expect(s.fetchImpl).not.toHaveBeenCalled();
  });
});

describe('the table', () => {
  it('passes every endpoint OpenRouter has on the customer\'s key, and every open one on STACK\'s', async () => {
    const own = await serve('customer', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    const account = await serve('account', () => new Response('{}', { status: 200, headers: JSON_HEADERS }));
    for (const endpoint of OPENROUTER_ENDPOINTS) {
      const path = endpoint.path.replace(/\{[^}]+\}/g, (name) => (name === '{jobId}' ? 'gen-vid-mine' : 'sample-1'));
      const init: RequestInit = endpoint.method === 'GET' || endpoint.method === 'DELETE' ? { method: endpoint.method } : { method: endpoint.method, ...post({ model: 'acme/x' }) };
      const ownRes = await call(own, path, init);
      expect(ownRes.status, `own key: ${endpoint.method} ${endpoint.path}`).toBe(200);
      const accountRes = await call(account, path, init);
      expect(accountRes.status === 200, `STACK key: ${endpoint.method} ${endpoint.path} (${endpoint.kind})`).toBe(endpoint.kind !== 'account');
    }
    const urls = own.fetchImpl.mock.calls.map((c) => c[0]);
    expect(urls).toHaveLength(OPENROUTER_ENDPOINTS.length);
    expect(urls.every((url) => String(url).startsWith('https://openrouter.ai/api/v1/'))).toBe(true);
  }, 120_000);

  it('is small enough that the gateway reads a request of its stated size', () => {
    expect(OPENROUTER_REQUEST_MAX_BYTES).toBe(64 * 1024 * 1024);
  });
});
