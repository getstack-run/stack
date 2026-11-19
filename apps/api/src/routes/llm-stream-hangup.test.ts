// A streamed model call hijacks its reply, so Fastify's response hooks never
// describe how it ended: a client that hangs up mid-stream, or a throw after
// the first byte, used to leave the counted action, the control decision's
// lease, the reserved approval and the fleet admission open. Over a real
// socket: the end hooks run once, when the call is really over, with the
// status its answer had.

import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FleetAdmission } from '@stack/vault';
import type { Services } from '../config/services.js';
import { trackFleetAdmission, registerFleetRuntimeLifecycle } from '../lib/agent-runtime.js';
import { registerControlSettle } from '../middleware/control-settle.js';
import { registerMeterRefund } from '../middleware/meter.js';
import { registerApprovalRelease } from '../middleware/request-cleanup.js';
import { listen, pause } from '../test/http-hangup.js';
import { OPENAI_CONFIG } from './llm-gateway/provider-configs.js';
import { forwardStreamingResponse } from './llm-gateway/stream-forward.js';
import type { AdmittedCall, BillingHold, ForwardContext } from './llm-gateway/types.js';

const BODY = { model: 'gpt-4o', stream: true, messages: [{ role: 'user', content: 'hello' }], max_tokens: 200 };
const PRICING = { input_cents_per_1m: 300, output_cents_per_1m: 1500 };
const HELD_AUTH = { bounded: true, denyReason: null, heldCents: 7, pricing: PRICING };
const HOLD: BillingHold = {
  providerBody: BODY, authorization: HELD_AUTH, requestBodyStr: JSON.stringify(BODY),
};

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

function admitted(): AdmittedCall {
  return {
    body: BODY, method: 'POST', isStreaming: true, passportToken: 'passport.jwt', claims: {} as AdmittedCall['claims'], jti: 'pas_1',
    agentId: 'agt_1', operatorId: 'op_1', mode: 'standard', missionIds: ['msn_1'], missionRef: 'msn_1',
    upstream: new URL('https://api.openai.com/v1/chat/completions'), normalizedRequest: {} as AdmittedCall['normalizedRequest'],
    connectionId: 'conn', authorityConnectionId: 'conn', authorityDecision: { enforced: false } as AdmittedCall['authorityDecision'],
    modelAccess: { kind: 'customer' },
  };
}

async function serve(options: { upstreamStatus?: number; failAfterFirstEvent?: boolean } = {}) {
  const app = Fastify();
  apps.push(app);
  registerMeterRefund(app);
  registerControlSettle(app);
  registerApprovalRelease(app);
  registerFleetRuntimeLifecycle(app);

  let open!: () => void;
  const gate = new Promise<void>((resolve) => { open = resolve; });
  // Like the real ledger, finishing or aborting an admission closes it.
  const closes = async (admission: { state: string }) => { admission.state = 'finished'; };
  const calls = {
    rollback: vi.fn(async () => undefined),
    controlSettle: vi.fn(async (_outcome: { ok: boolean; handedBack: boolean }) => undefined),
    release: vi.fn(async () => undefined),
    fleetFinish: vi.fn(closes),
    fleetAbort: vi.fn(closes),
  };
  async function* events() {
    yield { bytes: 'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n', text: 'hi' };
    await gate;
    if (options.failAfterFirstEvent) throw new Error('upstream died');
    yield { bytes: 'data: [DONE]\n\n', text: '' };
  }
  const services = {
    authority: { markRuntimeAuthorityDispatched: vi.fn(), completeRuntimeAuthorityUse: vi.fn() },
    llmUsage: { record: vi.fn(async () => ({ llmUsageId: 'usg_1', walletDebited: false, cost: null })), releaseGatewayAuthorization: vi.fn(async () => undefined) },
    llmGateway: {
      forwardStreaming: vi.fn(async () => ({
        events: events(),
        usage: () => ({ prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 }),
        status: options.upstreamStatus ?? 200,
        generationId: () => null,
      })),
    },
    detector: { scanOutput: vi.fn(async () => ({ match: false, redactedBody: null })) },
    audit: { write: vi.fn(async () => undefined) },
    claimRegistry: { registerClaim: vi.fn() },
    approvalGate: { markConsumed: vi.fn() },
    fleetAdmission: { finish: calls.fleetFinish, abort: calls.fleetAbort },
  } as unknown as Services;

  app.post('/llm', async (request, reply) => {
    // What the stages before the forward leave open.
    request.meterRollback = calls.rollback;
    request.controlSettle = [calls.controlSettle];
    request.approvalToRelease = calls.release;
    const admission = { state: 'dispatched', operationId: 'flo_1', authorization: { operatorId: 'op_1' } } as unknown as FleetAdmission;
    trackFleetAdmission(request, services, admission);
    const ctx: ForwardContext = {
      services, request, reply, config: OPENAI_CONFIG, start: Date.now(), call: admitted(),
      gate: { allowed: true, skipped: true } as ForwardContext['gate'], approvalIdHeader: undefined, fleetAdmission: admission,
      hold: HOLD, apiKey: 'sk-or-stack', carriedSources: [], piiHits: 0,
    };
    await forwardStreamingResponse(ctx);
  });
  const client = await listen(app);
  return { ...client, calls, services, open: () => open() };
}

const POST = { method: 'POST', body: BODY } as const;
const nothingEnded = (calls: Awaited<ReturnType<typeof serve>>['calls']) => {
  expect(calls.controlSettle).not.toHaveBeenCalled();
  expect(calls.release).not.toHaveBeenCalled();
  expect(calls.fleetFinish).not.toHaveBeenCalled();
  expect(calls.fleetAbort).not.toHaveBeenCalled();
};

describe('a streamed model call and the end of its request', () => {
  it('ends once, after its records, when the client stays to the last byte', async () => {
    const t = await serve();
    const done = t.call('/llm', POST);
    await pause(50);
    nothingEnded(t.calls);
    t.open();
    expect(await done).toBe(200);
    await pause(100);
    expect(t.calls.controlSettle).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledWith({ ok: true, handedBack: false });
    // An approval the call did not consume is given back; the counted action stays counted.
    expect(t.calls.release).toHaveBeenCalledTimes(1);
    expect(t.calls.rollback).not.toHaveBeenCalled();
    expect(t.calls.fleetFinish).toHaveBeenCalledTimes(1);
    expect(t.services.audit.write).toHaveBeenCalledTimes(1);
  });

  it('ends once, when the call is over, for a client that hung up mid-stream', async () => {
    const t = await serve();
    await t.hangUp('/llm', 100, POST);
    // The client is gone but the upstream is still being read and priced: not over.
    nothingEnded(t.calls);
    t.open();
    await pause(150);
    expect(t.services.llmUsage.record).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledWith({ ok: true, handedBack: false });
    expect(t.calls.release).toHaveBeenCalledTimes(1);
    expect(t.calls.rollback).not.toHaveBeenCalled();
    expect(t.calls.fleetFinish).toHaveBeenCalledTimes(1);
  });

  it('hands the action back for a streamed refusal the client never read', async () => {
    const t = await serve({ upstreamStatus: 429 });
    await t.hangUp('/llm', 100, POST);
    nothingEnded(t.calls);
    t.open();
    await pause(150);
    expect(t.calls.rollback).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledTimes(1);
    expect(t.calls.controlSettle).toHaveBeenCalledWith({ ok: false, handedBack: true });
    expect(t.calls.release).toHaveBeenCalledTimes(1);
  });

  it('ends once, and ends the connection, when the stream fails after the first byte', async () => {
    const t = await serve({ failAfterFirstEvent: true });
    const done = t.call('/llm', POST);
    await pause(50);
    t.open();
    expect(await done).toBe(200);
    await pause(100);
    expect(t.calls.controlSettle).toHaveBeenCalledTimes(1);
    expect(t.calls.release).toHaveBeenCalledTimes(1);
    expect(t.calls.fleetFinish).toHaveBeenCalledTimes(1);
  });
});
