// /v1/llm/<provider>/* route family.
//
// Provider-specific routes that proxy LLM calls to Anthropic, OpenAI,
// and OpenRouter through STACK's full passport + intent + approval +
// mission + audit substrate. Same gating shape as /v1/proxy
// (apps/api/src/routes/proxy.ts) but with provider-specific request
// schemas + SSE streaming passthrough + LlmGatewayService.forward as
// the credential-injection + upstream-call primitive.
//
// Two chat routes, on the customer's own key:
//   POST /v1/llm/anthropic/messages          → api.anthropic.com/v1/messages
//   POST /v1/llm/openai/chat/completions     → api.openai.com/v1/chat/completions
//
// and, for an image on the customer's own key (makeImageHandler, below the chat handler):
//   POST /v1/llm/openai/images               → api.openai.com/v1/images/generations
//   POST /v1/llm/anthropic/images            → refused: Anthropic has no image endpoint
//
// OpenRouter is not one of these: every endpoint of its API, any method, goes through
//   ANY  /v1/llm/openrouter/*                → openrouter.ai/api/v1/*
// as a passthrough (llm-gateway/openrouter/handler.ts), on the customer's own OpenRouter
// key or, for an agent account's agent, on STACK's, charged at the cost OpenRouter reports.
//
// Gate sequence of the Anthropic and OpenAI routes (mirrors proxy.ts):
//   1.  Parse + validate body (provider Zod schema)
//   2.  Passport verification (X-Passport-Token header required)
//   3.  Approval gate (X-Intent-Approval-Id header for enforced mode)
//   4.  Scope check (provider in claims.stk.intent_services / services)
//   5.  Mission gate (if passport carries mission_ids)
//   6.  Inbound prompt-injection scan (DetectorService L1-L5)
//   7.  Credential retrieval (operator's anthropic/openai/openrouter conn)
//   8.  PII redaction on user messages (5.2.3)
//   9.  Reserve the maximum STACK gateway fee in the wallet
//   10. Forward via LlmGatewayService (streaming or non-streaming)
//   11. Outbound scan — body swap on non-streaming, per-event gate on
//       streaming (ahead of the bytes not after them)
//   12. Capture the exact fee, then emit audit + intent records
//
// Order-of-operations invariant: scan(user) → redact(user) → forward. STACK
// adds nothing to the customer's request: no system prompt, no extra message.
//
// Streaming path: when body.stream === true, set SSE headers and walk the
// upstream one complete event block at a time. Each block's assistant text
// is scanned BEFORE its bytes are written. On the verdict that redacts a
// non-streaming body (enforced mode, critical severity) the block is
// withheld, a `stack_leak_blocked` event replaces it and the stream ends;
// anything already written was scanned clean. Below that bar — and in
// logged/standard, where the contract is record-do-not-gate — bytes flow
// and a `stack_leak_warning` is appended at the tail as before.
//
// This is why forwardStreaming no longer tee()s. With a tee, the forward
// branch had already written the bytes by the time the parse branch knew
// what they said, so `stream: true` was a way around a control the
// non-streaming path enforced.

//
// Layout: this file registers the routes and composes the handler. Each stage
// of the gate sequence above is a module in ./llm-gateway/, in the order the
// handler calls them:
//
//   admit-call.ts            1-2   body, passport, authority decision
//   meter.ts                 0     the meter call
//   (here)                   3     Mission admission, before anything below
//   approval-gate.ts         3     approval gate, call-shape pin, reservation
//   scope-wall.ts            4-5   granted provider, scope wall
//   inbound-scan.ts          6     prompt-injection scan of untrusted text
//   pii-redaction.ts         8     PII redaction
//   billing-hold.ts          9     provider body, the fleet's reservation
//   credential-retrieval.ts  9     the only credential decryption
//   stream-forward.ts        10-12 streaming forward, scan, settle, record
//   direct-forward.ts        10-12 non-streaming forward, scan, settle, record
//   post-call-telemetry.ts   12    audit and intent records
//   usage-routes.ts                handlers for the two usage routes
//   openrouter/                    the OpenRouter passthrough, its own sequence (handler.ts)
//
// Registration order, auth hooks and the order of side effects are the
// contract: a stage may not run before the one above it.

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import {
  ForbiddenError,
  ImageNotSupportedError,
  OPENROUTER_REQUEST_MAX_BYTES,
  type LlmImageRequest,
} from '@stack/shared';
import { beginAgentRuntime } from '../lib/agent-runtime.js';
import { decideModelCall } from './llm-gateway/control-decision.js';
import { admitCall } from './llm-gateway/admit-call.js';
import { meterLlmCall } from './llm-gateway/meter.js';
import { enforceApprovalGate } from './llm-gateway/approval-gate.js';
import { enforceProviderScope } from './llm-gateway/scope-wall.js';
import { scanInboundMessages } from './llm-gateway/inbound-scan.js';
import { redactUserPii } from './llm-gateway/pii-redaction.js';
import { authorizeBillingHold } from './llm-gateway/billing-hold.js';
import { retrieveProviderCredential } from './llm-gateway/credential-retrieval.js';
import { forwardStreamingResponse } from './llm-gateway/stream-forward.js';
import { forwardDirectResponse } from './llm-gateway/direct-forward.js';
import { forwardImageResponse } from './llm-gateway/image-forward.js';
import { asChatCall, imageProviderBody, promptOf } from './llm-gateway/image-request.js';
import { listLlmUsage, summarizeLlmUsage } from './llm-gateway/usage-routes.js';
import {
  ANTHROPIC_CONFIG,
  OPENAI_CONFIG,
  OPENAI_IMAGES_CONFIG,
  type LlmHandlerConfig,
} from './llm-gateway/provider-configs.js';
import { makeOpenRouterHandler, type OpenRouterHandlerDeps } from './llm-gateway/openrouter/handler.js';

// Re-exported for the tests and scripts that import them from this module.
export {
  applyOpenRouterPriceCeiling,
  countImageInputs,
  maxOutputTokens,
  prepareProviderBody,
  unsupportedVariableCost,
} from './llm-gateway/request-shaping.js';
export { streamBillingErrorNote } from './llm-gateway/stream-forward.js';

export function registerLlmRoutes(app: FastifyInstance, services: Services, openRouter: OpenRouterHandlerDeps = {}) {
  const auth = createAuthMiddleware(services);

  const opts = { preHandler: auth };
  app.post('/v1/llm/anthropic/messages', opts, makeLlmHandler(services, ANTHROPIC_CONFIG));
  app.post('/v1/llm/openai/chat/completions', opts, makeLlmHandler(services, OPENAI_CONFIG));

  // Images on the customer's own key, through the same gates. Anthropic has no image endpoint: a clear refusal.
  app.post('/v1/llm/openai/images', opts, makeImageHandler(services, OPENAI_IMAGES_CONFIG));
  app.post('/v1/llm/anthropic/images', opts, anthropicImages);

  // OpenRouter: its whole API, any method, passed through. The routes live in a scope of their own because the body is
  // read as the bytes it came as (any content type, up to OPENROUTER_REQUEST_MAX_BYTES) and forwarded as it is, and
  // the caller is known before a byte of it is read: authentication is an `onRequest` hook here, not a `preHandler`.
  // The scope names its instance `app` like the other registrars, so the structural route scanners read these routes too.
  app.register(async (app) => {
    app.removeAllContentTypeParsers();
    app.addContentTypeParser('*', { parseAs: 'buffer', bodyLimit: OPENROUTER_REQUEST_MAX_BYTES }, (_request, body, done) => {
      done(null, body);
    });
    const options = { onRequest: auth, bodyLimit: OPENROUTER_REQUEST_MAX_BYTES, exposeHeadRoute: false };
    const handler = makeOpenRouterHandler(services, openRouter);
    // One path, every method OpenRouter's API uses: what comes after the prefix is OpenRouter's own.
    app.get('/v1/llm/openrouter/*', options, handler);
    app.post('/v1/llm/openrouter/*', options, handler);
    app.put('/v1/llm/openrouter/*', options, handler);
    app.patch('/v1/llm/openrouter/*', options, handler);
    app.delete('/v1/llm/openrouter/*', options, handler);
  });

  // Observability surface for the llm_usage rows written on every successful
  // POST above. Operator-scoped, read-only, unmetered; see usage-routes.ts.
  app.get('/v1/llm/usage', opts, async (request, reply) => listLlmUsage(services, request, reply));

  app.get('/v1/llm/usage/summary', opts, async (request, reply) => summarizeLlmUsage(services, request, reply));
}

function makeLlmHandler(services: Services, config: LlmHandlerConfig) {
  return async function llmHandler(request: FastifyRequest, reply: FastifyReply) {
    const start = Date.now();

    const call = await admitCall(services, request, config);
    await meterLlmCall(services, request, call.agentId);

    // Mission admission (lifecycle, Mission scope, caps): before the credential
    // is retrieved or the request is forwarded. One implementation, shared with
    // every other agent action: lib/agent-runtime.ts.
    const runtime = await beginAgentRuntime(services, request, { agentId: call.agentId, passportId: call.jti, producer: 'llm',
      // Verified once in admitCall on this request; not verified again.
      verifiedPassport: { token: call.passportToken, claims: call.claims },
      requestedService: config.provider, connectionId: call.authorityConnectionId, targetId: config.provider,
      action: config.action, normalizedRequest: call.normalizedRequest,
      denial: { intentType: 'http_call', namedIntent: config.namedIntent, parameters: { provider: config.provider, model: call.body.model ?? null } } });
    if (!runtime) throw new ForbiddenError('Passport must carry exactly one Mission to act');
    const fleetAdmission = runtime.fleet;

    const { gate, approvalIdHeader } = await enforceApprovalGate(services, request, config, call, fleetAdmission);
    const { carriedSources } = await enforceProviderScope(services, config, call);
    const agent = await scanInboundMessages(services, request, config, call);
    // The customer's decider, once per call (a stream included), before any hold or credential.
    await decideModelCall(services, request, config, call, runtime);
    const { redactedBody, piiHits } = await redactUserPii(services, request, config, call, agent);
    const hold = await authorizeBillingHold(services, config, call, fleetAdmission, redactedBody);
    const apiKey = await retrieveProviderCredential(services, request, config, call, hold);
    if (fleetAdmission) await services.fleetAdmission.dispatch(fleetAdmission);

    const forward = { services, request, reply, config, start, call, gate, approvalIdHeader, fleetAdmission, hold, apiKey, carriedSources, piiHits };
    if (call.isStreaming) {
      await forwardStreamingResponse(forward);
      return;
    }
    await forwardDirectResponse(forward);
  };
}

/**
 * An image on the customer's own OpenAI key: the same gates as a chat call, in the same order, to OpenAI's images
 * endpoint. STACK counts one action and nothing else (the provider bills the customer); the picture is saved to the
 * agent's drive and comes back marked untrusted. A fleet passport has no spend reservation to make for this and is
 * refused. (OpenRouter's images, like everything else it has, go through its passthrough.)
 */
export function makeImageHandler(services: Services, config: LlmHandlerConfig) {
  return async function imageHandler(request: FastifyRequest, reply: FastifyReply) {
    const start = Date.now();

    const call = await admitCall(services, request, config);
    if (call.claims.stk.fleet) throw new ForbiddenError('A fleet passport cannot make images on its own provider key');
    await meterLlmCall(services, request, call.agentId);

    const runtime = await beginAgentRuntime(services, request, { agentId: call.agentId, passportId: call.jti, producer: 'llm',
      verifiedPassport: { token: call.passportToken, claims: call.claims },
      requestedService: config.provider, connectionId: call.authorityConnectionId, targetId: config.provider,
      action: config.action, normalizedRequest: call.normalizedRequest,
      denial: { intentType: 'http_call', namedIntent: config.namedIntent, parameters: { provider: config.provider, model: call.body['model'] ?? null } } });
    if (!runtime) throw new ForbiddenError('Passport must carry exactly one Mission to act');

    const { gate, approvalIdHeader } = await enforceApprovalGate(services, request, config, call, null);
    const { carriedSources } = await enforceProviderScope(services, config, call);
    // The text stages read messages: the prompt is the one piece of text an image call carries.
    const asChat = asChatCall(call);
    const agent = await scanInboundMessages(services, request, config, asChat);
    await decideModelCall(services, request, config, call, runtime);
    const { redactedBody, piiHits } = await redactUserPii(services, request, config, asChat, agent);
    const input = call.body as LlmImageRequest;
    const providerBody = imageProviderBody(input, promptOf(redactedBody, input.prompt));
    const apiKey = await retrieveProviderCredential(services, request, config, call, null);

    await forwardImageResponse({
      services, request, reply, config, start, call, gate, approvalIdHeader, fleetAdmission: null,
      apiKey, carriedSources, piiHits, providerBody, asked: input.n ?? 1,
    });
  };
}

/** Anthropic has no image generation endpoint: a clear refusal, before anything is read or counted. */
export async function anthropicImages(): Promise<never> {
  throw new ImageNotSupportedError(
    'anthropic',
    'Anthropic has no image generation endpoint. Make the image on OpenAI (POST /v1/llm/openai/images) with your own key, or on OpenRouter (POST /v1/llm/openrouter/images, with OpenRouter\'s own request body).',
  );
}
