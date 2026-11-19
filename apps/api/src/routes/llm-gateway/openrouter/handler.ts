// The OpenRouter passthrough: every endpoint of OpenRouter's API under `/v1/llm/openrouter/*`, any method, to
// `https://openrouter.ai/api/v1/*`, with the body and the answer as they are (streams included).
//
// Whose key it runs on is decided as it always was: an agent account's agent runs on STACK's own key and is charged what
// OpenRouter reports the call cost; every other agent runs on its operator's own OpenRouter connection, which OpenRouter
// bills, and STACK counts one action.
//
// Gate sequence, in order (a stage never runs before the one above it):
//   1. The call: path, query, body. The path stays below the one API base; the host is fixed.
//   2. Passport, whose key it runs on, which endpoints that key reaches (policy.ts), the runtime authority.
//   3. The meter: one action per call.
//   4. Mission admission, before anything that costs or sends.
//   5. The approval gate and the scope wall (the granted provider, the data-flow rule).
//   6. The customer's decider (`model.call`, with the held amount), for every call that is not a read. A call whose answer
//      is saved to the drive then passes the drive's own gates (its Mission admission and the `drive.upload` decider).
//   7. On STACK's key, the hold: the call's worst case from the model's listed prices and the request, or an estimate from
//      those prices and named assumptions where that cannot be worked out (hold-size.ts); never a refusal for want of a
//      price. The caller's `X-Max-Cost-Cents` lowers the hold to it.
//   8. The credential, read only now. The call.
//   9. The answer, passed on as it comes. Then, before it ends: the charge (the cost OpenRouter reported: the rest of the
//      hold given back, or a cost above the hold taken from the wallet at once), the data trail, the audit and the signed
//      record.
//
// Redaction is a controls feature: with the owner's controls on, the user and tool messages of a JSON body are redacted
// (unless the agent's flag or the account's switch is off), with the same service as the other model routes; without controls
// nothing is redacted. A body with nothing to redact is forwarded byte for byte.
//
// Not here, by decision: STACK's system prompt and the prompt-injection scans of a chat body. The rest of the body and the
// answer are the agent's own, untouched.

import { z } from 'zod';
import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  ForbiddenError,
  NotFoundError,
  SpendSettlementPendingError,
  OPENROUTER_VIDEO_JOB_ID,
  StackError,
  reasoningBudgetTokens,
  requestedOutputTokens,
  safeErrorSummary,
  type LlmCostBreakdown,
} from '@stack/shared';
import type { Services } from '../../../config/services.js';
import { beginAgentRuntime } from '../../../lib/agent-runtime.js';
import { decideControl } from '../../../lib/control-decision.js';
import { controlTargets, usdAmount } from '../../../lib/control-socket/targets.js';
import { llmResponseText, recordLlmResponseProvenance } from '../../../lib/provenance.js';
import {
  completeRuntimeAuthorityUse,
  isEnforcedRuntimeAuthority,
  markRuntimeAuthorityDispatched,
  runtimeAuthorityFailureResult,
} from '../../../lib/runtime-authority.js';
import { releaseRequestEnd } from '../../../middleware/request-end.js';
import { admitCaller } from '../admit-call.js';
import { enforceApprovalGate } from '../approval-gate.js';
import { readCostCap } from '../billing-hold.js';
import { retrieveProviderCredential } from '../credential-retrieval.js';
import { meterLlmCall } from '../meter.js';
import { writePostCallTelemetry } from '../post-call-telemetry.js';
import { redactUserPii } from '../pii-redaction.js';
import type { LlmHandlerConfig } from '../provider-configs.js';
import { enforceProviderScope } from '../scope-wall.js';
import type { AdmittedCall } from '../types.js';
import { holdSizeFor } from './hold-size.js';
import { streamDelivery, type FinalizeInput, type FinalizeResult, type HoldMode } from './delivery.js';
import { endpointGate, holdsOnStackKey, isRead, labelsOf } from './policy.js';
import { isJsonType, readOpenRouterCall, type OpenRouterCall } from './request.js';
import { requestedDelivery } from './save-output.js';
import { ResponseTap, type TapResult } from './tap.js';
import { callOpenRouter, type FetchLike, type UpstreamAnswer } from './upstream.js';

export interface OpenRouterHandlerDeps {
  /** The call to OpenRouter; the global `fetch` unless a test supplies its own. */
  fetchImpl?: FetchLike;
}

const SAVED_FOR_RETRY = 'STACK saved this charge for retry. The wallet hold remains reserved.';
const NOT_SETTLED = 'STACK could not settle this call. The wallet hold was not released.';

/**
 * The output limit a body names, for the customer's decider: the largest of the chat, completions and Responses API limits, plus
 * the reasoning budget it names, as the hold counts them.
 */
function outputLimit(body: Record<string, unknown>): number | null {
  const requested = requestedOutputTokens(body);
  return requested === null ? null : requested + reasoningBudgetTokens(body);
}

/** Chat, Responses, embeddings and the rest name their model in the body; most endpoints of the API name none. */
function modelOf(body: Record<string, unknown>): string {
  return typeof body['model'] === 'string' ? body['model'] : '';
}

/** The id a video job starts under: the `id` of the 202 answer (OpenRouter documents ids such as `y34x1YREG4Pkdcj7f02v`). */
function videoJobId(call: OpenRouterCall, status: number, tap: TapResult): string | null {
  if (call.method !== 'POST' || call.match?.endpoint.path !== '/videos' || status < 200 || status >= 300) return null;
  const id = tap.json && typeof tap.json === 'object' ? (tap.json as Record<string, unknown>)['id'] : null;
  return typeof id === 'string' && OPENROUTER_VIDEO_JOB_ID.test(id) ? id : null;
}

/** The video job a call started, in the shape the account's billing keeps it. */
function jobOf(call: OpenRouterCall, status: number, tap: TapResult): { kind: 'video_job'; id: string } | null {
  const id = videoJobId(call, status, tap);
  return id ? { kind: 'video_job', id } : null;
}

/** The most of a refusal's body read to tell whether it is about STACK's key; larger, it is passed on as it is. */
const REFUSAL_PEEK_BYTES = 64 * 1024;

/**
 * Whether a 403 is OpenRouter refusing STACK's key itself (its credit limit or a budget on it, `error.metadata.limit_source`),
 * rather than the request (a moderation flag or a guardrail, which the agent should read). The body is read only up to
 * `REFUSAL_PEEK_BYTES`; the answer handed back passes on every byte that was read.
 */
async function keyRefusal(answer: UpstreamAnswer): Promise<{ keyRefused: boolean; answer: UpstreamAnswer }> {
  if (!answer.body) return { keyRefused: false, answer };
  const iterator = answer.body[Symbol.asyncIterator]();
  const read: Uint8Array[] = [];
  let size = 0;
  let done = false;
  while (size < REFUSAL_PEEK_BYTES) {
    const next = await iterator.next();
    if (next.done) { done = true; break; }
    read.push(next.value);
    size += next.value.byteLength;
  }
  let keyRefused = false;
  if (done) {
    try {
      const parsed = JSON.parse(Buffer.concat(read).toString('utf8')) as { error?: { metadata?: { limit_source?: unknown } } };
      const source = parsed?.error?.metadata?.limit_source;
      // Any limit OpenRouter names is a limit on STACK's own account or key, never the agent's to read.
      keyRefused = typeof source === 'string' && source.length > 0;
    } catch {
      keyRefused = false;
    }
  }
  const body: AsyncIterable<Uint8Array> = {
    async *[Symbol.asyncIterator]() {
      yield* read;
      if (done) return;
      for (;;) {
        const next = await iterator.next();
        if (next.done) return;
        yield next.value;
      }
    },
  };
  return { keyRefused, answer: { ...answer, body } };
}

/** An answer of STACK's own key's account (no credit, a revoked key, a limit) is STACK's to carry, never the agent's to read. */
function providerUnavailable(): StackError {
  return new StackError(
    "This service is briefly unavailable on STACK's side. Nothing was charged and your budget is unchanged; retry in a few minutes.",
    'PROVIDER_CAPACITY_UNAVAILABLE',
    503,
    { provider: 'openrouter' },
    { stackSide: true },
  );
}

/**
 * With controls on, redacts the user and tool messages of a JSON body in place (the call's bytes and the admitted body both),
 * returning the audit's `pii_hits` (-1: redaction skipped). A body with no hit is left exactly as the caller sent it.
 */
async function redactCallBody(
  services: Services,
  request: FastifyRequest,
  call: OpenRouterCall,
  admitted: AdmittedCall,
): Promise<number | null> {
  if (call.rawBody === null || !isJsonType(call.contentType)) return null;
  const agent = await services.agent.getById(admitted.agentId, admitted.operatorId);
  if (!agent) throw new NotFoundError('agent', admitted.agentId);
  const { redactedBody, piiHits } = await redactUserPii(services, request, { provider: 'openrouter' }, admitted, agent);
  if (piiHits > 0) {
    call.body = redactedBody;
    call.rawBody = Buffer.from(JSON.stringify(redactedBody), 'utf8');
    admitted.body = redactedBody;
  }
  return piiHits;
}

export function makeOpenRouterHandler(services: Services, deps: OpenRouterHandlerDeps = {}) {
  return async function openRouterHandler(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const start = Date.now();
    const call = readOpenRouterCall(request);
    // The caller hanging up stops a STREAMED call to OpenRouter at any point, including while OpenRouter has not answered yet;
    // any other call runs to its end. The close is read from the start of the request: a listener added later never hears a
    // close that has already happened.
    const hangup = new AbortController();
    let streamedCall = false;
    let callerLeft = false;
    const onHangup = () => {
      if (reply.raw.writableEnded) return;
      callerLeft = true;
      if (streamedCall) hangup.abort();
    };
    reply.raw.once('close', onHangup);
    if (reply.raw.destroyed) onHangup();
    // Chosen before anything is sent, held or counted: a request for a place to save the answer that this deployment does
    // not have is refused here, not after the call has run.
    const delivery = requestedDelivery(services, request) ?? streamDelivery;
    const { action, namedIntent } = labelsOf(call);
    const config: LlmHandlerConfig = {
      provider: 'openrouter',
      schema: z.unknown(),
      action,
      namedIntent,
      upstreamUrl: `${call.upstream.origin}${call.upstream.pathname}`,
    };

    const admitted = await admitCaller(services, request, config, {
      body: call.body,
      method: call.method,
      upstream: call.upstream,
      allowOn: endpointGate(services, call),
    });
    const { operatorId, agentId, jti, missionRef, modelAccess, authorityDecision } = admitted;
    const account = modelAccess.kind === 'account' ? modelAccess : null;
    streamedCall = admitted.isStreaming;
    if (streamedCall && callerLeft) hangup.abort();
    // A cap sizes the hold on STACK's key; the customer's own key has no hold for it to size, so the header is ignored there.
    const cap = account ? readCostCap(request) : null;
    await meterLlmCall(services, request, agentId);

    const state = { hijacked: false };
    let hold: Awaited<ReturnType<Services['modelAccessPolicy']['hold']>> | null = null;
    try {
      // Mission admission (lifecycle, Mission scope, caps): before the credential is read or anything is sent.
      const runtime = await beginAgentRuntime(services, request, {
        agentId, passportId: jti, producer: 'llm',
        // Verified once in admitCaller on this request; not verified again.
        verifiedPassport: { token: admitted.passportToken, claims: admitted.claims },
        requestedService: config.provider, connectionId: admitted.authorityConnectionId, targetId: config.provider,
        action, normalizedRequest: admitted.normalizedRequest,
        denial: { intentType: 'http_call', namedIntent, parameters: { provider: config.provider, model: admitted.body['model'] ?? null, endpoint: call.path } },
      });
      if (!runtime) throw new ForbiddenError('Passport must carry exactly one Mission to act');
      const fleetAdmission = runtime.fleet;

      const { gate, approvalIdHeader } = await enforceApprovalGate(services, request, config, admitted, fleetAdmission);
      const { carriedSources } = await enforceProviderScope(services, config, admitted);

      const piiHits = await redactCallBody(services, request, call, admitted);

      const size = account && holdsOnStackKey(call) ? await holdSizeFor(services, call, cap) : null;
      const heldCents = size?.heldCents ?? null;
      // The customer's decider, once per call that is not a read, before any hold or credential, with what the call can cost.
      if (!isRead(call)) {
        await decideControl(services, request, {
          action: 'model.call',
          scope: 'agent',
          agentId,
          runtime,
          target: controlTargets.modelCall({
            provider: config.provider,
            model: admitted.body['model'],
            stream: admitted.isStreaming,
            maxOutputTokens: outputLimit(admitted.body),
          }),
          // The decider is shown what is held: the worst case or estimate, lowered to the caller's cap when that is below.
          ...(size !== null ? { amount: usdAmount(size.heldCents) } : {}),
        });
      }
      // A delivery that saves the answer somewhere of the caller's own (the drive) runs that place's gates before anything is held.
      if (delivery.admit) await delivery.admit({ services, request, operatorId, agentId });
      if (account && heldCents !== null) {
        hold = await services.modelAccessPolicy.hold({
          operatorId,
          accountId: account.accountId,
          missionId: missionRef,
          provider: config.provider,
          model: modelOf(admitted.body),
          heldCents,
        });
      }
      let answer: UpstreamAnswer;
      try {
        if (fleetAdmission) await services.fleetAdmission.reserve(fleetAdmission);
        const apiKey = account
          ? services.modelAccessPolicy.stackKey(account)
          : await retrieveProviderCredential(services, request, config, admitted, null);
        if (fleetAdmission) await services.fleetAdmission.dispatch(fleetAdmission);
        await markRuntimeAuthorityDispatched(services.authority, operatorId, authorityDecision);

        answer = await callOpenRouter({
          call, apiKey, incomingHeaders: request.headers, signal: hangup.signal,
          ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
        });
        if (account && answer.status === 403) {
          const peeked = await keyRefusal(answer);
          answer = peeked.answer;
          if (peeked.keyRefused) {
            answer.cancel();
            request.log.error({ status: answer.status }, '[openrouter] STACK key limit reached at OpenRouter');
            throw providerUnavailable();
          }
        }
        if (account && (answer.status === 401 || answer.status === 402)) {
          // STACK's own key was refused or is out of credit: the agent is told it is STACK's to carry, nothing of the key's state.
          answer.cancel();
          request.log.error({ status: answer.status }, '[openrouter] STACK key refused by OpenRouter');
          throw providerUnavailable();
        }
      } catch (err) {
        // The call never ran: the hold is given back. Once it has run, settling it is what gives back or charges the hold.
        if (hold) await services.modelAccessPolicy.release(operatorId, hold).catch(() => undefined);
        throw err;
      }

      const success = answer.status >= 200 && answer.status < 400;
      const tap = new ResponseTap({
        contentType: answer.contentType,
        generationIdHeader: answer.generationIdHeader,
        wantText: success && carriedSources.length > 0,
      });
      const holdMode: HoldMode = isEnforcedRuntimeAuthority(authorityDecision)
        ? 'whole'
        : success && carriedSources.length > 0 ? 'if_small' : 'no';

      const finalize = async (input: FinalizeInput): Promise<FinalizeResult> => {
        const result = tap.result();
        let billingNote: string | undefined;
        let recordedCost: LlmCostBreakdown | null = null;
        // The charge first: whatever came back, the call ran, and what OpenRouter reports it cost is owed. A caller that hung up
        // on a streamed call before any generation id or cost was known is charged for the tokens its answer showed, at the
        // catalogue price; with no usage at all the hold is released and nothing is charged.
        try {
          if (hold !== null && input.callerLeft && result.generationId === null && result.usage?.provider_cost_usd === undefined) {
            await services.accountModelBilling.retrySettlement({ ...retryOf(admitted), operatorId, hold, generationId: null, streaming: admitted.isStreaming, usage: result.usage });
          } else {
            recordedCost = await settle(services, { call, admitted, hold, status: answer.status, result, callerLeft: input.callerLeft === true });
          }
        } catch (err) {
          request.log.error({ err: safeErrorSummary(err) }, '[openrouter] settlement failed');
          // The call ran at OpenRouter: a charge saved for retry stands, and any other failure of STACK's own settlement goes to
          // the retry that reads the cost from OpenRouter's record of the generation, which charges the tokens it showed at the
          // catalogue price if the cost never resolves, and gives the hold back only when no usage is known.
          const retried = !(err instanceof SpendSettlementPendingError) && hold !== null
            && await services.accountModelBilling.retrySettlement({
              ...retryOf(admitted), operatorId, hold, generationId: result.generationId, job: jobOf(call, answer.status, result),
              streaming: admitted.isStreaming, usage: result.usage,
            }).then(() => true, (error: unknown) => {
              request.log.error({ err: safeErrorSummary(error) }, '[openrouter] settlement could not be saved for retry');
              return false;
            });
          if (!retried) {
            // An answer not yet sent is withheld (the caller can retry); a stream already out says so on the stream.
            if (!input.bytesAlreadySent) throw err;
            billingNote = err instanceof SpendSettlementPendingError ? SAVED_FOR_RETRY : NOT_SETTLED;
          }
        }
        // The answer inherits the sources its call carried, recorded before the agent has all of it.
        if (success && carriedSources.length > 0) {
          await recordLlmResponseProvenance(services, {
            operatorId, agentId, passportJti: jti, missionId: missionRef,
            sources: carriedSources, text: result.json ? llmResponseText(result.json) : result.text, provider: config.provider,
            mode: admitted.mode, bytesAlreadySent: input.bytesAlreadySent,
          });
        }
        const authorityClaimRefs = await writePostCallTelemetry({
          services, request, config, start, success,
          body: admitted.body,
          responseStr: result.sample,
          responseBytes: result.bytes,
          responseStatus: answer.status,
          usage: result.usage,
          claims: admitted.claims, jti, agentId, operatorId, mode: admitted.mode,
          missionIds: admitted.missionIds, missionRef, gate, approvalIdHeader,
          // The audit row's entropy is read from the first 64 KiB of what the caller sent, its size from the whole.
          requestBodyStr: call.rawBody ? call.rawBody.subarray(0, 64 * 1024).toString('latin1') : '',
          requestBytes: call.rawBody?.length ?? 0,
          piiHits,
          recordedCost,
          stackKey: account !== null,
        });
        await completeRuntimeAuthorityUse(
          services.authority, operatorId, authorityDecision, success ? 'succeeded' : 'failed',
          {
            status: answer.status,
            headers: { 'content-type': answer.contentType },
            ...(input.held ? { body_base64: input.held.toString('base64') } : { bytes: result.bytes }),
          },
          authorityClaimRefs,
        );
        if (fleetAdmission) await services.fleetAdmission.finish(fleetAdmission);
        return billingNote ? { billingNote } : {};
      };

      await delivery({
        request, reply, answer, call,
        caller: { operatorId, agentId, missionId: missionRef, passportJti: jti, ...(admitted.mode ? { accountability: admitted.mode } : {}) },
        hold: holdMode,
        abortOnHangup: admitted.isStreaming,
        onChunk: (chunk) => tap.push(chunk),
        finalize,
        state,
      });
    } catch (err) {
      try {
        await completeRuntimeAuthorityUse(services.authority, operatorId, authorityDecision, 'failed', runtimeAuthorityFailureResult(err));
      } catch (finalizationError) {
        request.log.error(
          { code: (finalizationError as { code?: unknown })?.code ?? 'AUTHORITY_FINALIZATION_FAILED' },
          '[authority] failed to finalize OpenRouter failure',
        );
      }
      throw err;
    } finally {
      reply.raw.off('close', onHangup);
      if (state.hijacked) await releaseRequestEnd(request, reply.raw.statusCode);
    }
  };
}

/**
 * The charge for a finished call. On STACK's key: the account's billing settles it (the reported cost, a lookup of it
 * later, or the hold). On the customer's own key: nothing is charged, and a call that
 * reported usage is recorded for the usage list.
 */
/** The call's own identity, for the usage row a settlement that failed writes when it is priced from the call's tokens. */
function retryOf(admitted: AdmittedCall) {
  return { agentId: admitted.agentId, passportJti: admitted.jti, missionId: admitted.missionRef, model: modelOf(admitted.body) };
}

async function settle(
  services: Services,
  input: {
    call: OpenRouterCall;
    admitted: AdmittedCall;
    hold: Awaited<ReturnType<Services['modelAccessPolicy']['hold']>> | null;
    status: number;
    result: TapResult;
    /** The caller hung up: a call left to the retry whose cost never resolves is charged from its tokens, or released when it showed none. */
    callerLeft: boolean;
  },
): Promise<LlmCostBreakdown | null> {
  const { call, admitted, hold, status, result } = input;
  const { operatorId, agentId, jti, missionRef, body } = admitted;
  const model = modelOf(body);
  const success = status >= 200 && status < 300;
  const streaming = admitted.isStreaming;
  if (hold) {
    const jobId = videoJobId(call, status, result);
    const settled = await services.accountModelBilling.settleCall({
      operatorId, agentId, passportJti: jti, missionId: missionRef, model,
      status, usage: result.usage, generationId: result.generationId,
      ...(jobId ? { job: { kind: 'video_job' as const, id: jobId } } : {}),
      streaming, authorization: hold,
      ...(input.callerLeft ? { releaseIfUnresolved: true } : {}),
    });
    return settled.cost;
  }
  if (call.method === 'POST' && success && result.usage) {
    const authorization = await services.llmUsage.authorizeGateway({
      operatorId, provider: 'openrouter', model, requestBytes: 0, maxOutputTokens: null, completionCount: 1, imageCount: 0,
    });
    const recorded = await services.llmUsage.record({
      operatorId, agentId, passportJti: jti, missionId: missionRef, provider: 'openrouter', model,
      usage: result.usage, streaming, authorization,
    });
    return recorded.cost;
  }
  return null;
}
