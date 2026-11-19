// Non-streaming forward stage. Forwards the call, scans the full response
// body (and swaps it for a refusal envelope when the detector says so),
// settles the wallet hold, then writes the audit and intent records and
// replies.

import type { LlmCostBreakdown } from '@stack/shared';
import {
  completeRuntimeAuthorityUse,
  markRuntimeAuthorityDispatched,
  runtimeAuthorityFailureResult,
} from '../../lib/runtime-authority.js';
import { llmResponseText, recordLlmResponseProvenance } from '../../lib/provenance.js';
import { writePostCallTelemetry } from './post-call-telemetry.js';
import { releaseBillingHold } from './billing-hold.js';
import type { ForwardContext } from './types.js';

export async function forwardDirectResponse(ctx: ForwardContext): Promise<void> {
  const {
    services, request, reply, config, start, call, gate, approvalIdHeader,
    hold, apiKey, carriedSources, piiHits,
  } = ctx;
  const {
    body, claims, jti, agentId, operatorId, mode, missionIds, missionRef, authorityDecision,
  } = call;
  const { providerBody, requestBodyStr } = hold;
  await markRuntimeAuthorityDispatched(services.authority, operatorId, authorityDecision);
  try {
  let result;
  try {
    result = await services.llmGateway.forward({
      provider: config.provider,
      apiKey,
      body: providerBody,
    });
  } catch (err) {
    await releaseBillingHold(services, operatorId, hold).catch(() => {});
    throw err;
  }

  // 11 (non-streaming). outbound scan — mirror of
  //     proxy.ts:556-570. scanOutput runs the L6 detector chain
  //     (prompt_injection_output + leak patterns) on the FULL
  //     response body. On enforced-mode + critical verdict, returns
  //     a refusal envelope as `redactedBody`; we swap the response
  //     body before returning to the caller. Logged + standard modes
  //     record the event but forward unchanged.
  //
  //     Whole-body swap (not just assistant message content) matches
  //     proxy.ts. Per-provider content-only redaction is backlog v1.1.
  const preRedactBodyStr = typeof result.body === 'string'
    ? result.body
    : JSON.stringify(result.body ?? '');
  const outScanResult = await services.detector.scanOutput({
    ctx: { operatorId, agentId, passportJti: jti, mode, tier: request.operatorTier },
    body: preRedactBodyStr,
    headers: {},
    metadata: {
      response_status: result.status,
      request_service: config.provider,
      request_method: 'POST',
      model: body.model,
    },
  });
  if (outScanResult.redactedBody !== null) {
    result.body = outScanResult.redactedBody;
  }

  // Recompute response string after potential redaction so the audit
  // log records what STACK actually returned to the caller (not the
  // unredacted upstream response).
  const responseStr = JSON.stringify(result.body);
  const success = result.status >= 200 && result.status < 400;
  let recordedCost: LlmCostBreakdown | null = null;
  if (success && result.usage) {
    const recorded = await services.llmUsage.record({
      operatorId,
      agentId,
      passportJti: jti,
      missionId: missionRef,
      provider: config.provider,
      model: typeof body.model === 'string' ? body.model : '',
      usage: result.usage,
      streaming: false,
      authorization: hold.authorization,
    });
    recordedCost = recorded.cost;
  } else {
    await releaseBillingHold(services, operatorId, hold);
  }

  // The response inherits the sources its prompt carried: a summary that
  // copies the bank's figures is still bank data. Recorded before the agent
  // receives it. A model call is a write, so with controls on a failure to
  // record withholds the response (503); with controls off it only alarms.
  if (success) {
    await recordLlmResponseProvenance(services, {
      operatorId, agentId, passportJti: jti, missionId: missionRef,
      sources: carriedSources, text: llmResponseText(result.body), provider: config.provider,
      mode, bytesAlreadySent: false,
    });
  }

  // 12. Audit + intent_claim/outcome producer (synchronous on non-streaming).
  const authorityClaimRefs = await writePostCallTelemetry({
    services,
    request,
    config,
    start,
    success,
    body,
    responseStr,
    responseStatus: result.status,
    usage: result.usage,
    claims,
    jti,
    agentId,
    operatorId,
    mode,
    missionIds,
    missionRef,
    gate,
    approvalIdHeader,
    requestBodyStr,
    piiHits,
    recordedCost,
  });

  await completeRuntimeAuthorityUse(
    services.authority,
    operatorId,
    authorityDecision,
    success ? 'succeeded' : 'failed',
    { status: result.status, body: result.body },
    authorityClaimRefs,
  );

  reply.status(result.status).send(result.body);
  } catch (err) {
    try {
      await completeRuntimeAuthorityUse(
        services.authority,
        operatorId,
        authorityDecision,
        'failed',
        runtimeAuthorityFailureResult(err),
      );
    } catch (finalizationError) {
      request.log.error(
        { code: (finalizationError as { code?: unknown })?.code ?? 'AUTHORITY_FINALIZATION_FAILED' },
        '[authority] failed to finalize LLM failure',
      );
    }
    throw err;
  }
}
