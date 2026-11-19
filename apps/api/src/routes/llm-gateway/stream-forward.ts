// Streaming forward stage (body.stream === true). Opens the upstream stream,
// scans every event block BEFORE its bytes are written, settles the wallet
// hold, then writes the audit and intent records. When the runtime authority
// is enforced, the bytes are withheld until the authority record is durable.

import { SpendSettlementPendingError, StackError, safeErrorSummary, type LlmCostBreakdown } from '@stack/shared';
import {
  completeRuntimeAuthorityUse,
  isEnforcedRuntimeAuthority,
  markRuntimeAuthorityDispatched,
  runtimeAuthorityFailureResult,
} from '../../lib/runtime-authority.js';
import { llmResponseText, recordLlmResponseProvenance } from '../../lib/provenance.js';
import { holdRequestEnd, releaseRequestEnd } from '../../middleware/request-end.js';
import { writePostCallTelemetry } from './post-call-telemetry.js';
import { releaseBillingHold } from './billing-hold.js';
import type { ForwardContext } from './types.js';

/** How much of a streamed response is read for the data trail. */
const PROVENANCE_TEXT_CHARS = 64 * 1024;

export function streamBillingErrorNote(err: unknown): string {
  return err instanceof SpendSettlementPendingError
    ? 'STACK saved this charge for retry. The wallet hold remains reserved.'
    : 'STACK could not settle this call. The wallet hold was not released.';
}

export async function forwardStreamingResponse(ctx: ForwardContext): Promise<void> {
  const {
    services, request, reply, config, start, call, gate, approvalIdHeader,
    fleetAdmission, hold, apiKey, carriedSources, piiHits,
  } = ctx;
  const {
    body, claims, jti, agentId, operatorId, mode, missionIds, missionRef, authorityDecision,
  } = call;
  const { providerBody, requestBodyStr } = hold;
  const bufferUntilAuthorityFinalized = isEnforcedRuntimeAuthority(authorityDecision);
  await markRuntimeAuthorityDispatched(services.authority, operatorId, authorityDecision);
  // A hijacked reply is not Fastify's to end: neither the response finishing
  // nor the client leaving says this call is over, because the settlement, the
  // approval's consumption and the records go on after the last byte (or
  // after the client is gone: the upstream stream is still read to its end and
  // priced). The request's end hooks (meter refund, control settle, approval
  // release, fleet admission) run when this function is done, with the status
  // the answer really had, however it ended.
  let hijacked = false;
  const hijackReply = () => {
    hijacked = true;
    holdRequestEnd(request);
    reply.hijack();
  };
  try {
  let streamed;
  try {
    streamed = await services.llmGateway.forwardStreaming({
      provider: config.provider,
      apiKey,
      body: providerBody,
    });
  } catch (err) {
    await releaseBillingHold(services, operatorId, hold).catch(() => {});
    throw err;
  }
  const { events, usage: readUsage, status } = streamed;

  const bufferedResponseChunks: Buffer[] = [];
  let bufferedResponseBytes = 0;
  const MAX_AUTHORITY_STREAM_BYTES = 16 * 1024 * 1024;
  const emitStreamChunk = (chunk: string | Uint8Array) => {
    const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk);
    if (bufferUntilAuthorityFinalized) {
      bufferedResponseBytes += bytes.byteLength;
      if (bufferedResponseBytes > MAX_AUTHORITY_STREAM_BYTES) {
        throw new StackError(
          'Authority-protected streamed response exceeds the safe evidence buffer limit',
          'AUTHORITY_STREAM_RESPONSE_TOO_LARGE',
          502,
        );
      }
      bufferedResponseChunks.push(bytes);
    } else reply.raw.write(bytes);
  };
  if (!bufferUntilAuthorityFinalized) {
    reply.raw.statusCode = status;
    reply.raw.setHeader('content-type', 'text/event-stream');
    reply.raw.setHeader('cache-control', 'no-cache');
    reply.raw.setHeader('connection', 'keep-alive');
    hijackReply();
  }

  // 11 (streaming). — the scan runs AHEAD OF THE FIRST BYTE of
  // each event block, not after the stream closes.
  //
  // It used to run at the end, on text the client had already received in
  // full, and append a `stack_leak_warning` event. A warning about bytes
  // that already left is a notice, not a control: on the non-streaming
  // path the same detector REDACTS the body in enforced mode, so the two
  // paths gave opposite answers to the same leak and `stream: true` was
  // the way around the stricter one.
  //
  // Now each block is held until whole, its text scanned, and the bytes
  // written only if the scan lets them. On the verdict that would have
  // redacted a non-streaming body (enforced mode, critical severity), the
  // block is withheld, a `stack_leak_blocked` event goes out in its place
  // and the stream ends. Blocks already written were scanned clean.
  //
  // Everything below critical, and every non-enforced mode, keeps the old
  // behaviour exactly: bytes flow, the security event is recorded, and the
  // warning is appended at the end. That is deliberate — `logged` means
  // record and do not gate.
  //
  // Scanning is windowed: each pass sees the tail of what was already
  // scanned plus the new text, so a pattern straddling a block boundary is
  // still caught without re-scanning the whole transcript per block. The
  // incremental passes run dryRun so one leak produces one security event,
  // not one per block from the leak onward.
  const SCAN_WINDOW_CHARS = 2048;
  let scanWindow = '';
  let fullText = '';
  let streamLeakWarning: { redacted_body: unknown } | null = null;
  let blocked = false;
  let scanFired = false;

  try {
    for await (const event of events) {
      if (event.text) {
        fullText += event.text;
        scanWindow = (scanWindow + event.text).slice(-SCAN_WINDOW_CHARS);
        if (!scanFired) {
          const probe = await services.detector.scanOutput({
            ctx: { operatorId, agentId, passportJti: jti, mode, tier: request.operatorTier },
            body: scanWindow,
            headers: {},
            dryRun: true,
          });
          if (probe.match) {
            scanFired = true;
            // Re-run without dryRun so the security event is recorded once,
            // with the full text as evidence rather than the window.
            const recorded = await services.detector.scanOutput({
              ctx: { operatorId, agentId, passportJti: jti, mode, tier: request.operatorTier },
              body: fullText,
              headers: {},
              metadata: {
                response_status: status,
                request_service: config.provider,
                request_method: 'POST',
                model: body.model,
                streaming: true,
                scanned_before_send: true,
              },
            });
            if (recorded.redactedBody !== null) {
              blocked = true;
              streamLeakWarning = { redacted_body: recorded.redactedBody };
              emitStreamChunk(
                `event: stack_leak_blocked\ndata: ${JSON.stringify({
                  type: 'leak_blocked',
                  redacted_body: recorded.redactedBody,
                  note:
                    'STACK detected a leak in the next chunk of this response and refused to forward it. The stream ends here. Content delivered before this point was scanned and clean.',
                })}\n\n`,
              );
              break;
            }
            streamLeakWarning = { redacted_body: null };
          }
        }
      }
      emitStreamChunk(event.bytes);
    }
  } catch (err) {
    if (bufferUntilAuthorityFinalized) throw err;
    request.log.error({ err: safeErrorSummary(err) }, '[LLM] stream forward error');
  }

  // A match that did not warrant blocking still gets its end-of-stream
  // notice, unchanged from before.
  try {
    if (scanFired && !blocked) {
      emitStreamChunk(
        `event: stack_leak_warning\ndata: ${JSON.stringify({
          type: 'leak_detected',
          note:
            'STACK detected a potential leak in the streamed content. The stream completed normally; this warning is appended for operator awareness.',
        })}\n\n`,
      );
    }
  } catch (err) {
    request.log.error({ err: safeErrorSummary(err) }, '[LLM] stream warning emission failed');
  }

  // After stream closes: usage + audit + intent_claim/outcome
  // (fire-and-forget — the response was already sent).
  const usage = readUsage();
  const success = status >= 200 && status < 400;
  let recordedCost: LlmCostBreakdown | null = null;
  if (success && usage) {
    try {
      const recorded = await services.llmUsage.record({
        operatorId,
        agentId,
        passportJti: jti,
        missionId: missionRef,
        provider: config.provider,
        model: typeof body.model === 'string' ? body.model : '',
        usage,
        streaming: true,
        authorization: hold.authorization,
      });
      recordedCost = recorded.cost;
    } catch (err) {
      request.log.error({ err: safeErrorSummary(err) }, '[LLM] stream settlement failed');
      if (bufferUntilAuthorityFinalized) throw err;
      try {
        emitStreamChunk(
          `event: stack_billing_error\ndata: ${JSON.stringify({
            type: 'billing_error',
            note: streamBillingErrorNote(err),
          })}\n\n`,
        );
      } catch {
        // The client can close the socket before settlement completes.
      }
    }
  } else {
    await releaseBillingHold(services, operatorId, hold).catch((err) => {
      request.log.error({ err: safeErrorSummary(err) }, '[LLM] stream hold release failed');
    });
  }
  // The response inherits the sources its prompt carried, recorded before the
  // stream closes. Unbuffered bytes have already reached the client, so a
  // failure there can only alarm; a buffered (authority) response is still
  // withheld on failure when controls are on. The text is bounded like a
  // proxied response's fingerprints: past the bound it is not recorded.
  if (success) {
    await recordLlmResponseProvenance(services, {
      operatorId, agentId, passportJti: jti, missionId: missionRef,
      sources: carriedSources, text: llmResponseText(fullText.slice(0, PROVENANCE_TEXT_CHARS)), provider: config.provider,
      mode, bytesAlreadySent: !bufferUntilAuthorityFinalized,
    });
  }
  const telemetryArgs = {
    services,
    request,
    config,
    start,
    success: bufferUntilAuthorityFinalized ? success && !blocked : success,
    body,
    responseStr: streamLeakWarning
      ? JSON.stringify({ stream_leak_warning: { ...streamLeakWarning, blocked } })
      : '',
    responseStatus: status,
    usage,
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
  };
  if (bufferUntilAuthorityFinalized) {
    const authorityClaimRefs = await writePostCallTelemetry(telemetryArgs);
    const responseBytes = Buffer.concat(bufferedResponseChunks);
    await completeRuntimeAuthorityUse(
      services.authority,
      operatorId,
      authorityDecision,
      success && !blocked ? 'succeeded' : 'failed',
      {
        status,
        headers: {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
        },
        body_base64: responseBytes.toString('base64'),
      },
      authorityClaimRefs,
    );
    reply.raw.statusCode = status;
    reply.raw.setHeader('content-type', 'text/event-stream');
    reply.raw.setHeader('cache-control', 'no-cache');
    reply.raw.setHeader('connection', 'keep-alive');
    hijackReply();
    reply.raw.write(responseBytes);
    reply.raw.end();
  } else {
    reply.raw.end();
    // The client has its whole answer; the records follow, and the request is
    // not over until they are written (the approval is consumed there).
    await writePostCallTelemetry(telemetryArgs)
      .catch((err) => request.log.error({ err: safeErrorSummary(err) }, '[LLM] post-stream telemetry failed'));
  }
  if (fleetAdmission) await services.fleetAdmission.finish(fleetAdmission);
  return;
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
        '[authority] failed to finalize streamed LLM failure',
      );
    }
    throw err;
  } finally {
    if (hijacked) {
      // Fastify only logs a throw after a hijack: it would leave the client's
      // connection open and the request unended.
      if (reply.raw.writableEnded === false) reply.raw.end();
      await releaseRequestEnd(request, reply.raw.statusCode);
    }
  }
}
