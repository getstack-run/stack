// Audit log and intent_claim/intent_outcome producer, shared by the streaming
// and non-streaming forwarding stages.

import type { FastifyRequest } from 'fastify';
import { shannonEntropy, safeErrorSummary, type IntentClaim, type LlmCostBreakdown } from '@stack/shared';
import { auditCtx } from '../../middleware/audit.js';
import type { Services } from '../../config/services.js';
import type { LlmHandlerConfig } from './provider-configs.js';

/**
 * Audit log + intent_claim/intent_outcome producer. Shared between the
 * streaming and non-streaming paths. Best-effort on the claim writes —
 * the caller has already returned the response by the time these run.
 */
export async function writePostCallTelemetry(args: {
  services: Services;
  request: FastifyRequest;
  config: LlmHandlerConfig;
  start: number;
  success: boolean;
  body: Record<string, unknown>;
  /** The response, or a sample of it when it is too large to hold: what the audit row's entropy is read from. */
  responseStr: string;
  /** The response's size when `responseStr` is only a sample of it. */
  responseBytes?: number;
  responseStatus: number;
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number } | null;
  claims: unknown;
  jti: string;
  agentId: string;
  operatorId: string;
  mode: 'enforced' | 'logged' | 'standard' | undefined;
  missionIds: readonly string[] | undefined;
  missionRef: string;
  gate: { skipped: boolean; intentClaimId?: string; approvalId?: string };
  approvalIdHeader: string | undefined;
  requestBodyStr: string;
  /** The request's size when `requestBodyStr` is only a sample of it. */
  requestBytes?: number;
  /** count of PII matches the redactor replaced in user
   * messages before forward. Surfaces on the audit_log metadata so
   * operators can spot user-supplied-PII spikes.: -1 means the
   * agent has llm_redact_pii=false and redaction was skipped entirely —
   * forensically distinct from "scanned, zero hits". */
  piiHits: number | null;
  recordedCost: LlmCostBreakdown | null;
  /** On STACK's key the wallet pays provider cost plus fee; otherwise only the fee. */
  stackKey?: boolean;
}): Promise<{ intentClaimId?: string; outcomeClaimId?: string }> {
  const {
    services, request, config, start, success, body, responseStr, responseStatus,
    usage, jti, agentId, operatorId, mode, missionRef, gate, requestBodyStr, piiHits,
    recordedCost, stackKey = false,
  } = args;
  const walletCents = recordedCost
    ? stackKey ? recordedCost.total_cost_cents : recordedCost.markup_cents
    : 0;

  // Audit log — records request/response bytes + entropy for the
  // behavioral_genome producer. The audit_log row has no
  // generic metadata column today, so pii_hits surfaces only via the
  // request log line below (Fastify pino). Adding a `pii_hits` audit
  // column + dashboard visualization is a follow-up if customer signal
  // surfaces.
  if (piiHits === null) {
    // No redaction stage ran for this call (it carries no JSON body to read).
  } else if (piiHits > 0) {
    request.log.info(
      { provider: config.provider, pii_hits: piiHits, agent_id: agentId, passport_jti: jti },
      '[LLM] PII redacted before forward',
    );
  } else if (piiHits < 0) {
    // redaction was skipped: the owner has no controls, or switched it off for this agent. Logged on
    // every call so a forensic read of the request log can never mistake
    // "not scanned" for "scanned clean".
    request.log.info(
      { provider: config.provider, agent_id: agentId, passport_jti: jti },
      '[LLM] PII redaction skipped (no controls, or switched off)',
    );
  }
  await services.audit.write({
    ctx: auditCtx(request, { agent_id: agentId, passport_jti: jti }),
    layer: 'vault',
    action: config.action,
    outcome: success ? 'success' : 'failure',
    duration_ms: Date.now() - start,
    request_bytes: args.requestBytes ?? Buffer.byteLength(requestBodyStr, 'utf8'),
    response_bytes: args.responseBytes ?? Buffer.byteLength(responseStr, 'utf8'),
    request_entropy: shannonEntropy(requestBodyStr),
    response_entropy: shannonEntropy(responseStr),
  });

  // The route settled the usage record and wallet hold before this hook.
  // The hook writes audit and signed intent records from that settled cost.
  // Gross provider cost remains on llm_usage and the mission cap.
  // Intent claim + outcome producer for enforced/logged passports.
  // Standard-mode passports skip — explicit opt-out from signed claim
  // emission (mirrors proxy.ts:664 policy).
  let emittedIntentClaimId: string | undefined;
  let emittedOutcomeClaimId: string | undefined;
  if ((mode === 'enforced' || mode === 'logged') && success) {
    let intentClaimId: string | undefined;
    if (!gate.skipped) {
      intentClaimId = gate.intentClaimId;
      // Settle the reservation on success and clear the release. approvalId is
      // threaded through args because this helper is a separate function and
      // does not share the handler's scope.
      if (gate.approvalId) {
        try {
          await services.approvalGate.markConsumed(gate.approvalId);
          request.approvalToRelease = undefined;
        } catch (err) {
          console.error('[llm] markConsumed failed:', safeErrorSummary(err));
        }
      }
    } else {
      const intentBody: IntentClaim = {
        type: 'intent_claim',
        intent_type: 'http_call',
        agent_id: agentId,
        named_intent: config.namedIntent,
        target: config.provider,
        action: config.action,
        parameters: {
          provider: config.provider,
          model: body.model,
          stream: body.stream === true,
          // Hash the messages array rather than embedding it — keeps the
          // claim PII-safe + bounded size.
          ...(usage ? { tokens: usage.total_tokens } : {}),
        },
        estimated_cost: {
          wallet_cents: walletCents,
          tokens: usage?.total_tokens ?? null,
          gas_gwei: null,
        },
        accountability: mode,
        reason: null,
        requires: [],
        user_subject: null,
        mission_ref: missionRef,
        submitted_at: start,
      };
      try {
        const intentRes = await services.claimRegistry.registerClaim({
          operatorId,
          passportJti: jti,
          claimType: 'intent_claim',
          payload: intentBody,
        });
        intentClaimId = intentRes.claimId;
      } catch (err) {
        console.error('llm intent_claim emission failed:', safeErrorSummary(err));
      }
    }
    emittedIntentClaimId = intentClaimId;

    if (intentClaimId) {
      try {
        const outcomeResult = await services.claimRegistry.registerClaim({
          operatorId,
          passportJti: jti,
          claimType: 'intent_outcome',
          payload: {
            type: 'intent_outcome',
            intent_claim_ref: intentClaimId,
            outcome_type: 'task_complete',
            status: 'succeeded',
            cost_actual: {
              wallet_cents: walletCents,
              tokens: usage?.total_tokens ?? null,
              gas_gwei: null,
            },
            response_summary: `${config.provider} ${responseStatus}: ${usage ? `${usage.total_tokens} tokens` : 'no usage'}`,
            outcome_at: Date.now(),
            mission_ref: missionRef,
          },
        });
        emittedOutcomeClaimId = outcomeResult.claimId;
      } catch (err) {
        console.error('llm intent_outcome emission failed:', safeErrorSummary(err));
      }
    }
  }
  return {
    ...(emittedIntentClaimId ? { intentClaimId: emittedIntentClaimId } : {}),
    ...(emittedOutcomeClaimId ? { outcomeClaimId: emittedOutcomeClaimId } : {}),
  };
}
