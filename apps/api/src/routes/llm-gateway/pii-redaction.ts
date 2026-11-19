// Stage 8: PII redaction on user-supplied messages. Honours both the agent
// flag and the account-wide switch.

import type { FastifyRequest } from 'fastify';
import { PII_DEFAULT_THRESHOLD, safeErrorSummary } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import type { AdmittedCall, GatewayAgent } from './types.js';

/**
 * Redaction is a controls feature. Without the owner's controls no model call is redacted, whatever the agent's
 * `llm_redact_pii` says; with them it runs on every call unless the owner switched it off.
 */
export type RedactedCall = Pick<AdmittedCall, 'body' | 'jti' | 'agentId' | 'operatorId'>;

export async function redactUserPii(
  services: Services,
  request: FastifyRequest,
  config: Pick<LlmHandlerConfig, 'provider'>,
  call: RedactedCall,
  agent: GatewayAgent,
): Promise<{ redactedBody: Record<string, unknown>; piiHits: number }> {
  const { body, jti, agentId, operatorId } = call;
  // Agent row already fetched above the inbound scan; its llm_redact_pii
  // flag governs the mutation step below.

  // 8. — PII redaction on user messages.
  //
  // Walks role:user (and role:tool on OpenAI/OpenRouter) messages and
  // replaces each match in the catalog (email, SSN, phone, credit card,
  // IBAN, IPv4/IPv6) with `[REDACTED:<category>]`. Idempotent.
  //
  // Returns a deep clone — the caller's `body` reference is unchanged.
  // totalHits surfaces as `pii_hits` on the audit log metadata so an
  // operator can spot a spike in user-supplied PII.
  //
  // gated on agents.llm_redact_pii (default true, fail-closed).
  // When the operator has flipped it off, user content flows to the
  // provider unredacted — their explicit call (schema comment has the
  // threat note); pii_hits is -1 on the audit metadata so "redaction
  // skipped" is forensically distinct from "scanned, zero hits".
  // What counts as PII is now scored, not decided by a check
  // digit alone, and the operator owns two of the inputs — the confidence
  // threshold and which countries to scan for. Resolving returns null when
  // the operator has switched redaction off account-wide, which is a
  // DIFFERENT answer from "use defaults"; collapsing the two would silently
  // re-enable a control they turned off. The agent flag and the account
  // switch are both honoured, and either one off means no redaction.
  // Controls are read first and fail closed: a read that cannot be made fails the call rather than skipping redaction.
  const controlsOn = await services.entitlements.controlsEnabled(operatorId);
  const piiScanOptions = controlsOn ? await services.operatorPiiConfig.resolveScanOptions(operatorId) : null;

  let redactedBody: Record<string, unknown> = body as Record<string, unknown>;
  let piiHits = -1;
  let piiNearMisses = 0;
  let piiNearMissCategories: string[] = [];
  if (controlsOn && agent.llm_redact_pii && piiScanOptions !== null) {
    const piiResult = services.llmGateway.redactUserMessages({
      provider: config.provider,
      body,
      redactor: services.piiRedactor,
      scanOptions: piiScanOptions,
    });
    redactedBody = piiResult.body as Record<string, unknown>;
    piiHits = piiResult.totalHits;
    piiNearMisses = piiResult.nearMisses;
    piiNearMissCategories = piiResult.nearMissCategories;
  }

  // Near-misses: text that passed a country's check digit but scored under
  // the threshold, so was forwarded intact. Recorded once per request as an
  // info-severity security event, never per match and never with contents —
  // the whole point is that we are unsure, and writing the string down
  // would leak exactly what the redactor exists to contain. An operator
  // seeing these repeatedly should scope to their countries and lower the
  // threshold, which is the combination that catches bare formats safely.
  if (piiNearMisses > 0) {
    await services.securityEvent
      .record({
        operatorId,
        agentId,
        passportJti: jti,
        signalType: 'pii_below_threshold',
        severity: 'info',
        message:
          `${piiNearMisses} value(s) matched a personal-identifier format but scored below the redaction threshold, and were forwarded to ${config.provider}. ` +
          'Scope PII redaction to your countries and lower the threshold to catch these.',
        metadata: {
          count: piiNearMisses,
          categories: piiNearMissCategories,
          provider: config.provider,
          threshold: piiScanOptions?.threshold ?? PII_DEFAULT_THRESHOLD,
          countries: piiScanOptions?.countries ?? null,
        },
        // Deduped per agent + shape of finding: an agent handling a queue of
        // similar documents would otherwise write one of these per request
        // and bury the operator's real security events under a diagnostic.
        dedupKey: `pii_below_threshold:${agentId}:${[...piiNearMissCategories].sort().join(',')}`,
      })
      .catch((err: unknown) => {
        // Diagnostic only. A failure here must never fail the model call.
        request.log.warn({ err: safeErrorSummary(err) }, '[LLM] failed to record pii_below_threshold event');
      });
  }
  return { redactedBody, piiHits };
}
