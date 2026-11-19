// Stage 3: the approval gate. Checks the X-Intent-Approval-Id header against
// the passport's accountability mode, records a denial when the gate refuses,
// pins the call shape to what the approval recorded, and reserves the approval
// so a failure below can release it.

import type { FastifyRequest } from 'fastify';
import { ForbiddenError, safeErrorSummary, type IntentClaim } from '@stack/shared';
import { LLM_PROVIDERS, type FleetAdmission } from '@stack/vault';
import { compareApprovedShape } from '../../lib/approval-shape.js';
import { approvalWaitSeverity } from '../../lib/approval-wait-severity.js';
import type { Services } from '../../config/services.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import type { AdmittedCall, ApprovedGate } from './types.js';

export async function enforceApprovalGate(
  services: Services,
  request: FastifyRequest,
  config: LlmHandlerConfig,
  call: AdmittedCall,
  fleetAdmission: FleetAdmission | null,
): Promise<{ gate: ApprovedGate; approvalIdHeader: string | undefined }> {
  const { body, isStreaming, claims, jti, agentId, operatorId, mode, missionIds, missionRef } = call;
  const approvalIdHeader = request.headers['x-intent-approval-id'] as string | undefined;
  const gate = await services.approvalGate.check({
    ...(fleetAdmission ? { policyAuthorization: fleetAdmission.authorization } : {}),
    passportJti: jti,
    agentId,
    missionId: missionRef,
    operatorId,
    sessionId: (claims.stk.session_id ?? '') as string,
    accountabilityMode: (mode ?? 'standard') as 'enforced' | 'logged' | 'standard',
    approvalIdHeader,
  });
  if (!gate.allowed) {
    // Emit denial + security_event mirroring proxy.ts:79-128.
    const attemptedIntent: IntentClaim = gate.intentClaim ?? {
      type: 'intent_claim',
      intent_type: 'http_call',
      agent_id: agentId,
      named_intent: config.namedIntent,
      target: config.provider,
      action: config.action,
      parameters: { provider: config.provider, model: body.model, stream: isStreaming },
      estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
      accountability: (mode as 'enforced' | 'logged' | 'standard' | undefined) ?? 'standard',
      reason: null,
      requires: [],
      user_subject: null,
      mission_ref: missionRef,
      submitted_at: Date.now(),
    };
    await services.claimRegistry
      .recordIntentDenial({
        operatorId,
        passportJti: jti,
        attemptedIntent,
        denialReason: gate.reason === 'requires_unmet' ? 'requires_unmet' : 'scope_mismatch',
        message: gate.message,
        metadata: { ...gate.metadata },
      })
      .catch((err) => console.error('[llm] intent_denial emission failed at gate:', safeErrorSummary(err)));
    await services.securityEvent
      .record({
        operatorId,
        agentId,
        passportJti: jti,
        signalType: 'credential_outside_scope',
        // Waiting on the person, or no approval yet, is a warning; another's approval or a replay stays critical.
        severity: approvalWaitSeverity(gate.reason),
        message: `Approval gate denied LLM request: ${gate.message}`,
        metadata: { ...gate.metadata, provider: config.provider },
        missionIds,
      })
      .catch((err) => console.error('[llm] security_event emission failed at gate:', safeErrorSummary(err)));
    throw new ForbiddenError(gate.message);
  }

  // 3c. Call-shape comparator. The proxy has had this since D9; this route
  //     did not, and the gap was measured rather than argued: an approval
  //     issued for one model and one prompt admitted a different model with
  //     a different prompt, and the request left the building. See
  //     the threat model, cell `llm.approval-admits-any-call`.
  //
  //     An operator approving an agent's LLM spend was approving a TOKEN,
  //     not a call. Same shared comparator as the proxy so the two doors
  //     cannot drift apart again.
  //
  //     The provider endpoint is fixed for this route, so method and url
  //     always match; what this actually pins is the BODY - the model and
  //     the messages - through canonicalBodyHash, when the approved intent
  //     recorded one. An approval that pinned no body still admits any body,
  //     which is the same contract the proxy has.
  if (!gate.skipped && !fleetAdmission) {
    const approved = gate.intentClaim;
    const mismatch = compareApprovedShape(
      {
        target: approved.target,
        intent_type: approved.intent_type,
        parameters: approved.parameters as Record<string, unknown>,
      },
      {
        service: config.provider,
        method: call.method,
        url: config.upstreamUrl ?? LLM_PROVIDERS[config.provider].url,
        body,
      },
    );
    if (mismatch) {
      try {
        await services.claimRegistry.recordIntentDenial({
          operatorId,
          passportJti: jti,
          attemptedIntent: approved,
          denialReason: 'scope_mismatch',
          message: `Call does not match approved intent (field=${mismatch.field})`,
          metadata: {
            approval_id: gate.approvalId,
            gate_reason: 'call_mismatch',
            field_mismatch: mismatch,
          },
        });
      } catch (err) {
        console.error('[llm] intent_denial emission failed for call_mismatch:', safeErrorSummary(err));
      }
      try {
        await services.securityEvent.record({
          operatorId,
          agentId,
          passportJti: jti,
          signalType: 'credential_outside_scope',
          severity: 'critical',
          message: `Approval gate call mismatch: ${mismatch.field}`,
          metadata: {
            approval_id: gate.approvalId,
            field_mismatch: mismatch,
            service: config.provider,
          },
          missionIds,
        });
      } catch (err) {
        console.error('[llm] security_event emission failed for call_mismatch:', safeErrorSummary(err));
      }
      throw new ForbiddenError(`Call does not match approved intent (field=${mismatch.field})`);
    }
  }

  // The gate reserved this approval; release it if anything below refuses or
  // the upstream fails. Settled on success in the emission block. Mirrors the
  // proxy; before this the LLM route never settled an approval at all, so an
  // enforced approval here was effectively reusable.
  const gateApprovalId = gate.skipped || fleetAdmission ? undefined : gate.approvalId;
  if (gateApprovalId) {
    const reservedId = gateApprovalId;
    request.approvalToRelease = async () => {
      await services.approvalGate.releaseReservation(reservedId);
    };
  }
  return { gate, approvalIdHeader };
}
