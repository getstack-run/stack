import { ForbiddenError, evidenceAction, evidenceIntentClaim, evidenceUrl, safeErrorSummary, type IntentClaim } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { compareApprovedShape } from '../../lib/approval-shape.js';
import { denialDedup, hostnameOf, pathnameOf } from '../../lib/denial-dedup.js';
import type {
  AdmittedGate,
  ApprovalGateOutcome,
  FleetAdmission,
  ParsedProxyRequest,
  ProxyHttpRequest,
  VerifiedProxyPassport,
} from './types.js';

/**
 * D2 — severity for an approval-gate denial, graded by reason.
 *
 * The approval-gate block previously recorded EVERY denial as `critical`,
 * which — combined with `on_critical: block` — auto-bricks the whole agent
 * (passport_blocked → active Passport chain revoked and future issuance refused). That is far too
 * harsh for pure USAGE errors: forgetting the X-Intent-Approval-Id header
 * (`missing`), a typo'd/expired/wrong-status approval id. Those are the same
 * class as a mis-ordered call, not a credential breach — every OTHER denial
 * path in this handler already grades non-malicious denials down to `warning`.
 *
 * Policy: usage errors → `warning` (no brick);
 * anything that could be a genuine attack — presenting someone else's approval
 * (`wrong_passport`), replaying a consumed one (`already_consumed`), or a real
 * unmet policy requirement (`requires_unmet`) — stays `critical` and keeps
 * bricking by design. Fail-closed: an unrecognized reason stays `critical`.
 */
const APPROVAL_GATE_USAGE_ERROR_REASONS = new Set([
  'missing', // header absent — the classic fat-finger
  'not_found', // approval id doesn't resolve — typo / wrong id
  'expired', // approval lapsed — timing
  'wrong_status', // approval not in an approved state yet
]);

export function approvalGateDenialSeverity(gateReason: string): 'warning' | 'critical' {
  return APPROVAL_GATE_USAGE_ERROR_REASONS.has(gateReason) ? 'warning' : 'critical';
}

/**
 * 3b. Universal approval gate. Enforced-mode
 *     passports must present an X-Intent-Approval-Id matching
 *     an approved intent_approvals row scoped to this passport,
 *     AND the call shape must match the approved IntentClaim.
 *     Logged + standard skip entirely (gate.skipped=true).
 *     Cheaper than scope check (gate denials short-circuit on
 *     missing header / unknown row before any expensive read).
 */
export async function checkApprovalGate(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  fleetAdmission: FleetAdmission,
): Promise<ApprovalGateOutcome> {
  const { input, isMutation, operationKey } = parsedRequest;
  const { claims, jti, agentId, operatorId, mode, missionIds, missionRef } = verified;
  const approvalIdHeader = request.headers['x-intent-approval-id'] as string | undefined;
  const checkedGate = await services.approvalGate.check({
    ...(fleetAdmission ? { policyAuthorization: fleetAdmission.authorization } : {}),
    passportJti: jti,
    agentId,
    missionId: missionRef,
    operatorId,
    sessionId: (claims.stk.session_id ?? '') as string,
    accountabilityMode: (mode ?? 'standard') as 'enforced' | 'logged' | 'standard',
    approvalIdHeader,
    ...(isMutation ? { reservationOwner: operationKey!, deferReservation: true } : {}),
  });

  const replayGate = !checkedGate.allowed
    && 'replay' in checkedGate
    && checkedGate.replay === true
    ? checkedGate
    : null;
  const approvalReplay = replayGate !== null && isMutation;
  if (!checkedGate.allowed && !approvalReplay) {
    // Build attempted_intent for the denial claim. If the gate
    // loaded the approved IntentClaim (requires_unmet path) we
    // use it; otherwise synthesise from the request shape.
    // Either way the denial is a signed record: the URL in it is where the
    // call went, never its query string (evidenceUrl).
    const attemptedIntent: IntentClaim = checkedGate.intentClaim ? evidenceIntentClaim(checkedGate.intentClaim) : {
      type: 'intent_claim',
      intent_type: 'http_call',
      agent_id: agentId,
      named_intent: `${input.service}:http:proxy`,
      target: input.service,
      action: evidenceAction(input.method, input.url),
      parameters: { service: input.service, method: input.method, url: evidenceUrl(input.url) },
      estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
      accountability: (mode as 'enforced' | 'logged' | 'standard' | undefined) ?? 'standard',
      reason: null,
      requires: [],
      user_subject: null,
      mission_ref: missionRef,
      submitted_at: Date.now(),
    };
    try {
      await services.claimRegistry.recordIntentDenial({
        operatorId,
        passportJti: jti,
        attemptedIntent,
        denialReason: checkedGate.reason === 'requires_unmet' ? 'requires_unmet' : 'scope_mismatch',
        message: checkedGate.message,
        metadata: { ...checkedGate.metadata },
      });
    } catch (err) {
      console.error('[proxy] intent_denial emission failed at gate:', safeErrorSummary(err));
    }
    // Surface as a security event too so the dashboard /reviews UI
    // catches it via the standard pipeline (the same path scope/
    // constraint denials already use).
    try {
      await services.securityEvent.record({
        operatorId,
        agentId,
        passportJti: jti,
        signalType: 'credential_outside_scope',
        // D2 — grade by reason: usage errors (missing header
        // typo'd/expired approval) are `warning` so a fat-finger doesn't
        // brick the whole agent; genuine misuse stays `critical`.
        severity: approvalGateDenialSeverity(checkedGate.reason),
        message: `Approval gate denied request: ${checkedGate.message}`,
        metadata: { ...checkedGate.metadata, service: input.service },
        missionIds,
        // The same refusal again is one event with a count, not a card each.
        ...denialDedup({
          agentId,
          service: input.service,
          method: input.method,
          host: hostnameOf(input.url),
          pathname: pathnameOf(input.url),
          op: `gate:${checkedGate.reason}`,
        }),
      });
    } catch (err) {
      console.error('[proxy] security_event emission failed at gate:', safeErrorSummary(err));
    }
    throw new ForbiddenError(checkedGate.message);
  }
  const gate: AdmittedGate = checkedGate.allowed
    ? checkedGate
    : {
        allowed: true as const,
        skipped: false as const,
        intentClaim: replayGate!.intentClaim,
        intentClaimId: replayGate!.intentClaimId,
        approvalId: approvalIdHeader!,
      };

  // The gate reserved this approval (approved -> consuming) so a concurrent
  // twin cannot spend it too. Register the release: if anything below
  // refuses or the upstream fails, the onResponse hook restores it to
  // 'approved' for retry. Cleared on successful consume.
  if (!fleetAdmission && !isMutation && !gate.skipped && gate.approvalId) {
    const reservedId = gate.approvalId;
    request.approvalToRelease = async () => {
      await services.approvalGate.releaseReservation(reservedId);
    };
  }

  return { gate, approvalReplay };
}

/**
 * 3c. Call-shape comparator (D9). When the gate ADMITTED an
 *     approved IntentClaim, the producer compares the actual
 *     call to the approved payload. Mismatch = 403 + signed
 *     intent_denial (metadata.gate_reason='call_mismatch').
 *     Approval row stays 'approved' — the agent can retry with
 *     the right shape until the row's TTL.
 */
export async function enforceApprovedCallShape(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  gate: AdmittedGate,
  fleetAdmission: FleetAdmission,
): Promise<void> {
  const { input } = parsedRequest;
  const { jti, agentId, operatorId, missionIds } = verified;
  if (!gate.skipped && !fleetAdmission) {
    // Shape comparison lives in lib/approval-shape.ts so the route and
    // its tests exercise one implementation. It compares the PATH as
    // well as the host — checking the host alone let an approval for
    // /v1/customers admit /v1/transfers — and it fails CLOSED when the
    // approved intent omits method or url, which used to skip the check
    // entirely because `parameters` is an unvalidated record.
    const approved = gate.intentClaim;
    const mismatch = compareApprovedShape(
      {
        target: approved.target,
        intent_type: approved.intent_type,
        parameters: approved.parameters as Record<string, unknown>,
      },
      {
        service: input.service,
        method: input.method,
        url: input.url,
        headers: input.headers,
        body: input.body,
        query: input.query,
      },
    );
    if (mismatch) {
      try {
        await services.claimRegistry.recordIntentDenial({
          operatorId,
          passportJti: jti,
          attemptedIntent: evidenceIntentClaim(approved),
          denialReason: 'scope_mismatch',
          message: `Call does not match approved intent (field=${mismatch.field})`,
          metadata: {
            approval_id: gate.approvalId,
            gate_reason: 'call_mismatch',
            field_mismatch: mismatch,
          },
        });
      } catch (err) {
        console.error('[proxy] intent_denial emission failed for call_mismatch:', safeErrorSummary(err));
      }
      try {
        await services.securityEvent.record({
          operatorId,
          agentId,
          passportJti: jti,
          signalType: 'credential_outside_scope',
          severity: 'critical',
          message: `Approval gate call mismatch: ${mismatch.field}`,
          metadata: { approval_id: gate.approvalId, field_mismatch: mismatch, service: input.service },
          missionIds,
          ...denialDedup({
            agentId,
            service: input.service,
            method: input.method,
            host: hostnameOf(input.url),
            pathname: pathnameOf(input.url),
            op: `mismatch:${mismatch.field}`,
          }),
        });
      } catch (err) {
        console.error('[proxy] security_event emission failed for call_mismatch:', safeErrorSummary(err));
      }
      throw new ForbiddenError(`Call does not match approved intent (field=${mismatch.field})`);
    }
  }
}
