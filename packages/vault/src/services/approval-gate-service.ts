// universal approval gate.
//
// The producer-side counterpart to /v1/intents/submit. Enforced-mode
// passports cannot reach the producer (proxy.ts / skills.ts / a2a.ts)
// without an approved IntentApproval row of this agent and this Mission
// AND a call shape that matches the approved IntentClaim payload. The approval is bound to the agent and the Mission,
// not the passport that submitted it, so a routine passport refresh while the person decides does not orphan it.
//
// Single substrate (D4 in the plan): one copy of the policy, three
// call sites. The producer routes call `services.approvalGate.check(...)`
// and translate the GateResult into either a 403 + signed
// `intent_denial` claim OR a continue-with-IntentClaim-in-hand path.
//
// Call-shape comparison (D9) is performed in the producer, NOT here —
// each producer has its own canonicaliser (`host(input.url)` for
// proxy, a canonical input hash for skills, `argsHash` for a2a)
// and a central comparator would duplicate that canonicalisation. The
// gate hands back the approved IntentClaim; the producer does the
// match.
//
// Order of checks inside `check` (D19): cheapest first.
//   (a) skip-if-not-enforced
//   (b) header presence
//   (c) row load + operator/passport binding
//   (d) consume-state (already_consumed)
//   (e) status (must be 'approved')
//   (f) TTL (must be in the future)
//   (g) load IntentClaim payload
//   (h) requires_unmet enforcement
//
// Pre-gate checks (a-f) take precedence over expensive DB reads in (g+h)
// so a malformed request doesn't load claim envelopes unnecessarily.
//
// `markConsumed` is called by the producer AFTER a successful 2xx-3xx
// outcome lands. Idempotent — concurrent in-flight calls can both
// admit (pre-consume), but only one consume-flip wins. The losers'
// CAS misses are swallowed; their outcomes are nonetheless emitted
// (the producer call already happened).

import { createHash } from 'node:crypto';
import type { IntentClaim } from '@stack/shared';
import type {
  IntentApprovalRepository,
  IntentApprovalTransaction,
} from '../repositories/intent-approval-repo.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import { enforceRequires } from './requires-enforcer.js';
import type { FleetPolicyAuthorization } from './fleet-admission-service.js';

export type GateReason =
  | 'missing'          // header absent under enforced mode
  | 'not_found'        // approval id does not exist or wrong operator
  | 'wrong_passport'   // approval belongs to another agent or another Mission
  | 'wrong_status'     // pending / rejected
  | 'expired'          // past expires_at, OR row.status==='expired'
  | 'already_consumed' // row.status==='consumed'
  | 'requires_unmet';  // intent.requires[] not satisfied on this session
  // Note: 'call_mismatch' is a GATE OUTCOME but decided in the producer
  // (after the gate returns the IntentClaim). It is enumerated in the
  // denial metadata's gate_reason field. See producer wiring for the
  // call-shape comparator that emits this reason.

export interface GateInput {
  /** Produced by FleetAdmissionService, never accepted from request JSON. */
  policyAuthorization?: FleetPolicyAuthorization;
  /** Verified-passport jti (from claims.jti). */
  passportJti: string;
  /** The agent the verified passport is for (claims.stk.agent_id): an approval is bound to it. */
  agentId: string;
  /** The Mission the call runs under (the passport's one Mission): an approval is bound to it. */
  missionId: string | null;
  /** Operator scope (from claims.stk.operator_id). */
  operatorId: string;
  /** Delegation chain identifier (from claims.stk.session_id). */
  sessionId: string;
  /** Passport accountability mode (from claims.stk.accountability). */
  accountabilityMode: 'enforced' | 'logged' | 'standard';
  /** Raw X-Intent-Approval-Id header value, or undefined when missing. */
  approvalIdHeader: string | undefined;
  /**
   * Caller-stable operation handle. The gate hashes this before persistence so
   * the recoverable request identifier is never stored on the approval row.
   */
  reservationOwner?: string;
  /**
   * One-way deterministic operation owner. It lets the same fenced operation
   * recover its own consuming reservation after a process crash. Kept for
   * existing internal producers that already derive their deterministic owner.
   */
  reservationOwnerHash?: string;
  /** Validate without reserving; the proxy reserves inside its dispatch transaction. */
  deferReservation?: boolean;
}

export interface GateDenialMetadata {
  approval_id: string | null;
  gate_reason: GateReason | 'call_mismatch';
  failing_requires?: string[];
}

export type GateResult =
  | { allowed: true; skipped: true }
  | {
      allowed: true;
      skipped: false;
      /** Approved IntentClaim payload — producer compares call shape against this. */
      intentClaim: IntentClaim;
      /** The approval row id, threaded back so the producer can markConsumed on success. */
      approvalId: string | undefined;
      origin?: 'fleet_policy';
      /**
       * The pc_* id of the approved intent_claim. Producers use this
       * as `intent_claim_ref` on the emitted intent_outcome so the
       * chain links to the gate-approved Intent instead of synthesising
       * a duplicate intent_claim per call.
       */
      intentClaimId: string;
    }
  | {
      /**
       * This authenticates ownership of an existing reservation only. It is
       * deliberately not an execution authorization, so existing producers
       * continue to fail closed unless they explicitly handle replay.
       */
      allowed: false;
      replay: true;
      reason: 'already_consumed';
      message: string;
      intentClaim: IntentClaim;
      intentClaimId: string;
      metadata: GateDenialMetadata;
    }
  | {
      allowed: false;
      replay?: false;
      reason: GateReason;
      message: string;
      /**
       * The approved IntentClaim payload when we managed to load it
       * (only the `requires_unmet` denial reaches this state). For
       * earlier denials the producer falls back to a synthetic intent
       * shape derived from the request.
       */
      intentClaim: IntentClaim | null;
      metadata: GateDenialMetadata;
    };

export interface ApprovalGateDeps {
  approvalRepo: IntentApprovalRepository;
  claimRegistry: Pick<ClaimRegistryService, 'getClaim'>;
  passportClaimsRepo: Pick<
    PassportClaimsRepository,
    'findActiveOutcomesByClaimIdsAndSessionId'
  >;
}

export class ApprovalGateService {
  constructor(private readonly deps: ApprovalGateDeps) {}

  async check(input: GateInput): Promise<GateResult> {
    const policy = input.policyAuthorization;
    if (policy) {
      if (policy.operatorId !== input.operatorId || policy.passportJti !== input.passportJti || input.accountabilityMode !== 'enforced') {
        throw new Error('Invalid input');
      }
      if (!policy.reviewApprovalId) {
        return { allowed: true, skipped: false, origin: 'fleet_policy', approvalId: undefined,
          intentClaim: policy.intentClaim, intentClaimId: policy.intentClaimId };
      }
      input = { ...input, approvalIdHeader: policy.reviewApprovalId, deferReservation: true };
    }
    if (input.reservationOwner !== undefined && input.reservationOwnerHash !== undefined) {
      throw new Error('Provide an approval reservation owner or owner hash, not both');
    }
    if (
      input.reservationOwner !== undefined &&
      !/^[A-Za-z0-9_-]{22,256}$/.test(input.reservationOwner)
    ) {
      throw new Error('Approval reservation owner must be a 22-256 character base64url handle');
    }
    if (
      input.reservationOwnerHash !== undefined &&
      !/^[0-9a-f]{64}$/.test(input.reservationOwnerHash)
    ) {
      throw new Error('Approval reservation owner must be a SHA-256 hex digest');
    }
    const reservationOwnerHash = input.reservationOwner === undefined
      ? input.reservationOwnerHash
      : createHash('sha256').update(input.reservationOwner, 'utf8').digest('hex');
    // (a) skip-if-not-enforced
    if (input.accountabilityMode !== 'enforced') {
      return { allowed: true, skipped: true };
    }

    // (b) header presence
    if (!input.approvalIdHeader) {
      return {
        allowed: false,
        reason: 'missing',
        message:
          'Enforced-mode passport requires X-Intent-Approval-Id header. ' +
          'Submit the intent via /v1/intents/submit and wait for approval first.',
        intentClaim: null,
        metadata: { approval_id: null, gate_reason: 'missing' },
      };
    }

    // (c) row load + operator binding
    const row = await this.deps.approvalRepo.findById(input.approvalIdHeader);
    if (!row || row.operator_id !== input.operatorId) {
      return {
        allowed: false,
        reason: 'not_found',
        message: `Approval ${input.approvalIdHeader} not found.`,
        intentClaim: null,
        metadata: { approval_id: input.approvalIdHeader, gate_reason: 'not_found' },
      };
    }

    // agent and Mission binding: the approval belongs to the agent that submitted it, under the Mission it was submitted
    // in, whichever of that agent's Passports presents it (a refresh mints a new one).
    const fleetBindingMatches = policy && row.fleet_policy_id === policy.binding.policy_id &&
      row.fleet_policy_revision === policy.binding.policy_revision && row.fleet_mission_id === policy.binding.mission_id &&
      row.agent_id === policy.agentId && row.fleet_request_hash === policy.requestHash;
    let boundClaim: IntentClaim | null = null;
    let ownBinding = false;
    if (!row.fleet_policy_id) {
      boundClaim = (await this.deps.claimRegistry.getClaim(row.intent_claim_id)).body_json as IntentClaim;
      const missionRef = boundClaim.mission_ref ?? null;
      ownBinding = row.agent_id === input.agentId && (missionRef === null
        // An approval written before intents named their Mission keeps its passport binding.
        ? row.passport_jti === input.passportJti
        : input.missionId !== null && missionRef === input.missionId);
    }
    if (row.fleet_policy_id ? !fleetBindingMatches : !ownBinding) {
      return {
        allowed: false,
        reason: 'wrong_passport',
        message: 'Approval is bound to another agent or another Mission.',
        intentClaim: null,
        metadata: { approval_id: row.id, gate_reason: 'wrong_passport' },
      };
    }

    // (d) A consuming/consumed row remains closed to every other request. The
    // same stable operation may authenticate that the reservation is its own,
    // but receives a replay-only result with no approval id or dispatch grant.
    if (row.status === 'consuming' || row.status === 'consumed') {
      const ownsReplay =
        reservationOwnerHash !== undefined &&
        row.consuming_owner_hash === reservationOwnerHash;
      if (ownsReplay) {
        const claimRow = await this.deps.claimRegistry.getClaim(row.intent_claim_id);
        return {
          allowed: false,
          replay: true,
          reason: 'already_consumed',
          message: 'Approval belongs to this existing operation; replay does not authorize dispatch.',
          intentClaim: claimRow.body_json as IntentClaim,
          intentClaimId: row.intent_claim_id,
          metadata: { approval_id: row.id, gate_reason: 'already_consumed' },
        };
      }
      return {
        allowed: false,
        reason: 'already_consumed',
        message: 'Approval is already in use or spent.',
        intentClaim: null,
        metadata: { approval_id: row.id, gate_reason: 'already_consumed' },
      };
    }

    // (e) status must be 'approved'
    if (row.status === 'expired') {
      return {
        allowed: false,
        reason: 'expired',
        message: 'Approval expired.',
        intentClaim: null,
        metadata: { approval_id: row.id, gate_reason: 'expired' },
      };
    }
    if (row.status !== 'approved') {
      return {
        allowed: false,
        reason: 'wrong_status',
        message: `Approval status is '${row.status}', not 'approved'.`,
        intentClaim: null,
        metadata: { approval_id: row.id, gate_reason: 'wrong_status' },
      };
    }

    // (f) TTL — the sweep cron flips past-TTL pending rows to
    // 'expired', but an approved row past its TTL is still tagged
    // 'approved' until next sweep. Defensive check here.
    if (row.expires_at.getTime() <= Date.now()) {
      return {
        allowed: false,
        reason: 'expired',
        message: 'Approval expired.',
        intentClaim: null,
        metadata: { approval_id: row.id, gate_reason: 'expired' },
      };
    }

    // (g) load IntentClaim payload (already read for the binding, unless the approval is a fleet review's)
    const intentClaim = boundClaim ?? (await this.deps.claimRegistry.getClaim(row.intent_claim_id)).body_json as IntentClaim;

    // (h) requires_unmet
    const req = await enforceRequires(
      { passportClaimsRepo: this.deps.passportClaimsRepo },
      { sessionId: input.sessionId, requires: intentClaim.requires ?? [] },
    );
    if (!req.allowed) {
      return {
        allowed: false,
        reason: 'requires_unmet',
        message:
          `Intent requires ${req.failingRequires.length} prerequisite outcome(s) ` +
          `that are missing or not succeeded: ${req.failingRequires.join(', ')}.`,
        intentClaim,
        metadata: {
          approval_id: row.id,
          gate_reason: 'requires_unmet',
          failing_requires: req.failingRequires,
        },
      };
    }

    // (i) RESERVE — the single-winner admit. This is a CAS approved ->
    // consuming, so of two requests presenting the same approval at the same
    // instant, exactly one wins here and the other is denied 'already_consumed'.
    // Before this the admit only READ status='approved' and the flip happened
    // after the call returned, so both dispatched and a human's one approval
    // bought two actions (the threat model, approval.consume-is-racy).
    // The caller MUST, on any path that does not end in a successful call,
    // release the reservation so a transient failure does not burn the approval.
    const reserved = input.deferReservation
      ? true
      : await this.deps.approvalRepo.markReserved(row.id, reservationOwnerHash);
    if (!reserved) {
      return {
        allowed: false,
        reason: 'already_consumed',
        message: 'Approval is already in use or spent.',
        intentClaim,
        metadata: { approval_id: row.id, gate_reason: 'already_consumed' },
      };
    }

    return {
      allowed: true,
      skipped: false,
      intentClaim,
      approvalId: row.id,
      intentClaimId: row.intent_claim_id,
    };
  }

  /**
   * Post-success finaliser: consuming -> consumed. The reservation was taken at
   * admit, so this only settles it. Idempotent; a miss means another path
   * already settled or released it.
   */
  async markConsumed(
    approvalId: string,
    reservationOwnerHash?: string,
    transaction?: IntentApprovalTransaction,
  ): Promise<boolean> {
    return this.deps.approvalRepo.markConsumed(approvalId, reservationOwnerHash, transaction);
  }

  /** Atomic approved -> consuming transition used by the proxy dispatch fence. */
  reserveForDispatch(
    approvalId: string,
    reservationOwnerHash: string,
    transaction: IntentApprovalTransaction,
  ): Promise<boolean> {
    return this.deps.approvalRepo.markReserved(approvalId, reservationOwnerHash, transaction);
  }

  /**
   * Release a reservation taken at admit when the call did not complete: a
   * later gate refused it, or the upstream failed. Restores consuming ->
   * approved so the agent can retry under the same human approval, which is the
   * contract the old post-success consume had by never flipping on failure.
   */
  async releaseReservation(approvalId: string, reservationOwnerHash?: string): Promise<boolean> {
    return this.deps.approvalRepo.releaseReservation(approvalId, reservationOwnerHash);
  }
}
