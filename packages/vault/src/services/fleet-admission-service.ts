import {
  ForbiddenError, ConflictError, StackError, fleetDigest, fleetAccessConstraints, findFailingConstraint,
  type FleetPassportBinding, type IntentClaim, type NormalizedRequest,
} from '@stack/shared';
import type { FleetRepository, FleetTransaction } from '../repositories/fleet-repo.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type { IntentApprovalService } from './intent-approval-service.js';
import type { ApprovalGateService } from './approval-gate-service.js';
import type { PassportJWTPayload } from './passport-service.js';


/** What an agent is told when its fleet policy holds a request for a person, by where the review stands. */
const FLEET_REVIEW_MESSAGES: Record<'pending' | 'rejected' | 'used' | 'expired', string> = {
  pending: 'This request waits for a person to approve it. Send it again with the same operation key once it is approved.',
  rejected: 'A person rejected this request.',
  used: 'The approval for this request has already been used.',
  expired: 'The review of this request expired before it was used. Send it again with the same operation key to ask again.',
};

export type FleetProducer = 'proxy' | 'llm' | 'skill' | 'a2a' | 'dropoff';
export interface FleetPolicyAuthorization {
  origin: 'fleet_policy';
  operatorId: string;
  agentId: string;
  passportJti: string;
  binding: FleetPassportBinding;
  requestHash: string;
  intentClaim: IntentClaim;
  intentClaimId: string;
  reviewApprovalId?: string;
}
export interface FleetAdmission {
  authorization: FleetPolicyAuthorization;
  producer: FleetProducer;
  operationKeyHash: string;
  ruleId: string;
  bytes: number;
  operationId?: string;
  state: 'prepared' | 'reserved' | 'dispatched' | 'finished';
}
export interface PrepareFleetAdmission {
  claims: PassportJWTPayload;
  producer: FleetProducer;
  operationKey: string | undefined;
  connectionId?: string;
  targetId?: string;
  action: string;
  normalizedRequest: NormalizedRequest;
  intent: IntentClaim;
  bytes?: number;
}

/** Deterministic evaluation over the real canonical request, independent of model text. */
export function decideFleetRequest(
  live: Awaited<ReturnType<FleetRepository['liveMission']>>,
  input: Pick<PrepareFleetAdmission, 'producer' | 'connectionId' | 'targetId' | 'action' | 'normalizedRequest'>,
): { effect: 'allow' | 'review'; ruleId: string } {
  const matches = (constraints: Parameters<typeof findFailingConstraint>[0]) => !findFailingConstraint(constraints, input.normalizedRequest);
  if (input.producer === 'proxy' || input.producer === 'llm') {
    if (!input.connectionId) throw new ForbiddenError();
    const access = live.binding.access.find(entry => entry.access.connection_id === input.connectionId);
    if (!access || !matches(access.constraints)) throw new ForbiddenError();
    const rules = live.policy.definition.rules.filter(rule => rule.access.connection_id === input.connectionId && matches(fleetAccessConstraints(rule.access)));
    if (rules.some(rule => rule.effect === 'deny')) throw new ForbiddenError();
    const review = rules.find(rule => rule.effect === 'review');
    if (review) return { effect: 'review', ruleId: review.id };
    if (access.effect === 'review') return { effect: 'review', ruleId: access.rule_id };
    if (!rules.some(rule => rule.id === access.rule_id && rule.effect === 'allow')) throw new ForbiddenError();
    return { effect: 'allow', ruleId: access.rule_id };
  }
  const requested = live.binding.operations.filter(entry => entry.access.producer === input.producer &&
    entry.access.target_id === input.targetId && entry.access.action === input.action && matches(entry.access.constraints));
  if (!requested.length) throw new ForbiddenError();
  const rules = live.policy.definition.operation_rules.filter(rule => rule.access.producer === input.producer &&
    rule.access.target_id === input.targetId && rule.access.action === input.action && matches(rule.access.constraints));
  if (rules.some(rule => rule.effect === 'deny')) throw new ForbiddenError();
  const review = rules.find(rule => rule.effect === 'review') ?? requested.find(entry => entry.effect === 'review');
  if (review) return { effect: 'review', ruleId: 'id' in review ? review.id : review.rule_id };
  const allow = requested.find(entry => rules.some(rule => rule.id === entry.rule_id && rule.effect === 'allow'));
  if (!allow) throw new ForbiddenError();
  return { effect: 'allow', ruleId: allow.rule_id };
}

export class FleetAdmissionService {
  constructor(private deps: {
    repo: FleetRepository;
    claimRegistry: Pick<ClaimRegistryService, 'registerClaim'>;
    intentApproval: Pick<IntentApprovalService, 'submitFleetReview'>;
    approvalGate: Pick<ApprovalGateService, 'reserveForDispatch' | 'markConsumed'>;
  }) {}

  /** A fleet member holds no Passport but its fleet's, except one another agent of the account delegated to it (`delegated`). */
  async assertUnboundAgent(operatorId: string, agentId: string, options?: { delegated?: boolean }): Promise<void> {
    if (await this.deps.repo.rootForAgent(agentId)) throw new ForbiddenError();
    if (!options?.delegated && await this.deps.repo.membership(operatorId, agentId)) throw new ForbiddenError();
  }

  async prepare(input: PrepareFleetAdmission): Promise<FleetAdmission | null> {
    const { claims } = input;
    const binding = claims.stk.fleet;
    if (!binding) {
      await this.assertUnboundAgent(claims.stk.operator_id, claims.stk.agent_id, { delegated: claims.stk.delegation_depth > 0 });
      return null;
    }
    if (binding.internal_root || claims.stk.accountability !== 'enforced' || claims.stk.mission_ids?.length !== 1 ||
        claims.stk.mission_ids[0] !== binding.mission_id || !input.operationKey || !/^[A-Za-z0-9_-]{8,256}$/.test(input.operationKey)) throw new ForbiddenError();
    const live = await this.deps.repo.liveMission(claims.stk.operator_id, binding.mission_id, claims.stk.agent_id, undefined, true);
    if (live.policy.id !== binding.policy_id || live.policy.revision !== binding.policy_revision || live.member.id !== binding.membership_id ||
        live.binding.session_id !== claims.stk.session_id) throw new ForbiddenError();
    const decision = decideFleetRequest(live, input);
    const exactRequest = { producer: input.producer, connection_id: input.connectionId, target_id: input.targetId,
      action: input.action, request: input.normalizedRequest };
    const requestHash = fleetDigest(exactRequest);
    const operationKeyHash = fleetDigest(input.operationKey);
    const intentClaim: IntentClaim = {
      ...input.intent, agent_id: claims.stk.agent_id, accountability: 'enforced', mission_ref: binding.mission_id,
      policy_decision: { origin: 'fleet_policy', policy_id: binding.policy_id, policy_revision: binding.policy_revision,
        mission_id: binding.mission_id, rule_id: decision.ruleId, request_hash: requestHash, effect: decision.effect },
    };
    // Required evidence is written before any reservation or credential use.
    const signed = await this.deps.claimRegistry.registerClaim({ operatorId: claims.stk.operator_id,
      passportJti: claims.jti, claimType: 'intent_claim', payload: intentClaim });
    let reviewApprovalId: string | undefined;
    if (decision.effect === 'review') {
      const review = await this.deps.intentApproval.submitFleetReview({
        operatorId: claims.stk.operator_id, agentId: claims.stk.agent_id, passportJti: claims.jti, intentClaimId: signed.claimId,
        policyId: binding.policy_id, policyRevision: binding.policy_revision, missionId: binding.mission_id, requestHash,
        reviewKey: fleetDigest({ binding, agentId: claims.stk.agent_id, operationKeyHash, requestHash }),
        exactRequest,
        expiresAt: new Date(Math.min(live.mission.expires_at.getTime(), Date.now() + 900_000)),
      });
      if (review.status !== 'approved' || review.expires_at.getTime() <= Date.now()) {
        // A typed answer the agent can act on: wait (pending), stop (rejected) or ask again with the same key (expired).
        const status = review.status === 'pending' && review.expires_at.getTime() > Date.now() ? 'pending'
          : review.status === 'rejected' ? 'rejected'
            : review.status === 'consumed' || review.status === 'consuming' ? 'used'
              : 'expired';
        throw new StackError(FLEET_REVIEW_MESSAGES[status], `FLEET_REVIEW_${status.toUpperCase()}`, 403, { approval_id: review.id, status });
      }
      reviewApprovalId = review.id;
    }
    return { producer: input.producer, operationKeyHash, ruleId: decision.ruleId, bytes: input.bytes ?? 0, state: 'prepared',
      authorization: { origin: 'fleet_policy', operatorId: claims.stk.operator_id, agentId: claims.stk.agent_id,
        passportJti: claims.jti, binding, requestHash, intentClaim, intentClaimId: signed.claimId,
        ...(reviewApprovalId ? { reviewApprovalId } : {}) } };
  }

  async reserve(admission: FleetAdmission, maxSpendCents?: number, replayOnly = false): Promise<void> {
    if (admission.state !== 'prepared') throw new ConflictError('Conflict');
    const a = admission.authorization;
    const reserved = await this.deps.repo.reserve({ operatorId: a.operatorId, policyId: a.binding.policy_id,
      missionId: a.binding.mission_id, agentId: a.agentId, producer: admission.producer, ruleId: admission.ruleId,
      operationKeyHash: admission.operationKeyHash, requestHash: a.requestHash, bytes: admission.bytes,
      intentClaimId: a.intentClaimId, ...(maxSpendCents === undefined ? {} : { maxSpendCents }) });
    if (reserved.replay) {
      if (!replayOnly) throw new ConflictError('Conflict');
      // Existing proxy custody can return its screened result. This admission
      // can never dispatch again, even when transport recovery is uncertain.
      admission.operationId = reserved.operation.id;
      admission.state = 'finished';
      return;
    }
    admission.operationId = reserved.operation.id;
    admission.state = 'reserved';
  }

  async dispatch(admission: FleetAdmission, maxSpendCents?: number): Promise<void> {
    if (admission.state === 'prepared') await this.reserve(admission, maxSpendCents);
    if (admission.state !== 'reserved' || !admission.operationId) throw new ConflictError('Conflict');
    const a = admission.authorization;
    await this.deps.repo.dispatch(a.operatorId, a.binding.policy_id, admission.operationId, async tx => {
      if (a.reviewApprovalId) {
        const reservedReview = await this.deps.approvalGate.reserveForDispatch(a.reviewApprovalId, admission.operationKeyHash, tx);
        if (!reservedReview || !await this.deps.approvalGate.markConsumed(a.reviewApprovalId, admission.operationKeyHash, tx)) throw new ForbiddenError();
      }
    });
    admission.state = 'dispatched';
  }

  async linkProxyOperation(admission: FleetAdmission, proxyOperationId: string, operationKey: string, tx: FleetTransaction) {
    if (!admission.operationId || admission.producer !== 'proxy') throw new ForbiddenError();
    await this.deps.repo.linkProxyOperation({ operatorId: admission.authorization.operatorId,
      fleetOperationId: admission.operationId, proxyOperationId, operationKey, requestHash: admission.authorization.requestHash }, tx);
  }

  async finish(admission: FleetAdmission, actualSpendCents?: number): Promise<void> {
    if (admission.state !== 'dispatched' || !admission.operationId) return;
    await this.deps.repo.settle(admission.authorization.operatorId, admission.operationId, 'settled', actualSpendCents);
    admission.state = 'finished';
  }

  async abort(admission: FleetAdmission): Promise<void> {
    if (!admission.operationId || admission.state === 'finished') return;
    await this.deps.repo.settle(admission.authorization.operatorId, admission.operationId,
      admission.state === 'dispatched' ? 'unknown' : 'cancelled');
    admission.state = 'finished';
  }
}
