import { createHash } from 'node:crypto';
import {
  ConflictError,
  ForbiddenError,
  GOVERNANCE_CHAT_APP_PAYMENT_ACTIONS,
  HumanOperatorAuthor,
  NotFoundError,
  PartnerAdminAuthor,
  canonicalize,
  safeErrorSummary,
  ids,
  sha256,
  type HumanOperatorAuthor as HumanOperatorAuthorType,
  type OperatorDecisionAuthor,
  type PartnerAdminAuthor as PartnerAdminAuthorType,
  type GovernanceApprovalView,
  type OperatorDecisionAction,
  type OperatorDecisionEffect,
  type OperatorDecisionSourceRefs,
} from '@stack/shared';
import type { ClaimVerifyResult } from '../crypto/claim-signer.js';
import type { AuditContext, AuditService, AuditTransaction } from './audit-service.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type {
  CheckoutDecisionSource,
  GovernanceDecisionChannel,
  GovernanceDecisionSource,
  OperatorDecisionRepository,
  OperatorDecisionRow,
  OperatorDecisionTransaction,
  SecurityEventDecisionSource,
} from '../repositories/operator-decision-repo.js';
import { isChatAppChannel } from '../repositories/operator-decision-repo.js';
import type { PassportService } from './passport-service.js';
import type { RevokedPassportRow } from '../repositories/passport-repo.js';
import { assertBrowserDecisionSession, type BrowserDecisionSession } from './browser-decision-session.js';
import { assertChatDecisionPrincipal } from './chat-decision-principal.js';

const CHECKOUT_ACTIONS = new Set<OperatorDecisionAction>([
  'checkout_approved',
  'checkout_blocked',
  'future_warning_block_enabled',
  'future_critical_block_enabled',
]);
const SECURITY_ACTIONS = new Set<OperatorDecisionAction>([
  'security_events_dismissed',
  'agent_suspended',
]);

const ACTION_EFFECT: Record<OperatorDecisionAction, OperatorDecisionEffect> = {
  checkout_approved: 'checkout_released',
  checkout_blocked: 'checkout_blocked_and_agent_blocked',
  security_events_dismissed: 'security_events_resolved',
  agent_suspended: 'agent_suspended_and_events_resolved',
  future_warning_block_enabled: 'checkouts_released_and_agent_warning_policy_set_to_block',
  future_critical_block_enabled: 'checkouts_released_and_agent_critical_policy_set_to_block',
  governance_approved: 'governance_approval_approved',
  governance_rejected: 'governance_approval_rejected',
};

const ACTION_SCOPE: Record<OperatorDecisionAction, 'mission' | 'agent_global'> = {
  checkout_approved: 'mission',
  checkout_blocked: 'agent_global',
  security_events_dismissed: 'mission',
  agent_suspended: 'agent_global',
  future_warning_block_enabled: 'agent_global',
  future_critical_block_enabled: 'agent_global',
  governance_approved: 'mission',
  governance_rejected: 'mission',
};

export interface OperatorDecisionRequest {
  operatorId: string;
  authoredBy: HumanOperatorAuthorType;
  action: OperatorDecisionAction;
  sourceIds: string[];
  auditContext?: AuditContext;
  browserSession?: BrowserDecisionSession;
}

export interface OperatorDecisionResult {
  decision_id: string;
  claim_id: string;
  mission_id: string;
  action: OperatorDecisionAction;
  effect: OperatorDecisionEffect;
  effect_scope: 'mission' | 'agent_global';
  target_agent_id: string | null;
  decided_at_ms: number;
  repeated: boolean;
}

export interface GovernanceOperatorDecisionResult {
  approval: GovernanceApprovalView;
  operator_decision: OperatorDecisionResult | null;
}

export interface OperatorDecisionServiceDeps {
  repo: OperatorDecisionRepository;
  claimRegistry: Pick<ClaimRegistryService, 'registerClaim'>;
  claimVerifier: { verifyClaim(claimId: string): Promise<ClaimVerifyResult> };
  audit: Pick<AuditService, 'write'>;
  passportRevocation?: Pick<PassportService, 'syncBlockedAgentRevocations'>;
  /**
   * Told after a governance approval was decided and the decision committed, with what it was about, so what waited
   * on it can follow at once (a held action's review tells its agent). A failure is logged and never undoes the decision.
   */
  onGovernanceDecided?: (decided: GovernanceDecided) => Promise<void>;
  now?: () => number;
  generateId?: () => string;
}

/** A governance approval that was just decided: whose, which, what it was for, and the decision. */
export interface GovernanceDecided {
  operatorId: string;
  approvalId: string;
  action: string;
  resourceId: string;
  decision: 'approve' | 'reject';
}

function postgresCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  if ('code' in error && typeof error.code === 'string') return error.code;
  if ('cause' in error) return postgresCode(error.cause);
  return undefined;
}

function fromRow(row: OperatorDecisionRow, repeated: boolean): OperatorDecisionResult {
  return {
    decision_id: row.id,
    claim_id: row.claim_id,
    mission_id: row.mission_id,
    action: row.action as OperatorDecisionAction,
    effect: row.effect as OperatorDecisionEffect,
    effect_scope: row.effect_scope as 'mission' | 'agent_global',
    target_agent_id: row.target_agent_id,
    decided_at_ms: row.decided_at.getTime(),
    repeated,
  };
}

export class OperatorDecisionService {
  private readonly now: () => number;
  private readonly generateId: () => string;

  constructor(private readonly deps: OperatorDecisionServiceDeps) {
    this.now = deps.now ?? Date.now;
    this.generateId = deps.generateId ?? ids.operatorDecision;
  }

  async decide(request: OperatorDecisionRequest): Promise<OperatorDecisionResult> {
    const authoredBy = HumanOperatorAuthor.parse(request.authoredBy);
    if (authoredBy.kind === 'operator_owner' && authoredBy.operator_id !== request.operatorId) {
      throw new ForbiddenError('operator decision author does not match the authenticated operator');
    }
    if (request.sourceIds.length === 0 || new Set(request.sourceIds).size !== request.sourceIds.length) {
      throw new ForbiddenError('operator decision source ids must be non-empty and unique');
    }
    if (!CHECKOUT_ACTIONS.has(request.action) && !SECURITY_ACTIONS.has(request.action)) {
      throw new ForbiddenError('this Home decision has no exact mission-bound source implementation');
    }

    const normalizedIds = [...request.sourceIds].sort();
    const idempotencyKey = createHash('sha256')
      .update(JSON.stringify({ action: request.action, source_ids: normalizedIds }))
      .digest('hex');

    try {
      const transactionResult = await this.deps.repo.transaction(async ({ decisions, claimPersistence, transaction }) => {
        if (request.browserSession) await assertBrowserDecisionSession(transaction, request.operatorId, request.browserSession, { allowedMemberRoles: authoredBy.kind === 'team_member' ? [authoredBy.role_at_signing] : [] });
        const existing = await decisions.findByIdempotencyKey(request.operatorId, idempotencyKey);
        if (existing) return {
          decision: fromRow(existing, true),
          revokedPassports: [] as RevokedPassportRow[],
        };

        const decisionId = this.generateId();
        const decidedAtMs = this.now();
        const decidedAt = new Date(decidedAtMs);
        const effect = ACTION_EFFECT[request.action];

        let missionId: string;
        let targetAgentId: string;
        let sourceRefs: OperatorDecisionSourceRefs;
        let sourceRows: Array<{ source_type: string; source_id: string }>;
        let revokedPassports: RevokedPassportRow[] = [];

        if (CHECKOUT_ACTIONS.has(request.action)) {
          const sources = await decisions.findCheckoutSources(normalizedIds);
          this.assertExactCheckoutSources(request.operatorId, request.action, normalizedIds, sources);
          missionId = sources[0]!.mission_id!;
          targetAgentId = sources[0]!.agent_id;
          sourceRefs = {
            checkout_ids: normalizedIds,
            security_event_ids: [],
            detector_claim_ids: [],
            approval_ids: [],
          };
          sourceRows = normalizedIds.map((sourceId) => ({ source_type: 'checkout', source_id: sourceId }));
          revokedPassports = await decisions.applyCheckoutEffect({
            decisionId,
            operatorId: request.operatorId,
            action: request.action,
            sources,
            decidedAt,
          });
        } else {
          const sources = await decisions.findSecurityEventSources(normalizedIds);
          const detectorClaimIds = await this.assertExactSecuritySources(
            request.operatorId,
            normalizedIds,
            sources,
          );
          missionId = sources[0]!.mission_id!;
          targetAgentId = sources[0]!.agent_id;
          sourceRefs = {
            checkout_ids: [],
            security_event_ids: normalizedIds,
            detector_claim_ids: detectorClaimIds,
            approval_ids: [],
          };
          sourceRows = [
            ...normalizedIds.map((sourceId) => ({ source_type: 'security_event', source_id: sourceId })),
            ...detectorClaimIds.map((sourceId) => ({ source_type: 'detector_claim', source_id: sourceId })),
          ];
          await decisions.applySecurityEventEffect({
            operatorId: request.operatorId,
            action: request.action,
            sources,
            resolvedBy: authoredBy.kind === 'operator_owner'
              ? `operator:${request.operatorId}`
              : `member:${authoredBy.member_id}`,
            decidedAt,
          });
        }

        const effectScope = ACTION_SCOPE[request.action];
        const claim = await this.deps.claimRegistry.registerClaim({
          operatorId: request.operatorId,
          subjectOverride: 'operator',
          claimType: 'operator_decision',
          payload: {
            type: 'operator_decision',
            decision_id: decisionId,
            mission_ref: missionId,
            operator_id: request.operatorId,
            authored_by: authoredBy,
            action: request.action,
            effect,
            effect_scope: effectScope,
            source_refs: sourceRefs,
            target_agent_id: targetAgentId,
            decided_at_ms: decidedAtMs,
          },
        }, { persistence: claimPersistence });

        const row = await decisions.create({
          id: decisionId,
          claim_id: claim.claimId,
          operator_id: request.operatorId,
          mission_id: missionId,
          idempotency_key: idempotencyKey,
          action: request.action,
          effect,
          effect_scope: effectScope,
          target_agent_id: targetAgentId,
          author_kind: authoredBy.kind,
          author_member_id: authoredBy.kind === 'team_member' ? authoredBy.member_id : null,
          author_role: authoredBy.kind === 'team_member' ? authoredBy.role_at_signing : null,
          decided_at: decidedAt,
        });
        await decisions.createSources(sourceRows.map((source) => ({
          decision_id: decisionId,
          operator_id: request.operatorId,
          source_type: source.source_type,
          source_id: source.source_id,
        })));
        await this.deps.audit.write({
          ctx: this.auditContext(request.auditContext, request.operatorId, targetAgentId, decisionId),
          layer: 'vault',
          action: 'operator_decision.create',
          outcome: 'success',
        }, transaction as AuditTransaction);
        return { decision: fromRow(row, false), revokedPassports };
      });

      if (request.action === 'checkout_blocked' && transactionResult.revokedPassports.length > 0) {
        await this.deps.passportRevocation?.syncBlockedAgentRevocations(
          request.operatorId,
          transactionResult.decision.target_agent_id!,
          `Blocked by signed Home decision ${transactionResult.decision.decision_id}`,
          transactionResult.revokedPassports,
        );
      }
      return transactionResult.decision;
    } catch (error) {
      if (error instanceof ForbiddenError) throw error;
      const existing = await this.deps.repo.findByIdempotencyKey(request.operatorId, idempotencyKey);
      if (existing) return fromRow(existing, true);
      if (postgresCode(error) === '23505') {
        throw new ConflictError('one or more Home sources already have a signed operator decision');
      }
      throw error;
    }
  }

  async decideGovernance(request: {
    operatorId: string;
    approvalId: string;
    decision: 'approve' | 'reject';
    authoredBy: HumanOperatorAuthorType;
    auditContext?: AuditContext;
    browserSession?: BrowserDecisionSession;
    /**
     * A decision that did not come from the dashboard. `chat_elicitation`
     * must carry the payload hash the person was shown; the transaction
     * re-proves the signed-in principal and binds that hash to the row.
     */
    channel?: GovernanceDecisionChannel;
    expectedPayloadHash?: string;
  }): Promise<GovernanceOperatorDecisionResult> {
    const authoredBy = HumanOperatorAuthor.parse(request.authoredBy);
    if (authoredBy.kind === 'operator_owner' && authoredBy.operator_id !== request.operatorId) {
      throw new ForbiddenError('governance decision author does not match the authenticated operator');
    }
    const channel: GovernanceDecisionChannel = request.channel ?? { via: 'dashboard' };
    // A rejection never widens anything, so any non-agent principal of the
    // account may record one. Every approval still needs an admin.
    if (authoredBy.kind === 'team_member' && authoredBy.role_at_signing !== 'admin'
      && !(channel.via === 'bearer_reject' && request.decision === 'reject')) {
      throw new ForbiddenError('governance decisions require an admin member');
    }
    if (channel.via === 'bearer_reject' && request.decision !== 'reject') {
      throw new ForbiddenError('a Bearer credential can only reject a governance approval');
    }
    if ((channel.via === 'chat_elicitation' || isChatAppChannel(channel)) && !request.expectedPayloadHash) {
      throw new ForbiddenError('a chat confirmation must name the change it confirms');
    }

    let decidedSource = null as GovernanceDecisionSource | null;
    const result = await this.deps.repo.transaction(async (context) => {
      if (request.browserSession) await assertBrowserDecisionSession(context.transaction, request.operatorId, request.browserSession);
      if (channel.via === 'chat_elicitation' || isChatAppChannel(channel)) {
        await assertChatDecisionPrincipal(
          context.transaction,
          request.operatorId,
          authoredBy.kind === 'team_member' ? authoredBy.member_id : undefined,
        );
      }
      const source = await context.decisions.findGovernanceApprovalSource(request.approvalId, request.operatorId);
      if (!source) throw new NotFoundError('governance approval', request.approvalId);
      if (request.expectedPayloadHash !== undefined && source.payload_hash !== request.expectedPayloadHash) {
        throw new ForbiddenError('governance approval does not match the confirmed change');
      }
      // A chat app may carry one kind of decision only: a held payment (a control review). Every other
      // browser-only action, and every action the chat may not carry, is refused here whatever the caller says.
      if (isChatAppChannel(channel) && !(GOVERNANCE_CHAT_APP_PAYMENT_ACTIONS as ReadonlySet<string>).has(source.action)) {
        throw new ForbiddenError('this change is approved only on its approval page in a signed-in browser');
      }
      const applied = await this.applyGovernance(context, { ...request, channel }, source, authoredBy);
      decidedSource = source;
      return applied;
    });
    if (decidedSource) await this.governanceDecided(request.operatorId, decidedSource, request.decision);
    return result;
  }

  private async governanceDecided(operatorId: string, source: GovernanceDecisionSource, decision: 'approve' | 'reject'): Promise<void> {
    if (!this.deps.onGovernanceDecided) return;
    try {
      await this.deps.onGovernanceDecided({ operatorId, approvalId: source.id, action: source.action, resourceId: source.resource_id, decision });
    } catch (error) {
      console.error('[OperatorDecisionService] onGovernanceDecided failed:', safeErrorSummary(error));
    }
  }

  /**
   * a white-label partner's human decides an approval that belongs
   * to one of its tenants. Tenants never have a human user, so without this
   * their governance approvals (fleet policies included) could never be
   * decided.
   *
   * Everything is re-proven inside one transaction: the partner's dashboard
   * session (owner, or an ACTIVE admin member, read from the DB row), the
   * partner being active and a partner, and the approval's operator being an
   * active tenant of exactly this partner. Any mismatch is "not found", so a
   * partner cannot probe for another account's approvals. The decision lands
   * on the tenant's audit chain (hash-bound to the acting partner) and on the
   * partner's own chain.
   */
  async decideGovernanceForTenant(request: {
    partnerOperatorId: string;
    approvalId: string;
    decision: 'approve' | 'reject';
    authoredBy: PartnerAdminAuthorType;
    browserSession: BrowserDecisionSession;
    auditContext?: AuditContext;
  }): Promise<GovernanceOperatorDecisionResult & { tenant_operator_id: string }> {
    const authoredBy = PartnerAdminAuthor.parse(request.authoredBy);
    if (authoredBy.partner_operator_id !== request.partnerOperatorId) {
      throw new ForbiddenError('governance decision author does not match the authenticated partner');
    }
    if ((authoredBy.member_id === null) !== (request.browserSession.memberId === undefined)
      || (authoredBy.member_id !== null && authoredBy.member_id !== request.browserSession.memberId)) {
      throw new ForbiddenError('governance decision author does not match the dashboard session');
    }

    let decidedSource = null as GovernanceDecisionSource | null;
    const decided = await this.deps.repo.transaction(async (context) => {
      // Locks the partner, rechecks it is active, and rechecks a member is an
      // ACTIVE ADMIN of the partner (the default allowedMemberRoles).
      await assertBrowserDecisionSession(context.transaction, request.partnerOperatorId, request.browserSession);
      const source = await context.decisions.findTenantGovernanceApprovalSource(
        request.approvalId,
        request.partnerOperatorId,
      );
      if (!source) throw new NotFoundError('governance approval', request.approvalId);
      const result = await this.applyGovernance(
        context,
        {
          operatorId: source.operator_id,
          approvalId: request.approvalId,
          decision: request.decision,
          ...(request.auditContext ? { auditContext: request.auditContext } : {}),
        },
        source,
        authoredBy,
      );
      decidedSource = source;
      return { ...result, tenant_operator_id: source.operator_id };
    });
    if (decidedSource) await this.governanceDecided(decided.tenant_operator_id, decidedSource, request.decision);
    return decided;
  }

  private async applyGovernance(
    { decisions, claimPersistence, transaction }: OperatorDecisionTransaction,
    request: {
      operatorId: string;
      approvalId: string;
      decision: 'approve' | 'reject';
      auditContext?: AuditContext;
      channel?: GovernanceDecisionChannel;
    },
    source: GovernanceDecisionSource,
    authoredBy: OperatorDecisionAuthor,
  ): Promise<GovernanceOperatorDecisionResult> {
    const partner = authoredBy.kind === 'partner_admin' ? authoredBy : null;
    if (source.status !== 'pending') throw new ForbiddenError('governance approval already decided');
    if (source.expires_at.getTime() < this.now()) {
      throw new NotFoundError('governance approval', 'expired');
    }

    const decidedAtMs = this.now();
    const decidedAt = new Date(decidedAtMs);
    const status = request.decision === 'approve' ? 'approved' : 'rejected';
    const updated = await decisions.applyGovernanceDecision({
      id: source.id,
      operatorId: request.operatorId,
      status,
      decidedByMemberId: authoredBy.kind === 'team_member' ? authoredBy.member_id : partner?.member_id ?? null,
      decidedByPartnerOperatorId: partner?.partner_operator_id ?? null,
      decidedAt,
      ...(request.channel ? { channel: request.channel } : {}),
    });
    if (!updated) throw new ForbiddenError('governance approval already decided');

    const approval = this.governanceApprovalView(source, status, decidedAt);
    if (!source.mission_id) {
      await this.writeGovernanceAudit(request, source, transaction as AuditTransaction, partner);
      return { approval, operator_decision: null };
    }

    const action: OperatorDecisionAction = request.decision === 'approve'
      ? 'governance_approved'
      : 'governance_rejected';
    const effect = ACTION_EFFECT[action];
    const idempotencyKey = createHash('sha256')
      .update(JSON.stringify({ action, source_ids: [source.id] }))
      .digest('hex');
    const existing = await decisions.findByIdempotencyKey(request.operatorId, idempotencyKey);
    if (existing) {
      await this.writeGovernanceAudit(request, source, transaction as AuditTransaction, partner);
      return { approval, operator_decision: fromRow(existing, true) };
    }

    const decisionId = this.generateId();
    const claim = await this.deps.claimRegistry.registerClaim({
      operatorId: request.operatorId,
      subjectOverride: 'operator',
      claimType: 'operator_decision',
      payload: {
        type: 'operator_decision',
        decision_id: decisionId,
        mission_ref: source.mission_id,
        operator_id: request.operatorId,
        authored_by: authoredBy,
        action,
        effect,
        effect_scope: 'mission',
        source_refs: {
          checkout_ids: [],
          security_event_ids: [],
          detector_claim_ids: [],
          approval_ids: [source.id],
        },
        target_agent_id: source.agent_id,
        decided_at_ms: decidedAtMs,
      },
    }, { persistence: claimPersistence });
    const row = await decisions.create({
      id: decisionId,
      claim_id: claim.claimId,
      operator_id: request.operatorId,
      mission_id: source.mission_id,
      idempotency_key: idempotencyKey,
      action,
      effect,
      effect_scope: 'mission',
      target_agent_id: source.agent_id,
      author_kind: authoredBy.kind,
      author_member_id: authoredBy.kind === 'team_member' ? authoredBy.member_id : partner?.member_id ?? null,
      author_role: authoredBy.kind === 'team_member'
        ? authoredBy.role_at_signing
        : partner?.member_id ? 'admin' : null,
      author_partner_operator_id: partner?.partner_operator_id ?? null,
      decided_at: decidedAt,
    });
    await decisions.createSources([{
      decision_id: decisionId,
      operator_id: request.operatorId,
      source_type: 'approval',
      source_id: source.id,
    }]);
    await this.writeGovernanceAudit(request, source, transaction as AuditTransaction, partner);
    return { approval, operator_decision: fromRow(row, false) };
  }

  private auditContext(
    input: AuditContext | undefined,
    operatorId: string,
    agentId: string,
    spanId: string,
  ): AuditContext {
    return {
      trace_id: input?.trace_id ?? ids.session(),
      span_id: input?.span_id ?? spanId,
      parent_span_id: input?.parent_span_id,
      operator_id: operatorId,
      agent_id: agentId,
      passport_jti: input?.passport_jti ?? 'none',
    };
  }

  private async writeGovernanceAudit(
    request: {
      operatorId: string;
      approvalId: string;
      decision: 'approve' | 'reject';
      auditContext?: AuditContext;
      channel?: GovernanceDecisionChannel;
    },
    source: GovernanceDecisionSource,
    transaction: AuditTransaction,
    partner: PartnerAdminAuthorType | null = null,
  ): Promise<void> {
    // On the approval's own chain. When a partner decided for its tenant, the
    // acting partner is hash-bound into the entry.
    await this.deps.audit.write({
      ctx: this.auditContext(
        request.auditContext,
        request.operatorId,
        source.agent_id ?? 'system',
        source.id,
      ),
      layer: 'system',
      action: `governance.approval.${request.decision}`,
      outcome: 'success',
      ...(partner ? { actor_partner_operator_id: partner.partner_operator_id } : {}),
      // A decision made outside the dashboard binds how it arrived into the
      // chained entry: the channel, and for a chat confirmation the hashed
      // MCP session, the one-time elicitation id and the OAuth client.
      ...(request.channel && request.channel.via !== 'dashboard'
        ? {
            payload_hash: sha256(canonicalize({
              approval_id: source.id,
              approval_payload_hash: source.payload_hash ?? null,
              decided_via: request.channel.via,
              ...(request.channel.via === 'chat_elicitation'
                ? {
                    mcp_session_hash: request.channel.mcpSessionHash,
                    elicitation_id: request.channel.elicitationId,
                    oauth_client_id: request.channel.oauthClientId,
                  }
                : {}),
              // A chat app's answer binds who answered, which prompt carried it and the amount it was bound to.
              ...(isChatAppChannel(request.channel)
                ? {
                    chat_identity_id: request.channel.identityId,
                    chat_request_id: request.channel.requestId,
                    amount_cents: request.channel.amountCents,
                  }
                : {}),
            })),
          }
        : {}),
    }, transaction);
    if (!partner) return;
    // and on the partner's own chain, binding which tenant approval
    // its human decided. Always tenant chain first, then partner chain.
    await this.deps.audit.write({
      ctx: this.auditContext(
        request.auditContext,
        partner.partner_operator_id,
        'system',
        source.id,
      ),
      layer: 'system',
      action: `governance.tenant_approval.${request.decision}`,
      outcome: 'success',
      payload_hash: sha256(canonicalize({
        approval_id: source.id,
        tenant_operator_id: request.operatorId,
        decision: request.decision,
        member_id: partner.member_id,
      })),
    }, transaction);
  }

  private governanceApprovalView(
    source: GovernanceDecisionSource,
    status: 'approved' | 'rejected',
    decidedAt: Date,
  ): GovernanceApprovalView {
    return {
      id: source.id,
      action: source.action as GovernanceApprovalView['action'],
      resource_id: source.resource_id,
      summary: source.summary,
      requested_via: source.requested_via as GovernanceApprovalView['requested_via'],
      status,
      expires_at: source.expires_at.toISOString(),
      created_at: source.created_at.toISOString(),
      decided_at: decidedAt.toISOString(),
    };
  }

  private assertExactCheckoutSources(
    operatorId: string,
    action: OperatorDecisionAction,
    requestedIds: string[],
    sources: CheckoutDecisionSource[],
  ): void {
    if (sources.length !== requestedIds.length || sources.some((source) => source.operator_id !== operatorId)) {
      throw new NotFoundError('Home checkout source', requestedIds.join(','));
    }
    if (sources.some((source) => !source.mission_id)) {
      throw new ForbiddenError('Home checkout source has no exact mission binding');
    }
    if (new Set(sources.map((source) => source.mission_id)).size !== 1) {
      throw new ForbiddenError('Home decision sources must belong to one mission');
    }
    if (new Set(sources.map((source) => source.agent_id)).size !== 1) {
      throw new ForbiddenError('Home decision sources must belong to one agent');
    }
    const allowedStatuses = action === 'checkout_approved'
      ? new Set(['flagged', 'blocked'])
      : new Set(['flagged']);
    if (sources.some((source) => !allowedStatuses.has(source.review_status))) {
      throw new ConflictError('Home checkout source is stale or already decided');
    }
  }

  private async assertExactSecuritySources(
    operatorId: string,
    requestedIds: string[],
    sources: SecurityEventDecisionSource[],
  ): Promise<string[]> {
    if (sources.length !== requestedIds.length || sources.some((source) => source.operator_id !== operatorId)) {
      throw new NotFoundError('Home security-event source', requestedIds.join(','));
    }
    if (sources.some((source) => !source.mission_id || !source.claim_id || source.resolved)) {
      throw new ForbiddenError('Home security-event source is resolved or lacks an exact signed mission binding');
    }
    if (new Set(sources.map((source) => source.mission_id)).size !== 1) {
      throw new ForbiddenError('Home decision sources must belong to one mission');
    }
    if (new Set(sources.map((source) => source.agent_id)).size !== 1) {
      throw new ForbiddenError('Home decision sources must belong to one agent');
    }

    const missionId = sources[0]!.mission_id;
    const claimIds: string[] = [];
    for (const source of sources) {
      const verified = await this.deps.claimVerifier.verifyClaim(source.claim_id!);
      const envelope = verified.envelope;
      const payload = envelope?.payload as Record<string, unknown> | undefined;
      if (
        !verified.valid
        || !envelope
        || envelope.issuer !== operatorId
        || envelope.claim_type !== 'detector_signal'
        || payload?.['type'] !== 'detector_signal'
        || payload?.['mission_ref'] !== missionId
      ) {
        throw new ForbiddenError('security-event detector claim failed exact operator and mission verification');
      }
      claimIds.push(source.claim_id!);
    }
    return claimIds.sort();
  }
}
