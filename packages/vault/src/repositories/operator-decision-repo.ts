import { and, eq, inArray, or } from 'drizzle-orm';
import {
  agents,
  ConflictError,
  governanceApprovals,
  ids,
  NotFoundError,
  operatorDecisionSources,
  operatorDecisions,
  operators,
  passportCheckouts,
  passportReviews,
  passports,
  securityEvents,
  type Database,
  type OperatorDecisionAction,
} from '@stack/shared';
import { PassportClaimsRepository } from './passport-claims-repo.js';
import {
  blockAgentAndRevokePassportChain,
  type RevokedPassportRow,
} from './passport-repo.js';

export type OperatorDecisionRow = typeof operatorDecisions.$inferSelect;
export type OperatorDecisionInsert = typeof operatorDecisions.$inferInsert;
export type OperatorDecisionSourceInsert = typeof operatorDecisionSources.$inferInsert;
export type OperatorDecisionDbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export interface CheckoutDecisionSource {
  id: string;
  operator_id: string;
  mission_id: string | null;
  agent_id: string;
  review_status: string;
}

export interface SecurityEventDecisionSource {
  id: string;
  operator_id: string;
  mission_id: string | null;
  agent_id: string;
  claim_id: string | null;
  resolved: boolean;
}

export interface GovernanceDecisionSource {
  id: string;
  operator_id: string;
  action: string;
  resource_id: string;
  summary: string;
  requested_via: string;
  status: string;
  expires_at: Date;
  created_at: Date;
  decided_at: Date | null;
  /** Present on rows read from the table; the chat path binds to it. */
  payload_hash?: string;
  mission_id: string | null;
  agent_id: string | null;
}

/**
 * How a governance decision reached STACK. `dashboard` is the cookie-session
 * decide route; `chat_elicitation` is a human confirmation in an MCP client,
 * relayed and attested by the hosted MCP server; `bearer_reject` is a
 * rejection from a non-agent Bearer caller (rejecting never needs a human).
 */
export type GovernanceDecisionChannel =
  | { via: 'dashboard' }
  | { via: 'bearer_reject' }
  | {
      via: 'chat_elicitation';
      mcpSessionHash: string;
      elicitationId: string;
      oauthClientId: string;
    }
  // The owner's bound identity answering a single-use prompt in Telegram, a text or Slack: only for a held
  // payment within the customer's own limits (the hosted chat approval service).
  | {
      via: 'chat_telegram' | 'chat_sms' | 'chat_slack';
      identityId: string;
      requestId: string;
      /** The payment's amount the prompt was bound to, in USD cents. */
      amountCents: number;
    };

/** The channels whose decision is an answer in a chat app, not the browser and not an MCP client. */
export const CHAT_APP_CHANNELS = ['chat_telegram', 'chat_sms', 'chat_slack'] as const;
export function isChatAppChannel(channel: GovernanceDecisionChannel): channel is Extract<GovernanceDecisionChannel, { identityId: string }> {
  return (CHAT_APP_CHANNELS as readonly string[]).includes(channel.via);
}

export interface OperatorDecisionTransaction {
  decisions: OperatorDecisionRepository;
  claimPersistence: Pick<PassportClaimsRepository, 'insert'>;
  transaction: OperatorDecisionDbTransaction;
}

export class OperatorDecisionRepository {
  constructor(private readonly db: Database) {}

  async transaction<T>(callback: (context: OperatorDecisionTransaction) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => callback({
      decisions: new OperatorDecisionRepository(tx as unknown as Database),
      claimPersistence: new PassportClaimsRepository(tx as unknown as Database),
      transaction: tx,
    }));
  }

  async findByIdempotencyKey(operatorId: string, key: string): Promise<OperatorDecisionRow | null> {
    const row = await this.db.query.operatorDecisions.findFirst({
      where: and(
        eq(operatorDecisions.operator_id, operatorId),
        eq(operatorDecisions.idempotency_key, key),
      ),
    });
    return row ?? null;
  }

  async findCheckoutSources(ids: string[]): Promise<CheckoutDecisionSource[]> {
    if (ids.length === 0) return [];
    return this.db
      .select({
        id: passportCheckouts.id,
        operator_id: passportCheckouts.operator_id,
        mission_id: passportCheckouts.mission_id,
        agent_id: passports.agent_id,
        review_status: passportCheckouts.review_status,
      })
      .from(passportCheckouts)
      .innerJoin(passports, eq(passportCheckouts.passport_jti, passports.jti))
      .where(inArray(passportCheckouts.id, ids))
      .for('update');
  }

  async findSecurityEventSources(ids: string[]): Promise<SecurityEventDecisionSource[]> {
    if (ids.length === 0) return [];
    return this.db
      .select({
        id: securityEvents.id,
        operator_id: securityEvents.operator_id,
        mission_id: securityEvents.mission_id,
        agent_id: securityEvents.agent_id,
        claim_id: securityEvents.claim_id,
        resolved: securityEvents.resolved,
      })
      .from(securityEvents)
      .where(inArray(securityEvents.id, ids))
      .for('update');
  }

  async findGovernanceApprovalSource(id: string, operatorId: string): Promise<GovernanceDecisionSource | null> {
    const [approval] = await this.db
      .select()
      .from(governanceApprovals)
      .where(and(eq(governanceApprovals.id, id), eq(governanceApprovals.operator_id, operatorId)))
      .limit(1)
      .for('update');
    if (!approval) return null;
    return this.withMissionBinding(approval);
  }

  /**
   * lock an approval only when it belongs to an ACTIVE white-label
   * tenant of an ACTIVE partner. The relation comes from the authoritative
   * operators row (parent_operator_id), read in the deciding transaction, so
   * a tenant moved, revoked or a partner suspended between list and decide
   * resolves to "not found". Any other approval id returns null without
   * revealing whether it exists.
   */
  async findTenantGovernanceApprovalSource(
    id: string,
    partnerOperatorId: string,
  ): Promise<GovernanceDecisionSource | null> {
    const [partner] = await this.db
      .select({ status: operators.status, is_partner: operators.is_partner })
      .from(operators)
      .where(eq(operators.id, partnerOperatorId))
      .limit(1);
    if (!partner || partner.status !== 'active' || !partner.is_partner) return null;
    const [row] = await this.db
      .select({ approval: governanceApprovals })
      .from(governanceApprovals)
      .innerJoin(operators, eq(operators.id, governanceApprovals.operator_id))
      .where(and(
        eq(governanceApprovals.id, id),
        eq(operators.parent_operator_id, partnerOperatorId),
        eq(operators.status, 'active'),
      ))
      .limit(1)
      .for('update', { of: governanceApprovals });
    if (!row) return null;
    return this.withMissionBinding(row.approval);
  }

  private async withMissionBinding(
    approval: typeof governanceApprovals.$inferSelect,
  ): Promise<GovernanceDecisionSource> {
    let missionId: string | null = null;
    let agentId: string | null = null;
    if (approval.action === 'review_decide_approve') {
      const [checkout] = await this.db
        .select({ mission_id: passportCheckouts.mission_id, agent_id: passports.agent_id })
        .from(passportCheckouts)
        .innerJoin(passports, eq(passportCheckouts.passport_jti, passports.jti))
        .where(and(
          eq(passportCheckouts.id, approval.resource_id),
          eq(passportCheckouts.operator_id, approval.operator_id),
        ))
        .limit(1);
      missionId = checkout?.mission_id ?? null;
      agentId = checkout?.agent_id ?? null;
    }
    return { ...approval, mission_id: missionId, agent_id: agentId };
  }

  async applyGovernanceDecision(input: {
    id: string;
    operatorId: string;
    status: 'approved' | 'rejected';
    decidedByMemberId: string | null;
    /** the partner deciding for its tenant; omitted otherwise. */
    decidedByPartnerOperatorId?: string | null;
    decidedAt: Date;
    channel?: GovernanceDecisionChannel;
  }): Promise<GovernanceDecisionSource | null> {
    const channel = input.channel ?? { via: 'dashboard' as const };
    const [row] = await this.db
      .update(governanceApprovals)
      .set({
        status: input.status,
        decided_by_member_id: input.decidedByMemberId,
        decided_by_partner_operator_id: input.decidedByPartnerOperatorId ?? null,
        decided_at: input.decidedAt,
        decided_via: channel.via,
        decided_mcp_session_hash: channel.via === 'chat_elicitation' ? channel.mcpSessionHash : null,
        decided_elicitation_id: channel.via === 'chat_elicitation' ? channel.elicitationId : null,
        decided_oauth_client_id: channel.via === 'chat_elicitation' ? channel.oauthClientId : null,
        decided_chat_identity_id: isChatAppChannel(channel) ? channel.identityId : null,
        decided_chat_request_id: isChatAppChannel(channel) ? channel.requestId : null,
      })
      .where(and(
        eq(governanceApprovals.id, input.id),
        eq(governanceApprovals.operator_id, input.operatorId),
        eq(governanceApprovals.status, 'pending'),
      ))
      .returning();
    return row ? { ...row, mission_id: null, agent_id: null } : null;
  }

  async applyCheckoutEffect(input: {
    decisionId: string;
    operatorId: string;
    action: OperatorDecisionAction;
    sources: CheckoutDecisionSource[];
    decidedAt: Date;
  }): Promise<RevokedPassportRow[]> {
    const blocked = input.action === 'checkout_blocked';
    const policyAction = input.action === 'future_warning_block_enabled'
      || input.action === 'future_critical_block_enabled';
    const eligibleState = input.action === 'checkout_approved'
      ? or(
          eq(passportCheckouts.review_status, 'flagged'),
          eq(passportCheckouts.review_status, 'blocked'),
        )
      : eq(passportCheckouts.review_status, 'flagged');
    const updatedCheckouts = await this.db
      .update(passportCheckouts)
      .set({
        review_status: blocked ? 'blocked' : 'clean',
        reviewed_at: input.decidedAt,
      })
      .where(and(
        eq(passportCheckouts.operator_id, input.operatorId),
        inArray(passportCheckouts.id, input.sources.map((source) => source.id)),
        eligibleState,
      ))
      .returning({ id: passportCheckouts.id });
    if (updatedCheckouts.length !== input.sources.length) {
      throw new ConflictError('Home checkout source changed before the decision could commit');
    }

    let revokedPassports: RevokedPassportRow[] = [];
    if (blocked) {
      revokedPassports = await blockAgentAndRevokePassportChain(
        this.db as unknown as OperatorDecisionDbTransaction,
        {
          agentId: input.sources[0]!.agent_id,
          operatorId: input.operatorId,
          reason: `Blocked by signed Home decision ${input.decisionId}`,
          blockedAt: input.decidedAt,
        },
      );
    } else if (policyAction) {
      const updatedAgents = await this.db.update(agents).set(
        input.action === 'future_warning_block_enabled'
          ? { on_warning: 'block' }
          : { on_critical: 'block' },
      )
        .where(and(eq(agents.id, input.sources[0]!.agent_id), eq(agents.operator_id, input.operatorId)))
        .returning({ id: agents.id });
      if (updatedAgents.length !== 1) throw new NotFoundError('agent', input.sources[0]!.agent_id);
    }

    await this.db.insert(passportReviews).values(input.sources.map((source) => ({
      id: ids.review(),
      checkout_id: source.id,
      operator_id: input.operatorId,
      agent_id: source.agent_id,
      decision: blocked ? 'blocked' : 'approved',
      notes: null,
      block_future: blocked || policyAction,
      decided_at: input.decidedAt,
    })));

    return revokedPassports;
  }

  async applySecurityEventEffect(input: {
    operatorId: string;
    action: OperatorDecisionAction;
    sources: SecurityEventDecisionSource[];
    resolvedBy: string;
    decidedAt: Date;
  }): Promise<void> {
    const updatedEvents = await this.db
      .update(securityEvents)
      .set({ resolved: true, resolved_by: input.resolvedBy, resolved_at: input.decidedAt })
      .where(and(
        eq(securityEvents.operator_id, input.operatorId),
        inArray(securityEvents.id, input.sources.map((source) => source.id)),
        eq(securityEvents.resolved, false),
      ))
      .returning({ id: securityEvents.id });
    if (updatedEvents.length !== input.sources.length) {
      throw new ConflictError('Home security-event source changed before the decision could commit');
    }
    if (input.action === 'agent_suspended') {
      const updatedAgents = await this.db
        .update(agents)
        .set({ status: 'suspended' })
        .where(and(
          eq(agents.id, input.sources[0]!.agent_id),
          eq(agents.operator_id, input.operatorId),
        ))
        .returning({ id: agents.id });
      if (updatedAgents.length !== 1) throw new NotFoundError('agent', input.sources[0]!.agent_id);
    }
  }

  async create(input: OperatorDecisionInsert): Promise<OperatorDecisionRow> {
    const [row] = await this.db.insert(operatorDecisions).values(input).returning();
    return row!;
  }

  async createSources(inputs: OperatorDecisionSourceInsert[]): Promise<void> {
    if (inputs.length === 0) return;
    await this.db.insert(operatorDecisionSources).values(inputs);
  }
}
