// the operate-vs-govern step-up service.
//
// A gated governance action hit from a Bearer-credential context (an
// operator key or OAuth token — i.e. potentially an agentic MCP
// session) does not execute: it creates a PENDING approval here, the
// human approves in the DASHBOARD (the decide path requires a cookie
// session — a Bearer credential can never decide), and the caller
// retries with X-Governance-Approval. consume() then enforces: same
// operator, same action, same resource, EXACT payload-hash match
// (what was approved is what executes), approved status, unexpired —
// all CAS single-use. Fail closed on every mismatch.
//
// Doctrine (dashboard-definition.md §1/§5): this gate deliberately
// covers only the scope-EXPANDING actions (detector loosening/reset,
// review approve, agent unblock) — gating everything is the
// rubber-stamp trap this design exists to avoid.

import { timingSafeEqual } from 'node:crypto';
import { safeErrorSummary, FleetPolicyInput } from '@stack/shared';
import {
  ids,
  sha256,
  canonicalize,
  NotFoundError,
  ForbiddenError,
  GovernanceApprovalStateError,
  GovernanceApprovalRequiredError,
  GOVERNANCE_APPROVAL_TTL_SECONDS,
  GOVERNANCE_TENANT_APPROVAL_TTL_SECONDS,
  type GovernanceAction,
  type GovernanceApprovalDetail,
  type GovernanceApprovalView,
} from '@stack/shared';
import type {
  GovernanceApprovalRepository,
  GovernanceApprovalRow,
} from '../repositories/governance-approval-repo.js';
import type { NotificationService } from './notification-service.js';

/**
 * The governance actions a deployment adds to the engine's: the shape of the
 * payload an approval binds, and what the person is shown of it. An action the
 * engine does not know and a deployment did not register has no preview.
 */
export interface GovernanceActionPreviews {
  get(action: string): { payload: { parse(value: unknown): unknown }; preview?: (payload: unknown) => Record<string, unknown> } | undefined;
}

export interface GovernanceApprovalDeps {
  repo: GovernanceApprovalRepository;
  /** Optional — pending-approval pushes degrade to nothing without it. */
  notification: NotificationService | null;
  /** Base URL for the approvals page link (e.g. https://getstack.run). */
  dashboardUrl: string;
  /** The deployment's own governance actions. Absent: the engine's alone. */
  actions?: GovernanceActionPreviews;
}

/** Canonical hash binding an approval to the exact mutation payload. */
export function hashGovernancePayload(payload: unknown): string {
  return sha256(canonicalize(payload ?? {}));
}

const IDEMPOTENT_AUTHORITY_GOVERNANCE_ACTIONS = new Set<GovernanceAction>([
  'fleet_policy_activate',
  'authority_proof_erase',
  'authority_binding_activate',
  'authority_receiver_key_add',
  'authority_profile_activate',
  'authority_principal_erase',
  'authority_binding_erase',
  'authority_presentation_erase',
  // The full account request is the approval payload; the key binds the retry.
  'account_open',
]);

/**
 * Actions whose identical pending request reuses one prompt instead of asking
 * the human again: retries of the same request see the same approval. "Identical" is the same
 * customer, the same requester (the member, or the operator key), the same action, the same
 * resource and the same payload hash, and still pending or approved and unused: a person is
 * never asked twice for the one thing, however often the client retries it.
 */
const SINGLE_PROMPT_GOVERNANCE_ACTIONS = new Set<GovernanceAction>([
  'fleet_policy_activate',
  'account_open',
  'service_grant_expand',
  'account_control_loosen',
  'agent_register',
  'agent_setup',
  'agent_authority_expand',
  'service_allowed_hosts_expand',
  'trust_widen',
]);

/**
 * An approval is for the person who asked for it: when the caller says who is retrying (a member, or null for an
 * operator key), it must be the one the approval was requested by, so another admin cannot replay a byte-identical
 * request under the approval a colleague's request earned. Left out, nothing is checked (a held agent action is bound
 * to its exact call another way).
 */
function assertSameRequester(row: GovernanceApprovalRow, memberId: string | null | undefined): void {
  if (memberId === undefined) return;
  if ((row.member_id ?? null) !== memberId) {
    throw new ForbiddenError('This approval was requested by someone else. Request a new one.');
  }
}

function constantTimeDigestEqual(left: string | null, right: string): boolean {
  if (left === null) return false;
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

/** The stored preview of an `account_open` approval, or null for a row written before previews were kept. */
function storedAccountPreview(stored: Record<string, unknown> | null | undefined): GovernanceApprovalView['account_preview'] {
  if (!stored) return null;
  const { name, monthly_budget_cents: budget, pieces } = stored;
  if (typeof name !== 'string' || (typeof budget !== 'number' && budget !== null) || !Array.isArray(pieces)) return null;
  return { name, monthly_budget_cents: budget, pieces: pieces.filter((piece): piece is string => typeof piece === 'string') };
}

/** What a pending approval is created from. */
export interface PendingApprovalInput {
  operatorId: string;
  memberId: string | null;
  action: GovernanceAction;
  resourceId: string;
  payload: unknown;
  summary: string;
  requestedVia: 'operator_key' | 'member_session' | 'oauth';
  /**
   * What the approval card shows of an `agent_setup`: every part of the request, with the names of the customer's
   * own connections. Built by the route from the request and the customer's rows; the approval itself binds the
   * payload hash, so this is only what the person reads.
   */
  preview?: Record<string, unknown>;
}

export class GovernanceApprovalService {
  constructor(private deps: GovernanceApprovalDeps) {}

  /**
   * What an approval of a deployment's own action shows of its payload, kept
   * beside the row. Derived from the same payload the approval hash binds; an
   * unparseable payload throws, so no approval is created for a request the
   * human could not read.
   */
  private actionPreview(action: GovernanceAction, payload: unknown): Record<string, unknown> | null {
    const spec = this.deps.actions?.get(action);
    if (!spec?.preview) return null;
    return spec.preview(spec.payload.parse(payload));
  }

  /**
   * The page for exactly this approval. A human following the link lands on
   * the one change they are asked to decide, never on a generic list. The
   * dashboard route is /app/approve/[approvalId]; a test pins that every URL
   * the API emits matches a dashboard route.
   */
  approvalUrl(approvalId: string): string {
    return `${this.deps.dashboardUrl}/app/approve/${encodeURIComponent(approvalId)}`;
  }

  /**
   * Create a pending approval and throw the 403 that carries the retry
   * protocol. Called by the route gate when the header is absent.
   */
  async requireApproval(input: PendingApprovalInput): Promise<never> {
    const { row, partner } = await this.createPending(input);
    throw new GovernanceApprovalRequiredError(row.id, this.approvalUrl(row.id), partner ? 'partner' : 'operator');
  }

  /**
   * Create a pending approval for a person to decide, and push it to their
   * channels, without refusing anything: the caller carries the approval's id
   * and link wherever the person is waiting for them (a held agent action
   * names it in its refusal). The same approval, expiry and notification as
   * `requireApproval`, which is this plus the 403.
   */
  async createPending(
    input: PendingApprovalInput,
  ): Promise<{ row: GovernanceApprovalRow; approvalUrl: string; partner: boolean }> {
    // A failed lookup falls back to the ordinary window and wording: the
    // approval is still created and still needs a human, so nothing loosens.
    const partner = await this.deps.repo.findActivePartnerOf(input.operatorId).catch((err: unknown) => {
      console.error('[GOVERNANCE] partner lookup failed:', safeErrorSummary(err));
      return undefined;
    });
    const ttlSeconds = partner ? GOVERNANCE_TENANT_APPROVAL_TTL_SECONDS : GOVERNANCE_APPROVAL_TTL_SECONDS;
    const insert = {
      id: ids.governanceApproval(),
      operator_id: input.operatorId,
      member_id: input.memberId,
      action: input.action,
      resource_id: input.resourceId,
      payload_hash: hashGovernancePayload(input.payload),
      summary: input.summary,
      requested_via: input.requestedVia,
      expires_at: new Date(Date.now() + ttlSeconds * 1000),
      policy_preview: input.action === 'fleet_policy_activate' ? (() => {
        const raw = input.payload as Record<string, unknown>;
        if (raw['policy']) return { policy: FleetPolicyInput.parse(raw['policy']), expected_revision: raw['expected_revision'] };
        return FleetPolicyInput.parse(raw);
      })() : (input.action === 'agent_setup' || input.action === 'service_grant_expand'
        || input.action === 'intent_approve' || input.action === 'intent_approve_payment')
        ? (input.preview ?? null)
        : this.actionPreview(input.action, input.payload),
    };
    const { row, created } = SINGLE_PROMPT_GOVERNANCE_ACTIONS.has(input.action)
      ? await this.deps.repo.insertIdenticalOnce(insert)
      : { row: await this.deps.repo.insert(insert), created: true };

    if (created && this.deps.notification) {
      void this.notifyPending(this.deps.notification, row, input, partner);
    }

    return { row, approvalUrl: this.approvalUrl(row.id), partner: Boolean(partner) };
  }

  /** The approval as stored, scoped to its customer. */
  async findForOperator(approvalId: string, operatorId: string): Promise<GovernanceApprovalRow | undefined> {
    return this.deps.repo.findByIdForOperator(approvalId, operatorId);
  }

  /**
   * Push a pending approval to the requesting operator's channels and, for a
   * white-label tenant, to its partner's channels too: a tenant has
   * no people and no channels of its own, and its partner's admins are the
   * ones who decide. Best-effort: a failed push never blocks the 403.
   */
  private async notifyPending(
    notification: NotificationService,
    row: GovernanceApprovalRow,
    input: { operatorId: string; action: GovernanceAction; resourceId: string; summary: string; requestedVia: string },
    partner: { partner_operator_id: string; external_customer_id: string | null } | undefined,
  ): Promise<void> {
    const payload = {
      approval_id: row.id,
      action: input.action,
      resource_id: input.resourceId,
      requested_via: input.requestedVia,
      expires_at: row.expires_at.toISOString(),
      approval_url: this.approvalUrl(row.id),
      summary: input.summary,
    };
    // How many channels of the account the event reached: a failed push reached none.
    const own = notification
      .publishEvent({ operatorId: input.operatorId, eventType: 'governance.approval_pending', severity: 'warning', payload })
      .then((published) => published.dispatched)
      .catch((err) => {
        console.error('[GOVERNANCE] approval notification failed:', safeErrorSummary(err));
        return 0;
      });
    try {
      if (partner) {
        const tenantName = partner.external_customer_id ?? input.operatorId;
        await notification.publishEvent({
          operatorId: partner.partner_operator_id,
          eventType: 'governance.approval_pending',
          severity: 'warning',
          payload: {
            ...payload,
            tenant_operator_id: input.operatorId,
            tenant_external_customer_id: partner.external_customer_id,
            summary: `Tenant ${tenantName}: ${input.summary}`,
          },
        });
      }
    } catch (err) {
      console.error('[GOVERNANCE] partner approval notification failed:', safeErrorSummary(err));
    }
    const delivered = await own;
    // A new account has no delivery method, so the event above reached nobody and the owner would only learn of the
    // approval by opening the Console. The owner of a partner-managed tenant is not a person (the partner's admins
    // decide, and were told above), so nothing goes to it.
    if (delivered === 0 && !partner) {
      await notification
        .mailOwner({ operatorId: input.operatorId, eventType: 'governance.approval_pending', severity: 'warning', payload })
        .catch((err) => console.error('[GOVERNANCE] owner approval mail failed:', safeErrorSummary(err)));
    }
  }

  /**
   * Consume an approval for execution. Every check fails closed; the
   * CAS consume means a replayed id dies even in a race.
   */
  async consume(input: {
    approvalId: string;
    operatorId: string;
    action: GovernanceAction;
    resourceId: string;
    payload: unknown;
    /** Who is retrying: the member, or null for an operator key. Absent: the requester is not checked. */
    memberId?: string | null;
  }): Promise<void> {
    const row = await this.deps.repo.findByIdForOperator(input.approvalId, input.operatorId);
    if (!row) throw new NotFoundError('governance approval', input.approvalId);
    assertSameRequester(row, input.memberId);

    if (row.status === 'pending') {
      if (row.expires_at.getTime() < Date.now()) {
        await this.deps.repo.expire(row.id).catch(() => undefined);
        throw new GovernanceApprovalStateError(row.id, 'expired', 'governance approval expired before it was decided');
      }
      throw new GovernanceApprovalStateError(
        row.id,
        'pending',
        'governance approval is still pending — a human must approve it in the dashboard first',
      );
    }
    if (row.status === 'rejected' || row.status === 'expired') {
      throw new GovernanceApprovalStateError(row.id, row.status, `governance approval is ${row.status}: request a new one`);
    }
    if (row.status !== 'approved') {
      throw new ForbiddenError(`governance approval is ${row.status} — request a new one`);
    }
    if (row.action !== input.action || row.resource_id !== input.resourceId) {
      throw new ForbiddenError('governance approval does not match this action');
    }
    if (row.payload_hash !== hashGovernancePayload(input.payload)) {
      // The retried payload differs from what the human saw. Refuse —
      // this is the whole point of the hash binding.
      throw new ForbiddenError(
        'governance approval does not match this exact change — request a new one',
      );
    }
    if (row.expires_at.getTime() < Date.now()) {
      throw new GovernanceApprovalStateError(row.id, 'expired', 'governance approval expired');
    }

    const consumed = await this.deps.repo.consume(row.id);
    if (!consumed) {
      // Lost the CAS — someone else consumed it first. Single-use.
      throw new ForbiddenError('governance approval already used');
    }
  }

  /**
   * Authority management retries may reuse one consumed human approval only
   * when the exact mutation Idempotency-Key and every approved commitment
   * match. This closes the consume-then-crash gap without weakening consume()
   * for any existing governance action.
   */
  async consumeAuthorityIdempotently(input: {
    approvalId: string;
    operatorId: string;
    action: GovernanceAction;
    resourceId: string;
    payload: unknown;
    idempotencyKey: string;
    /** Who is retrying: the member, or null for an operator key. Absent: the requester is not checked. */
    memberId?: string | null;
  }): Promise<void> {
    if (!IDEMPOTENT_AUTHORITY_GOVERNANCE_ACTIONS.has(input.action)) {
      throw new ForbiddenError('governance action does not permit idempotent approval consumption');
    }
    if (input.idempotencyKey.length === 0) {
      throw new ForbiddenError('Idempotency-Key is required for authority governance');
    }

    const row = await this.deps.repo.findByIdForOperator(input.approvalId, input.operatorId);
    if (!row) throw new NotFoundError('governance approval', input.approvalId);
    assertSameRequester(row, input.memberId);

    const payloadHash = hashGovernancePayload(input.payload);
    if (row.action !== input.action || row.resource_id !== input.resourceId) {
      throw new ForbiddenError('governance approval does not match this action');
    }
    if (row.payload_hash !== payloadHash) {
      throw new ForbiddenError(
        'governance approval does not match this exact change — request a new one',
      );
    }

    const idempotencyKeyHash = sha256(input.idempotencyKey);
    if (row.status === 'consumed') {
      if (constantTimeDigestEqual(row.consumed_idempotency_key_hash, idempotencyKeyHash)) return;
      throw new ForbiddenError('governance approval already used for another authority operation');
    }
    if (row.status === 'pending') {
      if (row.expires_at.getTime() < Date.now()) {
        await this.deps.repo.expire(row.id).catch(() => undefined);
        throw new GovernanceApprovalStateError(row.id, 'expired', 'governance approval expired before it was decided');
      }
      throw new GovernanceApprovalStateError(
        row.id,
        'pending',
        'governance approval is still pending — a human must approve it in the dashboard first',
      );
    }
    if (row.status === 'rejected' || row.status === 'expired') {
      throw new GovernanceApprovalStateError(row.id, row.status, `governance approval is ${row.status}: request a new one`);
    }
    if (row.status !== 'approved') {
      throw new ForbiddenError(`governance approval is ${row.status} — request a new one`);
    }
    const now = new Date();
    if (row.expires_at.getTime() < now.getTime()) {
      throw new GovernanceApprovalStateError(row.id, 'expired', 'governance approval expired');
    }

    const result = await this.deps.repo.consumeAuthorityIdempotently({
      id: row.id,
      operatorId: input.operatorId,
      action: input.action,
      resourceId: input.resourceId,
      payloadHash,
      idempotencyKeyHash,
      now,
    });
    if (!result) throw new NotFoundError('governance approval', input.approvalId);
    if (result.consumedNow) return;
    if (
      result.row.status === 'consumed' &&
      result.row.action === input.action &&
      result.row.resource_id === input.resourceId &&
      result.row.payload_hash === payloadHash &&
      constantTimeDigestEqual(result.row.consumed_idempotency_key_hash, idempotencyKeyHash)
    )
      return;
    throw new ForbiddenError('governance approval already used or changed concurrently');
  }

  /**
   * Human decision. The ROUTE enforces that the caller is a dashboard
   * cookie session for this operator (a Bearer credential must never
   * reach this) — service re-scopes by operator as defense-in-depth.
   */
  async decide(
    approvalId: string,
    operatorId: string,
    decision: 'approve' | 'reject',
    decidedByMemberId?: string | null,
  ): Promise<GovernanceApprovalView> {
    const row = await this.deps.repo.findByIdForOperator(approvalId, operatorId);
    if (!row) throw new NotFoundError('governance approval', approvalId);
    if (row.status === 'pending' && row.expires_at.getTime() < Date.now()) {
      await this.deps.repo.expire(row.id).catch(() => undefined);
      throw new NotFoundError('governance approval', 'expired');
    }
    const updated = await this.deps.repo.decide(
      approvalId,
      decision === 'approve' ? 'approved' : 'rejected',
      decidedByMemberId ?? null,
    );
    if (!updated) throw new ForbiddenError('governance approval already decided');
    return this.toView(updated);
  }

  async listForOperator(operatorId: string): Promise<GovernanceApprovalView[]> {
    const rows = await this.deps.repo.listForOperator(operatorId);
    // Lazy-expire stale pendings so the list shows truth.
    const out: GovernanceApprovalView[] = [];
    for (const row of rows) {
      if (row.status === 'pending' && row.expires_at.getTime() < Date.now()) {
        const expired = await this.deps.repo.expire(row.id).catch(() => undefined);
        out.push(this.toView(expired ?? { ...row, status: 'expired' }));
      } else {
        out.push(this.toView(row));
      }
    }
    return out;
  }

  /**
   * a partner's own approvals plus those of its active white-label
   * tenants. Tenants have no human user, so the partner's admin decides them;
   * each tenant item is labelled with the tenant id and the partner's own
   * name for it (external_customer_id, else the id).
   */
  async listForPartner(partnerOperatorId: string): Promise<GovernanceApprovalView[]> {
    const own = await this.listForOperator(partnerOperatorId);
    const tenantRows = await this.deps.repo.listForPartnerTenants(partnerOperatorId);
    const tenantViews: GovernanceApprovalView[] = [];
    for (const { row, tenant } of tenantRows) {
      let current = row;
      if (row.status === 'pending' && row.expires_at.getTime() < Date.now()) {
        current = (await this.deps.repo.expire(row.id).catch(() => undefined)) ?? { ...row, status: 'expired' };
      }
      tenantViews.push({
        ...this.toView(current),
        tenant: { operator_id: tenant.id, name: tenant.external_customer_id ?? tenant.id },
      });
    }
    return [...own, ...tenantViews];
  }

  /**
   * One approval of this operator, with the payload hash a chat confirmation
   * binds to and the link to its own page. A stale pending row is expired
   * first so the caller sees the truth. Another operator's id is not found.
   */
  async getDetailForOperator(approvalId: string, operatorId: string): Promise<GovernanceApprovalDetail> {
    const row = await this.deps.repo.findByIdForOperator(approvalId, operatorId);
    if (!row) throw new NotFoundError('governance approval', approvalId);
    const current = await this.expireIfStale(row);
    return { approval: this.toView(current), payload_hash: current.payload_hash, approval_url: this.approvalUrl(current.id) };
  }

  /**
   * One approval of an active white-label tenant, for the partner whose admin
   * decides it. Same shape as getDetailForOperator, labelled with the tenant.
   * Any other id is not found, so a partner cannot probe other accounts.
   */
  async getDetailForPartnerTenant(approvalId: string, partnerOperatorId: string): Promise<GovernanceApprovalDetail> {
    const found = await this.deps.repo.findForPartnerTenant(approvalId, partnerOperatorId);
    if (!found) throw new NotFoundError('governance approval', approvalId);
    const current = await this.expireIfStale(found.row);
    return {
      approval: {
        ...this.toView(current),
        tenant: { operator_id: found.tenant.id, name: found.tenant.external_customer_id ?? found.tenant.id },
      },
      payload_hash: current.payload_hash,
      approval_url: this.approvalUrl(current.id),
    };
  }

  private async expireIfStale(row: GovernanceApprovalRow): Promise<GovernanceApprovalRow> {
    if (row.status === 'pending' && row.expires_at.getTime() < Date.now()) {
      return (await this.deps.repo.expire(row.id).catch(() => undefined)) ?? { ...row, status: 'expired' };
    }
    return row;
  }

  /** True when the approval exists and belongs to exactly this operator. */
  async belongsTo(approvalId: string, operatorId: string): Promise<boolean> {
    return (await this.deps.repo.findByIdForOperator(approvalId, operatorId)) !== undefined;
  }

  private toView(row: GovernanceApprovalRow): GovernanceApprovalView {
    return {
      id: row.id,
      action: row.action as GovernanceApprovalView['action'],
      resource_id: row.resource_id,
      summary: row.summary,
      ...(row.action === 'fleet_policy_activate' ? { policy_preview: row.policy_preview ?? null } : {}),
      ...(row.action === 'account_open' ? { account_preview: storedAccountPreview(row.policy_preview) } : {}),
      ...(row.action === 'agent_setup' ? { setup_preview: row.policy_preview ?? null } : {}),
      ...(row.action === 'service_grant_expand' ? { grant_preview: row.policy_preview ?? null } : {}),
      ...(row.action === 'intent_approve' || row.action === 'intent_approve_payment' ? { intent_preview: row.policy_preview ?? null } : {}),
      requested_via: row.requested_via as GovernanceApprovalView['requested_via'],
      status: row.status as GovernanceApprovalView['status'],
      expires_at: row.expires_at.toISOString(),
      created_at: row.created_at.toISOString(),
      decided_at: row.decided_at?.toISOString() ?? null,
      decided_via: row.decided_via ?? null,
    };
  }
}
