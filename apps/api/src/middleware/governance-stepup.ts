// the operate-vs-govern step-up gate.
//
// Applied INSIDE the handlers of the four gated actions (detector config
// loosening/reset, review decide=approved, agent unblock) — deliberately
// NOT a blanket preHandler: the doctrine's rubber-stamp trap says gate
// only the scope-EXPANDING minority (dashboard-definition.md §1).
//
// Context rules:
//   - Dashboard cookie sessions (aud stack:dashboard) pass free — the
//     human at the dashboard IS the ceremony this gate exists to force.
//   - Agent contexts never reach this gate
//     except the detector PUT, where the route's direction gate handles
//     them before step-up is considered.
//   - The owner's own API key (no member, no OAuth client, no agent) passes
//     without an approval when the account trusts its agents (the trust
//     switch, "Trust my agents"), for every action except the browser-only
//     ones (GOVERNANCE_BROWSER_ONLY_ACTIONS). The waiver is recorded in the
//     audit log as `governance.step_up.waived_by_trust`.
//   - Every other Bearer credential (operator key or OAuth
//     api/mcp token — i.e. potentially an agentic MCP session) must
//     present X-Governance-Approval naming a HUMAN-approved, unexpired,
//     unconsumed approval whose payload hash matches this exact request.
//     Absent → a pending approval is created and the 403 carries the
//     retry protocol.

import type { FastifyRequest } from 'fastify';
import { GOVERNANCE_BROWSER_ONLY_ACTIONS, sha256, type GovernanceAction } from '@stack/shared';
import type { Services } from '../config/services.js';
import { auditCtx } from './audit.js';

export const GOVERNANCE_APPROVAL_HEADER = 'x-governance-approval';

/** The audit action of a step-up the owner's own key did not have to repeat, because the account trusts its agents. */
export const GOVERNANCE_STEP_UP_WAIVED_ACTION = 'governance.step_up.waived_by_trust';

/** Whether an account lets its owner's own API key through a governance step-up (the trust switch's account value). */
export interface StepUpWaiver {
  waives(operatorId: string): Promise<boolean>;
}

/** The owner's own API key: no member, no OAuth client (a chat), no agent of any kind. */
function isOwnersOwnKey(request: FastifyRequest): boolean {
  return (
    !request.memberId &&
    !request.oauthClientId &&
    !request.agentId &&
    !request.enrollmentTicket &&
    !request.platformPassport &&
    !request.passportContext
  );
}

export async function enforceGovernanceStepUp(
  services: Services,
  request: FastifyRequest,
  input: {
    action: GovernanceAction;
    resourceId: string;
    /** The exact mutation payload the approval must bind to. */
    payload: unknown;
    /** Human-facing one-liner rendered on the approvals page. */
    summary: string;
    /** Present only for authority mutations whose exact retry may reuse a consumed approval. */
    idempotencyKey?: string;
    /** What the approval card lists of a combined request (an `agent_setup`); display only, the payload is what binds. */
    preview?: Record<string, unknown>;
  },
): Promise<void> {
  if (request.isDashboardSession === true) return;

  const approvalId = request.headers[GOVERNANCE_APPROVAL_HEADER] as string | undefined;
  if (
    !approvalId &&
    !GOVERNANCE_BROWSER_ONLY_ACTIONS.has(input.action) &&
    isOwnersOwnKey(request) &&
    services.stepUpWaiver !== undefined &&
    (await services.stepUpWaiver.waives(request.operatorId))
  ) {
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: GOVERNANCE_STEP_UP_WAIVED_ACTION,
      outcome: 'success',
      payload_hash: sha256(JSON.stringify({ action: input.action, resource_id: input.resourceId })),
    });
    return;
  }
  if (approvalId) {
    const approval = {
      approvalId,
      operatorId: request.operatorId,
      action: input.action,
      resourceId: input.resourceId,
      payload: input.payload,
      // The approval is the requester's: another member (or a key) replaying the same request does not get to use it.
      memberId: request.memberId ?? null,
    };
    if (input.idempotencyKey !== undefined) {
      await services.governanceApprovals.consumeAuthorityIdempotently({
        ...approval,
        idempotencyKey: input.idempotencyKey,
      });
    } else {
      await services.governanceApprovals.consume(approval);
    }
    return;
  }

  await services.governanceApprovals.requireApproval({
    operatorId: request.operatorId,
    memberId: request.memberId ?? null,
    action: input.action,
    resourceId: input.resourceId,
    payload: input.payload,
    summary: input.summary,
    ...(input.preview ? { preview: input.preview } : {}),
    requestedVia: request.memberId
      ? 'member_session'
      : request.oauthClientId
        ? 'oauth'
        : 'operator_key',
  });
}
