// governance approvals surface (operate-vs-govern step-up).
//
// Two registrars:
//   registerGovernanceRoutes        — operator scope: list approvals
//   registerGovernancePublicRoutes  — public scope: the DECIDE endpoint.
//     Mounted public because its auth is the dashboard COOKIE SESSION
//     (forwarded by the dashboard proxy — POST /oauth/authorize
//     posture), never a Bearer credential: the entire point of the
//     step-up is that no Bearer-holding session can approve its own
//     elevation. A Bearer here would recreate the rubber-stamp loop.

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  GOVERNANCE_BROWSER_ONLY_ACTIONS,
  GovernanceChatDecisionInput,
  GovernanceDecisionInput,
  ForbiddenError,
  ServiceUnavailableError,
  UnauthorizedError,
  isUsableMcpElicitationAttestationKey,
  verifyMcpElicitationAttestation,
  type HumanOperatorAuthor,
  type PartnerAdminAuthor,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { assertOperatorActive } from '@stack/vault';
import { createAuthMiddleware, enforceAccessForRequest } from '../middleware/auth.js';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { enforceMemberFloorForSession } from '../middleware/member-floor.js';

export function registerGovernanceRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  // List this operator's approvals (pending first-class; terminal states
  // included for the page's history). Agents are denied — the watched
  // system has no business enumerating the operator's pending elevations.
  //
  // a white-label partner also sees its active tenants' approvals
  // each labelled `tenant: { operator_id, name }`, because tenants have no
  // human user and the partner's admin decides them. request.isPartner is
  // false for tenant keys (tenants are never partners) and for Connect-grant
  // contexts, so a tenant key only ever lists its own approvals.
  app.get('/v1/governance/approvals', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    const approvals = request.isPartner === true
      ? await services.governanceApprovals.listForPartner(request.operatorId)
      : await services.governanceApprovals.listForOperator(request.operatorId);
    return { approvals };
  });

  // One approval: its status, the hash of the exact change it covers and the
  // link to its own page. The chat surface reads this to describe the change
  // before it asks the person to confirm. Agents are denied, as for the list.
  // A partner also reads an approval of one of its active tenants.
  app.get('/v1/governance/approvals/:id', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    const { id } = ApprovalParams.parse(request.params);
    if (request.isPartner === true && !(await services.governanceApprovals.belongsTo(id, request.operatorId))) {
      return services.governanceApprovals.getDetailForPartnerTenant(id, request.operatorId);
    }
    return services.governanceApprovals.getDetailForOperator(id, request.operatorId);
  });

  // A decision made in the chat client (MCP elicitation), relayed by the
  // hosted MCP server. Doctrine: the governance step-up design.
  //
  //   reject  - open to any non-agent caller of this account. Rejecting never
  //             widens anything.
  //   approve - only an OAuth access token (never a plain API key, never a
  //             dashboard cookie, never an agent context) presenting the MCP
  //             server's attestation over (approval id, payload hash, MCP
  //             session hash, signed-in principal, one-time elicitation id,
  //             decision, time). The model cannot produce that attestation:
  //             only the MCP server holds the key, and it signs only after the
  //             person accepted the elicitation in their client. Actions in
  //             GOVERNANCE_BROWSER_ONLY_ACTIONS are never approved here.
  app.post('/v1/governance/approvals/:id/chat-decision', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const { id } = ApprovalParams.parse(request.params);
    const input = GovernanceChatDecisionInput.parse(request.body);
    if (request.isDashboardSession === true) {
      throw new ForbiddenError('use the dashboard decision for a dashboard session');
    }
    if (request.memberRole === 'readonly') {
      throw new ForbiddenError('a read-only member cannot decide a governance approval');
    }
    const authoredBy = chatAuthor(request);
    const auditContext = {
      trace_id: request.id,
      span_id: id,
      operator_id: request.operatorId,
      agent_id: 'system',
      passport_jti: 'none',
    };

    if (input.decision === 'reject') {
      const result = await services.operatorDecision.decideGovernance({
        operatorId: request.operatorId,
        approvalId: id,
        decision: 'reject',
        authoredBy,
        channel: { via: 'bearer_reject' },
        auditContext,
      });
      return reply.send({ decision: 'reject', approval: result.approval });
    }

    const oauthClientId = request.oauthClientId;
    if (request.oauthScope === undefined || typeof oauthClientId !== 'string' || oauthClientId.length === 0) {
      throw new ForbiddenError(
        'approving in chat needs a person signed in to the chat client with OAuth; use the approval page',
      );
    }
    const pending = await services.governanceApprovals.getDetailForOperator(id, request.operatorId);
    if (GOVERNANCE_BROWSER_ONLY_ACTIONS.has(pending.approval.action)) {
      throw new ForbiddenError('this change is approved only on its approval page in a signed-in browser');
    }
    const key = chatApprovalKey();
    if (!isUsableMcpElicitationAttestationKey(key)) {
      throw new ServiceUnavailableError('chat approval is not configured; use the approval page');
    }
    if (!input.payload_hash || !input.mcp_session_hash || !input.elicitation_id
      || input.issued_at === undefined || !input.attestation) {
      throw new ForbiddenError('chat approval requires the confirmation attestation');
    }
    const principal = request.memberId ? `member:${request.memberId}` : `operator:${request.operatorId}`;
    const attested = verifyMcpElicitationAttestation(key, {
      approvalId: id,
      payloadHash: input.payload_hash,
      mcpSessionHash: input.mcp_session_hash,
      principal,
      elicitationId: input.elicitation_id,
      decision: 'approve',
      issuedAt: input.issued_at,
    }, input.attestation);
    if (!attested) {
      throw new ForbiddenError('chat confirmation could not be verified');
    }

    try {
      const result = await services.operatorDecision.decideGovernance({
        operatorId: request.operatorId,
        approvalId: id,
        decision: 'approve',
        authoredBy,
        channel: {
          via: 'chat_elicitation',
          mcpSessionHash: input.mcp_session_hash,
          elicitationId: input.elicitation_id,
          oauthClientId,
        },
        expectedPayloadHash: input.payload_hash,
        auditContext,
      });
      return reply.send({ decision: 'approve', approval: result.approval });
    } catch (error) {
      // The unique elicitation id is the replay guard of last resort.
      if (postgresCode(error) === '23505') throw new ForbiddenError('chat confirmation already used');
      throw error;
    }
  });
}

const ApprovalParams = z.object({ id: z.string().regex(/^gvr_[A-Za-z0-9_-]{1,64}$/) }).strict();

/** The shared MCP attestation key, read at request time. */
function chatApprovalKey(): string {
  return (process.env['MCP_ELICITATION_ATTESTATION_KEY'] ?? '').trim();
}

/** The account principal deciding in chat. A member's role is re-read from the DB inside the decision. */
function chatAuthor(request: FastifyRequest): HumanOperatorAuthor {
  if (request.memberId) {
    return { kind: 'team_member', member_id: request.memberId, role_at_signing: request.memberRole === 'admin' ? 'admin' : 'standard' };
  }
  return { kind: 'operator_owner', operator_id: request.operatorId };
}

function postgresCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  if ('code' in error && typeof error.code === 'string') return error.code;
  if ('cause' in error) return postgresCode(error.cause);
  return undefined;
}

export function registerGovernancePublicRoutes(app: FastifyInstance, services: Services) {
  app.post<{ Params: { id: string } }>(
    '/v1/governance/approvals/:id/decide',
    async (request, reply) => {
      const input = GovernanceDecisionInput.parse(request.body);

      const session = await services.signer
        .verifyAccessOrSession(services.browserSessions.extractCookie(request.headers.cookie) ?? '')
        .catch(() => null);
      // Only a dashboard session may decide — reject Bearer-shaped or
      // absent auth uniformly. aud is re-checked: an OAuth access token
      // smuggled into the cookie must not pass.
      if (!session || session.aud !== 'stack:dashboard') {
        throw new UnauthorizedError(
          'a signed-in dashboard session is required to decide a governance approval',
        );
      }

      const operator = await services.operator.getById(session.sub);
      assertOperatorActive(operator);
      // An account with no platform subscription does nothing here: the same 402 as every other route.
      await enforceAccessForRequest(services, request, session.sub);
      const identity = await services.browserSessions.identity(session, operator);
      // A read-only member decides nothing: the floor under every route, before the stricter admin check below.
      enforceMemberFloorForSession(services, request, identity.member);

      // A member's dashboard session carries member_id. Deciding an
      // elevation is an admin act within the account — the same posture
      // requireOperatorAdmin takes for destructive intra-operator ops —
      // so a readonly/standard member cannot rubber-stamp one. The role
      // comes from the DB row, never the JWT claim: a role downgrade
      // must bite before the token expires.
      const sessionMemberId = session.payload['member_id'] as string | undefined;
      let authoredBy: HumanOperatorAuthor = {
        kind: 'operator_owner',
        operator_id: session.sub,
      };
      if (sessionMemberId) {
        const member = identity.member;
        if (!member || member.status !== 'active' || member.operator_id !== session.sub) {
          throw new UnauthorizedError(
            'a signed-in dashboard session is required to decide a governance approval',
          );
        }
        if (member.role !== 'admin') {
          throw new ForbiddenError('deciding a governance approval requires the admin role');
        }
        authoredBy = {
          kind: 'team_member',
          member_id: member.id,
          role_at_signing: 'admin',
        };
      }

      // a partner's admin deciding for one of its white-label
      // tenants (tenants have no human user). Same cookie-only session and
      // admin-only rule as above; the tenant relation, partner status and
      // member role are all re-proven inside the deciding transaction, and
      // any approval that is not an active tenant's of THIS partner is a 404.
      if (operator.is_partner && !(await services.governanceApprovals.belongsTo(request.params.id, session.sub))) {
        const partnerAuthor: PartnerAdminAuthor = {
          kind: 'partner_admin',
          partner_operator_id: session.sub,
          member_id: authoredBy.kind === 'team_member' ? authoredBy.member_id : null,
        };
        const tenantResult = await services.operatorDecision.decideGovernanceForTenant({
          partnerOperatorId: session.sub,
          approvalId: request.params.id,
          decision: input.decision,
          authoredBy: partnerAuthor,
          browserSession: services.browserSessions.decisionSession(session),
          auditContext: {
            trace_id: request.id,
            span_id: request.params.id,
            operator_id: session.sub, // replaced per chain by the service
            agent_id: 'system',
            passport_jti: 'none',
          },
        });
        return reply.send({ decision: input.decision, approval: tenantResult.approval });
      }

      const decisionResult = await services.operatorDecision.decideGovernance({
        operatorId: session.sub,
        approvalId: request.params.id,
        decision: input.decision,
        authoredBy,
        browserSession: services.browserSessions.decisionSession(session),
        auditContext: {
          trace_id: request.id,
          span_id: request.params.id,
          operator_id: session.sub,
          agent_id: 'system',
          passport_jti: 'none',
        },
      });
      const view = decisionResult.approval;
      return reply.send({ decision: input.decision, approval: view });
    },
  );
}
