import type { FastifyInstance } from 'fastify';
import {
  ClearSsoBindingsInput,
  InviteMemberInput,
  NotFoundError,
  UpdateMemberInput,
  canonicalize,
  deployment,
  sha256,
  memberInviteEmail,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { env } from '../config/env.js';
import { auditCtx } from '../middleware/audit.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']);

/**
 * Fail closed before persisting an invitation when its emailed handoff URL
 * would be invalid or unsafe in production. Local HTTP remains available for
 * development, where the default dashboard runs on localhost.
 */
export function resolveMemberInviteBaseUrl(
  configuredUrl: string,
  nodeEnv: string,
): URL | null {
  try {
    const url = new URL(configuredUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    if (
      nodeEnv === 'production'
      && (url.protocol !== 'https:' || LOOPBACK_HOSTS.has(url.hostname.toLowerCase()))
    ) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}

/**
 * (auth refactor): operator-admin-scoped routes.
 *
 * Mounted through the operator-admin encapsulation block in server.ts —
 * the [auth, requireOperatorAdmin] preHandler chain is inherited from
 * the scope, NOT declared per-route. A new admin-only member route
 * added here automatically inherits the gate without the developer
 * having to remember.
 *
 * The accept-invite route is intentionally separate — see
 * registerMemberAcceptRoutes below.
 */
export function registerMemberRoutes(app: FastifyInstance, services: Services) {
  // Invite a new member
  app.post('/v1/team/members', async (request, reply) => {
    const input = InviteMemberInput.parse(request.body);
    const start = Date.now();
    // Roles beyond a plain member are an enterprise feature of a self-managed install.
    if (input.role !== 'standard') services.features.require('roles');

    // A self-managed install that sends no email hands the invitation link back
    // to the admin who is inviting, to pass on themselves. Hosted always mails it.
    const noEmail = !services.authEmail;
    if (noEmail && !deployment().selfManaged) {
      return reply.status(503).send({
        error: { message: 'Invitation email is not configured.' },
      });
    }

    const dashboardUrl = resolveMemberInviteBaseUrl(env.DASHBOARD_URL, env.NODE_ENV);
    if (!dashboardUrl) {
      return reply.status(503).send({
        error: { message: 'Invitation URL is not configured.' },
      });
    }

    const operator = await services.operator.getById(request.operatorId);
    const { member, inviteToken } = await services.member.invite(request.operatorId, input);

    const inviteUrl = new URL('/team/invite', dashboardUrl);
    inviteUrl.hash = `token=${encodeURIComponent(inviteToken)}`;
    if (!services.authEmail) {
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'member.invite',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return reply.status(201).send({
        ...toPublicMember(member),
        invite_url: inviteUrl.toString(),
        invite_token: inviteToken,
      });
    }
    const email = memberInviteEmail({
      inviterEmail: operator.email,
      inviteUrl: inviteUrl.toString(),
    });
    try {
      await services.authEmail.sendEmail(member.email, email.subject, email.text, email.html, {
        skipSignature: true,
      });
    } catch {
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'member.invite',
        outcome: 'failure',
        duration_ms: Date.now() - start,
      });
      return reply.status(502).send({
        error: { message: 'The invitation could not be delivered. Try again.' },
      });
    }

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'member.invite',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.status(201).send(toPublicMember(member));
  });

  // List all members
  app.get('/v1/team/members', async (request) => {
    const members = await services.member.list(request.operatorId);
    return members.map(toPublicMember);
  });

  // Update member access
  app.patch<{ Params: { id: string } }>('/v1/team/members/:id', async (request) => {
    const input = UpdateMemberInput.parse(request.body);
    const start = Date.now();
    if (input.role !== undefined && input.role !== 'standard') services.features.require('roles');

    const member = await services.member.updateAccess(request.params.id, request.operatorId, input);
    if (!member) throw new NotFoundError('Member', request.params.id);

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'member.update',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return toPublicMember(member);
  });

  // Revoke a member
  app.delete<{ Params: { id: string } }>('/v1/team/members/:id', async (request) => {
    const start = Date.now();

    await services.member.revoke(request.params.id, request.operatorId);

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'member.revoke',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return { success: true };
  });

  // Forget the single sign-on binding of one member, or of every member bound to one issuer. A person bound to the
  // old provider's subject is refused under the new one, so replacing the provider locks out everyone who had signed
  // in until this runs. After it the next verified sign-in with the provider in use binds them again, so whoever
  // that provider says holds the address takes the seat: a person approves it (governance step-up, browser-only).
  // Owner or admin only, agent contexts refused by the scope this route is mounted in.
  app.post('/v1/team/sso-bindings/clear', async (request) => {
    const start = Date.now();
    const input = ClearSsoBindingsInput.parse(request.body);
    const target = 'member_id' in input ? { memberId: input.member_id } : { issuer: input.issuer };
    await enforceGovernanceStepUp(services, request, {
      action: 'member_sso_binding_clear',
      resourceId: 'member_id' in input ? input.member_id : input.issuer,
      payload: input,
      summary: 'member_id' in input
        ? 'Forget the single sign-on identity of one member. The next person your identity provider confirms to have their address becomes that member.'
        : `Forget the single sign-on identity of every member signed in through ${input.issuer}. The next person your identity provider confirms to have each address becomes that member.`,
    });
    const cleared = await services.member.clearSsoBindings(request.operatorId, target);
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'member.sso_binding.clear',
      outcome: 'success',
      duration_ms: Date.now() - start,
      payload_hash: sha256(canonicalize({ target: input, members: cleared.map((member) => member.id) })),
    });
    return { cleared };
  });
}

/**
 * Public accept-invite route. Mounted on the unauthenticated public
 * scope in server.ts — the invitation token itself is the bearer (single-use,
 * server-side check that the invite is still pending).
 *
 * Intentionally registered as a separate function from registerMemberRoutes
 * so the operator-admin encapsulation block doesn't accidentally gate
 * a public-by-design route. If a future ALL-routes-need-auth pattern
 * lands, this function is the one place to revisit.
 */
export function registerMemberAcceptRoutes(app: FastifyInstance, services: Services) {
  app.post<{ Body: { token?: string } }>('/v1/team/invites/accept', async (request, reply) => {
    const start = Date.now();
    const token = request.body?.token;
    // ids.inviteToken() emits the inv_ prefix plus 32 URL-safe NanoID characters.
    if (typeof token !== 'string' || token.length !== 36 || !/^inv_[A-Za-z0-9_-]{32}$/.test(token)) {
      return reply.status(400).send({ error: { message: 'This invite is no longer valid.' } });
    }

    const { member } = await services.member.acceptInvite(token, {
      trace_id: request.id ?? 'accept',
      span_id: 'accept',
      started_at_ms: start,
    });

    return reply.status(200).send({
      member_id: member.id,
      operator_id: member.operator_id,
      email: member.email,
      role: member.role,
    });
  });
}

function toPublicMember(member: {
  id: string;
  operator_id: string;
  email: string;
  name: string;
  role: string;
  allowed_connections: string[] | null;
  status: string;
  invited_at: Date;
  joined_at: Date | null;
  revoked_at: Date | null;
  sso_issuer?: string | null;
}) {
  return {
    id: member.id,
    operator_id: member.operator_id,
    email: member.email,
    name: member.name,
    role: member.role,
    allowed_connections: member.allowed_connections,
    status: member.status,
    invited_at: member.invited_at,
    joined_at: member.joined_at,
    revoked_at: member.revoked_at,
    // The identity provider this member signed in through, when they have; null until then.
    sso_issuer: member.sso_issuer ?? null,
  };
}
