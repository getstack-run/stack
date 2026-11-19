import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import {
  ids, OAUTH_FAMILY_REVOKED_KEY, OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP, UpdateIdentitySettingsInput,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';

/** The address typed back to confirm deletion; the erasure service compares it to the account email. */
const DeleteAccountBody = z.object({ confirm_email: z.string() });

export interface EffectiveAuthContext {
  principal: {
    type: 'operator' | 'member' | 'agent';
    id: string;
  };
  is_platform_staff: boolean;
  /**
   * The exact resource an OAuth MCP access token was granted for. Present
   * only for MCP tokens that carry the signed claim. The MCP transport uses
   * it to keep /mcp and /directory tokens on their own paths.
   */
  oauth_resource?: string;
}

export function getEffectiveAuthContext(request: FastifyRequest): EffectiveAuthContext {
  const resource = request.oauthResource ? { oauth_resource: request.oauthResource } : {};
  if (request.agentId) {
    return {
      principal: { type: 'agent', id: request.agentId },
      is_platform_staff: false,
      ...resource,
    };
  }
  if (request.memberId) {
    return {
      principal: { type: 'member', id: request.memberId },
      is_platform_staff: false,
      ...resource,
    };
  }
  return {
    principal: { type: 'operator', id: request.operatorId },
    is_platform_staff: request.isPlatformStaff === true,
    ...resource,
  };
}

export function registerOperatorRoutes(app: FastifyInstance, services: Services) {
  const authenticate = createAuthMiddleware(services);

  // This is a live credential check for internal callers such as MCP.
  // It does not read the operator profile or write a profile audit event.
  app.get('/v1/auth/context', { preHandler: authenticate }, async (request, reply) => {
    return reply.send(getEffectiveAuthContext(request));
  });

  // Authenticated — get current operator profile
  app.get('/v1/operators/me', { preHandler: authenticate }, async (request, reply) => {
    const start = Date.now();

    const operator = await services.operator.getById(request.operatorId);
    const { plan } = await services.entitlements.resolve(request.operatorId);

    await services.audit.write({
      ctx: {
        trace_id: request.id,
        span_id: ids.session(),
        operator_id: operator.id,
        agent_id: 'system',
        passport_jti: 'none',
      },
      layer: 'vault',
      action: 'operator.profile',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.send({
      id: operator.id,
      email: operator.email,
      plan,
      // Expose the authenticated caller's effective platform-staff status.
      // This lets privilege-aware clients such as the MCP
      // server — decide whether to surface platform-staff-only tooling
      // without a separate admin call. Not enumeration: only ever your
      // effective flag. Members and agents never inherit it.
      is_platform_staff: request.isPlatformStaff === true,
      identity_claim_ttl: operator.identity_claim_ttl,
      identity_claim_inheritance: operator.identity_claim_inheritance,
      identity_auto_revoke: operator.identity_auto_revoke,
      created_at: operator.created_at,
    });
  });

  // Get identity settings
  app.get('/v1/operators/me/identity-settings', { preHandler: authenticate }, async (request, reply) => {
    const settings = await services.operator.getIdentitySettings(request.operatorId);
    return reply.send(settings);
  });

  // Update identity settings
  app.patch('/v1/operators/me/identity-settings', {
    preHandler: [authenticate, denyAgentContexts, requireOperatorAdmin],
  }, async (request, reply) => {
    const start = Date.now();
    const input = UpdateIdentitySettingsInput.parse(request.body ?? {});
    // The owner or an admin changes the identity settings directly, loosening or tightening.
    const settings = await services.operator.updateIdentitySettings(request.operatorId, input);

    await services.audit.write({
      ctx: {
        trace_id: request.id,
        span_id: ids.session(),
        operator_id: request.operatorId,
        agent_id: 'system',
        passport_jti: 'none',
      },
      layer: 'vault',
      action: 'operator.identity_settings.update',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.send(settings);
  });

  // List MCP sessions for the authed caller. An MCP session = an OAuth
  // refresh-token family (one /authorize grant + all its rotations).
  // Operator-scoped sessions are returned for operator-authed callers;
  // member-scoped sessions are returned for member-authed callers. The
  // partition is hard-enforced in OperatorService.listMcpSessions.
  app.get(
    '/v1/operators/me/mcp-sessions',
    { preHandler: authenticate },
    async (request, reply) => {
      const sessions = await services.operator.listMcpSessions(
        request.operatorId,
        request.memberId,
      );
      return reply.send({ sessions });
    },
  );

  // Revoke an entire token family. All tokens in the family are marked
  // revoked and the next refresh attempt fails. Enforcement of the revoke is
  // live on the next STACK-verified call (the auth path re-checks token state),
  // NOT dependent on access-token TTL expiry; the access token also self-
  // expires within its TTL (OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP/_API, 1h).
  app.delete<{ Params: { familyId: string } }>(
    '/v1/operators/me/mcp-sessions/:familyId',
    { preHandler: [authenticate, denyAgentContexts] },
    async (request, reply) => {
      const start = Date.now();
      const { revoked } = await services.operator.revokeMcpSession(
        request.operatorId,
        request.memberId,
        request.params.familyId,
      );

      // Kill any already-issued access token of this family on its next call.
      // revokeMcpSession threw NotFoundError above if the family isn't the
      // caller's, so writing the flag here is safe (ownership already checked).
      try {
        await services.redis.set(
          OAUTH_FAMILY_REVOKED_KEY(request.params.familyId), '1', 'EX', OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP,
        );
      } catch {
        // The database revocation already committed. Do not turn success
        // into a 500 or skip its audit when the Redis accelerator is down.
        // Keep this log static. Family ids and bearer values are sensitive.
        console.error('[operators] MCP session Redis revocation write failed');
      }

      await services.audit.write({
        ctx: {
          trace_id: request.id,
          span_id: ids.session(),
          operator_id: request.operatorId,
          agent_id: 'system',
          passport_jti: 'none',
        },
        layer: 'vault',
        action: 'mcp_session.revoke',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.send({ revoked });
    },
  );

  // Delete operator account (requires email confirmation)
  app.delete('/v1/operators/me', { preHandler: [authenticate, denyAgentContexts] }, async (request, reply) => {
    const { confirm_email } = DeleteAccountBody.parse(request.body);
    const result = await services.operator.deleteAccount(request.operatorId, confirm_email);

    // Intentional GDPR exception to the normal mutation-audit rule.
    // deleteAccount erases the operator and its complete audit chain.
    // A success write here would recreate orphan personal data after erasure.

    return reply.status(result.status === 'completed' ? 204 : 202).send();
  });

  // ─── Email transfer ───────────────────────────────────────────────
  //
  // The email IS the credential here - there are no passwords, so whoever
  // receives the magic link owns the account. Changing it is a transfer of
  // control, and the shape reflects that:
  //
  //   request  authenticated, agents denied. Sends a confirm link to the NEW
  //            address and a cancel link to the OLD one. Changes nothing.
  //   confirm  PUBLIC. The token is the auth, exactly like a magic link.
  //   cancel   PUBLIC, and public is the point: the person cancelling may be
  //            locked out of a session someone else is holding.
  //
  // Only `confirm` writes operators.email.

  app.get('/v1/operators/me/email-change', { preHandler: [authenticate, denyAgentContexts] }, async (request) => {
    const pending = await services.emailChange.pendingFor(request.operatorId);
    return { pending };
  });

  app.post('/v1/operators/me/email-change', {
    preHandler: [authenticate, denyAgentContexts],
  }, async (request, reply) => {
    const start = Date.now();
    const { new_email } = (request.body ?? {}) as { new_email?: string };
    if (!new_email || typeof new_email !== 'string') {
      return reply.status(400).send({ error: { message: 'new_email is required' } });
    }

    const result = await services.emailChange.request({
      operatorId: request.operatorId,
      newEmail: new_email,
      requestedByMemberId: request.memberId ?? null,
    }, {
      traceId: request.id,
      spanId: ids.session(),
      startedAtMs: start,
    });

    return {
      pending: { id: result.id, new_email: result.newEmail, expires_at: result.expiresAt.toISOString() },
    };
  });
}
