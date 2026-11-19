import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  IssuePassportInput,
  DelegatePassportInput,
  RefreshPassportInput,
  VerifyPassportInput,
  RevokeAllInput,
  ForbiddenError,
  type AuthorityReference,
} from '@stack/shared';
import { PassportRevokeFlagsError, type PassportRevokeOutcome } from '@stack/vault';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { meterAction, meterPassportUpkeep } from '../middleware/meter.js';
import { requireRole } from '../middleware/require-role.js';

// SDK clients send `reason: null` when no reason was given, so every optional
// field accepts null as well as absence.
const RevokePassportBody = z.object({
  jti: z.string().min(1),
  reason: z.string().nullish(),
});
const RevokeReasonBody = z.object({ reason: z.string().nullish() });
const ActivePassportsQuery = z.object({
  agent_id: z.string().optional(),
  session_id: z.string().optional(),
});

/**
 * Authority-bearing Passport issuance keeps agent contexts on the safe side
 * of the self-authorization boundary. An agent may ask for its own Passport
 * carrying bindings that were assigned and activated elsewhere, but it may
 * not target another agent or select legacy identity evidence.
 */
export function assertPassportIssueActor(
  actor: { agentId?: string; passportContext?: unknown },
  input: {
    agent_id: string;
    identity_claim_ids?: string[];
    authority_binding_ids?: string[];
  },
): void {
  if (actor.passportContext) {
    throw new ForbiddenError('A Passport may refresh or delegate its authority, but may not issue a new root Passport');
  }
  if (actor.agentId) {
    if (input.agent_id !== actor.agentId) {
      throw new ForbiddenError('Agent context may issue a Passport only for itself');
    }
    if (input.identity_claim_ids !== undefined) {
      throw new ForbiddenError('Agent context may not select identity claims');
    }
  }
}

/** A continuation belongs to the bearer principal, even within one operator. */
export function assertPassportContinuationActor(
  actor: { operatorId: string; agentId?: string },
  claims: { stk: { operator_id: string; agent_id: string } },
): void {
  if (claims.stk.operator_id !== actor.operatorId ||
      (actor.agentId && claims.stk.agent_id !== actor.agentId)) {
    throw new ForbiddenError('Passport continuation belongs to a different principal');
  }
}

interface ActivePassportProjectionInput {
  jti: string;
  agent_id: string;
  session_id: string;
  delegation_depth: number;
  parent_passport_id: string | null;
  identity_claim_ids?: string[] | null;
  issued_at: Date;
  expires_at: Date;
  intent_summary?: string | null;
  intent_services?: string[] | null;
  intent_refs?: unknown[] | null;
  mission_ids?: string[] | null;
  estimated_duration_seconds?: number | null;
  checkpoint_interval_seconds?: number | null;
  checkpoint_count?: number | null;
  last_checkpoint_at?: Date | null;
}

/** Keep the active-Passport response PII-free while exposing signed opaque refs. */
export function projectActivePassport(
  passport: ActivePassportProjectionInput,
  authorityRefs: AuthorityReference[],
) {
  return {
    jti: passport.jti,
    agent_id: passport.agent_id,
    session_id: passport.session_id,
    delegation_depth: passport.delegation_depth,
    parent_passport_id: passport.parent_passport_id,
    identity_claim_ids: passport.identity_claim_ids ?? [],
    authority_refs: authorityRefs,
    issued_at: passport.issued_at.toISOString(),
    expires_at: passport.expires_at.toISOString(),
    intent_summary: passport.intent_summary ?? null,
    intent_services: passport.intent_services ?? [],
    intent_refs: passport.intent_refs ?? [],
    mission_ids: passport.mission_ids ?? [],
    estimated_duration_seconds: passport.estimated_duration_seconds ?? null,
    checkpoint_interval_seconds: passport.checkpoint_interval_seconds ?? null,
    checkpoint_count: passport.checkpoint_count ?? 0,
    last_checkpoint_at: passport.last_checkpoint_at ? passport.last_checkpoint_at.toISOString() : null,
  };
}

export function registerPassportRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.post('/v1/passports/issue', { preHandler: auth }, async (request, reply) => {
    // A read-only member may not act: opening, changing, ending or minting is for a standard member or above.
    requireRole(request, 'standard');
    const input = IssuePassportInput.parse(request.body);
    const start = Date.now();

    assertPassportIssueActor(request, input);

    await meterPassportUpkeep(services, request, input.agent_id);
    const signed = await services.fleet.issueFromMission(request.operatorId, input)
      ?? await services.passport.issue(request.operatorId, input);

    await services.audit.write({
      ctx: auditCtx(request, { agent_id: input.agent_id }),
      layer: 'vault',
      action: 'passport.issue',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    // Activation milestone — fires once per operator. Silent no-op
    // for repeat issuances (Redis SETNX dedup).
    services.analytics.fireOnce(request.operatorId, 'first_passport_issued', {
      agent_id: input.agent_id,
      tier: request.operatorTier,
    });

    return reply.status(201).send({
      token: signed.token,
      jti: signed.jti,
      expires_at: signed.expires_at.toISOString(),
    });
  });

  app.post('/v1/passports/verify', async (request) => {
    const { token, service_id } = VerifyPassportInput.parse(request.body);
    const start = Date.now();

    const claims = await services.passport.verify(token, { service_id: service_id ?? undefined });

    await services.audit.write({
      ctx: {
        trace_id: request.id,
        span_id: claims.jti,
        operator_id: claims.stk.operator_id,
        agent_id: claims.stk.agent_id,
        passport_jti: claims.jti,
      },
      layer: 'vault',
      action: 'passport.verify',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return {
      valid: true,
      jti: claims.jti,
      agent_id: claims.sub,
      expires_at: new Date(claims.exp * 1000).toISOString(),
      claims: claims.stk,
    };
  });

  app.post('/v1/passports/revoke', { preHandler: auth }, async (request) => {
    // A read-only member may not act: opening, changing, ending or minting is for a standard member or above.
    requireRole(request, 'standard');
    const { jti, reason } = RevokePassportBody.parse(request.body);
    const start = Date.now();

    // A flag that could not be written answers 503 after the revoke committed. The revoke cannot be repeated (a retry
    // finds nothing left to cascade), so its audit rows are written first and the 503 follows.
    let flagFailure: PassportRevokeFlagsError | undefined;
    let result: PassportRevokeOutcome | undefined;
    try {
      result = await services.passport.revoke({
        jti,
        operatorId: request.operatorId,
        reason: reason ?? 'Revoked by operator',
      });
    } catch (error) {
      if (!(error instanceof PassportRevokeFlagsError)) throw error;
      flagFailure = error;
      result = error.outcome;
    }

    // Parent revoke entry.
    await services.audit.write({
      ctx: auditCtx(request, { passport_jti: jti }),
      layer: 'vault',
      action: 'passport.revoke',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    // One audit entry per cascaded child so the chain reflects what
    // actually happened. Without this, an operator tailing /v1/audit
    // sees the parent revoke but no record of the children dying with it.
    if (result?.cascaded) {
      for (const childJti of result.cascaded) {
        await services.audit.write({
          ctx: auditCtx(request, { passport_jti: childJti }),
          layer: 'vault',
          action: 'passport.revoke_cascade',
          outcome: 'success',
          duration_ms: 0,
        });
      }
    }

    // one claim.revoke audit row per attached-claim cascaded
    // shut by the passport revoke (root + all descendants). payload_hash
    // carries the claim_hash so the chain entry binds back to the
    // specific revoked claim row in passport_claims.
    if (result?.revoked_claims) {
      for (const cl of result.revoked_claims) {
        await services.audit.write({
          ctx: auditCtx(request, { passport_jti: jti }),
          layer: 'vault',
          action: 'claim.revoke',
          outcome: 'success',
          duration_ms: 0,
          payload_hash: cl.claim_hash,
        });
      }
    }

    if (flagFailure) throw flagFailure;

    return {
      success: true,
      jti,
      cascaded_count: result?.cascaded.length ?? 0,
      revoked_claims_count: result?.revoked_claims?.length ?? 0,
    };
  });

  app.post('/v1/passports/delegate', { preHandler: auth }, async (request, reply) => {
    // A read-only member may not act: opening, changing, ending or minting is for a standard member or above.
    requireRole(request, 'standard');
    const input = DelegatePassportInput.parse(request.body);
    const start = Date.now();
    const parent = await services.signer.verify(input.parent_passport_token);
    assertPassportContinuationActor(request, parent);

    // A delegation mints a new passport, same as issue and refresh — one
    // recorded action. Narrowing scope for a sub-agent is a real credential
    // minted for a real hop, not free plumbing.
    await meterAction(services, request);
    const signed = await services.passport.delegate(request.operatorId, input);

    await services.audit.write({
      ctx: auditCtx(request, { agent_id: input.child_agent_id, passport_jti: signed.jti }),
      layer: 'vault',
      action: 'passport.delegate',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.status(201).send({
      token: signed.token,
      jti: signed.jti,
      expires_at: signed.expires_at.toISOString(),
    });
  });

  app.post('/v1/passports/refresh', { preHandler: auth }, async (request, reply) => {
    // A read-only member may not act: opening, changing, ending or minting is for a standard member or above.
    requireRole(request, 'standard');
    const input = RefreshPassportInput.parse(request.body);
    const start = Date.now();
    const previous = await services.signer.verify(input.token, { ignoreExpiration: true });
    assertPassportContinuationActor(request, previous);

    await meterPassportUpkeep(services, request, previous.stk.agent_id);
    const signed = await services.passport.refresh(request.operatorId, input.token, input.ttl_seconds);

    await services.audit.write({
      ctx: auditCtx(request, { passport_jti: signed.jti }),
      layer: 'vault',
      action: 'passport.refresh',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.status(201).send({
      token: signed.token,
      jti: signed.jti,
      expires_at: signed.expires_at.toISOString(),
    });
  });

  // ─── Active Passports & Bulk Revocation ──────────────────────────

  app.get('/v1/passports/active', { preHandler: auth }, async (request) => {
    const { agent_id, session_id } = ActivePassportsQuery.parse(request.query);
    const active = await services.passport.listActive(request.operatorId, { agent_id, session_id });
    const authorityRefs = await services.authority.listPassportAuthorityRefsForPassports(
      request.operatorId,
      active.map((passport) => passport.jti),
    );
    return active.map((passport) => projectActivePassport(
      passport,
      authorityRefs.get(passport.jti) ?? [],
    ));
  });


  app.post<{ Params: { agentId: string } }>(
    '/v1/passports/revoke-agent/:agentId',
    { preHandler: auth },
    async (request) => {
      requireRole(request, 'standard');
      const { reason } = RevokeReasonBody.parse(request.body ?? {});
      const start = Date.now();

      // Verify the caller owns the agent before revoking its passports
      await services.agent.getById(request.params.agentId, request.operatorId);

      const result = await services.passport.revokeAllForAgent(
        request.params.agentId,
        reason ?? 'Bulk revoke by operator',
      );

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: request.params.agentId }),
        layer: 'vault',
        action: 'passport.revoke_agent',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return { success: true, revoked_count: result.revoked_count };
    },
  );

  app.post<{ Params: { sessionId: string } }>(
    '/v1/passports/revoke-session/:sessionId',
    { preHandler: auth },
    async (request) => {
      requireRole(request, 'standard');
      const { reason } = RevokeReasonBody.parse(request.body ?? {});
      const start = Date.now();

      const result = await services.passport.revokeBySession(
        request.operatorId,
        request.params.sessionId,
        reason ?? 'Session revoked by operator',
      );

      await services.audit.write({
        ctx: auditCtx(request, {}),
        layer: 'vault',
        action: 'passport.revoke_session',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return { success: true, revoked_count: result.revoked_count };
    },
  );

  app.post('/v1/passports/revoke-all', { preHandler: auth }, async (request) => {
    // A read-only member may not act: opening, changing, ending or minting is for a standard member or above.
    requireRole(request, 'standard');
    const input = RevokeAllInput.parse(request.body);
    const start = Date.now();

    const result = await services.passport.revokeAllForOperator(
      request.operatorId,
      input.reason ?? 'Emergency revoke all',
    );

    await services.audit.write({
      ctx: auditCtx(request, {}),
      layer: 'vault',
      action: 'passport.revoke_all',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return { success: true, revoked_count: result.revoked_count };
  });

  // JWKS endpoint — public, used for offline passport verification
  app.get('/v1/.well-known/jwks.json', async () => {
    return services.signer.getJwks();
  });

  // The same document under the path the OAuth discovery document advertises as `jwks_uri`.
  app.get('/v1/internal/jwks', async () => {
    return services.signer.getJwks();
  });
}
