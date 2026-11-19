import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import {
  ConflictError,
  ForbiddenError,
  ProxyOperationLookupInput,
  SESSION_JWT_AUDIENCE,
  StackError,
  deployment,
  sha256,
  UnauthorizedError,
} from '@stack/shared';
import {
  assertBrowserDecisionSession,
  assertOperatorActive,
  PROXY_REPLACEMENT_WARNING,
  PROXY_REPLACEMENT_WARNING_HASH,
  PROXY_REPLACEMENT_WARNING_VERSION,
  type BrowserDecisionSession,
  type ProxyOperationMetadata,
} from '@stack/vault';
import { z } from 'zod';
import type { Services } from '../config/services.js';
import { createAuthMiddleware, enforceAccessForRequest } from '../middleware/auth.js';
import { enforceMemberFloorForSession } from '../middleware/member-floor.js';
import { requireBrowserSession } from '../lib/browser-session.js';
import { announceDecision } from '../lib/decision-reached.js';
import { enforceProxyOperationReadRate } from '../lib/proxy-operation-rate-limit.js';
import {
  reconcileStripeRefund,
  StripeReconciliationUnavailableError,
} from '../lib/stripe-proxy-reconciliation.js';

const OPERATION_NOT_FOUND = {
  error: {
    code: 'NOT_FOUND',
    message: 'Proxy operation not found',
  },
} as const;

const HumanOperationLookupInput = ProxyOperationLookupInput.pick({ operation_id: true }).strict();
const ReplacementAuthorizationInput = z.object({
  operation_id: ProxyOperationLookupInput.shape.operation_id,
  replacement_operation_id: ProxyOperationLookupInput.shape.operation_id,
  acknowledged_warning_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
}).strict();

type VerifiedPassport = Awaited<ReturnType<Services['passport']['verify']>>;

/**
 * The limiter keys on a durable authenticated principal, never a short-lived
 * JWT identifier. Rotating transport authentication therefore cannot reset a
 * caller's operation-read budget.
 */
export function proxyOperationReadPrincipal(request: FastifyRequest): string {
  if (request.agentId) return `agent:${request.agentId}`;
  if (request.memberId) return `member:${request.memberId}`;
  if (request.oauthClientId) return `oauth-client:${request.oauthClientId}`;
  return `operator:${request.operatorId}`;
}

function notFound(reply: FastifyReply) {
  reply.header('Cache-Control', 'private, no-store');
  return reply.status(404).send(OPERATION_NOT_FOUND);
}

function privateNoStore(reply: FastifyReply): void {
  reply.header('Cache-Control', 'private, no-store');
  reply.header('Pragma', 'no-cache');
  reply.header('Expires', '0');
}

export function humanProxyOperationState(metadata: ProxyOperationMetadata): string {
  if (metadata.reconciliationState === 'confirmed') return 'Confirmed by provider';
  if (metadata.reconciliationState === 'contradictory') return 'Provider outcome unknown';
  if (metadata.deliveryState === 'response_received' && metadata.replayState === 'expired') {
    return 'Stored response expired';
  }
  if (metadata.deliveryState === 'response_received') return 'Response stored';
  if (metadata.deliveryState === 'outcome_unknown' && metadata.unresolvedAt) return 'Unresolved: never sent again';
  if (metadata.deliveryState === 'outcome_unknown') return 'Provider outcome unknown';
  if (metadata.deliveryState === 'dispatching') return 'Sent; waiting for response';
  return 'Waiting to send';
}

/**
 * What a decision wake names a proxied write by: the SHA-256 of the operation id the agent sent, which is all STACK
 * keeps of it. The agent hashes its own id to match.
 */
export function proxyOperationItemId(operationKey: string): string {
  return `sha256:${sha256(operationKey)}`;
}

/** How a reconciliation that reached an end ended the write, as a decision names it; null while it has not ended. */
export function reconciledResult(metadata: Pick<ProxyOperationMetadata, 'reconciliationState' | 'reconciliationProviderStatus'>):
  'succeeded' | 'failed' | 'not_found' | 'contradictory' | 'unresolved' | null {
  if (metadata.reconciliationState === 'confirmed') {
    if (metadata.reconciliationProviderStatus === 'succeeded') return 'succeeded';
    if (metadata.reconciliationProviderStatus === 'failed' || metadata.reconciliationProviderStatus === 'canceled') return 'failed';
    return null;
  }
  if (metadata.reconciliationState === 'not_found') return 'not_found';
  if (metadata.reconciliationState === 'contradictory') return 'contradictory';
  // Past the provider's retry window nothing can settle it any more: it stays unknown and is never sent again.
  if (metadata.reconciliationState === 'expired') return 'unresolved';
  return null;
}

function humanStatus(operationKey: string, metadata: ProxyOperationMetadata) {
  const providerTerminal = metadata.reconciliationState === 'contradictory'
    || (metadata.reconciliationState === 'confirmed'
      && ['succeeded', 'failed', 'canceled'].includes(metadata.reconciliationProviderStatus ?? ''));
  const effectUnresolved = !providerTerminal && (
    metadata.deliveryState === 'outcome_unknown'
    || (metadata.adapterKind === 'stripe'
      && metadata.deliveryState === 'response_received'
      && ['pending', 'not_found', 'expired', 'confirmed'].includes(metadata.reconciliationState))
  );
  const canReconcile = metadata.adapterKind === 'stripe'
    && ['outcome_unknown', 'response_received'].includes(metadata.deliveryState)
    && (['pending', 'not_found'].includes(metadata.reconciliationState)
      || (metadata.reconciliationState === 'confirmed'
        && ['pending', 'requires_action'].includes(metadata.reconciliationProviderStatus ?? '')));
  return {
    operation_id: operationKey,
    state: humanProxyOperationState(metadata),
    provider: metadata.provider,
    method: metadata.method,
    transport_attempts: metadata.transportAttempts,
    created_at: metadata.createdAt.toISOString(),
    dispatched_at: metadata.dispatchedAt?.toISOString() ?? null,
    response_received_at: metadata.responseReceivedAt?.toISOString() ?? null,
    unresolved_at: metadata.unresolvedAt?.toISOString() ?? null,
    can_reconcile: canReconcile,
    can_authorize_replacement: effectUnresolved,
    replacement_warning: effectUnresolved ? {
      version: PROXY_REPLACEMENT_WARNING_VERSION,
      text: PROXY_REPLACEMENT_WARNING,
      hash: PROXY_REPLACEMENT_WARNING_HASH,
    } : null,
  };
}

type VerifiedSession = Awaited<ReturnType<Services['signer']['verifyAccessOrSession']>>;

async function resolveRecoveryHuman(services: Services, request: FastifyRequest): Promise<{
  operatorId: string;
  session: VerifiedSession;
  browserSession: BrowserDecisionSession;
  humanAuthor: { kind: 'operator_owner'; operatorId: string } | { kind: 'team_member'; memberId: string };
  allowedConnections?: readonly string[];
}> {
  if (request.headers.authorization !== undefined) {
    throw new UnauthorizedError('A signed-in dashboard session is required');
  }
  assertRecoveryOrigin(request.headers.origin);
  const token = services.browserSessions.extractCookie(request.headers.cookie);
  const session = token
    ? await services.signer.verifyAccessOrSession(token).catch(() => null)
    : null;
  if (!session || session.aud !== SESSION_JWT_AUDIENCE) {
    throw new UnauthorizedError('A signed-in dashboard session is required');
  }
  const operator = await services.operator.getById(session.sub);
  assertOperatorActive(operator);
  // An account with no platform subscription does nothing here: the same 402 as every other route.
  await enforceAccessForRequest(services, request, session.sub);
  const identity = await services.browserSessions.identity(session, operator);
  // A read-only member recovers nothing: the floor under every route, before this flow's own admin check.
  enforceMemberFloorForSession(services, request, identity.member);
  if (identity.member && identity.member.role !== 'admin') {
    throw new ForbiddenError('An owner or admin is required for proxy recovery');
  }
  return {
    operatorId: session.sub,
    session,
    browserSession: services.browserSessions.decisionSession(session),
    humanAuthor: identity.member
      ? { kind: 'team_member', memberId: identity.member.id }
      : { kind: 'operator_owner', operatorId: session.sub },
    ...(identity.member?.allowed_connections !== null
      ? { allowedConnections: identity.member?.allowed_connections ?? undefined }
      : {}),
  };
}

export function assertRecoveryOrigin(originHeader: string | undefined): void {
  let expected: string;
  try { expected = new URL(deployment().dashboardUrl).origin; }
  catch { throw new StackError('Dashboard origin configuration is invalid', 'SERVICE_UNAVAILABLE', 503); }
  if (!originHeader) throw new ForbiddenError('Dashboard request origin is required');
  try {
    const supplied = new URL(originHeader);
    if (supplied.origin !== originHeader || supplied.origin !== expected) {
      throw new ForbiddenError('Dashboard request origin is invalid');
    }
  } catch (error) {
    if (error instanceof ForbiddenError) throw error;
    throw new ForbiddenError('Dashboard request origin is invalid');
  }
}

function currentPassportAuthority(claims: VerifiedPassport) {
  return {
    services: claims.stk.services.map((service) => ({
      service_id: service.service_id,
      service_name: service.service_name,
      scopes: [...service.scopes],
      ...(service.connection_id ? { connection_id: service.connection_id } : {}),
      constraints: [...(service.constraints ?? [])],
      policy: service.policy ?? null,
      allow_data_from: [...(service.allow_data_from ?? [])],
    })),
    intentServices: [...(claims.stk.intent_services ?? [])],
    authorityRefs: [...(claims.stk.authority_refs ?? [])],
  };
}

function publicStatus(
  operationId: string,
  includeResponse: boolean,
  result: Awaited<ReturnType<Services['proxyOperation']['authorizeRead']>>,
) {
  if (!result) return null;
  const metadata = result.metadata;
  return {
    operation_id: operationId,
    delivery_state: metadata.deliveryState,
    replay_state: metadata.replayState,
    accounting_state: metadata.accountingState,
    provider: metadata.provider,
    method: metadata.method,
    created_at: metadata.createdAt.toISOString(),
    dispatched_at: metadata.dispatchedAt?.toISOString() ?? null,
    response_received_at: metadata.responseReceivedAt?.toISOString() ?? null,
    // The outcome stayed unknown for PROXY_OPERATION_UNRESOLVED_AFTER_DAYS with nothing settling it: it is never sent again.
    unresolved_at: metadata.unresolvedAt?.toISOString() ?? null,
    provider_outcome: metadata.reconciliationState,
    provider_status: metadata.reconciliationProviderStatus,
    ...(includeResponse && result.replay?.state === 'available'
      ? {
          response: {
            status: result.replay.status,
            headers: result.replay.headers,
            body: result.replay.body,
          },
        }
      : {}),
  };
}

export function registerProxyOperationRoutes(
  app: FastifyInstance,
  services: Services,
  overrides: { reconcileStripeRefund?: typeof reconcileStripeRefund } = {},
) {
  const auth = createAuthMiddleware(services);
  const reconcileRefund = overrides.reconcileStripeRefund ?? reconcileStripeRefund;

  app.post(
    '/v1/dashboard/proxy/operations/get',
    { preHandler: [auth, requireBrowserSession] },
    async (request, reply) => {
      privateNoStore(reply);
      const parsed = HumanOperationLookupInput.safeParse(request.body);
      if (!parsed.success) return notFound(reply);
      const metadata = await services.proxyOperation.authorizeHumanMetadata({
        operatorId: request.operatorId,
        operationKey: parsed.data.operation_id,
        allowedConnections: request.allowedConnections,
      });
      if (!metadata) return notFound(reply);
      return humanStatus(parsed.data.operation_id, metadata);
    },
  );

  app.post(
    '/v1/proxy/operations/reconcile',
    async (request, reply) => {
      privateNoStore(reply);
      const human = await resolveRecoveryHuman(services, request);
      const parsed = HumanOperationLookupInput.safeParse(request.body);
      if (!parsed.success) return notFound(reply);
      const visible = await services.proxyOperation.authorizeHumanMetadata({
        operatorId: human.operatorId,
        operationKey: parsed.data.operation_id,
        allowedConnections: human.allowedConnections,
      });
      if (!visible || visible.adapterKind !== 'stripe' || !visible.dispatchedAt) return notFound(reply);

      const now = new Date();
      const alreadyTerminal = ((visible.reconciliationState === 'confirmed'
        && ['succeeded', 'failed', 'canceled'].includes(visible.reconciliationProviderStatus ?? ''))
        || visible.reconciliationState === 'contradictory'
        || visible.reconciliationState === 'expired')
        && visible.reconciliationEvidenceHash !== null;
      const target = alreadyTerminal
        ? null
        : await services.proxyOperation.readStripeReconciliationTarget({
            operatorId: human.operatorId,
            operationKey: parsed.data.operation_id,
            allowedConnections: human.allowedConnections,
          });
      if (!alreadyTerminal && !target) return notFound(reply);
      const providerResult = alreadyTerminal
        ? {
            state: visible.reconciliationState as 'confirmed' | 'contradictory' | 'expired',
            evidenceHash: visible.reconciliationEvidenceHash!,
            resourceHash: undefined,
            providerStatus: visible.reconciliationProviderStatus ?? undefined,
          }
        : target!.metadata.retryDeadline && target!.metadata.retryDeadline <= now
          ? {
              state: 'expired' as const,
              evidenceHash: `sha256:${target!.operationKeyHash}`,
              resourceHash: undefined,
              providerStatus: undefined,
            }
          : await (async () => {
            const pinned = await services.serviceConnection.retrieveCredentialPinnedByConnectionId(
              human.operatorId,
              target!.metadata.connectionId,
              target!.metadata.credentialVersion,
              human.allowedConnections,
            );
            try {
              return await reconcileRefund({
                credential: 'credential' in pinned ? pinned.credential : pinned.credentials,
                stripeAccount: target!.stripeAccount,
                providerMarker: target!.providerMarker,
                firstDispatchedAt: target!.metadata.dispatchedAt!,
              });
            } catch (error) {
              if (error instanceof StripeReconciliationUnavailableError) {
                throw new StackError(error.message, 'SERVICE_UNAVAILABLE', 503);
              }
              throw error;
            }
          })();

      const recorded = await services.proxyOperation.transaction(async (tx) => {
        await services.browserSessions.assertActiveInTransaction(tx, human.session);
        await assertBrowserDecisionSession(tx, human.operatorId, human.browserSession, {
          allowedMemberRoles: ['admin'],
          requiredConnectionId: visible.connectionId,
        });
        if (alreadyTerminal) return true;
        return services.proxyOperation.recordGovernedReconciliation({
          operatorId: human.operatorId,
          operationKey: parsed.data.operation_id,
          state: providerResult.state,
          resourceHash: providerResult.resourceHash,
          evidenceHash: providerResult.evidenceHash,
          providerStatus: providerResult.providerStatus,
          transaction: tx,
        });
      });
      if (!recorded) throw new ConflictError('The proxy operation changed during reconciliation');
      const metadata = await services.proxyOperation.authorizeHumanMetadata({
        operatorId: human.operatorId,
        operationKey: parsed.data.operation_id,
        allowedConnections: human.allowedConnections,
      });
      if (!metadata) return notFound(reply);
      // A concurrent reconciliation may have appended this observation while
      // preserving a different terminal winner. Complete authority only from
      // the durable conclusion read back after the transaction.
      const authorityOutcome = metadata.reconciliationState === 'confirmed'
          && metadata.reconciliationProviderStatus === 'succeeded'
          ? 'succeeded' as const
        : metadata.reconciliationState === 'confirmed'
            && ['failed', 'canceled'].includes(metadata.reconciliationProviderStatus ?? '')
          ? 'failed' as const
          : null;
      if (metadata.authorityUseId && authorityOutcome && metadata.responseHash) {
        await services.authority.completeRuntimeAuthorityUseByHash({
          operatorId: human.operatorId,
          useId: metadata.authorityUseId,
          outcome: authorityOutcome,
          resultHash: metadata.responseHash.startsWith('sha256:')
            ? metadata.responseHash
            : `sha256:${metadata.responseHash}`,
        });
      }
      // The reconciliation this call recorded ended the write: tell the agent that sent it how.
      const ended = alreadyTerminal ? null : reconciledResult(metadata);
      if (ended) {
        await announceDecision(services.registries, {
          operatorId: human.operatorId,
          agentId: metadata.agentId,
          kind: 'proxy_operation',
          itemId: proxyOperationItemId(parsed.data.operation_id),
          result: ended,
        });
      }
      return humanStatus(parsed.data.operation_id, metadata);
    },
  );

  app.post(
    '/v1/proxy/operations/authorize-replacement',
    async (request, reply) => {
      privateNoStore(reply);
      const human = await resolveRecoveryHuman(services, request);
      const parsed = ReplacementAuthorizationInput.safeParse(request.body);
      if (!parsed.success) return notFound(reply);
      const metadata = await services.proxyOperation.authorizeHumanMetadata({
        operatorId: human.operatorId,
        operationKey: parsed.data.operation_id,
        allowedConnections: human.allowedConnections,
      });
      if (!metadata) return notFound(reply);
      const result = await services.proxyOperation.transaction(async (tx) => {
        await services.browserSessions.assertActiveInTransaction(tx, human.session);
        await assertBrowserDecisionSession(tx, human.operatorId, human.browserSession, {
          allowedMemberRoles: ['admin'],
          requiredConnectionId: metadata.connectionId,
        });
        return services.proxyOperation.authorizeReplacement({
          operatorId: human.operatorId,
          originalOperationKey: parsed.data.operation_id,
          replacementOperationKey: parsed.data.replacement_operation_id,
          acknowledgedWarningHash: parsed.data.acknowledged_warning_hash,
          humanAuthor: human.humanAuthor,
          dashboardSessionFamilyId: human.browserSession.sessionId ?? '',
          dashboardSessionTokenId: human.browserSession.tokenId ?? '',
          transaction: tx,
        });
      });
      if (result.state === 'unavailable') return notFound(reply);
      if (result.state === 'conflict') {
        throw new ConflictError('A different replacement was already authorized for this operation');
      }
      return reply.status(result.state === 'created' ? 201 : 200).send({
        status: 'authorized',
        operation_id: parsed.data.operation_id,
        replacement_operation_id: parsed.data.replacement_operation_id,
        warning: {
          version: PROXY_REPLACEMENT_WARNING_VERSION,
          text: PROXY_REPLACEMENT_WARNING,
          hash: PROXY_REPLACEMENT_WARNING_HASH,
        },
      });
    },
  );

  app.post(
    '/v1/proxy/operations/get',
    { preHandler: auth },
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      reply.header('Pragma', 'no-cache');
      const parsed = ProxyOperationLookupInput.safeParse(request.body);
      if (!parsed.success) {
        throw new StackError(
          parsed.error.errors.map((error) => error.message).join(', '),
          'INVALID_REQUEST',
          400,
        );
      }

      const passportToken = request.headers['x-passport-token'];
      if (typeof passportToken !== 'string' || passportToken.length === 0) {
        return notFound(reply);
      }

      await enforceProxyOperationReadRate({
        redis: services.redis,
        operatorId: request.operatorId,
        principalId: proxyOperationReadPrincipal(request),
        includeResponse: parsed.data.include_response,
      });

      let claims: VerifiedPassport;
      try {
        // Live signature, expiry, revocation, agent, grant and authority checks.
        claims = await services.passport.verify(passportToken, { check_freshness: true });
      } catch (error) {
        // Domain-level Passport rejection is deliberately opaque. Backing
        // service failure remains a 5xx rather than masquerading as absence.
        if (
          (error instanceof StackError && error.statusCode < 500)
          || (error instanceof Error && error.name.startsWith('JW'))
        ) {
          return notFound(reply);
        }
        throw error;
      }

      if (
        claims.stk.operator_id !== request.operatorId
        || (request.agentId !== undefined && request.agentId !== claims.stk.agent_id)
      ) {
        return notFound(reply);
      }

      const authorized = await services.proxyOperation.authorizeRead({
        operatorId: request.operatorId,
        operationKey: parsed.data.operation_id,
        currentAgentId: claims.stk.agent_id,
        allowedConnections: request.allowedConnections,
        freshAuthority: currentPassportAuthority(claims),
        includeResponse: parsed.data.include_response,
      });
      if (!authorized) return notFound(reply);

      return publicStatus(parsed.data.operation_id, parsed.data.include_response, authorized);
    },
  );
}
