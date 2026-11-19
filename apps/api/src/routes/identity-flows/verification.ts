import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  ConflictError,
  InvalidRequestError,
  InitiateVerificationInput,
  CompleteVerificationInput,
  type IdentityVerificationSessionView,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';

type ProviderList = Awaited<ReturnType<Services['identity']['listProviders']>>;
type SyncResult = Awaited<ReturnType<Services['identity']['syncProviderSessions']>>;
type CompleteResult = Awaited<ReturnType<Services['identity']['complete']>>;
type TokenResult = Awaited<ReturnType<Services['identity']['completeWithToken']>>;
type PendingSession = Awaited<ReturnType<Services['identity']['getPendingSessions']>>[number];

interface PendingSessionSummary {
  session_id: PendingSession['id'];
  provider_key: PendingSession['provider_key'];
  session_ref: PendingSession['session_ref'];
  status: PendingSession['status'];
  created_at: PendingSession['created_at'];
  expires_at: PendingSession['expires_at'];
}

const SessionParams = z.object({ id: z.string().min(1).max(128) });

// The body is optional: a bare sync checks the one registered provider that can be synced.
const SyncVerificationBody = z.object({ provider_key: z.string().nullish() });

const TokenVerificationBody = z.object({
  provider_key: z.string().min(1),
  session_ref: z.string().min(1),
  token: z.string().min(1),
});

// ── Provider discovery ────────────────────────────────────────────

export async function listProviders(
  request: FastifyRequest,
  services: Services,
): Promise<ProviderList> {
  return services.identity.listProviders(request.operatorId);
}

// ── Verification flow ─────────────────────────────────────────────

export async function initiateVerification(
  request: FastifyRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const input = InitiateVerificationInput.parse(request.body);
  const start = Date.now();

  // Only the account owner's own verification marks the operator verified, so
  // the session records who started it.
  const initiatedBy = request.memberId ? 'member' : 'owner';
  const result = await services.identity.initiate(
    request.operatorId,
    input.provider_key,
    input.requested_claims,
    input.return_url,
    undefined,
    initiatedBy,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.verify.initiate',
    outcome: 'success',
    duration_ms: Date.now() - start,
  });

  return reply.status(201).send(result);
}

export async function listPendingSessions(
  request: FastifyRequest,
  services: Services,
): Promise<PendingSessionSummary[]> {
  const sessions = await services.identity.getPendingSessions(request.operatorId);
  return sessions.map((s) => ({
    session_id: s.id,
    provider_key: s.provider_key,
    session_ref: s.session_ref,
    status: s.status,
    created_at: s.created_at,
    expires_at: s.expires_at,
  }));
}

/** One session of the caller's account and where it stands: pending, completed, failed or expired (final). */
export async function getVerificationSession(
  request: FastifyRequest,
  services: Services,
): Promise<IdentityVerificationSessionView> {
  const { id } = SessionParams.parse(request.params);
  return services.identity.getSession(request.operatorId, id);
}

// Sync with provider: queries the provider directly for verified sessions and auto-completes any that
// don't have claims yet. The provider is the source of truth.
/** The provider a sync without a key means: the only registered one that can be synced; never one this deployment lacks. */
function defaultSyncProvider(services: Services): string {
  const keys = services.identity.syncableProviderKeys();
  if (keys.length === 0) throw new ConflictError('No identity verification provider is registered on this installation');
  if (keys.length > 1) throw new InvalidRequestError('Name the provider to sync in provider_key', { provider_keys: keys });
  return keys[0]!;
}

export async function syncVerification(
  request: FastifyRequest,
  services: Services,
): Promise<SyncResult> {
  const body = SyncVerificationBody.parse(request.body ?? {});
  const providerKey = body.provider_key || defaultSyncProvider(services);
  return services.identity.syncProviderSessions(request.operatorId, providerKey);
}

export async function completeVerification(
  request: FastifyRequest,
  services: Services,
): Promise<CompleteResult> {
  const input = CompleteVerificationInput.parse(request.body);
  const start = Date.now();

  const result = await services.identity.complete(
    request.operatorId,
    input.provider_key,
    input.session_ref,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.verify.complete',
    outcome: result.success ? 'success' : 'failure',
    duration_ms: Date.now() - start,
  });

  if (result.success) {
    await services.identityVerificationCharge.charge(request.operatorId, input.provider_key, result.claims);
  }

  return result;
}

// ── Inline token verification (a provider's widget token) ─────────────────
//
// For providers that use an inline widget (no redirect), the frontend
// collects a token and POSTs it here to complete verification.

export async function completeVerificationWithToken(
  request: FastifyRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply | TokenResult> {
  // This route answers a malformed body with its own error code, so it replies
  // itself rather than throwing to the central handler.
  const parsed = TokenVerificationBody.safeParse(request.body ?? {});
  if (!parsed.success) {
    return reply.status(400).send({
      error: { code: 'INVALID_INPUT', message: 'provider_key, session_ref, and token are required' },
    });
  }
  const { provider_key: providerKey, session_ref: sessionRef, token } = parsed.data;

  const start = Date.now();

  // Complete the verification using the token as the session ref for the provider.
  // The provider's complete() validates the token with the external service.
  const result = await services.identity.completeWithToken(
    request.operatorId,
    providerKey,
    sessionRef,
    token,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.verify.token',
    outcome: result.success ? 'success' : 'failure',
    duration_ms: Date.now() - start,
  });

  if (result.success) {
    await services.identityVerificationCharge.charge(request.operatorId, providerKey, result.claims);
  }

  return result;
}
