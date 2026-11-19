import { ForbiddenError, evidenceAction, evidenceUrl, safeErrorSummary, isServiceInScope } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { enforceScopeWall, scopeForConnection, withDerivedEmail } from '../../lib/scope-wall.js';
import type {
  MissionAdmission,
  ParsedProxyRequest,
  ResolvedProxyTarget,
  ServiceScope,
  ServiceScopeFacts,
  VerifiedProxyPassport,
} from './types.js';

/**
 * 4. Scope check — service must be GRANTED. The grant is the
 *    sole authority; a self-declared intent may only narrow, never
 *    widen. Requiring the grant also means the ServiceScope lookup at
 *    step 4b always finds the grant row, so parameter constraints
 *    (spend caps, etc.) are actually enforced — an intent-only "grant"
 *    used to skip them silently.
 */
export async function enforceServiceScope(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
): Promise<ServiceScopeFacts> {
  const { input } = parsedRequest;
  const { claims, jti, agentId, operatorId, mode, missionIds, missionRef } = verified;
  const intentServices: string[] = claims.stk.intent_services ?? [];
  const grantedProviders: string[] = claims.stk.services.map(
    (s: { service_name: string }) => s.service_name,
  );
  const inScope = isServiceInScope(input.service, grantedProviders, intentServices);

  if (!inScope) {
    // Scope narrowing is a property of the passport and is always enforced.
    // The accountability mode only influences the severity recorded on the
    // associated security event — it does not gate the access decision.
    const severity = mode === 'logged' ? 'warning' : 'critical';
    await services.securityEvent.record({
      operatorId,
      agentId,
      passportJti: jti,
      signalType: 'credential_outside_scope',
      severity,
      message: `Proxy request for ${input.service} not in passport scope`,
      metadata: { intent_services: intentServices, granted_providers: grantedProviders },
      missionIds,
    });
    // denial-path producer (proxy scope_mismatch).
    try {
      await services.claimRegistry.recordIntentDenial({
        operatorId,
        passportJti: jti,
        attemptedIntent: {
          type: 'intent_claim',
          intent_type: 'http_call',
          agent_id: agentId,
          named_intent: `${input.service}:http:proxy`,
          target: input.service,
          action: evidenceAction(input.method, input.url),
          parameters: { service: input.service, method: input.method, url: evidenceUrl(input.url) },
          estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
          accountability: (mode as 'enforced' | 'logged' | 'standard' | undefined) ?? 'standard',
          reason: null,
          requires: [],
          user_subject: null,
          mission_ref: missionRef,
          submitted_at: Date.now(),
        },
        denialReason: 'scope_mismatch',
        message: `Proxy request for ${input.service} not in passport scope`,
        metadata: { intent_services: intentServices, granted_providers: grantedProviders },
      });
    } catch (err) {
      console.error('[proxy] intent_denial emission failed for scope_mismatch:', safeErrorSummary(err));
    }
    throw new ForbiddenError(`Service ${input.service} not in passport scope`);
  }
  return { intentServices, grantedProviders };
}

/**
 * 4b. The wall: closed-operation policy, the data-flow rule, and
 * parameter constraints, in that order. One implementation shared with
 * the LLM gateway - see apps/api/src/lib/scope-wall.ts for why.
 *
 * Runs BEFORE the credential is retrieved, so nothing leaves on a
 * refusal. A scope with no policy and no constraints passes through
 * untouched, which is what keeps legacy passports working.
 *
 * Returns the passport's scope for the requested service, which the
 * transaction-safe execution path needs.
 */
export async function runScopeWall(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  target: ResolvedProxyTarget,
  admission: MissionAdmission,
): Promise<ServiceScope | undefined> {
  const { input } = parsedRequest;
  const { claims, jti, agentId, operatorId, mode, missionIds } = verified;
  const { normalizedRequest } = target;
  const { observedPrefetch } = admission;
  // The scope of the connection the call resolved to, so a second connection of the service is held to its own policy.
  const serviceScope = scopeForConnection(
    claims.stk.services,
    input.service,
    target.conn.connection_id,
  ) as ServiceScope | undefined;

  // Gmail and Outlook carry recipients and text inside an encoded message.
  // Decode it once (bounded, fail closed) and attach it as derived.email so
  // the data-flow rule sees what the email carries. Derived from the body, so
  // not part of anything hashed for idempotency.
  await enforceScopeWall({
    services,
    operatorId,
    agentId,
    passportJti: jti,
    mode: mode as 'enforced' | 'logged' | 'standard' | undefined,
    missionIds,
    destinationService: input.service,
    destinationConnectionId: target.conn.connection_id,
    serviceScope,
    normalized: withDerivedEmail(normalizedRequest),
    rawUrl: input.url,
    namedIntent: `${input.service}:http:proxy`,
    producer: '[proxy]',
    controlAction: 'proxy.call',
    ...(observedPrefetch ? { observedRows: observedPrefetch } : {}),
  });
  return serviceScope;
}

/**
 * 5. Checkout check — cannot proxy after checkout. The row is the one
 *    the Passport verification above read (under the operator lock).
 */
export async function assertNotCheckedOut(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
): Promise<void> {
  const { input } = parsedRequest;
  const { passportRecord, jti, agentId, operatorId, missionIds } = verified;
  if (passportRecord?.checked_out_at) {
    await services.securityEvent.record({
      operatorId,
      agentId,
      passportJti: jti,
      signalType: 'credential_after_checkout',
      severity: 'critical',
      message: `Proxy request for ${input.service} after passport checkout`,
      missionIds,
    });
    throw new ForbiddenError('Passport already checked out');
  }
}
