// Stages 4 and 5b: the provider must be granted by the passport, and the
// call must pass the scope wall (closed-operation policy, data-flow rule and
// parameter constraints). Both run before any credential is retrieved and
// before anything is sent upstream.

import { ForbiddenError, isServiceInScope } from '@stack/shared';
import { enforceScopeWall, scopeForConnection, type WallServiceScope } from '../../lib/scope-wall.js';
import type { Services } from '../../config/services.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import type { AdmittedCall } from './types.js';

/**
 * The grant check, on its own so the gateway can run it before it resolves a connection: an agent that was never
 * granted the provider (or whose grant was revoked) is refused here, with the security event, and never reaches the
 * connection pick, which would otherwise answer it with the account's connection names.
 */
export async function assertProviderGranted(
  services: Services,
  provider: string,
  call: Pick<AdmittedCall, 'claims' | 'jti' | 'agentId' | 'operatorId' | 'mode' | 'missionIds'> & { modelAccess: AdmittedCall['modelAccess'] },
): Promise<string[]> {
  const { claims, jti, agentId, operatorId, mode, missionIds } = call;
  const intentServices: string[] = claims.stk.intent_services ?? [];
  const grantedProviders: string[] = claims.stk.services.map(
    (s: { service_name: string }) => s.service_name,
  );
  // An agent account's ready models piece is its grant for the provider STACK
  // supplies: there is no customer connection to grant. The account's status
  // is the kill switch (a closed account refuses in admitCall), and a
  // self-declared intent can still only narrow it.
  if (call.modelAccess.kind === 'account') grantedProviders.push(provider);
  const inScope = isServiceInScope(provider, grantedProviders, intentServices);
  if (!inScope) {
    const severity = mode === 'logged' ? 'warning' : 'critical';
    await services.securityEvent.record({
      operatorId,
      agentId,
      passportJti: jti,
      signalType: 'credential_outside_scope',
      severity,
      message: `LLM provider ${provider} not in passport scope`,
      metadata: { intent_services: intentServices, granted_providers: grantedProviders },
      missionIds,
    });
    throw new ForbiddenError(`LLM provider ${provider} not in passport scope`);
  }

  return intentServices;
}

export async function enforceProviderScope(
  services: Services,
  config: LlmHandlerConfig,
  call: AdmittedCall,
): Promise<{ intentServices: string[]; carriedSources: string[] }> {
  // 4. Scope check — provider must be GRANTED. The grant is the
  //    sole authority; a self-declared intent may only narrow, never
  //    widen. This is what makes revoke a real kill switch: a re-issued
  //    passport after revoke carries no grant for the provider, so the
  //    call is denied regardless of the intent it declares.
  const { jti, agentId, operatorId, mode, missionIds, upstream, normalizedRequest, claims } = call;
  const intentServices = await assertProviderGranted(services, config.provider, call);

  // 5b. The wall. Until now this route checked WHICH service the passport
  //     could reach and nothing about WHAT the call carried. So a scope
  //     closed for /v1/proxy was wide open here, on the higher-volume door:
  //     an operation the policy never declared, a field nobody permitted, or
  //     content read from another service could all ride out through the LLM
  //     gateway. Same three gates, same order, one implementation.
  //
  //     Evaluated against the body the AGENT submitted, before STACK's own
  //     redaction. We judge what was asked for, not what we changed.
  //
  //     The path and host are the provider's real endpoint, so a policy
  //     written for `api.anthropic.com/v1/messages` means what it says.
  //     The scope is the one of the connection the call resolved to, so a second connection is held to its own policy.
  const serviceScope = (call.connectionId
    ? scopeForConnection(claims.stk.services, config.provider, call.connectionId)
    : claims.stk.services.find((s: { service_name: string }) => s.service_name === config.provider)
  ) as WallServiceScope | undefined;

  const wall = await enforceScopeWall({
    services,
    operatorId,
    agentId,
    passportJti: jti,
    mode,
    missionIds,
    destinationService: config.provider,
    destinationConnectionId: call.connectionId ?? null,
    serviceScope,
    normalized: normalizedRequest,
    rawUrl: upstream.toString(),
    namedIntent: config.namedIntent,
    producer: '[llm]',
    controlAction: 'model.call',
  });
  return { intentServices, carriedSources: wall.carriedSources };
}
