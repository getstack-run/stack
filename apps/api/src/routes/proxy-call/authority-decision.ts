import type { Services } from '../../config/services.js';
import { enforceRuntimeAuthority } from '../../lib/runtime-authority.js';
import type {
  AuthorityDecision,
  ParsedProxyRequest,
  ProxyHttpRequest,
  ResolvedProxyTarget,
  VerifiedProxyPassport,
} from './types.js';

/**
 * Ask the runtime authority chokepoint to decide this call, before the
 * meter, the credential or anything that leaves.
 */
export async function authorizeProxyAuthority(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  target: ResolvedProxyTarget,
): Promise<AuthorityDecision> {
  const { input, operationKey } = parsedRequest;
  const { operatorId, agentId, jti, missionRef } = verified;
  const { normalizedRequest, conn } = target;
  return enforceRuntimeAuthority(services.authority, {
    operatorId,
    passportJti: jti,
    agentId,
    authenticatedAgentId: request.agentId ?? null,
    receiverRequestId: operationKey,
    missionId: missionRef,
    boundary: {
      kind: 'proxy',
      serviceConnectionId: conn.connection_id,
      provider: input.service,
      method: normalizedRequest.method,
    },
    normalizedRequest,
    verificationMode: 'proxy_mediated',
  });
}
