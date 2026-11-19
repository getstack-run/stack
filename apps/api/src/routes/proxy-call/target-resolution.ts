import { ForbiddenError, normalizeRequest } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { connectionEligibility } from '../../lib/agent-runtime.js';
import { enforceServiceScope } from './service-scope.js';
import type {
  ParsedProxyRequest,
  ProxyHttpRequest,
  ResolvedProxyTarget,
  VerifiedProxyPassport,
} from './types.js';

/**
 * Normalise the request, resolve the service connection it targets and check
 * the connection's proxy switch and per-service identity requirements.
 */
export async function resolveProxyTarget(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
): Promise<ResolvedProxyTarget> {
  const { input } = parsedRequest;
  const { claims, operatorId } = verified;
  const normalizedHttpRequest = normalizeRequest(input);
  const normalizedRequest = {
    ...normalizedHttpRequest,
    resource_type: 'http_endpoint',
    resource_ref: `${normalizedHttpRequest.url.origin}${normalizedHttpRequest.url.pathname}`,
  };
  // A service the Passport never granted is refused first, with its security event: the pick below would otherwise
  // answer that caller with the account's connection names.
  if (!claims.stk.services.some((service) => service.service_name === input.service)) {
    await enforceServiceScope(services, parsedRequest, verified);
  }
  // The one pick among the connections this caller may use. Refused here (ambiguous, or not the caller's) before any
  // credential is decrypted or anything is sent; everything after uses the connection it names.
  const conn = await services.serviceConnection.resolveProxyConnection(
    operatorId,
    input.service,
    connectionEligibility(request, input.service, claims),
    input.connection,
  );
  if (conn.proxy_enabled === false) {
    throw new ForbiddenError(`Proxy access disabled for service ${input.service}`);
  }
  // Per-service identity requirements (humanity / identity / assurance).
  // This used to be a second full verify with service_id; everything else
  // that verify re-checked was checked above on this same request.
  await services.passport.assertServiceIdentityRequirements(claims, conn.service_id);
  return { normalizedHttpRequest, normalizedRequest, conn };
}
