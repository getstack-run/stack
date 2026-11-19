import { defaultHostsForProvider } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type {
  FleetAdmission,
  ParsedProxyRequest,
  ProxyCredentialInjection,
  ProxyHttpRequest,
  ResolvedProxyTarget,
  VerifiedProxyPassport,
} from './types.js';

/**
 * 7. Retrieve the credential, then 7/8/8a build what the upstream call is
 * made from: auth headers, the resolved target URL and the hosts the
 * credential may be sent to. Reaching this point means Mission admission,
 * the approval gate and the scope wall have all passed.
 */
export async function retrieveProxyCredential(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  target: ResolvedProxyTarget,
  fleetAdmission: FleetAdmission,
): Promise<ProxyCredentialInjection> {
  const { input } = parsedRequest;
  const { operatorId } = verified;
  const { conn } = target;
  // 7. Retrieve credential
  if (fleetAdmission) await services.fleetAdmission.reserve(fleetAdmission);
  // The connection and version the pick above named, not a second lookup by provider.
  const credResult = await services.serviceConnection.retrieveCredentialPinnedByConnectionId(
    operatorId,
    conn.connection_id,
    conn.credential_version,
    request.allowedConnections,
  );

  // Get the raw credential string for auth injection
  const rawCredential = 'credential' in credResult
    ? credResult.credential
    : JSON.stringify(credResult.credentials);

  // 7. Build auth headers
  const authHeaders = services.proxy.resolveAuthHeaders(input.service, rawCredential);

  // 8. Resolve target URL (may contain {{instance_url}} etc.)
  const resolvedUrl = services.proxy.resolveTargetUrl(input.url, rawCredential);

  // 8a. Credential-to-destination binding. The connection's own
  // declaration wins; the catalog default is the fallback so a provider
  // added to PROVIDER_API_HOSTS starts protecting existing connections
  // without a repair pass. Neither present → empty → forward() denies.
  // `service` picks WHICH credential is injected; this is what picks
  // WHERE it may go.
  const connAllowedHosts =
    (conn as { allowed_hosts?: string[] | null }).allowed_hosts ??
    defaultHostsForProvider(input.service) ??
    [];
  return { authHeaders, resolvedUrl, connAllowedHosts, connectionId: conn.connection_id };
}
