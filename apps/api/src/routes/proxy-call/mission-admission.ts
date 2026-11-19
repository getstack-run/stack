import { ForbiddenError, evidenceUrl } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { beginAgentRuntime } from '../../lib/agent-runtime.js';
import { flowMissionId, readObservedRows } from '../../lib/provenance.js';
import type {
  MissionAdmission,
  ParsedProxyRequest,
  ProxyHttpRequest,
  ResolvedProxyTarget,
  VerifiedProxyPassport,
} from './types.js';

/**
 * Mission admission (lifecycle, Mission scope, caps) runs here, before the
 * credential is retrieved or anything leaves. Fleet Passports then enter
 * their admission ledger. One implementation: lib/agent-runtime.ts.
 *
 * The data-flow rule's one read (what this Mission has recorded as read)
 * does not depend on any gate, so it runs while admission runs. It is only a
 * read: every decision below is still made in the same order, and its errors
 * still reach the wall's own handler.
 */
export async function admitMission(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  target: ResolvedProxyTarget,
): Promise<MissionAdmission> {
  const { input } = parsedRequest;
  const { passportToken, claims, jti, agentId, operatorId, missionIds } = verified;
  const { normalizedHttpRequest, conn } = target;
  const observedPrefetch = services.passportClaimsRepo
    ? readObservedRows(services, { operatorId, passportJti: jti, missionId: flowMissionId(missionIds) })
    : undefined;
  observedPrefetch?.catch(() => undefined);
  const runtime = await beginAgentRuntime(services, request, { agentId, passportId: jti, producer: 'proxy',
    verifiedPassport: { token: passportToken, claims },
    requestedService: input.service, connectionId: conn.connection_id, targetId: input.service, action: input.method,
    normalizedRequest: normalizedHttpRequest,
    denial: { intentType: 'http_call', namedIntent: `${input.service}:http:proxy`,
      parameters: { service: input.service, method: input.method, url: evidenceUrl(input.url) } } });
  if (!runtime) throw new ForbiddenError('Passport must carry exactly one Mission to act');
  return { fleetAdmission: runtime.fleet, observedPrefetch };
}
