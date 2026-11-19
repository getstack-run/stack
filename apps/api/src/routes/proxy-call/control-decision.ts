import type { Services } from '../../config/services.js';
import { decideControl } from '../../lib/control-decision.js';
import { controlTargets } from '../../lib/control-socket/targets.js';
import type {
  ParsedProxyRequest,
  ProxyHttpRequest,
  ResolvedProxyTarget,
  VerifiedProxyPassport,
} from './types.js';

/**
 * The customer's decider, asked once per call to the customer's own systems.
 * Runs after Mission admission, the approval gate, the scope wall and the input
 * scan, and before the mutation executes and before the credential is
 * retrieved, so a refusal reaches nothing and decrypts nothing. Asked only for
 * an agent account's agent; any other agent keeps today's controls. The
 * request names the service, connection, method, host and path: never the
 * body, a header or the query string.
 */
export async function decideProxyCall(
  services: Pick<Services, 'controlDecisions' | 'accountDirectory'>,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  target: ResolvedProxyTarget,
): Promise<void> {
  const { input } = parsedRequest;
  await decideControl(services, request, {
    action: 'proxy.call',
    scope: 'agent',
    agentId: verified.agentId,
    runtime: { passportJti: verified.jti, missionId: verified.missionRef },
    target: controlTargets.proxyCall({
      service: input.service,
      connectionId: target.conn.connection_id,
      method: input.method,
      url: input.url,
    }),
    // In process only: a policy's rules for this connection are tried against the call itself.
    privileged: { request: target.normalizedHttpRequest },
  });
}
