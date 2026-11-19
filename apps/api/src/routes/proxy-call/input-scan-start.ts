import type { Services } from '../../config/services.js';
import { agentDetectorMode } from '../../lib/agent-detector-mode.js';
import type {
  EarlyInputScan,
  ParsedProxyRequest,
  ProxyHttpRequest,
  VerifiedProxyPassport,
} from './types.js';

/**
 * In enforced mode the L3 verdict can block, so the request has
 * to wait for it. Start it now, while the remaining gates run, instead
 * of after them. The body is final (parsed and bound to this Passport
 * and connection above). Nothing is recorded until the scan is finished
 * at step 6a (input-scan.ts); a request refused before then aborts it
 * (onResponse hook in server.ts), which cancels the classifier call and
 * releases its budget hold. Other modes never wait for L3 (see step 6a).
 */
export async function startEarlyInputScan(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
): Promise<EarlyInputScan | null> {
  const { input } = parsedRequest;
  const { operatorId, agentId, jti } = verified;
  // An account's agent scans as its owner's controls say, not by its Passport's mode.
  const detection = await agentDetectorMode(services, operatorId, agentId, verified.mode, 'proxy.call');
  const earlyInputScan = detection.mode === 'enforced' && input.body !== undefined && input.body !== null
    ? services.detector.beginInputScan({
        ctx: { operatorId, agentId, passportJti: jti, tier: request.operatorTier, ...detection },
        body: input.body,
        fieldPath: 'body',
        metadata: {
          request_method: input.method,
          request_service: input.service,
        },
      })
    : null;
  if (earlyInputScan) request.pendingInputScanAbort = () => earlyInputScan.abort();
  return earlyInputScan;
}
