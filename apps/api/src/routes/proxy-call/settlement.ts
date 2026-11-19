import { safeErrorSummary } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type {
  AdmittedGate,
  FleetAdmission,
  ParsedProxyRequest,
  ProxyHttpRequest,
  UpstreamResult,
  VerifiedProxyPassport,
} from './types.js';

/**
 * Flip the approval row 'approved' → 'consumed'
 * on first successful 2xx-3xx outcome. Idempotent: concurrent
 * in-flight calls can both admit, but only one consume-flip
 * wins. The losers' CAS misses are swallowed.
 */
export async function consumeApprovalOnSuccess(
  services: Services,
  request: ProxyHttpRequest,
  gate: AdmittedGate,
  fleetAdmission: FleetAdmission,
  result: UpstreamResult,
): Promise<void> {
  if (!fleetAdmission && !gate.skipped && gate.approvalId && result.status >= 200 && result.status < 400) {
    try {
      // Settle the reservation (consuming -> consumed) and clear the
      // release, so the onResponse hook does not hand it back.
      await services.approvalGate.markConsumed(gate.approvalId);
      request.approvalToRelease = undefined;
    } catch (err) {
      console.error('proxy markConsumed failed:', safeErrorSummary(err));
    }
  }
}

/**
 * Activation milestone (fire-once per operator) + every-call signal
 * (every successful proxy call). The fire-once feeds the activation
 * funnel; the every-call event is the WAU North Star input — distinct_id
 * is operator_id so PostHog `dau` math = unique active operators in
 * the period. Only successful (2xx-3xx) calls count: 4xx/5xx are
 * operator/upstream errors, not "operator was active and got value".
 */
export function captureProxyAnalytics(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  result: UpstreamResult,
  start: number,
): void {
  const { input } = parsedRequest;
  const { operatorId } = verified;
  if (result.status >= 200 && result.status < 400) {
    services.analytics.fireOnce(operatorId, 'first_proxy_call', {
      service: input.service,
      method: input.method,
    });
    services.analytics.capture(operatorId, 'proxy_call', {
      service: input.service,
      method: input.method,
      duration_ms: Date.now() - start,
      status_code: result.status,
    });
  }
}
