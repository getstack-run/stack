import { ForbiddenError } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { agentDetectorMode } from '../../lib/agent-detector-mode.js';
import { scoreScopeDrift } from '../../detectors/scope-drift.js';
import { scoreCrossCallDrift } from '../../detectors/cross-call-drift.js';
import type {
  EarlyInputScan,
  ParsedProxyRequest,
  ProxyHttpRequest,
  ServiceScopeFacts,
  VerifiedProxyPassport,
} from './types.js';

/**
 * 6. Check proxy_enabled + enforce per-service identity requirements.
 * We look up the connection row once and reuse it for both checks so
 * the requirements gate (humanity / identity / assurance level) actually
 * fires on this hot path. The second verify uses
 * check_freshness=false to avoid duplicating the agent/connection/
 * claim freshness check we already did at the top of the handler.
 * (Both checks now run in resolveProxyTarget, target-resolution.ts.)
 *
 * 6a. Prompt-injection chain scan (L1 regex + L2 normalize +
 * L3 LLM funnel). Delegated to DetectorService
 * / CR5) so the same chain serves Shroud-LITE without
 * drift. The service fetches L7 operator overrides, runs the
 * injected scanner functions (from apps/api/src/detectors/), and
 * records the appropriate security events. Behaviour matches
 * pre-extract policy:
 *   - logged   → record event (warning or critical), allow
 *   - enforced → record critical event AND return denyReason
 *   - standard → record event, allow
 * L3 degraded fallback fires its own info-level event with
 * metadata.l3_degraded = true.
 *
 * enforced mode waits for the full verdict, from the scan started
 * after verification. Every other mode records L3 but can never block on
 * it, so it gets the L1+L2 decision now and L3 is recorded when it lands
 * (`deferL3`); the caller no longer waits ~1 s for a verdict that cannot
 * change the outcome.
 *
 * 6b. Scope Drift scoring (L3 behavioral). Runs only after service-
 * scope has passed — we're measuring how much the permitted call
 * drifts from the declared intent, not gating allow/deny.
 */
export async function scanInputAndScoreDrift(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  scopeFacts: ServiceScopeFacts,
  earlyInputScan: EarlyInputScan | null,
): Promise<void> {
  const { input } = parsedRequest;
  const { jti, agentId, operatorId, mode } = verified;
  const { intentServices, grantedProviders } = scopeFacts;
  const piScan = earlyInputScan ?? services.detector.beginInputScan({
    // An account's agent scans as its owner's controls say (agentDetectorMode).
    ctx: { operatorId, agentId, passportJti: jti, tier: request.operatorTier, ...(await agentDetectorMode(services, operatorId, agentId, mode, 'proxy.call')) },
    body: input.body,
    fieldPath: 'body',
    metadata: {
      request_method: input.method,
      request_service: input.service,
    },
  });
  const scanDecision = piScan.finish({ deferL3: true }).finally(() => {
    request.pendingInputScanAbort = undefined;
  });

  const scoreDrift = async () => {
    let pathname = '';
    try {
      pathname = new URL(input.url).pathname;
    } catch {
      // Bad URL is caught later in proxy forward; leave pathname blank
      // so the novelty key falls back to just the service name.
    }
    // 6b + 6c run together: separate Redis keys, neither reads the other.
    await Promise.all([
      scoreScopeDrift(
        {
          jti,
          operatorId,
          agentId,
          service: input.service,
          intentServices,
          grantedProviders,
          noveltyKey: `${input.service}:${pathname}`,
          accountabilityMode: mode,
        },
        { redis: services.redis, securityEvent: services.securityEvent, passport: services.passport },
      ),
      // 6c. Cross-call drift (L6). Records per-passport rolling stats
      // for body length + entropy and fires a `behavior_drift` event
      // when the current call exceeds 3σ on either dimension. Cold-
      // start gate (≥5 prior calls) avoids false positives early in
      // a session. Best-effort: any internal failure is swallowed,
      // proxy MUST NOT fail because the drift detector failed.
      scoreCrossCallDrift(
        { jti, operatorId, agentId, body: input.body },
        { redis: services.redis, securityEvent: services.securityEvent },
      ),
    ]);
  };

  if (mode === 'enforced') {
    // The verdict can refuse the call, and a refused call is not scored
    // for drift (scoring can revoke an enforced Passport): verdict first.
    const piResult = await scanDecision;
    if (piResult.denyReason) {
      throw new ForbiddenError(`Request ${piResult.denyReason.charAt(0).toLowerCase() + piResult.denyReason.slice(1)}`);
    }
    await scoreDrift();
  } else {
    // denyReason is always null outside enforced mode, so the scan and the
    // drift scoring cannot affect each other: run them together.
    const [piResult] = await Promise.all([scanDecision, scoreDrift()]);
    if (piResult.denyReason) {
      throw new ForbiddenError(`Request ${piResult.denyReason.charAt(0).toLowerCase() + piResult.denyReason.slice(1)}`);
    }
  }
}
