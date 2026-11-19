import { redactRequestPath, safeErrorSummary } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type {
  OutputScanResult,
  ParsedProxyRequest,
  ProxyCredentialInjection,
  ProxyHttpRequest,
  ServiceScopeFacts,
  UpstreamResult,
  VerifiedProxyPassport,
} from './types.js';

/**
 * 9-bis. A refused destination is an exfiltration attempt until proven
 * otherwise: the agent asked for a host this credential does not belong
 * to. Record it as a security event so it surfaces like any other
 * denial, and emit the signed denial claim alongside the other denial
 * paths in this handler.
 */
export async function recordRefusedDestination(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  injection: ProxyCredentialInjection,
  result: UpstreamResult,
): Promise<void> {
  const { input } = parsedRequest;
  const { jti, agentId, operatorId, mode, missionIds, missionRef } = verified;
  const { resolvedUrl, connAllowedHosts } = injection;
  if (result.status === 403 &&
      (result.body as { code?: string } | undefined)?.code === 'DESTINATION_NOT_ALLOWED') {
    const deniedHost = (() => {
      try { return new URL(resolvedUrl).host; } catch { return 'unparseable'; }
    })();
    await services.securityEvent.record({
      operatorId,
      agentId,
      passportJti: jti,
      signalType: 'credential_outside_scope',
      severity: mode === 'logged' ? 'warning' : 'critical',
      message: `Proxy refused ${input.service} credential to undeclared host ${deniedHost}`,
      metadata: {
        requested_host: deniedHost,
        service: input.service,
        allowed_hosts: connAllowedHosts,
      },
      missionIds,
    });
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
          action: `${input.method} ${deniedHost}`,
          parameters: { service: input.service, method: input.method, host: deniedHost },
          estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
          accountability: (mode as 'enforced' | 'logged' | 'standard' | undefined) ?? 'standard',
          reason: null,
          requires: [],
          user_subject: null,
          mission_ref: missionRef,
          submitted_at: Date.now(),
        },
        denialReason: 'scope_mismatch',
        message: `Destination ${deniedHost} is not declared for the ${input.service} connection`,
        metadata: { requested_host: deniedHost, allowed_hosts: connAllowedHosts },
      });
    } catch (err) {
      console.error('[producer] intent_denial emission failed for destination_not_allowed:', safeErrorSummary(err));
    }
  }
}

/**
 * 9a. Output-side prompt-injection scan (L6). Delegated to
 * DetectorService. The service records
 * the prompt_injection_output event and, in enforced+critical
 * mode, returns the redacted body the caller should plug into
 * result.body. Same severity policy as before:
 *   - logged   → record event, forward unchanged
 *   - enforced → record event; on critical, REDACT body
 *   - standard → record event, forward unchanged
 * Deliberately NOT auto-revoking — operators decide via review.
 *
 * Redaction is applied to `result` in place, as it always was.
 */
export async function scanUpstreamOutput(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  result: UpstreamResult,
): Promise<OutputScanResult> {
  const { input } = parsedRequest;
  const { jti, agentId, operatorId, mode } = verified;
  const outResult = await services.detector.scanOutput({
    ctx: { operatorId, agentId, passportJti: jti, mode, tier: request.operatorTier },
    body: typeof result.body === 'string' ? result.body : JSON.stringify(result.body ?? ''),
    headers: result.headers as Record<string, string>,
    metadata: {
      response_status: result.status,
      request_service: input.service,
      request_method: input.method,
    },
  });
  if (outResult.redactedBody !== null) {
    // Preserve status code + headers; agent sees a structured
    // refusal envelope where the leaked content was.
    result.body = outResult.redactedBody;
  }
  return outResult;
}

/**
 * 9b. Upstream 404 telemetry. Surfaces intents whose URL patterns may
 * be wrong or hallucinated. Fire-and-forget: this is observability and
 * must never alter proxy behavior or block the response. We record
 * only path + host (no query string, no body, no full URL) to avoid
 * leaking PII into security events.
 */
export function recordUpstreamNotFound(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  scopeFacts: ServiceScopeFacts,
  injection: ProxyCredentialInjection,
  result: UpstreamResult,
): void {
  const { input } = parsedRequest;
  const { claims, jti, agentId, operatorId } = verified;
  const { intentServices } = scopeFacts;
  const { resolvedUrl } = injection;
  if (result.status === 404) {
    let pathname = '';
    let host = '';
    try {
      host = new URL(resolvedUrl).host;
      // The path the agent sent, redacted: the resolved one can carry a
      // credential a connection interpolated into it, and this is an event.
      pathname = redactRequestPath(new URL(input.url).pathname);
    } catch {
      // Leave blank; a malformed URL would have been caught upstream.
    }
    services.securityEvent
      .record({
        operatorId,
        agentId,
        passportJti: jti,
        signalType: 'upstream_not_found',
        severity: 'info',
        message: `Upstream 404 on ${input.method} ${pathname || input.service}`,
        metadata: {
          method: input.method,
          pathname,
          host,
          service: input.service,
          // Surface full named-intent list (with params) when the
          // passport carries one, so operators can pinpoint the
          // specific intent catalog entry responsible for the 404.
          // Falls back to intent_services / intent_summary for
          // pre-migration passports that never got refs preserved.
          intent_services: intentServices,
          ...(claims.stk.intent_refs && claims.stk.intent_refs.length > 0
            ? { intent_refs: claims.stk.intent_refs }
            : {}),
          ...(claims.stk.intent_summary
            ? { intent_summary: claims.stk.intent_summary }
            : {}),
        },
      })
      .catch((err) => {
        request.log.error(
          { err: safeErrorSummary(err), jti, service: input.service },
          '[PROXY] upstream_not_found telemetry emit failed',
        );
      });
  }
}
