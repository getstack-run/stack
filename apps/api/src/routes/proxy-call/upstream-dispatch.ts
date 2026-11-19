import type { Services } from '../../config/services.js';
import {
  completeRuntimeAuthorityUse,
  markRuntimeAuthorityDispatched,
  runtimeAuthorityFailureResult,
} from '../../lib/runtime-authority.js';
import {
  recordCredentialAccess,
  writeProxyAudit,
} from './audit-telemetry.js';
import { emitIntentAndOutcomeClaims, observeEntities } from './signed-claims.js';
import { captureProxyAnalytics, consumeApprovalOnSuccess } from './settlement.js';
import {
  recordRefusedDestination,
  recordUpstreamNotFound,
  scanUpstreamOutput,
} from './upstream-response.js';
import type {
  ApprovalGateOutcome,
  AuthorityDecision,
  FleetAdmission,
  ParsedProxyRequest,
  ProxyCredentialInjection,
  ProxyHttpReply,
  ProxyHttpRequest,
  RuntimeClaimIds,
  ServiceScopeFacts,
  VerifiedProxyPassport,
} from './types.js';

/**
 * 9. Forward, then finish the call: screen and record the response, settle
 * the approval, and complete (or fail) the runtime authority use. The reply
 * is sent here, inside the try, because the authority use is finalised as
 * failed if anything up to and including the send throws.
 */
export async function dispatchProxyRequest(
  services: Services,
  request: ProxyHttpRequest,
  reply: ProxyHttpReply,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  authorityDecision: AuthorityDecision,
  fleetAdmission: FleetAdmission,
  approval: ApprovalGateOutcome,
  scopeFacts: ServiceScopeFacts,
  injection: ProxyCredentialInjection,
  start: number,
): Promise<ProxyHttpReply> {
  const { input } = parsedRequest;
  const { operatorId } = verified;
  const { gate } = approval;
  const { authHeaders, resolvedUrl, connAllowedHosts } = injection;

  // 9. Forward
  if (fleetAdmission) await services.fleetAdmission.dispatch(fleetAdmission);
  await markRuntimeAuthorityDispatched(services.authority, operatorId, authorityDecision);
  let claimIds: RuntimeClaimIds = { intentClaimId: undefined, outcomeClaimId: undefined };
  try {
    const result = await services.proxy.forward(input, authHeaders, resolvedUrl, connAllowedHosts, {
      operatorId,
      agentId: verified.agentId,
    });

    await recordRefusedDestination(services, parsedRequest, verified, injection, result);

    const outResult = await scanUpstreamOutput(services, request, parsedRequest, verified, result);

    recordUpstreamNotFound(services, request, parsedRequest, verified, scopeFacts, injection, result);

    await recordCredentialAccess(services, parsedRequest, verified);

    await writeProxyAudit(services, request, parsedRequest, verified, result, start);

    claimIds = await emitIntentAndOutcomeClaims(
      services, parsedRequest, verified, gate, injection, result, outResult, start,
    );

    await observeEntities(services, parsedRequest, verified, injection, result);

    await consumeApprovalOnSuccess(services, request, gate, fleetAdmission, result);

    captureProxyAnalytics(services, parsedRequest, verified, result, start);

    await completeRuntimeAuthorityUse(
      services.authority,
      operatorId,
      authorityDecision,
      result.status >= 200 && result.status < 400 ? 'succeeded' : 'failed',
      { status: 200, body: result },
      {
        intentClaimId: claimIds.intentClaimId,
        outcomeClaimId: claimIds.outcomeClaimId,
      },
    );

    return reply.status(200).send(result);
  } catch (err) {
    try {
      await completeRuntimeAuthorityUse(
        services.authority,
        operatorId,
        authorityDecision,
        'failed',
        runtimeAuthorityFailureResult(err),
        {
          intentClaimId: claimIds.intentClaimId,
          outcomeClaimId: claimIds.outcomeClaimId,
        },
      );
    } catch (finalizationError) {
      request.log.error(
        { code: (finalizationError as { code?: unknown })?.code ?? 'AUTHORITY_FINALIZATION_FAILED' },
        '[authority] failed to finalize proxy failure',
      );
    }
    throw err;
  }
}
