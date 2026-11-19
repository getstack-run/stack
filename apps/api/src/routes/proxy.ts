import type { FastifyInstance } from 'fastify';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { actionPoolSnapshot } from '../lib/action-pool.js';
import { validateProxyRequest } from './proxy-call/request-validation.js';
import { verifyProxyPassport } from './proxy-call/passport-verification.js';
import { resolveProxyTarget } from './proxy-call/target-resolution.js';
import { startEarlyInputScan } from './proxy-call/input-scan-start.js';
import { recordProxyEvaluation } from './proxy-call/allowance-accounting.js';
import { authorizeProxyAuthority } from './proxy-call/authority-decision.js';
import { meterProxyAction } from './proxy-call/meter.js';
import { admitMission } from './proxy-call/mission-admission.js';
import { checkApprovalGate, enforceApprovedCallShape } from './proxy-call/approval-gate.js';
import { enforceServiceScope, runScopeWall, assertNotCheckedOut } from './proxy-call/service-scope.js';
import { scanInputAndScoreDrift } from './proxy-call/input-scan.js';
import { decideProxyCall } from './proxy-call/control-decision.js';
import { executeProxyMutation } from './proxy-call/mutation-execution.js';
import { retrieveProxyCredential } from './proxy-call/credential-retrieval.js';
import { dispatchProxyRequest } from './proxy-call/upstream-dispatch.js';
import { commitMissionAction } from '../middleware/mission-action.js';

// Still imported from here by tests and callers; the implementations live with
// the stage that uses them.
export { approvalGateDenialSeverity } from './proxy-call/approval-gate.js';
export { assertProxyPassportCallerBinding } from './proxy-call/passport-verification.js';

/**
 * POST /v1/proxy is composed from the stages in ./proxy-call/, run in the order
 * written here. A stage that refuses the call throws; the only early reply is
 * the transaction-safe path for a non-GET request.
 */
export function registerProxyRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.post(
    '/v1/proxy',
    { preHandler: auth },
    async (request, reply) => {
      const start = Date.now();

      const parsedRequest = validateProxyRequest(request);
      const { isMutation } = parsedRequest;
      const verified = await verifyProxyPassport(services, request);
      const target = await resolveProxyTarget(services, request, parsedRequest, verified);
      const earlyInputScan = await startEarlyInputScan(services, request, parsedRequest, verified);
      const accounting = await recordProxyEvaluation(services, request, parsedRequest, verified, target);
      const authorityDecision = await authorizeProxyAuthority(services, request, parsedRequest, verified, target);
      await meterProxyAction(services, request, isMutation, verified, accounting);
      const admission = await admitMission(services, request, parsedRequest, verified, target);
      const { fleetAdmission } = admission;
      const approval = await checkApprovalGate(services, request, parsedRequest, verified, fleetAdmission);
      await enforceApprovedCallShape(services, parsedRequest, verified, approval.gate, fleetAdmission);
      const scopeFacts = await enforceServiceScope(services, parsedRequest, verified);
      const serviceScope = await runScopeWall(services, parsedRequest, verified, target, admission);
      await assertNotCheckedOut(services, parsedRequest, verified);
      await scanInputAndScoreDrift(services, request, parsedRequest, verified, scopeFacts, earlyInputScan);
      // The customer's decider, once per call, before anything executes or a credential is read.
      await decideProxyCall(services, request, parsedRequest, verified, target);

      if (isMutation) {
        // An account agent's mutation was counted pending on its account
        // meter; it is final from here, right before dispatch.
        await request.meterCommit?.();
        await commitMissionAction(request);
        return reply.status(200).send(await executeProxyMutation(
          services, request, parsedRequest, verified, target, accounting, authorityDecision,
          fleetAdmission, approval, scopeFacts, serviceScope, start,
        ));
      }

      const injection = await retrieveProxyCredential(services, request, parsedRequest, verified, target, fleetAdmission);
      return dispatchProxyRequest(
        services, request, reply, parsedRequest, verified, authorityDecision,
        fleetAdmission, approval, scopeFacts, injection, start,
      );
    },
  );

  // Usage stats endpoint
  app.get('/v1/proxy/usage', { preHandler: auth }, async (request) => {
    const now = new Date();
    // The shared recorded-actions counter, which is what the proxy now spends
    // from. This hand-rolled the old `proxyCall` key, so from the moment the
    // five meters collapsed into one it read a key nothing writes and reported
    // zero used / full remaining on every tier. Reads go through
    // the one usage-key helper now so the writer and the reader cannot drift again.
    //
    // `used` is therefore the whole pool, not proxy calls alone — the number
    // that actually decides whether the next proxy call is free. The endpoint
    // collapses into /v1/usage, when the wire shape changes and
    // the SDKs republish together. For the accounts of a partner on a
    // negotiated hard cap it is the partner's pool.
    return actionPoolSnapshot(services, request.operatorId, now);
  });
}
