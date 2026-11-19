import { ForbiddenError } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { requireMissionRef } from '../../lib/agent-runtime.js';
import type { ProxyHttpRequest, VerifiedProxyPassport } from './types.js';

export function assertProxyPassportCallerBinding(input: {
  authenticatedOperatorId: string;
  authenticatedAgentId?: string;
  passportOperatorId: string;
  passportAgentId: string;
}): void {
  if (input.authenticatedOperatorId !== input.passportOperatorId) {
    throw new ForbiddenError('Passport does not belong to the authenticated operator');
  }
  if (input.authenticatedAgentId && input.authenticatedAgentId !== input.passportAgentId) {
    throw new ForbiddenError('Passport does not belong to the authenticated agent');
  }
}

/**
 * Step 2: the Passport is mandatory for proxy. Runs the one full
 * verification of it on this request, binds it to the authenticated caller
 * and resolves the one Mission the call runs under.
 */
export async function verifyProxyPassport(
  services: Services,
  request: ProxyHttpRequest,
): Promise<VerifiedProxyPassport> {
  // 2. Passport is mandatory for proxy
  const passportToken = request.headers['x-passport-token'] as string | undefined;
  if (!passportToken) {
    throw new ForbiddenError('X-Passport-Token header required for proxy requests');
  }

  // The ONE full verification of this Passport on this request:
  // signature, expiry, live revocation (Redis, then the database),
  // operator/agent/lineage liveness and grant freshness. The service
  // identity requirements and the Mission admission below reuse it rather
  // than verifying the same token again; the row it read carries the
  // checkout state checked at step 5.
  const { claims, record: passportRecord } = await services.passport.verifyDetailed(passportToken);
  const jti = claims.jti;
  const agentId = claims.stk.agent_id;
  const operatorId = claims.stk.operator_id;
  const mode = claims.stk.accountability as string | undefined;
  // The Passport selects authority inside the caller's authenticated
  // tenant; it never selects another tenant. Agent-bearing auth is also
  // bound to the same agent. This applies to every accountability mode,
  // including legacy Passports that do not enter runtime-authority PoP.
  assertProxyPassportCallerBinding({
    authenticatedOperatorId: request.operatorId,
    authenticatedAgentId: request.agentId,
    passportOperatorId: operatorId,
    passportAgentId: agentId,
  });
  // The one Mission this call runs under. Required here so the authority
  // attribution below cannot run Mission-less; beginAgentRuntime then
  // admits the call against it. Every downstream emission reuses it.
  const missionIds = claims.stk.mission_ids;
  const missionRef = requireMissionRef(missionIds);
  return { passportToken, claims, passportRecord, jti, agentId, operatorId, mode, missionIds, missionRef };
}
