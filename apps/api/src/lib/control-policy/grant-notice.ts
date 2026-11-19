import { connectionNeedsListing, safeErrorSummary, type GrantControlPolicyNotice } from '@stack/shared';
import type { Services } from '../../config/services.js';

/**
 * A connection granted after controls were switched on is not callable while
 * the agent's policy lists connections and does not list this one. The grant
 * itself stands (the person approved it); this says what else is needed, so the
 * agent is not left to find out from a refusal. Null when nothing is: controls
 * off, an agent outside an account, no policy, a policy that does not list
 * connections or already names this one.
 *
 * It only reads, and never fails the grant: a failed read answers nothing.
 */
export async function grantControlPolicyNotice(
  services: Pick<Services, 'entitlements' | 'controlPolicies' | 'controlPolicyRepo'>,
  operatorId: string,
  agentId: string,
  connectionId: string,
): Promise<GrantControlPolicyNotice | null> {
  try {
    if (!(await services.entitlements.controlsEnabled(operatorId))) return null;
    if (!(await services.controlPolicyRepo.accountOfAgent(operatorId, agentId))) return null;
    const policy = await services.controlPolicies.effective(operatorId, agentId);
    if (!policy || !connectionNeedsListing(policy.definition, connectionId)) return null;
    return {
      policy_id: policy.id,
      policy_revision: policy.revision,
      source: policy.source,
      agent_id: agentId,
      connection_id: connectionId,
      action_needed: 'list_connection',
      revision_needed: policy.revision + 1,
      message:
        `The grant is made, but this agent cannot call the connection until a revision of policy ${policy.id} after revision ${policy.revision} lists it. ` +
        'Adding it is a loosening, which a person approves in their browser.',
    };
  } catch (error) {
    console.error('[CONTROL] reading the policy for a new grant failed', safeErrorSummary(error));
    return null;
  }
}
