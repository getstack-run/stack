import type { ControlActionType } from '@stack/shared';
import type { Services } from '../config/services.js';

/**
 * The detector mode for an agent's call on a shared route (the proxy, the
 * model gateway). An agent outside an account keeps its Passport's mode while its
 * owner has controls, and without controls follows the same rule an account's
 * agent does. An account's agent follows its owner's controls: on, enforced with
 * the L3 classifier; off, the local patterns only, recorded and never refused.
 * No agent has content withheld without controls.
 * The classifier follows the customer's per-kind choice: a kind they did not
 * choose to check runs the local patterns only. Throws when the owner's
 * controls cannot be read, so the call fails closed.
 */
export async function agentDetectorMode(
  services: Pick<Services, 'accountDetection' | 'entitlements'>,
  operatorId: string,
  agentId: string,
  passportMode: string | undefined,
  action: ControlActionType | null = null,
): Promise<{ mode: string | undefined; skipL3?: true }> {
  const posture = await services.accountDetection.forAgent(operatorId, agentId, action);
  if (!posture) {
    // An agent outside an account keeps its Passport's mode only under the owner's controls; without them it is
    // flagged and delivered like an account agent's content. A controls read that fails throws, so the call fails closed.
    if (await services.entitlements.controlsEnabled(operatorId)) return { mode: passportMode };
    const off = await services.accountDetection.forOperator(operatorId, action);
    return { mode: off.mode, ...(off.skipL3 ? { skipL3: true as const } : {}) };
  }
  return { mode: posture.mode, ...(posture.skipL3 ? { skipL3: true as const } : {}) };
}
