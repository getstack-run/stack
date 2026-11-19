// Which of STACK's hosted checks apply to one action: the single reading every
// check shares.
//
// The customer chooses who decides (hosted controls, their own server, nobody)
// and which kinds of action are checked. The decision engine asks it to know
// whether to ask anyone; the checks that run inline at their own call site (the
// data-flow rule, the L3 classifier, the account budget and a policy's spend
// limits) ask the same question, so "is this kind checked" has exactly one
// source of truth: a kind that is not checked runs no hosted check, is not
// charged, and is not limited.

import type { ControlActionType, ControlDecider } from '@stack/shared';
import type { EntitlementResolver } from '../entitlements/entitlements.js';
import { effectiveDecider, type ControlSocketRuntime, type ControlSocketService } from './control-socket-service.js';

export interface ControlPostureDeps {
  sockets: Pick<ControlSocketService, 'runtime'>;
  controls: Pick<EntitlementResolver, 'controlsEnabled'>;
}

/** What the decision engine needs: who decides, and whether this kind is checked at all. */
export interface DecisionPosture {
  decider: ControlDecider;
  /** False: nobody is asked, nothing is charged. */
  checked: boolean;
  socket: ControlSocketRuntime;
}

export class ControlPosture {
  constructor(private readonly deps: ControlPostureDeps) {}

  /**
   * Who decides this action and whether it is checked. Hosted controls are
   * read only when they could decide: a customer on their own server, or who
   * chose none, never waits on the controls decision.
   */
  async decision(operatorId: string, action: ControlActionType): Promise<DecisionPosture> {
    const socket = await this.deps.sockets.runtime(operatorId);
    const hostedPossible = socket.modeSetting === 'auto' || socket.modeSetting === 'hosted';
    const controlsOn = hostedPossible ? await this.deps.controls.controlsEnabled(operatorId) : false;
    const decider = effectiveDecider(socket.modeSetting, controlsOn);
    if (decider === 'none') return { decider, checked: false, socket };
    return { decider, checked: isChecked(socket, action), socket };
  }

  /**
   * Do STACK's hosted checks apply to this kind of action? Yes when the owner's
   * controls are on, they did not choose none, and the kind is checked. `null`
   * is for content that is not an action of the agent's own (inbound mail, a
   * caller's words, page text): it follows the controls alone. Throws when the
   * controls cannot be read, so the call fails closed.
   */
  async hostedApplies(operatorId: string, action: ControlActionType | null): Promise<boolean> {
    if (!(await this.deps.controls.controlsEnabled(operatorId))) return false;
    const socket = await this.deps.sockets.runtime(operatorId);
    if (socket.modeSetting === 'none') return false;
    return action === null || isChecked(socket, action);
  }

  /**
   * Whether the account's own monthly budget refuses this spend. A budget the
   * customer set never switches off by itself: with controls off (a budget set
   * before a downgrade) and with nobody deciding (none chosen) it keeps
   * enforcing. Controls on and somebody deciding: it follows the per-kind
   * choice like every other hosted check.
   */
  async budgetEnforced(operatorId: string, action: ControlActionType | null): Promise<boolean> {
    if (!(await this.deps.controls.controlsEnabled(operatorId))) return true;
    const socket = await this.deps.sockets.runtime(operatorId);
    if (socket.modeSetting === 'none') return true;
    return action === null || isChecked(socket, action);
  }
}

function isChecked(socket: ControlSocketRuntime, action: ControlActionType): boolean {
  return socket.checkedTypes === null || socket.checkedTypes.has(action);
}
