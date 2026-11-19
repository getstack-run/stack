import type {
  ControlDecider,
  ControlDecisionRequest,
  ControlUnavailableCause,
  PolicyRefusalEvidence,
} from '@stack/shared';
import type { ControlSocketRuntime } from '@stack/vault';

/** What a decider is handed for one decision. */
export interface DecisionContext {
  request: ControlDecisionRequest;
  /** The exact bytes that are signed and sent to a remote decider. */
  body: string;
  operatorId: string;
  socket: ControlSocketRuntime;
  /**
   * In-process only and never serialised: what a hosted check may read that a
   * remote decider is deliberately not sent (the parsed body, for detectors).
   */
  privileged?: Readonly<Record<string, unknown>>;
  /**
   * Aborted when the engine has given up on a hosted decision (its deadline passed). A
   * check that sees it stops before its next side effect and hands back what it took.
   */
  signal?: AbortSignal;
}

export interface DecisionReason {
  code: string;
  message: string | null;
}

/**
 * What became of an allowed action, told to whatever the decision left open
 * (a counted action, a reserved approval, a lease on concurrency). `ok` is that
 * the response was a success; `handedBack` that the action never ran and so is
 * not charged (the meter's own rule, `actionHandedBack`).
 */
export interface ActionOutcome {
  ok: boolean;
  handedBack: boolean;
}
export type SettleHook = (outcome: ActionOutcome) => Promise<void>;

export type DecisionResult =
  | {
      verdict: 'allow';
      reason?: DecisionReason;
      policyRef?: string | null;
      /** Run once the action's outcome is known; see `ActionOutcome`. Hosted checks only. */
      settle?: SettleHook[];
    }
  | {
      verdict: 'deny';
      reason: DecisionReason;
      retry?: { ref: string; after_seconds?: number };
      policyRef?: string | null;
      /** Which rule of a hosted policy refused: its side of the comparison only. */
      evidence?: PolicyRefusalEvidence;
    }
  | { verdict: 'unavailable'; cause: ControlUnavailableCause };

/** One way of deciding: hosted, a customer's own server, or nobody. Same contract for all three. */
export interface Decider {
  readonly kind: ControlDecider;
  decide(context: DecisionContext): Promise<DecisionResult>;
}
