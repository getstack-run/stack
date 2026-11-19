// A pending item an agent waits on, and how it ended. The engine announces each end through one seam (the API's
// `decisionReached` registry); a deployment turns it into what reaches the agent (STACK's own: a `decision` wake-up).
// What is announced is facts, never content: what kind of item, which one, and its typed end.

/** The engine's pending items. A deployment adds its own kinds beside these. */
export const ENGINE_DECISION_ITEM_KINDS = [
  'intent_approval',
  'fleet_review',
  'control_review',
  'authority_request',
  'proxy_operation',
  'dropoff',
  'mission_review',
] as const;
export type EngineDecisionItemKind = (typeof ENGINE_DECISION_ITEM_KINDS)[number];

/** How each of the engine's pending items can end, as the item itself names its end. */
export const ENGINE_DECISION_RESULTS = {
  intent_approval: ['approved', 'rejected', 'expired'],
  fleet_review: ['approved', 'rejected', 'expired'],
  control_review: ['approved', 'rejected', 'expired'],
  authority_request: ['approved', 'rejected', 'expired'],
  proxy_operation: ['succeeded', 'failed', 'not_found', 'contradictory', 'unresolved'],
  dropoff: ['collected', 'expired'],
  mission_review: ['raised', 'continued', 'closed'],
} as const satisfies Record<EngineDecisionItemKind, readonly string[]>;

/** One pending item's end, for the agent that waited on it. */
export interface DecisionReachedEvent {
  operatorId: string;
  /** The agent waiting on the item: the one that asked for it. */
  agentId: string;
  kind: string;
  itemId: string;
  result: string;
  occurredAt?: Date;
}

/** What a deployment does with an end. A failure is logged by the caller and never undoes the decision. */
export type DecisionReachedHook = (event: DecisionReachedEvent) => Promise<void>;
