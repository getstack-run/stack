import { safeErrorSummary, type DecisionReachedEvent, type DecisionReachedHook } from '@stack/shared';
import type { EngineRegistries } from '../config/registries.js';

/**
 * Tell the deployment's hooks that a pending item an agent waited on has ended. Called after the end is stored (after
 * the transaction that wrote it). A hook that throws is logged and never fails or undoes the decision: the item has
 * ended either way, and the agent can still read it.
 */
export async function announceDecision(
  registries: Pick<EngineRegistries, 'decisionReached'>,
  event: DecisionReachedEvent,
): Promise<void> {
  for (const hook of registries.decisionReached.list()) {
    try {
      await hook(event);
    } catch (error) {
      console.error('[decision] a decision hook failed:', event.kind, safeErrorSummary(error));
    }
  }
}

/** The registry as one hook, for a service that takes a callback: it reads the registry each time it is called. */
export function decisionAnnouncer(registries: Pick<EngineRegistries, 'decisionReached'>): DecisionReachedHook {
  return (event) => announceDecision(registries, event);
}
