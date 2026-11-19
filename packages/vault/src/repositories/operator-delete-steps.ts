import type { LimitOverrides, OperatorTier } from '@stack/shared';
import type { DbTransaction } from './operator-repo.js';

/**
 * The points of `OperatorRepository.deleteById` where a deployment's own
 * statements run. The engine deletes an account's rows in an order the
 * foreign keys fix (a row goes before the rows it points at); a deployment
 * that keeps more tables about an operator puts its statements at the named
 * point between the engine's, so the whole order is the order it was when
 * everything was one method.
 *
 * In order:
 * - `beforePlatformEdges`: first, once the engine has read what it needs. Other
 *   operators' rows that point into this one are severed here.
 * - `afterAuthorityGraph`: after the engine's authority records, before its
 *   security events, Missions and Passports.
 * - `beforeLlmUsage`: after Passports, before the LLM usage rows. What points
 *   at those rows goes here.
 * - `afterLlmUsage`: after the LLM usage rows, before the services and agents.
 */
export const OPERATOR_DELETE_SLOTS = [
  'beforePlatformEdges',
  'afterAuthorityGraph',
  'beforeLlmUsage',
  'afterLlmUsage',
] as const;

export type OperatorDeleteSlot = (typeof OPERATOR_DELETE_SLOTS)[number];

/** One group of a deployment's delete statements, run inside the erasure's transaction at a named point. */
export interface OperatorDeleteStep {
  slot: OperatorDeleteSlot;
  run(tx: DbTransaction, operatorId: string): Promise<void>;
}

/** What `OperatorRepository` is built with beyond the database. */
export interface OperatorRepositoryOptions {
  /**
   * The steps a deployment adds to an erasure, read when an operator is deleted (so the list may be filled after the
   * repository exists, and is the same one the erasure always uses). Absent: the engine's own tables only.
   */
  deleteSteps?: () => readonly OperatorDeleteStep[];
  /**
   * The actions a plan includes in a month, which the repository snapshots beside a tier or limit write (`Infinity`:
   * none named). Absent: an install runs on the contract plan, which names none.
   */
  monthlyActionLimit?: (tier: OperatorTier, overrides: LimitOverrides | null) => number;
}
