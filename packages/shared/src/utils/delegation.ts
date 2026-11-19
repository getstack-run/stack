import { DelegationDepthExceededError } from '../errors/index.js';
import { PASSPORT_MAX_DELEGATION_DEPTH } from '../constants/index.js';

/**
 * Assert the parent at `parentDepth` may delegate once more. The child
 * receives `parentDepth + 1`. Throws if that would exceed the max.
 *
 * Root passports are depth 0. With max = 4, the longest chain is
 * 0 → 1 → 2 → 3 → 4 (four delegations). A parent at depth 4 cannot
 * delegate further.
 */
export function assertDelegationAllowed(parentDepth: number): void {
  if (parentDepth >= PASSPORT_MAX_DELEGATION_DEPTH) {
    throw new DelegationDepthExceededError();
  }
}
