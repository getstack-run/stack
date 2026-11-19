import { describe, it, expect } from 'vitest';
import { assertDelegationAllowed } from './delegation.js';
import { DelegationDepthExceededError } from '../errors/index.js';
import { PASSPORT_MAX_DELEGATION_DEPTH } from '../constants/index.js';

describe('assertDelegationAllowed', () => {
  it('allows delegation from a root passport (depth 0)', () => {
    expect(() => assertDelegationAllowed(0)).not.toThrow();
  });

  it('allows delegation from every intermediate depth up to max - 1', () => {
    for (let d = 0; d < PASSPORT_MAX_DELEGATION_DEPTH; d++) {
      expect(() => assertDelegationAllowed(d)).not.toThrow();
    }
  });

  it('rejects delegation from a parent already at max depth', () => {
    expect(() => assertDelegationAllowed(PASSPORT_MAX_DELEGATION_DEPTH)).toThrow(
      DelegationDepthExceededError,
    );
  });

  it('rejects delegation from parents beyond max depth', () => {
    expect(() => assertDelegationAllowed(PASSPORT_MAX_DELEGATION_DEPTH + 1)).toThrow(
      DelegationDepthExceededError,
    );
    expect(() => assertDelegationAllowed(99)).toThrow(DelegationDepthExceededError);
  });

  it('supports a full four-hop chain (landing claim of "4-hop delegation")', () => {
    // Root at depth 0, each call increments. After four successful
    // delegations the leaf sits at depth 4, at which point no further
    // hop is allowed. This pins the landing-page promise.
    const chain = [0, 1, 2, 3];
    for (const parentDepth of chain) {
      expect(() => assertDelegationAllowed(parentDepth)).not.toThrow();
    }
    expect(() => assertDelegationAllowed(4)).toThrow(DelegationDepthExceededError);
  });
});
