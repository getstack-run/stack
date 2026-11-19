import { describe, it, expect } from 'vitest';
import { invalidChildScopes, isServiceInScope } from './constraints.js';

// #7 — grant/connect scope subset check with '*' wildcard support.
// The root of the FamilyBot grant failure: a default ['*'] connection could
// only grant ['*'], never ['read'], because '*' was matched literally.

describe('invalidChildScopes', () => {
  it("treats '*' in the parent as allow-any", () => {
    expect(invalidChildScopes(['read'], ['*'])).toEqual([]);
    expect(invalidChildScopes(['read', 'write', 'anything'], ['*'])).toEqual([]);
    expect(invalidChildScopes(['*'], ['*'])).toEqual([]);
  });

  it('does literal subset check when no wildcard', () => {
    expect(invalidChildScopes(['read'], ['read', 'write'])).toEqual([]);
    expect(invalidChildScopes(['read', 'delete'], ['read', 'write'])).toEqual(['delete']);
  });

  it('returns every rejected scope (for the error detail)', () => {
    expect(invalidChildScopes(['a', 'b', 'c'], ['a'])).toEqual(['b', 'c']);
  });

  it('empty request is always a subset', () => {
    expect(invalidChildScopes([], ['read'])).toEqual([]);
    expect(invalidChildScopes([], [])).toEqual([]);
  });

  it("a child asking for '*' against a non-wildcard parent is rejected", () => {
    expect(invalidChildScopes(['*'], ['read', 'write'])).toEqual(['*']);
  });
});

// the grant is the sole authority; a self-declared intent may
// only narrow, never widen. This is the fix for the revoke-isn't-a-kill-
// switch bug: intent_services can no longer authorize a call on its own.
describe('isServiceInScope (grant is sole authority)', () => {
  it('allows when the provider is granted and no intent is declared', () => {
    expect(isServiceInScope('openrouter', ['openrouter'], [])).toBe(true);
  });

  it('allows when granted AND the intent includes it (intent narrows to it)', () => {
    expect(isServiceInScope('openrouter', ['openrouter', 'stripe'], ['openrouter'])).toBe(true);
  });

  it('DENIES intent-only (self-declared, not granted) — the core bypass', () => {
    // The old `||` returned true here. This is what let a revoked agent
    // re-authorize itself by declaring the intent.
    expect(isServiceInScope('openrouter', [], ['openrouter'])).toBe(false);
  });

  it('denies when neither granted nor intended', () => {
    expect(isServiceInScope('slack', ['openrouter'], ['openrouter'])).toBe(false);
  });

  it('denies a granted provider that the intent narrows OUT', () => {
    // Granted stripe+openrouter, but this passport declared intent only for
    // stripe → openrouter is out of scope for THIS passport.
    expect(isServiceInScope('openrouter', ['openrouter', 'stripe'], ['stripe'])).toBe(false);
  });

  it('empty grants deny everything regardless of intent', () => {
    expect(isServiceInScope('openrouter', [], [])).toBe(false);
    expect(isServiceInScope('openrouter', [], ['openrouter', 'stripe'])).toBe(false);
  });
});
