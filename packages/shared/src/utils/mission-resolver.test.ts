import { describe, it, expect } from 'vitest';
import { resolveMissionRef, MissionRefForbidden } from './index.js';

/**
 * resolveMissionRef contract pins.
 *
 * Auto-resolve rules:
 *   - explicit non-null → must be in passport's mission_ids
 *   - explicit null OR undefined + passport has exactly ONE active
 *     mission → return that mission_id
 *   - explicit null OR undefined + zero → return null unless required
 *   - multiple distinct bindings without a selection → deny
 *   - explicit not in passport.mission_ids → MissionRefForbidden
 */

describe('resolveMissionRef', () => {
  it('returns the single bound mission when no explicit override', () => {
    expect(resolveMissionRef(['ms_a'])).toBe('ms_a');
    expect(resolveMissionRef(['ms_a'], undefined)).toBe('ms_a');
    expect(resolveMissionRef(['ms_a'], null)).toBe('ms_a');
  });

  it('returns null when passport has zero bound missions', () => {
    expect(resolveMissionRef([])).toBeNull();
    expect(resolveMissionRef(null)).toBeNull();
    expect(resolveMissionRef(undefined)).toBeNull();
  });

  it('denies ambiguous mission attribution instead of bypassing all mission gates', () => {
    expect(() => resolveMissionRef(['ms_a', 'ms_b'])).toThrow();
    expect(() => resolveMissionRef(['ms_a', 'ms_b'], null)).toThrow();
    expect(() => resolveMissionRef(['ms_a', 'ms_b'], '')).toThrow();
  });

  it('cannot erase a mandatory mission binding', () => {
    expect(() => resolveMissionRef([], undefined, { required: true })).toThrow();
    expect(() => resolveMissionRef(undefined, null, { required: true })).toThrow();
  });

  it('collapses duplicate bindings to the same mission', () => {
    expect(resolveMissionRef(['ms_a', 'ms_a'])).toBe('ms_a');
  });

  it('returns the explicit mission_id when it is one of the passport bindings', () => {
    expect(resolveMissionRef(['ms_a', 'ms_b'], 'ms_b')).toBe('ms_b');
    expect(resolveMissionRef(['ms_only'], 'ms_only')).toBe('ms_only');
  });

  it('throws MissionRefForbidden when explicit mission_id is not in passport bindings', () => {
    expect(() => resolveMissionRef(['ms_a'], 'ms_other')).toThrow(MissionRefForbidden);
    expect(() => resolveMissionRef([], 'ms_anything')).toThrow(MissionRefForbidden);
    expect(() => resolveMissionRef(null, 'ms_anything')).toThrow(MissionRefForbidden);
  });

  it('MissionRefForbidden carries the offending id + passport bindings in the message', () => {
    try {
      resolveMissionRef(['ms_a', 'ms_b'], 'ms_evil');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(MissionRefForbidden);
      expect((err as Error).message).toContain('ms_evil');
      expect((err as Error).message).toContain('ms_a');
      expect((err as Error).message).toContain('ms_b');
    }
  });

  it('MissionRefForbidden message names "(none)" when passport has no bindings', () => {
    try {
      resolveMissionRef([], 'ms_anything');
      expect.fail('should have thrown');
    } catch (err) {
      expect((err as Error).message).toContain('(none)');
    }
  });
});
