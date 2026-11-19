import { describe, expect, it } from 'vitest';
import { DETECTORS } from '../constants/detectors.js';
import { ReviewFlag } from './passport.js';

const flag = (type: string) => ({ type, severity: 'warning', message: 'm' });

describe('ReviewFlag.type', () => {
  it('accepts every detector in the catalog', () => {
    for (const key of Object.keys(DETECTORS)) {
      expect(ReviewFlag.safeParse(flag(key)).success, key).toBe(true);
    }
  });

  it('accepts the passport-scoped signals that are recorded but are not detectors', () => {
    for (const type of ['unconstrained_scope', 'pii_below_threshold', 'audit_claim_binding_failure']) {
      expect(ReviewFlag.safeParse(flag(type)).success, type).toBe(true);
    }
  });

  it('rejects a type no code path writes', () => {
    expect(ReviewFlag.safeParse(flag('missed_checkout')).success).toBe(false);
    expect(ReviewFlag.safeParse(flag('not_a_signal')).success).toBe(false);
  });
});
