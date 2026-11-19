import { describe, expect, it } from 'vitest';
import { FleetLimits } from './fleet.js';

const base = { max_actions: 100, max_concurrent_actions: 4 };

describe('FleetLimits.max_duration_seconds', () => {
  it('has no 24 hour maximum: a Mission under a fleet policy may run for a week or a year', () => {
    for (const seconds of [86_400, 7 * 86_400, 365 * 86_400]) {
      expect(FleetLimits.parse({ ...base, max_duration_seconds: seconds }).max_duration_seconds).toBe(seconds);
    }
  });

  it('is a positive whole number of seconds the Mission can store', () => {
    expect(() => FleetLimits.parse({ ...base, max_duration_seconds: 0 })).toThrow();
    expect(() => FleetLimits.parse({ ...base, max_duration_seconds: 1.5 })).toThrow();
    expect(FleetLimits.parse({ ...base, max_duration_seconds: 2_147_483_647 }).max_duration_seconds).toBe(2_147_483_647);
    expect(() => FleetLimits.parse({ ...base, max_duration_seconds: 2_147_483_648 })).toThrow();
  });
});
