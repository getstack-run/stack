import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  MissionLimitBehaviorInput,
  MissionReviewInput,
  SetMissionMakingAllowanceInput,
  isIanaTimeZone,
  localDateIn,
  startOfDayIn,
} from './mission-limits.js';
import { isMissionSpendScope, missionDaySpendScope } from '../constants/control-policy.js';

describe('the day of a money cap', () => {
  it('is the local date of the Mission\'s time zone', () => {
    const at = new Date('2026-11-02T23:30:00Z');
    expect(localDateIn(at, 'UTC')).toBe('2026-11-02');
    expect(localDateIn(at, 'Asia/Tokyo')).toBe('2026-11-03');
    expect(localDateIn(at, 'America/Los_Angeles')).toBe('2026-11-02');
  });

  it('begins at midnight in that zone, across a change of clocks too', () => {
    expect(startOfDayIn(new Date('2026-11-02T23:30:00Z'), 'Asia/Tokyo').toISOString()).toBe('2026-11-02T15:00:00.000Z');
    expect(startOfDayIn(new Date('2026-11-02T12:00:00Z'), 'UTC').toISOString()).toBe('2026-11-02T00:00:00.000Z');
    // 1 November 2026: New York goes from daylight time (UTC-4) to standard time (UTC-5) at 02:00; midnight was still UTC-4.
    expect(startOfDayIn(new Date('2026-11-01T18:00:00Z'), 'America/New_York').toISOString()).toBe('2026-11-01T04:00:00.000Z');
    // 29 March 2026: Stockholm goes from UTC+1 to UTC+2 at 02:00; midnight was UTC+1.
    expect(startOfDayIn(new Date('2026-03-29T12:00:00Z'), 'Europe/Stockholm').toISOString()).toBe('2026-03-28T23:00:00.000Z');
  });

  it('has a counter of its own', () => {
    expect(missionDaySpendScope('2026-11-02')).toBe('mission_spend@2026-11-02');
    expect(isMissionSpendScope('mission_spend')).toBe(true);
    expect(isMissionSpendScope('mission_spend@2026-11-02')).toBe(true);
    expect(isMissionSpendScope('spend:rule_1')).toBe(false);
  });
});

describe('the inputs', () => {
  const Open = z.object(MissionLimitBehaviorInput).strict();

  it('takes pause, refuse_action and end_mission per cap, and nothing else', () => {
    expect(Open.safeParse({ cap_behavior: { max_actions: 'pause', coverage_cap_cents: 'end_mission', max_dropoff_bytes: 'refuse_action' } }).success).toBe(true);
    expect(Open.safeParse({ cap_behavior: { max_actions: 'auto_revoke' } }).success).toBe(false);
    expect(Open.safeParse({ cap_behavior: { max_actions: 'deny_and_flag' } }).success).toBe(false);
    expect(Open.safeParse({ cap_behavior: { not_a_cap: 'pause' } }).success).toBe(false);
  });

  it('takes a period of the Mission or of a day, and only an IANA time zone', () => {
    expect(Open.safeParse({ coverage_cap_period: 'day', cap_time_zone: 'Europe/Stockholm' }).success).toBe(true);
    expect(Open.safeParse({ coverage_cap_period: 'week' }).success).toBe(false);
    expect(Open.safeParse({ cap_time_zone: 'Mars/Olympus' }).success).toBe(false);
    expect(isIanaTimeZone('UTC')).toBe(true);
  });

  it('needs the new limit to raise, and takes one only then', () => {
    expect(MissionReviewInput.safeParse({ decision: 'raise', limit: 10 }).success).toBe(true);
    expect(MissionReviewInput.safeParse({ decision: 'raise' }).success).toBe(false);
    expect(MissionReviewInput.safeParse({ decision: 'continue' }).success).toBe(true);
    expect(MissionReviewInput.safeParse({ decision: 'close', limit: 10 }).success).toBe(false);
    expect(MissionReviewInput.safeParse({ decision: 'pause' }).success).toBe(false);
  });

  it('takes a making allowance in whole cents, or null for none', () => {
    expect(SetMissionMakingAllowanceInput.safeParse({ making_orders_up_to_cents: 5_000 }).success).toBe(true);
    // Nothing but the wallet bounds it: above $1,000,000 is taken as well.
    expect(SetMissionMakingAllowanceInput.safeParse({ making_orders_up_to_cents: 100_000_001 }).success).toBe(true);
    expect(SetMissionMakingAllowanceInput.safeParse({ making_orders_up_to_cents: 50_000_000_000 }).success).toBe(true);
    expect(SetMissionMakingAllowanceInput.safeParse({ making_orders_up_to_cents: null }).success).toBe(true);
    expect(SetMissionMakingAllowanceInput.safeParse({ making_orders_up_to_cents: -1 }).success).toBe(false);
    expect(SetMissionMakingAllowanceInput.safeParse({ making_orders_up_to_cents: 1.5 }).success).toBe(false);
  });
});
