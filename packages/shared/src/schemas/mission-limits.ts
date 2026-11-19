// A Mission's limits: what each cap does when it is reached, whether the money cap counts the whole Mission or one
// day, and the owner's review of a Mission a cap paused.
//
//   pause          the Mission is paused: every action under it is refused (MISSION_PAUSED) and nothing is revoked.
//                  The owner reviews it: raise the limit, continue, or close. The default for every cap.
//   refuse_action  the action that would pass the cap is refused; the Mission goes on.
//   end_mission    the Mission ends (completed, cap breached) and its Passports with it.
//
// A cap reached records no security event: the review is the record.

import { z } from 'zod';

/** The caps a Mission can carry. */
export const MISSION_CAP_NAMES = [
  'coverage_cap_cents',
  'max_dropoff_bytes',
  'max_concurrent_intents',
  'max_actions',
  'max_duration_seconds',
  'max_actions_per_service',
] as const;
export type MissionCapName = (typeof MISSION_CAP_NAMES)[number];

export const MISSION_CAP_BEHAVIORS = ['pause', 'refuse_action', 'end_mission'] as const;
export type MissionCapBehavior = (typeof MISSION_CAP_BEHAVIORS)[number];
/** What a cap does when the Mission's opener says nothing of it. */
export const DEFAULT_MISSION_CAP_BEHAVIOR: MissionCapBehavior = 'pause';

/** Whether the money cap counts everything the Mission spends, or what it spends in one day of its time zone. */
export const COVERAGE_CAP_PERIODS = ['mission', 'day'] as const;
export type CoverageCapPeriod = (typeof COVERAGE_CAP_PERIODS)[number];
export const DEFAULT_CAP_TIME_ZONE = 'UTC';

/** The owner's answer to a Mission a cap paused. */
export const MISSION_REVIEW_DECISIONS = ['raise', 'continue', 'close'] as const;
export type MissionReviewDecision = (typeof MISSION_REVIEW_DECISIONS)[number];

/** Whether a name is an IANA time zone this runtime knows. */
export function isIanaTimeZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

export const MissionCapBehaviorMap = z.record(z.enum(MISSION_CAP_NAMES), z.enum(MISSION_CAP_BEHAVIORS));

/** The fields of a Mission's open that say how its caps behave. */
export const MissionLimitBehaviorInput = {
  /** Per cap: pause (the default), refuse_action or end_mission. */
  cap_behavior: MissionCapBehaviorMap.optional(),
  /** `day`: coverage_cap_cents is what the Mission may spend in one day, ending at midnight in cap_time_zone. */
  coverage_cap_period: z.enum(COVERAGE_CAP_PERIODS).optional(),
  /** The IANA time zone a day of the money cap ends in. Default UTC. */
  cap_time_zone: z.string().min(1).max(64).refine(isIanaTimeZone, 'cap_time_zone must be an IANA time zone, such as Europe/Stockholm').optional(),
};

/** What the owner pre-approves of the Mission's print-on-demand orders, in cents across all of them; null: none. The wallet bounds what is spent. */
export const MakingOrdersAllowance = z.number().int().nonnegative().nullable();

export const SetMissionMakingAllowanceInput = z.object({
  making_orders_up_to_cents: MakingOrdersAllowance,
}).strict();
export type SetMissionMakingAllowanceInput = z.infer<typeof SetMissionMakingAllowanceInput>;

/**
 * The owner's review of a paused Mission. `raise` needs the new `limit` of the cap that paused it (above the old one);
 * `continue` lets it run with its limits as they are; `close` ends it.
 */
export const MissionReviewInput = z.object({
  decision: z.enum(MISSION_REVIEW_DECISIONS),
  limit: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
}).strict().refine((value) => (value.decision === 'raise') === (value.limit !== undefined), {
  message: 'raise needs the new limit, and only raise takes one',
  path: ['limit'],
});
export type MissionReviewInput = z.infer<typeof MissionReviewInput>;

/** The local calendar date of an instant in a zone, as YYYY-MM-DD. */
export function localDateIn(at: Date, zone: string): string {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(at);
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? '';
  return `${get('year')}-${get('month')}-${get('day')}`;
}

/** How far a zone's wall clock is ahead of UTC at an instant, in milliseconds. */
function zoneOffsetMs(at: Date, zone: string): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: zone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).formatToParts(at);
  const n = (type: string) => Number(parts.find((part) => part.type === type)?.value ?? 0);
  const wall = Date.UTC(n('year'), n('month') - 1, n('day'), n('hour'), n('minute'), n('second'));
  return wall - Math.floor(at.getTime() / 1000) * 1000;
}

/** The instant the day that holds `at` began, at midnight in `zone` (the first instant of that local date). */
export function startOfDayIn(at: Date, zone: string): Date {
  const [year, month, day] = localDateIn(at, zone).split('-').map(Number) as [number, number, number];
  const midnightAsUtc = Date.UTC(year, month - 1, day);
  // Midnight's offset can differ from now's across a change of clocks: settle on the offset at the candidate itself.
  let candidate = midnightAsUtc - zoneOffsetMs(new Date(midnightAsUtc), zone);
  candidate = midnightAsUtc - zoneOffsetMs(new Date(candidate), zone);
  return new Date(candidate);
}
