import { describe, expect, it } from 'vitest';
import { ControlLimitResolver } from './limit-resolver.js';

// A spend is held to the money cap of the Mission it runs under: of the whole Mission in `mission_spend`, or of one day
// in that day's own counter, the date being the Mission's time zone's. The cap is read for every spend, so a limit the
// owner raised on a paused Mission holds at once.

function resolverWith(mission: { coverage_cap_cents: number | null; coverage_cap_period?: string; cap_time_zone?: string } | null, now: Date) {
  const current = { value: mission };
  const resolver = new ControlLimitResolver({
    posture: { hostedApplies: async () => false, budgetEnforced: async () => true },
    policies: { effective: async () => null },
    accounts: { agentOfAccount: async () => null },
    missions: { findById: async () => current.value },
    now: () => now,
  });
  return { resolver, current };
}

const input = { operatorId: 'op_1', accountId: 'acct_1', action: null, missionId: 'ms_1' } as const;

describe('the Mission money cap a spend is held to', () => {
  it('counts a cap of the whole Mission in mission_spend', async () => {
    const { resolver } = resolverWith({ coverage_cap_cents: 500, coverage_cap_period: 'mission', cap_time_zone: 'UTC' }, new Date('2026-11-02T23:30:00Z'));
    expect(await resolver.resolve(input)).toMatchObject({ missionSpendCapCents: 500, missionSpendScope: 'mission_spend' });
  });

  it('counts a cap of one day in the counter of the day of the Mission\'s time zone', async () => {
    // 23:30 in UTC is already the next day in Tokyo, and still the day before in New York.
    const at = new Date('2026-11-02T23:30:00Z');
    expect(await resolverWith({ coverage_cap_cents: 500, coverage_cap_period: 'day', cap_time_zone: 'Asia/Tokyo' }, at).resolver.resolve(input))
      .toMatchObject({ missionSpendScope: 'mission_spend@2026-11-03' });
    expect(await resolverWith({ coverage_cap_cents: 500, coverage_cap_period: 'day', cap_time_zone: 'America/New_York' }, at).resolver.resolve(input))
      .toMatchObject({ missionSpendScope: 'mission_spend@2026-11-02' });
  });

  it('reads the cap for every spend: a raised limit holds at once', async () => {
    const { resolver, current } = resolverWith({ coverage_cap_cents: 100 }, new Date());
    expect(await resolver.resolve(input)).toMatchObject({ missionSpendCapCents: 100 });
    current.value = { coverage_cap_cents: 400 };
    expect(await resolver.resolve(input)).toMatchObject({ missionSpendCapCents: 400 });
  });

  it('holds nothing for a Mission with no money cap', async () => {
    const { resolver } = resolverWith({ coverage_cap_cents: null }, new Date());
    const limits = await resolver.resolve(input);
    expect(limits.missionSpendCapCents).toBeUndefined();
    expect(limits.missionSpendScope).toBeUndefined();
  });
});
