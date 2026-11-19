import { describe, it, expect } from 'vitest';
import { actionsMeter, resolvePeriod } from './usage.js';

/**
 * `resolvePeriod` maps a period preset to a [since, until) window in LOCAL
 * time. `now` is injected so these are deterministic. We anchor on a fixed
 * local instant: 2026-07-14 15:30 local. The assertions check the LOCAL
 * calendar boundaries (midnight, 1st-of-month), not UTC — that's the point of
 * resolving presets on the client.
 */
const NOW = new Date(2026, 6, 14, 15, 30, 0); // month is 0-indexed: 6 = July

describe('resolvePeriod', () => {
  it('billing returns no bounds (server uses the operator period)', () => {
    const r = resolvePeriod('billing', NOW);
    expect(r.since).toBeUndefined();
    expect(r.until).toBeUndefined();
    expect(r.label).toBe('billing period');
  });

  it('today is local-midnight → now', () => {
    const r = resolvePeriod('today', NOW);
    expect(r.since).toEqual(new Date(2026, 6, 14, 0, 0, 0));
    expect(r.until).toEqual(NOW);
    expect(r.label).toBe('today');
  });

  it('yesterday is prev-midnight → today-midnight (excludes today)', () => {
    const r = resolvePeriod('yesterday', NOW);
    expect(r.since).toEqual(new Date(2026, 6, 13, 0, 0, 0));
    expect(r.until).toEqual(new Date(2026, 6, 14, 0, 0, 0));
    expect(r.label).toBe('yesterday');
  });

  it('7d is now-7days → now', () => {
    const r = resolvePeriod('7d', NOW);
    expect(r.since).toEqual(new Date(2026, 6, 7, 15, 30, 0));
    expect(r.until).toEqual(NOW);
    expect(r.label).toBe('last 7 days');
  });

  it('week is an alias for 7d', () => {
    expect(resolvePeriod('week', NOW)).toEqual(resolvePeriod('7d', NOW));
  });

  it('30d is now-30days → now', () => {
    const r = resolvePeriod('30d', NOW);
    expect(r.since).toEqual(new Date(2026, 5, 14, 15, 30, 0)); // June 14
    expect(r.until).toEqual(NOW);
  });

  it('month is 1st-of-this-month → now', () => {
    const r = resolvePeriod('month', NOW);
    expect(r.since).toEqual(new Date(2026, 6, 1, 0, 0, 0));
    expect(r.until).toEqual(NOW);
    expect(r.label).toBe('this month');
  });

  it('last-month is 1st-prev-month → 1st-this-month (excludes this month)', () => {
    const r = resolvePeriod('last-month', NOW);
    expect(r.since).toEqual(new Date(2026, 5, 1, 0, 0, 0)); // June 1
    expect(r.until).toEqual(new Date(2026, 6, 1, 0, 0, 0)); // July 1
    expect(r.label).toBe('last month');
  });

  it('last-month rolls the year at January', () => {
    const jan = new Date(2026, 0, 10, 12, 0, 0); // 2026-01-10
    const r = resolvePeriod('last-month', jan);
    expect(r.since).toEqual(new Date(2025, 11, 1, 0, 0, 0)); // Dec 1 2025
    expect(r.until).toEqual(new Date(2026, 0, 1, 0, 0, 0)); // Jan 1 2026
  });
});

describe('actionsMeter', () => {
  const base = {
    used: 1200,
    limit: 10000,
    allowance_coverage: 'complete' as const,
    allowance_plan: 'platform' as const,
    detail_coverage: 'complete' as const,
  };

  it('reads a plain allowance as used / limit', () => {
    expect(actionsMeter(base)).toBe('1,200 / 10,000');
  });

  it('reads a white-label pool as the pool plus this account share', () => {
    expect(actionsMeter({ ...base, pooled: true, own_used: 300, tenants: 4 })).toBe(
      'Pool: 1,200 / 10,000 (your share: 300, 4 tenants)',
    );
  });

  it('uses the singular for a pool with one tenant', () => {
    expect(actionsMeter({ ...base, pooled: true, own_used: 0, tenants: 1 })).toBe(
      'Pool: 1,200 / 10,000 (your share: 0, 1 tenant)',
    );
  });
});
