import { describe, expect, it } from 'vitest';
import {
  applyHistoricalBoundaryCoverage,
  mergeUsageSlices,
  splitUsageWindow,
  UsageRepository,
} from './usage-repo.js';

describe('splitUsageWindow', () => {
  const now = new Date('2026-08-10T12:00:00.000Z');

  it('reads a closed month only from daily usage', () => {
    expect(splitUsageWindow(
      new Date('2026-07-01T00:00:00.000Z'),
      new Date('2026-08-01T00:00:00.000Z'),
      now,
    )).toEqual({
      historical: { startDay: '2026-07-01', endDay: '2026-08-01' },
      live: null,
      historicalBoundaryLowerBound: false,
    });
  });

  it('reads the current UTC day only from live audit rows', () => {
    expect(splitUsageWindow(
      new Date('2026-08-10T00:00:00.000Z'),
      undefined,
      now,
    )).toEqual({
      historical: null,
      live: {
        sinceMs: Date.parse('2026-08-10T00:00:00.000Z'),
        untilMs: Date.parse('2026-08-10T12:00:00.000Z'),
      },
      historicalBoundaryLowerBound: false,
    });
  });

  it('splits a range at UTC midnight with no overlap', () => {
    expect(splitUsageWindow(
      new Date('2026-08-01T00:00:00.000Z'),
      new Date('2026-09-01T00:00:00.000Z'),
      now,
    )).toEqual({
      historical: { startDay: '2026-08-01', endDay: '2026-08-10' },
      live: {
        sinceMs: Date.parse('2026-08-10T00:00:00.000Z'),
        untilMs: Date.parse('2026-08-10T12:00:00.000Z'),
      },
      historicalBoundaryLowerBound: false,
    });
  });

  it('excludes an old partial start day and marks the result as a lower bound', () => {
    expect(splitUsageWindow(
      new Date('2026-07-01T12:00:00.000Z'),
      new Date('2026-07-04T00:00:00.000Z'),
      now,
    )).toEqual({
      historical: { startDay: '2026-07-02', endDay: '2026-07-04' },
      live: null,
      historicalBoundaryLowerBound: true,
    });
  });

  it('excludes an old partial end day and marks the result as a lower bound', () => {
    expect(splitUsageWindow(
      new Date('2026-07-01T00:00:00.000Z'),
      new Date('2026-07-04T12:00:00.000Z'),
      now,
    )).toEqual({
      historical: { startDay: '2026-07-01', endDay: '2026-07-04' },
      live: null,
      historicalBoundaryLowerBound: true,
    });
  });

  it('keeps a range inside one old partial day as an empty lower bound', async () => {
    const repo = new UsageRepository({} as never);
    await expect(repo.getRange(
      'op_test',
      new Date('2026-07-04T10:00:00.000Z'),
      new Date('2026-07-04T12:00:00.000Z'),
      now,
    )).resolves.toEqual({
      meteredTotal: 0,
      activityTotal: 0,
      nonMetered: null,
      totalCoverage: 'lower_bound',
      detailCoverage: 'unavailable',
    });
  });
});

describe('mergeUsageSlices', () => {
  it('uses durable closed days and the live UTC day once', () => {
    const result = mergeUsageSlices({
      historicalDays: [{
        actions: 10,
        actions_total: 30,
        actions_detail_complete: true,
      }],
      historicalByKind: { 'passport.issue': 10 },
      liveByAction: {
        'passport.issue': 2,
        'audit.read': 5,
      },
      meteredActions: ['passport.issue'],
    });

    expect(result).toEqual({
      meteredTotal: 12,
      activityTotal: 37,
      nonMetered: 25,
      totalCoverage: 'complete',
      detailCoverage: 'complete',
      byKind: { 'passport.issue': 12 },
    });
  });

  it('counts no live action as metered when the deployment names none, as an engine with no meter', () => {
    const result = mergeUsageSlices({
      historicalDays: [],
      historicalByKind: {},
      liveByAction: { 'passport.issue': 2, 'audit.read': 5 },
    });

    expect(result).toMatchObject({ meteredTotal: 0, activityTotal: 7, nonMetered: 7, byKind: {} });
  });

  it('keeps a historical metered total but omits an unavailable breakdown', () => {
    const result = mergeUsageSlices({
      historicalDays: [{
        actions: 2_480,
        actions_total: 8_022,
        actions_detail_complete: false,
      }],
      historicalByKind: {},
      liveByAction: {},
    });

    expect(result).toEqual({
      meteredTotal: 2_480,
      activityTotal: 8_022,
      nonMetered: 5_542,
      totalCoverage: 'complete',
      detailCoverage: 'unavailable',
    });
  });

  it('reports partial detail when only part of the range has a split', () => {
    const result = mergeUsageSlices({
      historicalDays: [
        { actions: 7, actions_total: 20, actions_detail_complete: false },
        { actions: 3, actions_total: 5, actions_detail_complete: true },
      ],
      historicalByKind: { 'skill.invoke': 3 },
      liveByAction: {},
    });

    expect(result.detailCoverage).toBe('partial');
    expect(result.byKind).toBeUndefined();
    expect(result.meteredTotal).toBe(10);
  });

  it('marks activity as a lower bound when a durable total is unknown', () => {
    const result = mergeUsageSlices({
      historicalDays: [{
        actions: 6,
        actions_total: null,
        actions_detail_complete: false,
      }],
      historicalByKind: {},
      liveByAction: {},
    });

    expect(result.activityTotal).toBe(6);
    expect(result.totalCoverage).toBe('lower_bound');
    expect(result.nonMetered).toBeNull();
  });

  it('does not treat a proved zero-metered day as missing detail', () => {
    const result = mergeUsageSlices({
      historicalDays: [{
        actions: 0,
        actions_total: 8,
        actions_detail_complete: false,
      }],
      historicalByKind: {},
      liveByAction: {},
    });

    expect(result.detailCoverage).toBe('complete');
    expect(result.byKind).toEqual({});
  });

  it('does not claim complete detail when durable rows do not match the total', () => {
    const result = mergeUsageSlices({
      historicalDays: [{
        actions: 5,
        actions_total: 10,
        actions_detail_complete: true,
      }],
      historicalByKind: { 'passport.issue': 4 },
      liveByAction: {},
    });

    expect(result.detailCoverage).toBe('partial');
    expect(result.byKind).toBeUndefined();
  });
});

describe('applyHistoricalBoundaryCoverage', () => {
  it('marks excluded historical fragments as a lower bound', () => {
    expect(applyHistoricalBoundaryCoverage({
      meteredTotal: 4,
      activityTotal: 10,
      nonMetered: 6,
      totalCoverage: 'complete',
      detailCoverage: 'complete',
      byKind: { 'passport.issue': 4 },
    }, true)).toEqual({
      meteredTotal: 4,
      activityTotal: 10,
      nonMetered: null,
      totalCoverage: 'lower_bound',
      detailCoverage: 'partial',
    });
  });
});
