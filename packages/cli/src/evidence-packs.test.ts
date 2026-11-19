import { describe, expect, it } from 'vitest';
import { parseExportScope } from './evidence-packs.js';

describe('evidence-pack export --scope', () => {
  it('sends a period as the whole period ref the service reads', () => {
    expect(parseExportScope('period:2026-Q3')).toEqual({ kind: 'period', ref: 'period:2026-Q3' });
    expect(parseExportScope('period:2026-07')).toEqual({ kind: 'period', ref: 'period:2026-07' });
    expect(parseExportScope('period:2026-07-01/2026-08-01')).toEqual({ kind: 'period', ref: 'period:2026-07-01/2026-08-01' });
  });

  it('still takes the doubled form earlier versions needed, as the same period', () => {
    expect(parseExportScope('period:period:2026-Q3')).toEqual({ kind: 'period', ref: 'period:2026-Q3' });
  });

  it('sends the other kinds\' ref as given', () => {
    expect(parseExportScope('mission:ms_abc')).toEqual({ kind: 'mission', ref: 'ms_abc' });
    expect(parseExportScope('session:ses_1')).toEqual({ kind: 'session', ref: 'ses_1' });
    expect(parseExportScope('incident:inc_1')).toEqual({ kind: 'incident', ref: 'inc_1' });
  });

  it('refuses a kind STACK does not export, and a scope with no kind', () => {
    expect(parseExportScope('quarter:2026-Q3')).toBeNull();
    expect(parseExportScope('2026-Q3')).toBeNull();
  });
});
