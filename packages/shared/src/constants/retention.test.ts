import { describe, expect, it } from 'vitest';
import { AUDIT_RETENTION_DAYS } from './plan-limits.js';

// Every account keeps its record a year, whatever plan or tier its row carries; reading it needs controls.
describe('audit retention', () => {
  it('keeps the audit record, security events and signed claims 365 days for every account', () => {
    expect(AUDIT_RETENTION_DAYS).toBe(365);
  });
});
