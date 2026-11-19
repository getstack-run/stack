import { describe, expect, it } from 'vitest';
import { assertProductionEmailService } from './email-service-policy.js';

describe('production email service boot gate', () => {
  it('refuses production boot without a Resend key', () => {
    expect(() => assertProductionEmailService('production', '')).toThrow(/Resend email service is required/);
  });

  it('accepts a vaulted or environment Resend key', () => {
    expect(() => assertProductionEmailService('production', 're_test_key')).not.toThrow();
  });

  it('lets a staging deployment boot with no mail service, and still takes one when it has it', () => {
    expect(() => assertProductionEmailService('production', '', true)).not.toThrow();
    expect(() => assertProductionEmailService('production', 're_test_key', true)).not.toThrow();
    expect(() => assertProductionEmailService('production', '', false)).toThrow(/Resend email service is required/);
  });

  it('allows the safe no-provider fallback outside production', () => {
    expect(() => assertProductionEmailService('development', '')).not.toThrow();
    expect(() => assertProductionEmailService('test', '')).not.toThrow();
  });
});
