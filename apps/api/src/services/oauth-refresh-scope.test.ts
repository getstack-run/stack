import { describe, expect, it } from 'vitest';
import { resolveRefreshScope } from './oauth-grant-state.js';

describe('OAuth refresh scope narrowing', () => {
  const granted = 'agents:read agents:write audit:read';

  it('preserves the original family scope when scope is omitted', () => {
    expect(resolveRefreshScope(granted, undefined)).toBe(granted);
  });

  it('allows a requested subset and removes duplicates', () => {
    expect(resolveRefreshScope(granted, 'audit:read agents:read audit:read')).toBe(
      'audit:read agents:read',
    );
  });

  it('rejects an empty scope and every widening attempt', () => {
    expect(resolveRefreshScope(granted, '')).toBeNull();
    expect(resolveRefreshScope(granted, 'agents:read billing:write')).toBeNull();
  });
});
