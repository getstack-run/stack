import { describe, it, expect } from 'vitest';
import { UpdateNotificationRuleInput } from '@stack/shared';

// The console rendered a switch over `notification_channels.active` that could
// not move: the column existed, the PATCH input did not carry it. Silencing a
// noisy rule meant deleting it and rebuilding it later.
//
// Two things are pinned here. First that `active` survives parsing at all.
// Second - and this is the one that bites - that `false` survives, because the
// handler beside it reads `if (input.events)` and a truthiness check on a
// boolean would drop exactly the value the field exists for. Turning a rule
// OFF is the whole feature; a silent no-op there looks identical to a working
// switch until an alert the operator thought they had silenced fires anyway.

describe('UpdateNotificationRuleInput.active', () => {
  it('accepts active: true', () => {
    const parsed = UpdateNotificationRuleInput.parse({ active: true });
    expect(parsed.active).toBe(true);
  });

  it('accepts active: false and keeps it false', () => {
    const parsed = UpdateNotificationRuleInput.parse({ active: false });
    expect(parsed.active).toBe(false);
    // The distinction the handler depends on: present-and-false is not absent.
    expect('active' in parsed).toBe(true);
    expect(parsed.active).not.toBeUndefined();
  });

  it('leaves active undefined when the caller does not send it', () => {
    const parsed = UpdateNotificationRuleInput.parse({ min_severity: 'critical' });
    expect(parsed.active).toBeUndefined();
  });

  it('refuses a non-boolean rather than coercing it', () => {
    expect(() => UpdateNotificationRuleInput.parse({ active: 'false' })).toThrow();
    expect(() => UpdateNotificationRuleInput.parse({ active: 0 })).toThrow();
  });

  it('still accepts the three fields that shipped before it', () => {
    const parsed = UpdateNotificationRuleInput.parse({
      destination_ids: ['ndest_1'],
      events: ['passport.issued'],
      min_severity: 'warning',
      active: false,
    });
    expect(parsed.destination_ids).toEqual(['ndest_1']);
    expect(parsed.events).toEqual(['passport.issued']);
    expect(parsed.min_severity).toBe('warning');
    expect(parsed.active).toBe(false);
  });
});
