import { describe, it, expect } from 'vitest';
import { resolveDestinationAutoVerify } from './accountability.js';

// Complete mediation. A webhook destination was marked verified the
// moment it was named, so "verified" carried no information for the one
// channel type that points at an arbitrary URL and carries security events off
// our network. Anyone who could add a destination could receive STACK's
// security-event stream at a URL they never had to prove they controlled.
//
// The rule is now: nothing starts verified except the operator's own
// registered email, which is already proven because it is how they sign in.

describe('resolveDestinationAutoVerify', () => {
  it('auto-verifies the operator own registered email', () => {
    expect(
      resolveDestinationAutoVerify({
        channelType: 'email',
        destination: 'ops@example.com',
        operatorEmail: 'ops@example.com',
      }),
    ).toBe(true);
  });

  it('ignores case when matching the registered email', () => {
    expect(
      resolveDestinationAutoVerify({
        channelType: 'email',
        destination: 'OPS@Example.COM',
        operatorEmail: 'ops@example.com',
      }),
    ).toBe(true);
  });

  it('does not auto-verify a different email', () => {
    expect(
      resolveDestinationAutoVerify({
        channelType: 'email',
        destination: 'someone-else@example.com',
        operatorEmail: 'ops@example.com',
      }),
    ).toBe(false);
  });

  it('never auto-verifies a webhook', () => {
    for (const destination of [
      'https://hooks.example.com/stack',
      'https://ops@example.com',
      'https://example.com/ops@example.com',
    ]) {
      expect(
        resolveDestinationAutoVerify({
          channelType: 'webhook',
          destination,
          operatorEmail: 'ops@example.com',
        }),
      ).toBe(false);
    }
  });

  it('never auto-verifies sms', () => {
    expect(
      resolveDestinationAutoVerify({
        channelType: 'sms',
        destination: '+46701740606',
        operatorEmail: 'ops@example.com',
      }),
    ).toBe(false);
  });

  it('refuses when the operator email is unknown', () => {
    expect(
      resolveDestinationAutoVerify({
        channelType: 'email',
        destination: 'ops@example.com',
        operatorEmail: null,
      }),
    ).toBe(false);
  });
});
