import { describe, it, expect } from 'vitest';
import { isHostAllowed, hostOfUrl } from './host-binding.js';

describe('isHostAllowed', () => {
  describe('exact entries', () => {
    it('matches the declared host', () => {
      expect(isHostAllowed('api.stripe.com', ['api.stripe.com'])).toBe(true);
    });

    it('is case-insensitive on both sides', () => {
      expect(isHostAllowed('API.Stripe.COM', ['api.stripe.com'])).toBe(true);
      expect(isHostAllowed('api.stripe.com', ['API.STRIPE.COM'])).toBe(true);
    });

    it('does not match a different host', () => {
      expect(isHostAllowed('attacker.example.com', ['api.stripe.com'])).toBe(false);
    });

    it('does not match a lookalike that merely contains the declared host', () => {
      // The attack: register api.stripe.com.evil.com and hope for substring logic.
      expect(isHostAllowed('api.stripe.com.evil.com', ['api.stripe.com'])).toBe(false);
    });

    it('does not treat a subdomain as the declared host', () => {
      expect(isHostAllowed('evil.api.stripe.com', ['api.stripe.com'])).toBe(false);
    });

    it('matches through a trailing root dot', () => {
      // api.stripe.com. and api.stripe.com resolve identically, so treating
      // them as different strings would be a bypass in the permissive
      // direction for a deny-list and a false denial here.
      expect(isHostAllowed('api.stripe.com.', ['api.stripe.com'])).toBe(true);
    });
  });

  describe('dot-led suffix entries', () => {
    it('matches a subdomain', () => {
      expect(isHostAllowed('s3.eu-north-1.amazonaws.com', ['.amazonaws.com'])).toBe(true);
    });

    it('matches the bare parent domain', () => {
      expect(isHostAllowed('amazonaws.com', ['.amazonaws.com'])).toBe(true);
    });

    it('only matches on a label boundary', () => {
      expect(isHostAllowed('notamazonaws.com', ['.amazonaws.com'])).toBe(false);
      expect(isHostAllowed('evil-amazonaws.com', ['.amazonaws.com'])).toBe(false);
    });

    it('does not match when the declared domain is only a prefix', () => {
      expect(isHostAllowed('amazonaws.com.evil.com', ['.amazonaws.com'])).toBe(false);
    });

    it('refuses a wildcard broad enough to cover a TLD', () => {
      expect(isHostAllowed('api.stripe.com', ['.com'])).toBe(false);
      expect(isHostAllowed('api.stripe.com', ['.'])).toBe(false);
      expect(isHostAllowed('anything.co.uk', ['.uk'])).toBe(false);
    });
  });

  describe('deny by default', () => {
    it('denies against an empty allowlist', () => {
      expect(isHostAllowed('api.stripe.com', [])).toBe(false);
    });

    it('denies an empty host', () => {
      expect(isHostAllowed('', ['api.stripe.com'])).toBe(false);
      expect(isHostAllowed('   ', ['api.stripe.com'])).toBe(false);
    });

    it('ignores blank entries rather than treating them as wildcards', () => {
      expect(isHostAllowed('attacker.example.com', ['', '   '])).toBe(false);
    });
  });

  it('accepts when any one entry matches', () => {
    const allowed = ['api.stripe.com', 'files.stripe.com', '.stripe-cdn.com'];
    expect(isHostAllowed('files.stripe.com', allowed)).toBe(true);
    expect(isHostAllowed('assets.stripe-cdn.com', allowed)).toBe(true);
    expect(isHostAllowed('attacker.example.com', allowed)).toBe(false);
  });
});

describe('hostOfUrl', () => {
  it('extracts the hostname without the port', () => {
    expect(hostOfUrl('https://api.stripe.com:443/v1/charges')).toBe('api.stripe.com');
  });

  it('lowercases', () => {
    expect(hostOfUrl('https://API.Stripe.COM/v1/charges')).toBe('api.stripe.com');
  });

  it('strips IPv6 brackets', () => {
    expect(hostOfUrl('https://[2606:4700:4700::1111]/x')).toBe('2606:4700:4700::1111');
  });

  it('returns null for an unparseable URL', () => {
    expect(hostOfUrl('not a url')).toBeNull();
    expect(hostOfUrl('')).toBeNull();
  });

  it('is not fooled by userinfo pointing at another host', () => {
    // https://api.stripe.com@attacker.example.com/ resolves to attacker.example.com
    expect(hostOfUrl('https://api.stripe.com@attacker.example.com/v1')).toBe(
      'attacker.example.com',
    );
  });
});
