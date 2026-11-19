import { describe, it, expect } from 'vitest';
import { targetLooksLikeUrl } from './intent-simulation-service.js';

// #5 — detect a URL in an intent's `target` (which must be a service
// slug) so the scope_mismatch diagnostic can steer the caller instead of the
// misleading "this service isn't in scope".

describe('targetLooksLikeUrl', () => {
  it('flags full URLs', () => {
    expect(targetLooksLikeUrl('https://api.stripe.com/v1/charges')).toBe(true);
    expect(targetLooksLikeUrl('http://localhost:3000')).toBe(true);
  });

  it('flags bare hostnames', () => {
    expect(targetLooksLikeUrl('api.stripe.com')).toBe(true);
    expect(targetLooksLikeUrl('api.stripe.com/v1')).toBe(true);
    expect(targetLooksLikeUrl('api.stripe.com:443')).toBe(true);
  });

  it('does NOT flag plain service slugs', () => {
    expect(targetLooksLikeUrl('stripe')).toBe(false);
    expect(targetLooksLikeUrl('slack')).toBe(false);
    expect(targetLooksLikeUrl('my-custom-service')).toBe(false);
    expect(targetLooksLikeUrl('custom_hetzner')).toBe(false);
  });

  it('does not flag non-URL free-form labels', () => {
    expect(targetLooksLikeUrl('task_complete')).toBe(false);
    expect(targetLooksLikeUrl('')).toBe(false);
  });
});
