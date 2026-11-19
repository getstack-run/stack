import { describe, expect, it } from 'vitest';
import { OAUTH_CONSENT_JWT_TTL_SECONDS } from './index.js';

// The consent hand-off link has to outlive the sign-in it may send the owner through. A sign-in by e-mailed
// magic link lasts 15 minutes (the Console's own sign-in settings; they are not importable from here).
const MAGIC_LINK_LIFETIME_SECONDS = 15 * 60;

describe('OAuth consent hand-off lifetime', () => {
  it('is at least as long as the magic link the owner may have to sign in with first', () => {
    expect(OAUTH_CONSENT_JWT_TTL_SECONDS).toBeGreaterThanOrEqual(MAGIC_LINK_LIFETIME_SECONDS);
  });
});
