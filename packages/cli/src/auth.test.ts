import { describe, it, expect, afterEach } from 'vitest';
import { OAUTH_SCOPES } from '@stack/shared';
import { CLI_DEFAULT_OAUTH_SCOPES, DEFAULT_SCOPE, requestedScope } from './auth.js';

// The CLI retains routine operator workflows without turning every login into
// an account-management or secret-retrieval credential.

const CANONICAL = new Set<string>(OAUTH_SCOPES as readonly string[]);
const tokens = [...CLI_DEFAULT_OAUTH_SCOPES];

describe('DEFAULT_SCOPE', () => {
  it('is a subset of the API OAUTH_SCOPES catalog (no typos, no wildcards)', () => {
    const unknown = tokens.filter((t) => !CANONICAL.has(t));
    expect(unknown, `unknown scopes: ${unknown.join(', ')}`).toEqual([]);
  });

  it('serializes the reviewed least-privilege set exactly', () => {
    expect(DEFAULT_SCOPE).toBe(tokens.join(' '));
  });

  it('keeps routine runtime writes available', () => {
    for (const scope of [
      'passports:write',
      'agents:write',
      'services:write',
      'services:connect',
      'dropoffs:write',
      'missions:write',
      'llm:invoke',
      'scan:write',
      'skills:write',
      'proxy:write',
      'accounts:read',
      'accounts:write',
      'accounts:act',
    ]) {
      expect(tokens, `missing ${scope}`).toContain(scope);
    }
  });

  it('keeps sensitive management and secret-bearing scopes opt-in', () => {
    for (const scope of [
      'account:write',
      'team:write',
      'oauth-apps:read',
      'oauth-apps:write',
      'cmek:read',
      'cmek:write',
      'credentials:read',
      'credentials:write',
      'billing:write',
      'payouts:read',
      'payouts:write',
      'identity:write',
      'authority:write',
      'governance:write',
      'reviews:write',
      'skills:publish',
      'notifications:write',
      'security-events:write',
      'detectors:write',
      'pii:write',
      'partner:write',
      'accounts:manage',
      'admin',
    ]) {
      expect(tokens, `unsafe default scope: ${scope}`).not.toContain(scope);
    }
  });

  it('has no duplicate scopes', () => {
    expect(new Set(tokens).size).toBe(tokens.length);
  });
});

describe('requestedScope()', () => {
  const original = process.env['STACK_OAUTH_SCOPE'];
  afterEach(() => {
    if (original === undefined) delete process.env['STACK_OAUTH_SCOPE'];
    else process.env['STACK_OAUTH_SCOPE'] = original;
  });

  it('returns the reviewed default when STACK_OAUTH_SCOPE is unset', () => {
    delete process.env['STACK_OAUTH_SCOPE'];
    expect(requestedScope()).toBe(DEFAULT_SCOPE);
  });

  it('honors a read-only STACK_OAUTH_SCOPE override', () => {
    const readOnly = 'passports:read agents:read services:read audit:read';
    process.env['STACK_OAUTH_SCOPE'] = readOnly;
    expect(requestedScope()).toBe(readOnly);
    expect(requestedScope()).not.toContain('passports:write');
  });
});
