import { describe, expect, it } from 'vitest';
import {
  normalizeInteractiveOAuthScope,
  SDK_DEFAULT_OAUTH_SCOPE,
  SDK_DEFAULT_OAUTH_SCOPES,
} from './browser-bootstrap.js';

const scopes = [...SDK_DEFAULT_OAUTH_SCOPES];

describe('SDK interactive OAuth scope', () => {
  it('serializes the reviewed core runtime set exactly', () => {
    expect(SDK_DEFAULT_OAUTH_SCOPE).toBe(scopes.join(' '));
  });

  it('retains core agent-runtime calls', () => {
    for (const scope of [
      'passports:write',
      'agents:write',
      'services:read',
      'proxy:write',
      'audit:read',
    ]) {
      expect(scopes, `missing ${scope}`).toContain(scope);
    }
  });

  it('keeps management, secret and billing scopes opt-in', () => {
    for (const scope of [
      'account:write',
      'team:write',
      'oauth-apps:write',
      'cmek:write',
      'services:connect',
      'credentials:read',
      'billing:write',
      'payouts:write',
      'identity:write',
      'authority:write',
      'governance:write',
      'notifications:write',
      'security-events:write',
      'skills:publish',
      'admin',
    ]) {
      expect(scopes, `unsafe default scope: ${scope}`).not.toContain(scope);
    }
    expect(new Set(scopes).size).toBe(scopes.length);
  });

  it('normalizes an explicit opt-in without adding scopes', () => {
    expect(normalizeInteractiveOAuthScope('team:read  team:write team:read'))
      .toBe('team:read team:write');
    expect(() => normalizeInteractiveOAuthScope('   ')).toThrow(/at least one/);
  });
});
