import { describe, it, expect, afterEach } from 'vitest';
import { OAUTH_MCP_DEFAULT_SCOPES, OAUTH_SCOPES } from '@stack/shared';
import { CLI_DEFAULT_OAUTH_SCOPES, DEFAULT_SCOPE, requestedScope } from './auth.js';

// The CLI's default sign-in is the same set as a person's sign-in from an MCP
// client. Team, credential, payout and administration scopes stay opt-in.

const CANONICAL = new Set<string>(OAUTH_SCOPES as readonly string[]);
const tokens = [...CLI_DEFAULT_OAUTH_SCOPES];

describe('DEFAULT_SCOPE', () => {
  it('is a subset of the API OAUTH_SCOPES catalog (no typos, no wildcards)', () => {
    const unknown = tokens.filter((t) => !CANONICAL.has(t));
    expect(unknown, `unknown scopes: ${unknown.join(', ')}`).toEqual([]);
  });

  it('equals the default an MCP client requests for /mcp, in the same order', () => {
    expect(tokens).toEqual([...OAUTH_MCP_DEFAULT_SCOPES]);
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
      'accounts:manage',
      'account:write',
      'billing:write',
      'governance:write',
      'security-events:write',
    ]) {
      expect(tokens, `missing ${scope}`).toContain(scope);
    }
  });

  it('keeps team, credential, payout and administration scopes opt-in', () => {
    for (const scope of [
      'team:write',
      'oauth-apps:read',
      'oauth-apps:write',
      'cmek:read',
      'cmek:write',
      'credentials:read',
      'credentials:write',
      'payouts:read',
      'payouts:write',
      'identity:write',
      'authority:write',
      'skills:publish',
      'partner:write',
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
