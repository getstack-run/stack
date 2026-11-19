import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { defaultConnectionScopes } from '../utils/constraints.js';
import { engineSeedRows, grantable } from './catalogue-connection-scopes.checks.js';

/**
 * Every service a customer can connect from the catalogue ends up with a connection whose scopes let an agent be granted
 * access. A grant needs at least one scope that is within the connection's, so a connection that stores an empty list
 * can never be granted to anyone (the "no grantable scopes" a customer met in quickstart, for a key-only service such as
 * Anthropic whose catalogue row lists none). This file checks the engine's own seed; the hosted deployment's catalogue is
 * checked by the hosted test of the same name.
 */

describe('connections made from the engine seed have grantable scopes', () => {
  const rows = engineSeedRows();

  it('reads the seed', () => {
    expect(rows.length).toBeGreaterThan(0);
  });

  it.each(rows.map((r) => [r.provider, r.scopes] as const))('%s: a connect with no scopes stores a grantable list', (_provider, scopes) => {
    expect(grantable(defaultConnectionScopes(scopes))).toBe(true);
  });

  it('a service that lists scopes keeps them, and a list the caller names is never replaced', () => {
    expect(defaultConnectionScopes(['read', 'write'])).toEqual(['read', 'write']);
    expect(defaultConnectionScopes([])).toEqual(['*']);
  });

  it('the connect path stores the default, not the bare catalogue list', () => {
    const connect = readFileSync(new URL('../../../vault/src/services/service-connection/connect.ts', import.meta.url), 'utf8');
    expect(connect).toContain('input.scopes ?? defaultConnectionScopes(service.scopes_available)');
    expect(connect).not.toMatch(/input\.scopes \?\? service\.scopes_available/);
  });
});
