import { describe, expect, it } from 'vitest';
import {
  OAUTH_DIRECTORY_DEFAULT_SCOPES,
  OAUTH_MCP_DEFAULT_SCOPES,
  OAUTH_SCOPES,
} from '@stack/shared';
import { enforceOAuthRouteScope, ENGINE_ROUTE_SCOPES, ENGINE_ROUTE_ALSO_REQUIRED_SCOPES } from './oauth-scope.js';
import { declaredRouteKeys, fakeReply, readScopeLiteral } from './oauth-scope.checks.js';
import { engineRoutes } from '../test/route-scan.js';

describe('OAuth route scope ceiling', () => {
  it('classifies every route the engine declares and contains no dead entries', () => {
    const declared = declaredRouteKeys(engineRoutes);
    const mapped = new Set(Object.keys(ENGINE_ROUTE_SCOPES));
    expect([...declared].filter((key) => !mapped.has(key)), 'unclassified routes').toEqual([]);
    expect([...mapped].filter((key) => !declared.has(key)), 'dead scope-map entries').toEqual([]);
  });

  it('uses only scopes in the public OAuth vocabulary', () => {
    const known = new Set<string>(OAUTH_SCOPES);
    const unknown = Object.values(ENGINE_ROUTE_SCOPES)
      .filter((scope): scope is NonNullable<typeof scope> => scope !== null)
      .filter((scope) => !known.has(scope));
    expect(unknown).toEqual([]);
  });

  it('keeps each bundled client within the catalog without granting the whole operator surface', () => {
    const known = new Set<string>(OAUTH_SCOPES);
    const cliScopes = readScopeLiteral(
      '../../../../packages/cli/src/auth.ts',
      'CLI_DEFAULT_OAUTH_SCOPES',
    );
    const sdkScopes = readScopeLiteral(
      '../../../../packages/sdk/src/browser-bootstrap.ts',
      'SDK_DEFAULT_OAUTH_SCOPES',
    );
    // apps/mcp-server/src/oauth-scopes.ts re-exports these @stack/shared sets.
    const mcpScopes: string[] = [...OAUTH_MCP_DEFAULT_SCOPES];
    const directoryScopes: string[] = [...OAUTH_DIRECTORY_DEFAULT_SCOPES];
    for (const clientScopes of [
      cliScopes,
      sdkScopes,
      mcpScopes,
      directoryScopes,
    ]) {
      expect(clientScopes.filter((scope) => !known.has(scope))).toEqual([]);
      expect(clientScopes).not.toContain('admin');
      expect(clientScopes.length).toBeLessThan(OAUTH_SCOPES.length - 1);
    }
    expect(sdkScopes).not.toEqual(cliScopes);
  });

  it('classifies connection verification as a write because it calls out and changes state', () => {
    expect(ENGINE_ROUTE_SCOPES['POST /v1/services/:id/verify']).toBe('services:write');
  });

  it('requires agent scopes for Fleet administration and rejects agent-proof routes for OAuth', () => {
    expect(ENGINE_ROUTE_SCOPES['GET /v1/fleets']).toBe('agents:read');
    expect(ENGINE_ROUTE_SCOPES['POST /v1/fleets']).toBe('agents:write');
    expect(ENGINE_ROUTE_SCOPES['POST /v1/fleets/:id/revoke']).toBe('agents:write');
    for (const key of [
      'POST /v1/fleets/session',
      'POST /v1/fleets/:id/enroll',
      'POST /v1/fleets/:id/workload/enroll',
      'POST /v1/missions/:id/renew',
    ]) {
      expect(ENGINE_ROUTE_SCOPES[key]).toBeNull();
    }
  });

  it('lets an OAuth bearer start a Mission in one call only when it holds both scopes the two separate calls need', () => {
    const route = 'POST /v1/missions/start';
    expect(ENGINE_ROUTE_SCOPES[route]).toBe('missions:write');
    expect(ENGINE_ROUTE_SCOPES['POST /v1/missions']).toBe('missions:write');
    expect(ENGINE_ROUTE_SCOPES['POST /v1/passports/issue']).toBe('passports:write');
    expect(ENGINE_ROUTE_ALSO_REQUIRED_SCOPES[route]).toEqual(['passports:write']);
    const attempt = (scope: string) => {
      const reply = fakeReply();
      enforceOAuthRouteScope({ method: 'POST', routeOptions: { url: '/v1/missions/start' }, oauthScope: scope } as never, reply as never);
      return reply;
    };
    expect(attempt('missions:write passports:write').send).not.toHaveBeenCalled();
    for (const [scope, missing] of [
      ['missions:write', 'passports:write'],
      ['passports:write', 'missions:write'],
      ['missions:read passports:read', 'missions:write passports:write'],
      ['', 'missions:write passports:write'],
    ] as const) {
      const reply = attempt(scope);
      expect(reply.status, scope).toHaveBeenCalledWith(403);
      expect(reply.header).toHaveBeenCalledWith('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${missing}"`);
      expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ error: 'insufficient_scope', scope: missing }));
    }
  });

  it('keeps the all-of table to routes the ceiling maps, with scopes in the public vocabulary, and moves no other route', () => {
    const known = new Set<string>(OAUTH_SCOPES);
    for (const [key, scopes] of Object.entries(ENGINE_ROUTE_ALSO_REQUIRED_SCOPES)) {
      expect(ENGINE_ROUTE_SCOPES[key], key).toBeTruthy();
      expect(scopes.filter((scope) => !known.has(scope)), key).toEqual([]);
    }
    expect(Object.keys(ENGINE_ROUTE_ALSO_REQUIRED_SCOPES)).toEqual(['POST /v1/missions/start']);
    // The fleet's renewal stays closed to every OAuth token.
    expect(ENGINE_ROUTE_SCOPES['POST /v1/missions/:id/renew']).toBeNull();
  });

  it('keeps provider signing-secret setup closed to OAuth even with every scope', () => {
    const url = '/v1/operator/inbound-webhooks/:id/provider-signing-secret';
    expect(ENGINE_ROUTE_SCOPES[`PUT ${url}`]).toBeNull();
    const reply = fakeReply();
    enforceOAuthRouteScope({
      method: 'PUT', routeOptions: { url }, oauthScope: OAUTH_SCOPES.join(' '),
    } as never, reply as never);
    expect(reply.status).toHaveBeenCalledWith(403);
  });

  it('gives the owner\'s sign-in from a chat the owner\'s scopes, never to the directory, and keeps erasing the account closed to OAuth', () => {
    const mcp = new Set<string>(OAUTH_MCP_DEFAULT_SCOPES);
    const directory = new Set<string>(OAUTH_DIRECTORY_DEFAULT_SCOPES);
    for (const scope of ['account:write', 'billing:write', 'governance:write', 'security-events:write']) {
      expect(mcp.has(scope), `${scope} in /mcp`).toBe(true);
      expect(directory.has(scope), `${scope} in /directory`).toBe(false);
    }
    // account:write is in the default sign-in, so what it reaches must not include these two.
    for (const key of ['DELETE /v1/operators/me', 'POST /v1/operators/me/email-change']) {
      expect(ENGINE_ROUTE_SCOPES[key], key).toBeNull();
      const [method, url] = key.split(' ') as [string, string];
      const reply = fakeReply();
      enforceOAuthRouteScope({
        method, routeOptions: { url }, oauthScope: OAUTH_SCOPES.join(' '),
      } as never, reply as never);
      expect(reply.status, key).toHaveBeenCalledWith(403);
    }
    for (const route of ['DELETE /v1/operators/me/mcp-sessions/:familyId', 'PATCH /v1/operators/me/identity-settings']) {
      expect(ENGINE_ROUTE_SCOPES[route], route).toBe('account:write');
    }
  });

  it('requires mission read scope for mission passport history', () => {
    expect(ENGINE_ROUTE_SCOPES['GET /v1/missions/:id/passports']).toBe('missions:read');
    for (const [scope, admitted] of [['missions:read', true], ['passports:read', false]] as const) {
      const reply = fakeReply();
      enforceOAuthRouteScope({
        method: 'GET', routeOptions: { url: '/v1/missions/:id/passports' }, oauthScope: scope,
      } as never, reply as never);
      if (admitted) expect(reply.send).not.toHaveBeenCalled();
      else expect(reply.status).toHaveBeenCalledWith(403);
    }
  });

  it('does nothing for non-OAuth principals', () => {
    const reply = fakeReply();
    enforceOAuthRouteScope({
      method: 'GET',
      routeOptions: { url: '/v1/audit' },
    } as never, reply as never);
    expect(reply.send).not.toHaveBeenCalled();
  });

  it('cannot be disabled for an OAuth principal', () => {
    const reply = fakeReply();
    enforceOAuthRouteScope({
      method: 'GET',
      routeOptions: { url: '/v1/audit' },
      oauthScope: '',
    } as never, reply as never);
    expect(reply.status).toHaveBeenCalledWith(403);
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({
      error: 'insufficient_scope',
    }));
  });

  it('admits a mapped route only when the exact required scope is present', () => {
    const reply = fakeReply();
    enforceOAuthRouteScope({
      method: 'GET',
      routeOptions: { url: '/v1/audit' },
      oauthScope: 'agents:read audit:read',
    } as never, reply as never);
    expect(reply.send).not.toHaveBeenCalled();
  });

  it('returns the OAuth insufficient_scope response without upgrading legacy scopes', () => {
    const reply = fakeReply();
    enforceOAuthRouteScope({
      method: 'GET',
      routeOptions: { url: '/v1/audit' },
      oauthScope: 'agents:read',
    } as never, reply as never);
    expect(reply.status).toHaveBeenCalledWith(403);
    expect(reply.header).toHaveBeenCalledWith(
      'WWW-Authenticate',
      'Bearer error="insufficient_scope", scope="audit:read"',
    );
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({
      error: 'insufficient_scope',
      scope: 'audit:read',
    }));
  });

  it('fails closed for an unmapped route or a route owned by another auth protocol', () => {
    for (const url of ['/v1/future-route', '/oauth/token']) {
      const reply = fakeReply();
      enforceOAuthRouteScope({
        method: 'POST',
        routeOptions: { url },
        oauthScope: OAUTH_SCOPES.join(' '),
      } as never, reply as never);
      expect(reply.status).toHaveBeenCalledWith(403);
      expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({
        error: 'insufficient_scope',
      }));
    }
  });
  it('keeps provider OAuth and the operator-recovery routes closed to OAuth', () => {
    for (const key of [
      'POST /internal/provider-oauth/authorize',
      'POST /v1/dashboard/proxy/operations/get',
      'POST /v1/proxy/operations/reconcile',
      'POST /v1/proxy/operations/authorize-replacement',
    ]) {
      expect(ENGINE_ROUTE_SCOPES[key]).toBeNull();
      const separator = key.indexOf(' ');
      const reply = fakeReply();
      enforceOAuthRouteScope({
        method: key.slice(0, separator),
        routeOptions: { url: key.slice(separator + 1) },
        oauthScope: OAUTH_SCOPES.join(' '),
      } as never, reply as never);
      expect(reply.status).toHaveBeenCalledWith(403);
    }
  });

});
