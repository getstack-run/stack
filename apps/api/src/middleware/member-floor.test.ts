import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { EngineRegistries } from '../config/registries.js';
import { API_SRC, apiSourceFiles } from '../test/route-scan.js';
import { ENGINE_MEMBER_ACTION_ALLOWLIST, enforceMemberFloor } from './member-floor.js';
import { allowlistProblems, authenticationPathsWithoutFloor, sessionFlowsWithoutFloor, type TableRoute } from './member-floor.checks.js';

// The gate under every route: a read-only member reads and does not act (middleware/member-floor.ts). The checks are in
// member-floor.checks.ts; the hosted deployment's own run is its coverage test.

const REFUSED = { statusCode: 403, message: 'This action requires standard access or higher' };

describe('the gate itself', () => {
  const services = { registries: new EngineRegistries() };
  const as = (method: string, route: string, role: string | undefined, memberId: string | undefined = role ? 'mem_1' : undefined) =>
    () => enforceMemberFloor(services, { method, route, memberId, memberRole: role });

  it('refuses a read-only member, and one whose role nobody knows, on every mutating method', () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(as(method, '/v1/anything/:id', 'readonly')).toThrowError(expect.objectContaining(REFUSED));
      expect(as(method, '/v1/anything/:id', 'some-future-role')).toThrowError(expect.objectContaining(REFUSED));
      expect(as(method, '/v1/anything/:id', undefined, 'mem_1')).toThrowError(expect.objectContaining(REFUSED));
    }
  });

  it('refuses a request that names no method: unknown is not allowed', () => {
    expect(() => enforceMemberFloor(services, { method: undefined, route: '/v1/anything', memberId: 'mem_1', memberRole: 'readonly' })).toThrowError(expect.objectContaining(REFUSED));
    expect(() => enforceMemberFloor(services, { method: undefined, route: '/v1/anything', memberId: 'mem_1', memberRole: 'standard' })).not.toThrow();
  });

  it('refuses a route it could not name: unknown is not allowed', () => {
    expect(as('POST', '', 'readonly')).toThrowError(expect.objectContaining(REFUSED));
  });

  it('lets a read-only member read, and everyone else do everything', () => {
    for (const method of ['GET', 'HEAD', 'OPTIONS']) expect(as(method, '/v1/anything', 'readonly')).not.toThrow();
    for (const role of ['standard', 'admin']) {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) expect(as(method, '/v1/anything', role)).not.toThrow();
    }
    // No member: an owner's key or session, an agent, a Passport, a fleet session, a workload, staff.
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) expect(as(method, '/v1/anything', undefined, undefined)).not.toThrow();
  });

  it('lets a read-only member through only on the allowlist, by the method and the route pattern', () => {
    for (const key of Object.keys(ENGINE_MEMBER_ACTION_ALLOWLIST)) {
      const [method, route] = key.split(' ') as [string, string];
      expect(as(method, route, 'readonly'), key).not.toThrow();
    }
    expect(as('PUT', '/oauth/authorize', 'readonly')).toThrowError(expect.objectContaining(REFUSED));
    expect(as('POST', '/oauth/authorize/', 'readonly')).toThrowError(expect.objectContaining(REFUSED));
  });

  it('a deployment adds to the allowlist before the server listens and never after', () => {
    const own = new EngineRegistries();
    own.memberActionAllowlist.register('POST /v1/hosted/thing', 'reads: a reason a reviewer can check');
    expect(() => enforceMemberFloor({ registries: own }, { method: 'POST', route: '/v1/hosted/thing', memberId: 'm', memberRole: 'readonly' })).not.toThrow();
    expect(() => own.memberActionAllowlist.register('POST /oauth/authorize', 'again')).toThrow(/already has/);
    own.seal();
    expect(() => own.memberActionAllowlist.register('POST /v1/late', 'too late')).toThrow(/sealed/);
  });
});

describe('the gate is wired on every path a member arrives by', () => {
  it('runs in the shared authentication preHandler and in the enrollment ticket path, before the billing account', () => {
    expect(authenticationPathsWithoutFloor(readFileSync(join(API_SRC, 'middleware', 'auth.ts'), 'utf8'))).toEqual([]);
  });

  it('runs in every flow of the engine that reads the browser session itself', () => {
    const files = apiSourceFiles().filter((file) => !file.path.startsWith('hosted/'));
    expect(files.length).toBeGreaterThan(100);
    expect(sessionFlowsWithoutFloor(files)).toEqual([]);
  });

  it('notices an unwired path and an unwired flow (a control for the checks themselves)', () => {
    const unwired = [
      'export function createAuthMiddleware(services) {',
      '  return async function authenticate(request, reply) {',
      '    await authenticateCaller(request, reply);',
      '    await applyBillingAccount(services, request);',
      '  };',
      '}',
      'export function createEnrollmentAuthMiddleware(services) {',
      '  return async function enrollmentOrStandardAuth(request, reply) {',
      '    await applyMemberContext(services, request, id, op);',
      '    await applyBillingAccount(services, request);',
      '  };',
      '}',
    ].join('\n');
    expect(authenticationPathsWithoutFloor(unwired)).toHaveLength(2);
    expect(sessionFlowsWithoutFloor([
      { path: 'routes/new-flow.ts', text: 'const identity = await services.browserSessions.identity(session, operator);' },
      { path: 'routes/wired-flow.ts', text: 'const identity = await services.browserSessions.identity(s, o);\nenforceMemberFloorForSession(services, request, identity.member);' },
    ])).toEqual(['routes/new-flow.ts']);
  });
});

describe('the engine\'s allowlist names only real mutating routes, each with a reason', () => {
  let registered: TableRoute[] = [];
  beforeAll(async () => {
    process.env['OAUTH_ENABLED'] = 'true';
    const { collectRouteTable } = await import('../route-table.js');
    registered = await collectRouteTable(null);
  }, 300_000);

  it('every entry exists, mutates and says why', () => {
    expect(allowlistProblems(ENGINE_MEMBER_ACTION_ALLOWLIST, registered)).toEqual([]);
  });

  it('notices an entry for a route that does not exist, a read, or one with no reason (a control)', () => {
    const table = [{ method: 'POST', url: '/v1/a' }, { method: 'GET', url: '/v1/b' }];
    const reason = 'reads: something a reviewer can check';
    expect(allowlistProblems({ 'POST /v1/a': reason, 'POST /v1/gone': reason, 'GET /v1/b': reason }, table)).toEqual([
      'POST /v1/gone: names no route that is registered',
      'GET /v1/b: not a mutating METHOD /route entry',
    ]);
    expect(allowlistProblems({ 'POST /v1/a': '' }, table)).toEqual(['POST /v1/a: no reason (a route is allowed only for a reason a reviewer can check)']);
  });
});
