import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { declaredRouteKeys } from './middleware/oauth-scope.checks.js';
import { ENGINE_ROUTE_SCOPES } from './middleware/oauth-scope.js';
import { REPO_ROOT, engineRoutes } from './test/route-scan.js';

// Every route the engine registers has an entry in spec/rest-api/openapi.json, and the document has no entry for a
// route that does not exist. Three independent readings of "which routes are there" have to agree: the routes the
// server registers (listed by registering them, `route-table.ts`), the route files read as text (the reading the OAuth
// scope ceiling is checked against) and the document. The document itself is generated
// (`node scripts/generate-spec.mjs`, checked in CI); this is the test that fails when a route is added and the
// document is not regenerated, and the one that fails when the generator misses a route.

interface OpenApi {
  paths: Record<string, Record<string, { operationId: string; security: unknown[]; 'x-stack-oauth-scope'?: string }>>;
}

const document = JSON.parse(readFileSync(join(REPO_ROOT, 'spec', 'rest-api', 'openapi.json'), 'utf8')) as OpenApi;
const documented = Object.entries(document.paths)
  .flatMap(([path, item]) => Object.keys(item).map((method) => `${method.toUpperCase()} ${path.replace(/\{([^}]+)\}/g, ':$1')}`))
  .sort();

describe('spec/rest-api/openapi.json covers every route the engine serves', () => {
  let registered: string[] = [];
  beforeAll(async () => {
    // The OAuth endpoints are registered when OAuth is on, as it is in a deployment that serves them.
    process.env['OAUTH_ENABLED'] = 'true';
    const { collectRouteTable } = await import('./route-table.js');
    registered = (await collectRouteTable(null)).map((route) => `${route.method} ${route.url}`).sort();
  }, 120_000);

  it('lists exactly the routes the server registers', () => {
    expect(registered.filter((key) => !documented.includes(key)), 'routes with no entry in the document').toEqual([]);
    expect(documented.filter((key) => !registered.includes(key)), 'entries for routes that do not exist').toEqual([]);
  });

  it('lists every route the route files declare, besides the engine entry\'s health check', () => {
    const declared = [...declaredRouteKeys(engineRoutes)];
    expect(declared.filter((key) => !documented.includes(key)), 'declared in a route file, not in the document').toEqual([]);
    expect(documented.filter((key) => !declared.includes(key)), 'in the document, declared in no route file').toEqual(['GET /health']);
  });

  it('gives every operation of the OAuth ceiling the scope the ceiling gives it', () => {
    for (const [path, item] of Object.entries(document.paths)) {
      for (const [method, operation] of Object.entries(item)) {
        const key = `${method.toUpperCase()} ${path.replace(/\{([^}]+)\}/g, ':$1')}`;
        const ceiling = ENGINE_ROUTE_SCOPES[key];
        if (ceiling === undefined) continue; // the health check has none
        expect(operation['x-stack-oauth-scope'] ?? 'none', key).toBe(ceiling ?? 'none');
      }
    }
  });

  it('has one operation id per operation and a security entry on every operation', () => {
    const ids = Object.values(document.paths).flatMap((item) => Object.values(item).map((operation) => operation.operationId));
    expect(new Set(ids).size).toBe(ids.length);
    for (const item of Object.values(document.paths)) {
      for (const operation of Object.values(item)) expect(Array.isArray(operation.security)).toBe(true);
    }
  });
});
