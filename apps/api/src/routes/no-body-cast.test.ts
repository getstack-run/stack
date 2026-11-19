import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { findRequestInputCasts, requestInputCasts } from './no-body-cast.checks.js';

/**
 * Route handlers parse what a client sends; they never cast it (the rule, and why, are in
 * `no-body-cast.checks.ts`). This runs it over the engine's routes; the deployment's own test
 * runs it over its own.
 */

const ROUTES_DIR = dirname(fileURLToPath(import.meta.url));

describe('route inputs are parsed, not cast', () => {
  it('finds the casts the rule forbids', () => {
    const source = [
      'const a = request.body as { a: string };',
      'const b = (request.query as Record<string, string>).x;',
      'const c = <number>request.params;',
      'const d = req.body as unknown as string;',
      "const e = request['body'] as string;",
    ].join('\n');
    expect(findRequestInputCasts('fixture.ts', source)).toEqual([1, 2, 3, 4, 5]);
  });

  it('leaves parsing, typed access and unrelated casts alone', () => {
    const source = [
      'const a = Schema.parse(request.body);',
      'const b: unknown = request.body;',
      'const c = other.body as string;',
      'const d = request.headers as Record<string, string>;',
      'const e = request.ip as string;',
    ].join('\n');
    expect(findRequestInputCasts('fixture.ts', source)).toEqual([]);
  });

  it('has no cast of request.body, request.query or request.params in a route module', () => {
    expect(requestInputCasts(ROUTES_DIR)).toEqual([]);
  });
});
