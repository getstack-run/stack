import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Rate limits on the routes that unlimited counts require.
 *
 * Two decisions in the pricing model leave a route with no natural ceiling,
 * and each needs one drawn somewhere else:
 *
 *   - Agents are unlimited on every tier, and registering one is never
 *     metered, so `POST /v1/agents/register` has nothing counting it.
 *   - Audit export is contractually never metered — the published terms
 *     promise it works on a delinquent account — and it returns up to 50,000
 *     rows per call, so `GET /v1/audit/export` is free bulk egress.
 *
 * A rate limit is the honest ceiling for both: it bounds a script without
 * gating a customer. This test exists because the limit is invisible in
 * normal use, which makes it exactly the kind of line someone deletes while
 * refactoring a route signature and never notices.
 */

function route(name: string): string {
  return readFileSync(join(here, name), 'utf8');
}

/** The route declaration for `path`, up to the start of its handler body. */
function declarationOf(src: string, path: string): string {
  const at = src.indexOf(`'${path}'`);
  if (at === -1) return '';
  const handlerAt = src.indexOf('async (', at);
  return src.slice(at, handlerAt === -1 ? at + 400 : handlerAt);
}

describe('rate limits on the ungated routes', () => {
  it('agent registration carries a per-route rate limit', () => {
    const decl = declarationOf(route('agents.ts'), '/v1/agents/register');

    expect(decl, 'POST /v1/agents/register must declare config.rateLimit').toMatch(
      /config:\s*\{\s*rateLimit:/,
    );
  });

  it('audit export carries a per-route rate limit', () => {
    const decl = declarationOf(route('audit.ts'), '/v1/audit/export');

    expect(decl, 'GET /v1/audit/export must declare config.rateLimit').toMatch(
      /config:\s*\{\s*rateLimit:/,
    );
  });

  it('audit export is rate-limited instead of metered, never both', () => {
    // If this ever fails it means someone reached for the meter to solve the
    // egress problem, which breaks a promise in the published terms.
    expect(route('audit.ts')).not.toMatch(/\b(?:meterAction|enforceOverage)\s*\(/);
  });
});
