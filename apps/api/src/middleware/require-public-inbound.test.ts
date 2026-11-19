import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Structural test for the public inbound webhook receiver.
 *
 * The /v1/inbound/:provider/:slug route is mounted in the public-no-auth
 * scope by design — slug + HMAC IS the auth, NOT a Bearer key. This
 * test asserts the route file does NOT regress into operator scope and
 * preserves the load-bearing primitives:
 *
 *   - No import of createAuthMiddleware (or any auth-resolving helper)
 *   - Exactly one app.register call (the encapsulated content-type parser)
 *   - removeContentTypeParser + addContentTypeParser with parseAs:'buffer'
 *     (required for HMAC verification over the raw bytes)
 *   - Path starts with /v1/inbound/
 *
 * The structural test is static — reads the route file as text and
 * asserts substring presence/absence. Catches refactors that quietly
 * lose the gate or the parser scoping.
 */

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROUTE_FILE = join(__dirname, '..', 'routes', 'inbound.ts');

describe('require-public-inbound — structural invariants', () => {
  const source = readFileSync(ROUTE_FILE, 'utf8');

  it('does NOT import createAuthMiddleware', () => {
    expect(source).not.toContain('createAuthMiddleware');
  });

  it('does NOT import requireOperatorAdmin or requirePlatformStaff', () => {
    expect(source).not.toContain('requireOperatorAdmin');
    expect(source).not.toContain('requirePlatformStaff');
  });

  it('does NOT declare per-route preHandler', () => {
    // The route is mounted in the public-no-auth scope. Adding a
    // preHandler here would change the auth contract silently.
    expect(source).not.toMatch(/preHandler\s*:/);
  });

  it('declares exactly one app.register block for the encapsulated parser', () => {
    const matches = source.match(/app\.register\(/g) ?? [];
    expect(matches.length).toBe(1);
  });

  it('removes default JSON parser + adds buffer parser (HMAC needs raw bytes)', () => {
    expect(source).toContain("removeContentTypeParser('application/json')");
    expect(source).toContain("addContentTypeParser(");
    expect(source).toContain("parseAs: 'buffer'");
  });

  it('declares the canonical /v1/inbound/:provider/:slug path', () => {
    expect(source).toContain('/v1/inbound/:provider/:slug');
  });

  it('applies a Fastify route-level body size limit', () => {
    // 1 MB cap at the Fastify layer; constant defined in @stack/shared.
    expect(source).toContain('INBOUND_WEBHOOK_BODY_LIMIT_BYTES');
    expect(source).toContain('bodyLimit:');
  });

  it('applies a per-slug rate limit via Fastify rate-limit plugin', () => {
    expect(source).toContain('rateLimit');
    expect(source).toContain('keyGenerator');
  });

  it('delegates to services.inboundWebhooks.receive (NOT inline auth or logic)', () => {
    expect(source).toContain('services.inboundWebhooks.receive');
  });
});
