import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { requirePartner } from './require-platform.js';

/**
 * Structural + behavioural test for the partner scope.
 *
 * The /v1/partner/* routes are mounted via Fastify encapsulation with
 * [auth, requirePartner] preHandler chain — the gate is the URL, not
 * a developer choice. This test asserts:
 *
 *   1. requirePartner refuses non-partner callers (fail-closed).
 *   2. The partner route file declares only /v1/partner/* paths.
 *   3. The partner route file does NOT call createAuthMiddleware
 *      directly (the encapsulation block provides auth).
 *   4. Every sub-resource handler calls partnerTenants.assertTenantOwnership
 *      before dispatching to the underlying service — partner cannot
 *      operate on a non-owned tenant even if they know the id.
 */

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROUTE_FILE = join(__dirname, '..', 'routes', 'partner.ts');

function fakeRequest(overrides: Record<string, unknown>) {
  return overrides as unknown as Parameters<typeof requirePartner>[0];
}
const fakeReply = {} as unknown as Parameters<typeof requirePartner>[1];

describe('requirePartner middleware', () => {
  it('passes when isPartner = true', async () => {
    await expect(
      requirePartner(fakeRequest({ isPartner: true }), fakeReply),
    ).resolves.toBeUndefined();
  });

  it('refuses when isPartner = false', async () => {
    await expect(
      requirePartner(fakeRequest({ isPartner: false }), fakeReply),
    ).rejects.toThrow(/partner/);
  });

  it('refuses when isPartner is undefined (fail-closed)', async () => {
    await expect(
      requirePartner(fakeRequest({}), fakeReply),
    ).rejects.toThrow(/partner/);
  });

  it('refuses when only isPlatformStaff = true (platform-staff is NOT partner)', async () => {
    await expect(
      requirePartner(
        fakeRequest({ isPlatformStaff: true, isPartner: false }),
        fakeReply,
      ),
    ).rejects.toThrow(/partner/);
  });

  it('refuses when isPartner is truthy-but-not-true', async () => {
    await expect(
      requirePartner(fakeRequest({ isPartner: 'yes' }), fakeReply),
    ).rejects.toThrow(/partner/);
  });
});

describe('routes/partner.ts — structural invariants', () => {
  const source = readFileSync(ROUTE_FILE, 'utf8');

  it('does NOT import createAuthMiddleware (auth comes from encapsulation block)', () => {
    expect(source).not.toContain('createAuthMiddleware');
  });

  it('only adds the stricter administrator guard to inherited authentication', () => {
    // Fastify runs inherited hooks before route hooks. Replacing an account's
    // key, signing configuration and the rotation of a signing secret add an
    // administrator gate; partner-signing-secret.test.ts verifies non-partners
    // remain denied through that composed chain.
    expect(source.match(/preHandler\s*:\s*\w+/g)).toEqual([
      'preHandler: requireOperatorAdmin',
      'preHandler: requireOperatorAdmin',
      'preHandler: requireOperatorAdmin',
    ]);
  });

  it('every declared path starts with /v1/partner/', () => {
    // Find all 'app.<method>(...path...)' route declarations and assert
    // the path string starts with /v1/partner/.
    const pathPattern = /app\.(post|get|delete|patch|put)<.*?>\s*\(\s*'([^']+)'/g;
    const paths: string[] = [];
    let match: RegExpExecArray | null;
    while ((match = pathPattern.exec(source)) !== null) {
      paths.push(match[2]!);
    }
    // Also match the non-generic shape (no <...> arg).
    const simplePathPattern = /app\.(post|get|delete|patch|put)\s*\(\s*'([^']+)'/g;
    while ((match = simplePathPattern.exec(source)) !== null) {
      paths.push(match[2]!);
    }
    expect(paths.length).toBeGreaterThan(0);
    for (const p of paths) {
      expect(p).toMatch(/^\/v1\/partner\//);
    }
  });

  it('sub-resource handlers call assertTenantOwnership before mutating', () => {
    // An earlier change ships four sub-resource routes under :account_id:
    //   POST   /v1/partner/accounts/:account_id/inbound-webhooks
    //   GET    /v1/partner/accounts/:account_id/inbound-webhooks
    //   DELETE /v1/partner/accounts/:account_id/inbound-webhooks/:wh_id
    //   POST   /v1/partner/accounts/:account_id/passports/issue
    // Each must call assertTenantOwnership before dispatching. Plus
    // the PartnerTenantService has its own assertTenantOwnership
    // method definition (one). v1 baseline = 4 handler calls.
    // (Path literals match twice in the typed-route form: once in
    // the generic <{Params}> declaration, once in the actual route
    // string — so we count by handler shape, not path occurrence.)
    const ownershipChecks = source.match(/assertTenantOwnership\s*\(/g) ?? [];
    expect(ownershipChecks.length).toBeGreaterThanOrEqual(4);
  });
});
