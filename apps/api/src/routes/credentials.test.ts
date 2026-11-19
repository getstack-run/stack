import { describe, it, expect, vi } from 'vitest';
import { ForbiddenError } from '@stack/shared';
import {
  assertNotProxyOnlyAgent,
  assertNotTenantCredentialRead,
  markCredentialResponseUncacheable,
} from './credentials.js';

// D1 — the raw-credential-leak guard. These are pure-unit tests of the
// decision function (no dev stack). The behavioral contract is: every agent
// principal is denied a raw credential read, unconditionally.
// Operator/member contexts (no agentId) proceed to the route's owner/admin
// authorization gate.

describe('assertNotProxyOnlyAgent (raw agent credential boundary)', () => {
  it.each(['proxy_only', 'proxy_preferred', 'direct', 'future_mode'])(
    'DENIES an agent regardless of legacy credential_access=%s',
    async (credentialAccess) => {
      await expect(
        assertNotProxyOnlyAgent({
          agentId: 'agt_x',
          operatorId: 'op_1',
          credential_access: credentialAccess,
        } as never),
      ).rejects.toBeInstanceOf(ForbiddenError);
    },
  );

  it('ALLOWS an operator/member context (no agentId)', async () => {
    await expect(
      assertNotProxyOnlyAgent({ operatorId: 'op_1' }),
    ).resolves.toBeUndefined();
  });

  it('is HEADER-INDEPENDENT — denies a proxy_only agent regardless of any passport header', async () => {
    // The function signature takes no headers; this test documents intent —
    // the same agent principal is denied whether or not an X-Passport-Token
    // would have been present. (The route calls this BEFORE the header-gated
    // runPassportChecks, so omitting the header cannot bypass it.)
    await expect(
      assertNotProxyOnlyAgent({ agentId: 'agt_x', operatorId: 'op_1' }),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });
});

describe('credential reveal response policy', () => {
  it('marks a retained human reveal private and uncacheable', () => {
    const reply = { header: vi.fn() };
    reply.header.mockReturnValue(reply);

    markCredentialResponseUncacheable(reply as never);

    expect(reply.header).toHaveBeenCalledWith('Cache-Control', 'private, no-store');
    expect(reply.header).toHaveBeenCalledWith('Pragma', 'no-cache');
    expect(reply.header).toHaveBeenCalledWith('Expires', '0');
  });

  it('keeps both raw-credential routes behind the owner/admin gate', async () => {
    const source = await import('node:fs/promises').then(({ readFile }) =>
      readFile(new URL('./credentials.ts', import.meta.url), 'utf8'),
    );
    const routeBlocks = source.match(/app\.get<[\s\S]*?\n {2}\);/g) ?? [];
    expect(routeBlocks).toHaveLength(2);
    for (const route of routeBlocks) {
      expect(route).toContain('preHandler: [auth, requireOperatorAdmin]');
      expect(route).toContain('markCredentialResponseUncacheable(reply)');
    }
  });
});

// a white-label tenant's key is held by its partner. Tenants use the
// proxy only; a raw (decrypted) credential read would hand the partner every
// tenant's provider tokens.
describe('assertNotTenantCredentialRead (white-label tenant boundary)', () => {
  it('DENIES a white-label tenant', async () => {
    await expect(
      assertNotTenantCredentialRead({ operatorId: 'op_t', billingAccount: { isTenant: true } } as never),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('ALLOWS an ordinary operator', async () => {
    await expect(
      assertNotTenantCredentialRead({ operatorId: 'op_1', billingAccount: { isTenant: false } } as never),
    ).resolves.toBeUndefined();
  });

  it('fails closed when the billing account was never resolved', async () => {
    await expect(
      assertNotTenantCredentialRead({ operatorId: 'op_1' } as never),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('is enforced on both raw-credential routes before any retrieval', async () => {
    const source = await import('node:fs/promises').then(({ readFile }) =>
      readFile(new URL('./credentials.ts', import.meta.url), 'utf8'),
    );
    const routeBlocks = source.match(/app\.get<[\s\S]*?\n {2}\);/g) ?? [];
    expect(routeBlocks).toHaveLength(2);
    for (const route of routeBlocks) {
      const guard = route.indexOf('await assertNotTenantCredentialRead(request)');
      const retrieve = route.search(/retrieveCredential(ByConnectionId)?\(|resolveProxyConnection\(/);
      expect(guard).toBeGreaterThan(-1);
      expect(retrieve).toBeGreaterThan(guard);
    }
  });
});
