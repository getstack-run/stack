import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { createDb, identityVerificationSessions, operators, type Database } from '@stack/shared';
import { IdentityVerificationService } from './identity-verification-service.js';
import { IdentityProviderRegistry } from './provider-registry.js';
import type { IdentityVerificationProvider } from './types.js';
import { resolveVaultFixtureDatabaseUrl } from '../test/dedicated-test-database.js';

/**
 * Only the account owner's Stripe Identity verification marks the operator
 * verified. Members, authority ceremonies for other principals, sessions from
 * before the initiator was recorded, failed checks and other providers never do.
 */

const DATABASE_URL = resolveVaultFixtureDatabaseUrl();
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('owner identity verification marks the operator verified', () => {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
  const created: string[] = [];
  let db: Database;
  let sessionSeq = 0;
  let outcome = true;

  function provider(providerKey: string): IdentityVerificationProvider {
    return {
      providerKey,
      displayName: providerKey,
      claimTypes: ['verified_human'],
      supportedLayers: ['humanity'],
      assuranceLevel: 'high',
      initiate: vi.fn(async () => {
        sessionSeq += 1;
        return { session_ref: `vs_owner_${suffix}_${sessionSeq}`, expires_at: new Date(Date.now() + 600_000) };
      }),
      complete: vi.fn(async () => outcome
        ? {
            success: true,
            claims: [{
              claim_type: 'verified_human', layer: 'humanity' as const, assertion: '{}', assurance_level: 'high' as const,
              verified_at: new Date(), expires_at: new Date(Date.now() + 86_400_000), metadata: {},
            }],
          }
        : { success: false, claims: [] }),
    } as unknown as IdentityVerificationProvider;
  }

  let verification: IdentityVerificationService;

  beforeAll(() => {
    db = createDb(DATABASE_URL!);
    const registry = new IdentityProviderRegistry();
    registry.register(provider('stripe_identity'));
    registry.register(provider('cloudflare_turnstile'));
    verification = new IdentityVerificationService(
      db,
      registry,
      {
        findProviderByKey: async (key: string) => ({ id: `idp_${key}` }),
        createClaim: async (row: Record<string, unknown>) => row,
      } as never,
      { encrypt: async (value: string) => ({ ciphertext: Buffer.from(value).toString('base64'), keyRef: 'test' }) } as never,
    );
  });

  afterAll(async () => {
    for (const id of created) {
      await db.delete(identityVerificationSessions).where(eq(identityVerificationSessions.operator_id, id)).catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, id)).catch(() => undefined);
    }
  });

  async function operator(label: string) {
    const id = `op_ownerverify_${label}_${suffix}`;
    await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    created.push(id);
    return id;
  }

  async function verifiedAt(operatorId: string) {
    const [row] = await db.select({ at: operators.identity_verified_at }).from(operators).where(eq(operators.id, operatorId));
    return row?.at ?? null;
  }

  it('an owner-started Stripe Identity session sets identity_verified_at', async () => {
    outcome = true;
    const op = await operator('owner');
    const started = await verification.initiate(op, 'stripe_identity', ['verified_human'], undefined, undefined, 'owner');
    await verification.complete(op, 'stripe_identity', started.session_ref);
    expect(await verifiedAt(op)).toBeInstanceOf(Date);
  });

  it('the webhook path counts an owner session too, and a second verification keeps the first time', async () => {
    outcome = true;
    const op = await operator('webhook');
    const first = await verification.initiate(op, 'stripe_identity', ['verified_human'], undefined, undefined, 'owner');
    await verification.completeBySessionRef('stripe_identity', first.session_ref, op);
    const at = await verifiedAt(op);
    expect(at).toBeInstanceOf(Date);
    const second = await verification.initiate(op, 'stripe_identity', ['verified_human'], undefined, undefined, 'owner');
    await verification.complete(op, 'stripe_identity', second.session_ref);
    expect((await verifiedAt(op))?.getTime()).toBe(at!.getTime());
  });

  it.each([
    ['a member', 'member' as const, undefined],
    ['an authority ceremony', 'owner' as const, { kind: 'authority' as const, request_id: 'ar_fixture' }],
    ['an unrecorded initiator', undefined, undefined],
  ])('a session started by %s never verifies the operator', async (_label, initiatedBy, purpose) => {
    outcome = true;
    const op = await operator(`other${sessionSeq}`);
    const started = await verification.initiate(op, 'stripe_identity', ['verified_human'], undefined, purpose, initiatedBy);
    await verification.complete(op, 'stripe_identity', started.session_ref);
    expect(await verifiedAt(op)).toBeNull();
  });

  it('a failed check or another provider never verifies the operator', async () => {
    const failed = await operator('failed');
    outcome = false;
    const a = await verification.initiate(failed, 'stripe_identity', ['verified_human'], undefined, undefined, 'owner');
    await verification.complete(failed, 'stripe_identity', a.session_ref);
    expect(await verifiedAt(failed)).toBeNull();

    outcome = true;
    const turnstile = await operator('turnstile');
    const b = await verification.initiate(turnstile, 'cloudflare_turnstile', ['verified_human'], undefined, undefined, 'owner');
    await verification.completeWithToken(turnstile, 'cloudflare_turnstile', b.session_ref, 'token');
    expect(await verifiedAt(turnstile)).toBeNull();
  });
});
