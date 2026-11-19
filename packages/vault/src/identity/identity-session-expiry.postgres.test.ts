import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { eq, inArray } from 'drizzle-orm';
import { NotFoundError, createDb, identityVerificationSessions, operators, type Database } from '@stack/shared';
import { IdentityVerificationService } from './identity-verification-service.js';
import { IdentityProviderRegistry } from './provider-registry.js';
import { resolveVaultFixtureDatabaseUrl } from '../test/dedicated-test-database.js';

/**
 * A verification session nobody finished ends as `expired` at its time: the sweep marks it once, a read says so even
 * before the sweep ran, and it can no longer be completed. Only sessions already past their time are touched, so the
 * other suites' live sessions on the shared database are left alone.
 */

const DATABASE_URL = resolveVaultFixtureDatabaseUrl();
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('identity verification sessions end as expired', () => {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
  const operatorId = `op_idexpiry_${suffix}`;
  const otherOperatorId = `op_idexpiry_other_${suffix}`;
  let db: Database;
  let verification: IdentityVerificationService;
  let seq = 0;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    verification = new IdentityVerificationService(
      db,
      new IdentityProviderRegistry(),
      { findProviderByKey: async (key: string) => ({ id: `idp_${key}` }) } as never,
      { encrypt: async (value: string) => ({ ciphertext: Buffer.from(value).toString('base64'), keyRef: 'test' }) } as never,
    );
    await db.insert(operators).values([
      { id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` },
      { id: otherOperatorId, email: `${otherOperatorId}@test.invalid`, api_key_hash: `hash_${otherOperatorId}` },
    ]);
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(identityVerificationSessions).where(inArray(identityVerificationSessions.operator_id, [operatorId, otherOperatorId]));
    await db.delete(operators).where(inArray(operators.id, [operatorId, otherOperatorId]));
  });

  async function session(over: { expiresInMs: number; status?: string; owner?: string }) {
    seq += 1;
    const id = `ses_idexpiry_${suffix}_${seq}`;
    await db.insert(identityVerificationSessions).values({
      id,
      operator_id: over.owner ?? operatorId,
      provider_key: 'stripe_identity',
      session_ref: `vs_idexpiry_${suffix}_${seq}`,
      status: over.status ?? 'pending',
      requested_claims: ['verified_identity'],
      expires_at: new Date(Date.now() + over.expiresInMs),
    });
    return id;
  }
  const statusOf = async (id: string) =>
    (await db.select({ status: identityVerificationSessions.status }).from(identityVerificationSessions).where(eq(identityVerificationSessions.id, id)))[0]!.status;

  it('reads a pending session past its time as expired before the sweep, and the sweep marks it once', async () => {
    const lapsed = await session({ expiresInMs: -60_000 });
    const live = await session({ expiresInMs: 600_000 });
    const done = await session({ expiresInMs: -60_000, status: 'completed' });

    const read = await verification.getSession(operatorId, lapsed);
    expect(read).toMatchObject({ session_id: lapsed, provider_key: 'stripe_identity', status: 'expired', requested_claims: ['verified_identity'], completed_at: null });
    expect(await statusOf(lapsed)).toBe('pending');

    expect(await verification.expireDue(new Date(), 100_000)).toBeGreaterThanOrEqual(1);
    expect(await statusOf(lapsed)).toBe('expired');
    expect(await statusOf(live)).toBe('pending');
    expect(await statusOf(done)).toBe('completed');
    expect((await verification.getSession(operatorId, live)).status).toBe('pending');
    expect((await verification.getSession(operatorId, done)).status).toBe('completed');

    // The next pass finds nothing of ours to move, and an expired session is not offered as pending.
    await verification.expireDue(new Date(), 100_000);
    expect(await statusOf(lapsed)).toBe('expired');
    expect((await verification.getPendingSessions(operatorId)).map((s) => s.id)).toEqual([live]);
  });

  it('an expired session cannot be completed, even by its provider\'s webhook', async () => {
    const lapsed = await session({ expiresInMs: -60_000 });
    await verification.expireDue(new Date(), 100_000);
    const row = (await db.select().from(identityVerificationSessions).where(eq(identityVerificationSessions.id, lapsed)))[0]!;
    expect(await verification.completeBySessionRef('stripe_identity', row.session_ref)).toEqual({ success: false, reason: 'no_pending_session' });
  });

  it('reads another operator\'s session, or an unknown id, as absent', async () => {
    const theirs = await session({ expiresInMs: 600_000, owner: otherOperatorId });
    await expect(verification.getSession(operatorId, theirs)).rejects.toBeInstanceOf(NotFoundError);
    await expect(verification.getSession(operatorId, `ses_missing_${suffix}`)).rejects.toBeInstanceOf(NotFoundError);
  });
});
