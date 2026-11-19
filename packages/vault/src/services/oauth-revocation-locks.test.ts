import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createDb,
  oauthClients,
  oauthRefreshTokens,
  operatorErasureJobs,
  operators,
  teamMembers,
} from '@stack/shared';
import { eq, sql } from 'drizzle-orm';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { MemberRepository } from '../repositories/member-repo.js';
import { OperatorService } from './operator-service.js';
import { MemberService } from './member-service.js';
import { OperatorErasureService } from './operator-erasure-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('OAuth revocation locks', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_oauth_revoke_${suffix}`;
  const memberId = `mem_oauth_revoke_${suffix}`;
  const clientId = `oclient_oauth_revoke_${suffix}`;
  const operatorFamily = `rfam_operator_${suffix}`;
  const memberFamilies = [`rfam_member_a_${suffix}`, `rfam_member_b_${suffix}`];

  async function holdLock(value: string, namespace: number) {
    let release!: () => void;
    let held!: () => void;
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const heldPromise = new Promise<void>((resolve) => { held = resolve; });
    const lockPromise = db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${value}, ${namespace}))`);
      held();
      await releasePromise;
    });
    await heldPromise;
    return {
      async release() {
        release();
        await lockPromise;
      },
    };
  }

  async function settledWithin(promise: Promise<unknown>, milliseconds = 100) {
    return Promise.race([
      promise.then(() => true),
      new Promise<false>((resolve) => setTimeout(() => resolve(false), milliseconds)),
    ]);
  }

  beforeAll(async () => {
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@oauth-test.invalid`,
      tier: 'business',
      api_key_hash: `hash_${suffix}`,
    } as typeof operators.$inferInsert);
    await db.insert(teamMembers).values({
      id: memberId,
      operator_id: operatorId,
      email: `${memberId}@oauth-test.invalid`,
      name: 'OAuth revoke test',
      role: 'standard',
      status: 'active',
    });
    await db.insert(oauthClients).values({
      id: clientId,
      client_type: 'public',
      client_name: 'OAuth revoke test',
      redirect_uris: ['http://127.0.0.1/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      operator_id: operatorId,
    });
    await db.insert(oauthRefreshTokens).values([
      {
        token_hash: `hash_operator_${suffix}`,
        token_family_id: operatorFamily,
        client_id: clientId,
        operator_id: operatorId,
        member_id: null,
        scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp',
        expires_at: new Date(Date.now() + 60_000),
        replacement_token_encrypted: 'kms-operator',
        replacement_retry_expires_at: new Date(Date.now() + 60_000),
      },
      ...memberFamilies.map((familyId, index) => ({
        token_hash: `hash_member_${index}_${suffix}`,
        token_family_id: familyId,
        client_id: clientId,
        operator_id: operatorId,
        member_id: memberId,
        scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp',
        expires_at: new Date(Date.now() + 60_000),
        replacement_token_encrypted: `kms-member-${index}`,
        replacement_retry_expires_at: new Date(Date.now() + 60_000),
      })),
    ]);
  });

  afterAll(async () => {
    await db.delete(oauthRefreshTokens).where(eq(oauthRefreshTokens.operator_id, operatorId));
    await db.delete(oauthClients).where(eq(oauthClients.id, clientId));
    await db.delete(teamMembers).where(eq(teamMembers.id, memberId));
    await db.delete(operators).where(eq(operators.id, operatorId));
  });

  it('takes the family lock before an operator session revoke', async () => {
    const service = new OperatorService(new OperatorRepository(db));
    service.setDb(db);
    const lock = await holdLock(operatorFamily, 240);
    const operation = service.revokeMcpSession(operatorId, undefined, operatorFamily);
    const settled = await settledWithin(operation);
    await lock.release();
    const result = await operation;

    expect(settled).toBe(false);
    expect(result.revoked).toBe(1);
    const [row] = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, operatorFamily),
    });
    expect(row?.replacement_token_encrypted).toBeNull();
    expect(row?.replacement_retry_expires_at).toBeNull();
  });

  it('takes sorted family locks before a member OAuth cascade', async () => {
    const repo = new MemberRepository(db);
    const revoke = vi.spyOn(repo, 'revoke');
    const service = new MemberService(repo);
    service.setDb(db);
    const lock = await holdLock(memberFamilies[0]!, 240);
    const operation = service.revoke(memberId, operatorId);
    const settled = await settledWithin(operation);
    await lock.release();
    await operation;

    expect(settled).toBe(false);
    const rows = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.member_id, memberId),
    });
    expect(rows).toHaveLength(2);
    expect(rows.every((row) => row.revoked_reason === 'member_revoked')).toBe(true);
    expect(rows.every((row) => row.replacement_token_encrypted === null)).toBe(true);
    expect(rows.every((row) => row.replacement_retry_expires_at === null)).toBe(true);
    expect(revoke).toHaveBeenCalledWith(memberId, expect.anything());
  });

  it('takes the operator lock before account deletion', async () => {
    const deleteById = vi.fn(async (_id: string, executor?: unknown) => {
      expect(executor).toBeDefined();
    });
    const repo = {
      findById: vi.fn(async () => { throw new Error('used a second DB operation'); }),
      deleteById,
    } as unknown as OperatorRepository;
    const service = new OperatorService(repo);
    service.setDb(db);
    service.setErasureService(new OperatorErasureService({
      db,
      operatorRepo: repo,
      archive: { eraseOperatorArchive: async () => undefined },
    }));
    const lock = await holdLock(operatorId, 239);
    const operation = service.deleteAccount(operatorId, `${operatorId}@oauth-test.invalid`);
    const settled = await settledWithin(operation);
    await lock.release();
    await operation;

    expect(settled).toBe(false);
    expect(repo.findById).not.toHaveBeenCalled();
    expect(deleteById).toHaveBeenCalledWith(operatorId, expect.anything());
    await db.delete(operatorErasureJobs).where(eq(operatorErasureJobs.operator_id, operatorId));
    await db.update(operators)
      .set({ status: 'active', deleted_at: null })
      .where(eq(operators.id, operatorId));
  });

});
