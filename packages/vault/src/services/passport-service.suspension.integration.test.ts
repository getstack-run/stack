import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { Redis } from 'ioredis';
import {
  PassportRevokedError,
  agents,
  createDb,
  operators,
  passports,
  type Database,
} from '@stack/shared';
import { AgentRepository } from '../repositories/agent-repo.js';
import { OperatorRepository } from '../repositories/operator-repo.js';
import { PassportRepository } from '../repositories/passport-repo.js';
import { PassportService, REVOCATION_CHANNEL } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

const DATABASE_URL = process.env['DATABASE_URL'] ?? process.env['STACK_TEST_DATABASE_URL'];
const REDIS_URL = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];

/**
 * Suspending an account does what the off switch does for it: every Passport of the account is revoked in the
 * transaction that suspends it, the revocation reaches the revocation set and `stack:revoked`, and unsuspending
 * restores none of them. Real PostgreSQL and Redis; the signer is a stand-in that reads the claims of the Passport
 * row named by the token.
 */
describe.skipIf(!DATABASE_URL || !REDIS_URL)('suspending an account revokes its Passports', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_susp_${suffix}`;
  const otherOperatorId = `op_susp_other_${suffix}`;
  const agentId = `agt_susp_${suffix}`;
  const otherAgentId = `agt_susp_other_${suffix}`;
  const jtis = {
    one: `ppt_susp_one_${suffix}`,
    two: `ppt_susp_two_${suffix}`,
    other: `ppt_susp_other_${suffix}`,
    fresh: `ppt_susp_fresh_${suffix}`,
    held: `ppt_susp_held_${suffix}`,
  };
  let db: Database;
  let redis: Redis;
  let subscriber: Redis;
  let service: PassportService;
  const events: Array<Record<string, unknown>> = [];

  const token = (jti: string) => `token:${jti}`;
  const sessionOf = (jti: string) => `ses_${jti}`;

  async function addPassport(jti: string, forOperator = operatorId, forAgent = agentId) {
    await db.insert(passports).values({
      jti, operator_id: forOperator, agent_id: forAgent, session_id: sessionOf(jti), expires_at: new Date(Date.now() + 600_000),
    });
  }

  async function setStatus(status: 'active' | 'suspended') {
    await db.update(operators).set({ status }).where(eq(operators.id, operatorId));
  }

  async function suspend(reason: string) {
    let publish: () => Promise<void> = async () => undefined;
    await db.transaction(async (tx) => {
      await tx.update(operators).set({ status: 'suspended', suspended_reason: reason, suspended_at: new Date() }).where(eq(operators.id, operatorId));
      publish = (await service.revokeAllForSuspendedOperatorIn(operatorId, 'Account suspended', tx)).publish;
    });
    await publish();
  }

  const revokedAt = async (jti: string) => (await db.select({ at: passports.revoked_at }).from(passports).where(eq(passports.jti, jti)))[0]?.at ?? null;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    redis = new Redis(REDIS_URL!);
    subscriber = new Redis(REDIS_URL!);
    for (const id of [operatorId, otherOperatorId]) {
      await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    }
    await db.insert(agents).values([
      { id: agentId, operator_id: operatorId, name: 'Suspended account agent' },
      { id: otherAgentId, operator_id: otherOperatorId, name: 'Other account agent' },
    ]);
    await addPassport(jtis.one);
    await addPassport(jtis.two);
    await addPassport(jtis.other, otherOperatorId, otherAgentId);
    await subscriber.subscribe(REVOCATION_CHANNEL);
    subscriber.on('message', (_channel, body) => {
      events.push(JSON.parse(body) as Record<string, unknown>);
    });
    const signer = {
      verify: async (presented: string) => {
        const jti = presented.replace('token:', '');
        const [row] = await db.select().from(passports).where(eq(passports.jti, jti));
        if (!row) throw new Error('unknown token');
        return {
          jti,
          exp: Math.floor(row.expires_at.getTime() / 1000),
          stk: { operator_id: row.operator_id, agent_id: row.agent_id, session_id: row.session_id, delegation_depth: 0, services: [] },
        };
      },
    };
    service = new PassportService(
      new PassportRepository(db),
      new AgentRepository(db),
      {} as never,
      signer as never,
      redis,
      new OperatorRepository(db),
      '',
      db,
      passportTestWiring().dependencies,
    );
  });

  afterAll(async () => {
    if (redis) await redis.del(...Object.values(jtis).map((jti) => `revoked:${jti}`)).catch(() => undefined);
    if (db) {
      await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
      await db.delete(passports).where(eq(passports.operator_id, otherOperatorId)).catch(() => undefined);
      await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
      await db.delete(agents).where(eq(agents.operator_id, otherOperatorId)).catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, otherOperatorId)).catch(() => undefined);
    }
    if (subscriber) await subscriber.quit().catch(() => undefined);
    if (redis) await redis.quit().catch(() => undefined);
  });

  it('refuses a Passport of a suspended account at verify even when nothing revoked it', async () => {
    await addPassport(jtis.held);
    await expect(service.verify(token(jtis.held))).resolves.toMatchObject({ jti: jtis.held });
    await setStatus('suspended');
    await expect(service.verify(token(jtis.held))).rejects.toBeInstanceOf(PassportRevokedError);
    await setStatus('active');
    await expect(service.verify(token(jtis.held))).resolves.toMatchObject({ jti: jtis.held });
    await db.delete(passports).where(eq(passports.jti, jtis.held));
  });

  it('revokes every Passport of the account when it is suspended, announces it, and touches no other account', async () => {
    await expect(service.verify(token(jtis.one))).resolves.toMatchObject({ jti: jtis.one });
    events.length = 0;

    await suspend('abuse report');

    expect(await revokedAt(jtis.one)).not.toBeNull();
    expect(await revokedAt(jtis.two)).not.toBeNull();
    expect(await revokedAt(jtis.other)).toBeNull();
    expect(await redis.mget(`revoked:${jtis.one}`, `revoked:${jtis.two}`)).toEqual(['1', '1']);
    // The announcement arrives over Redis pub/sub: wait for it rather than a fixed time, which a busy machine outruns.
    await vi.waitFor(() => expect(events.length).toBeGreaterThan(0), { timeout: 5_000, interval: 20 });
    expect(events).toEqual([
      expect.objectContaining({ type: 'bulk_operator', operator_id: operatorId, revoked_count: 2, reason: 'Account suspended' }),
    ]);
    await expect(service.verify(token(jtis.one))).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(service.verify(token(jtis.two))).rejects.toBeInstanceOf(PassportRevokedError);
  });

  it('restores nothing when the account is unsuspended: old Passports stay revoked and a new one works', async () => {
    await setStatus('active');
    await expect(service.verify(token(jtis.one))).rejects.toBeInstanceOf(PassportRevokedError);
    await expect(service.verify(token(jtis.two))).rejects.toBeInstanceOf(PassportRevokedError);
    expect(await revokedAt(jtis.one)).not.toBeNull();

    await addPassport(jtis.fresh);
    await expect(service.verify(token(jtis.fresh))).resolves.toMatchObject({ jti: jtis.fresh });
  });

  it('rolls the revocation back with the suspension when the transaction fails', async () => {
    await expect(db.transaction(async (tx) => {
      await tx.update(operators).set({ status: 'suspended' }).where(eq(operators.id, operatorId));
      await service.revokeAllForSuspendedOperatorIn(operatorId, 'Account suspended', tx);
      throw new Error('the suspension did not commit');
    })).rejects.toThrow('the suspension did not commit');
    expect(await revokedAt(jtis.fresh)).toBeNull();
    const [row] = await db.select({ status: operators.status }).from(operators).where(eq(operators.id, operatorId));
    expect(row!.status).toBe('active');
  });
});
