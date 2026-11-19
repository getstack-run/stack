import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { Redis } from 'ioredis';
import {
  agents,
  createDb,
  operators,
  passports,
  type Database,
} from '@stack/shared';
import { AgentRepository } from '../repositories/agent-repo.js';
import { PassportRepository } from '../repositories/passport-repo.js';
import { PassportService, REVOCATION_CHANNEL } from './passport-service.js';
import { passportTestWiring } from './passport-service.test-support.js';

const DATABASE_URL = process.env['DATABASE_URL'] ?? process.env['STACK_TEST_DATABASE_URL'];
const REDIS_URL = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];

describe.skipIf(!DATABASE_URL || !REDIS_URL)('PassportService block integration', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_block_redis_${suffix}`;
  const agentId = `agt_block_redis_${suffix}`;
  const childAgentId = `agt_block_redis_child_${suffix}`;
  const rootJti = `ppt_block_redis_root_${suffix}`;
  const childJti = `ppt_block_redis_child_${suffix}`;
  let db: Database;
  let redis: Redis;
  let subscriber: Redis;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    redis = new Redis(REDIS_URL!);
    subscriber = new Redis(REDIS_URL!);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(agents).values([
      { id: agentId, operator_id: operatorId, name: 'Blocked Redis root' },
      { id: childAgentId, operator_id: operatorId, name: 'Blocked Redis child' },
    ]);
    const expiresAt = new Date(Date.now() + 60_000);
    await db.insert(passports).values([
      {
        jti: rootJti,
        operator_id: operatorId,
        agent_id: agentId,
        session_id: `ses_block_redis_${suffix}`,
        expires_at: expiresAt,
      },
      {
        jti: childJti,
        operator_id: operatorId,
        agent_id: childAgentId,
        session_id: `ses_block_redis_${suffix}`,
        parent_passport_id: rootJti,
        delegation_depth: 1,
        expires_at: expiresAt,
      },
    ]);
  });

  afterAll(async () => {
    if (redis) await redis.del(`revoked:${rootJti}`, `revoked:${childJti}`).catch(() => undefined);
    if (db) {
      await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
      await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
      await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
    }
    if (subscriber) await subscriber.quit().catch(() => undefined);
    if (redis) await redis.quit().catch(() => undefined);
  });

  it('writes real Redis revocation markers and publishes the committed cascade', async () => {
    await subscriber.subscribe(REVOCATION_CHANNEL);
    const eventPromise = new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Timed out waiting for revocation event')), 2_000);
      subscriber.once('message', (_channel, body) => {
        clearTimeout(timer);
        resolve(JSON.parse(body) as Record<string, unknown>);
      });
    });

    const service = new PassportService(
      new PassportRepository(db),
      new AgentRepository(db),
      {} as never,
      {} as never,
      redis,
      {} as never,
      '',
      db,
      passportTestWiring().dependencies,
    );
    const result = await service.blockAgent(operatorId, agentId, 'Redis integration incident');
    const event = await eventPromise;

    expect(result).toEqual({ revoked_count: 2 });
    expect(await redis.mget(`revoked:${rootJti}`, `revoked:${childJti}`)).toEqual(['1', '1']);
    expect(event).toMatchObject({
      type: 'bulk_agent',
      operator_id: operatorId,
      agent_id: agentId,
      revoked_count: 1,
      cascaded_count: 1,
      reason: 'Redis integration incident',
    });
  });
});
