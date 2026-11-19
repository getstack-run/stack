import Fastify from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { Redis } from 'ioredis';
import { and, eq } from 'drizzle-orm';
import {
  agents,
  auditLog,
  createDb,
  operators,
} from '@stack/shared';
import { AgentRepository, AgentService, AuditService } from '@stack/vault';
import { errorHandler } from '../middleware/error-handler.js';
import type { Services } from '../config/services.js';
import { registerAgentRoutes } from './agents.js';
import { fakeEntitlements } from '../test/entitlements.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const REDIS_URL = process.env['REDIS_URL'] ?? 'redis://127.0.0.1:6380';
const describeWithInfra = DATABASE_URL ? describe : describe.skip;

type RedisLike = Services['redis'];

function redisProxy(
  redis: Redis,
  overrides: Partial<Record<'eval' | 'get' | 'set', (...args: unknown[]) => unknown>>,
): RedisLike {
  return new Proxy(redis, {
    get(target, property) {
      if (property === 'eval' && overrides.eval) return overrides.eval;
      if (property === 'get' && overrides.get) return overrides.get;
      if (property === 'set' && overrides.set) return overrides.set;
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as RedisLike;
}

function twoPartyBarrier() {
  let arrivals = 0;
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  return async () => {
    arrivals += 1;
    if (arrivals === 2) release();
    await released;
  };
}

function keyPairForChallenge(challenge: string) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
  return {
    publicJwk,
    signature: sign(null, Buffer.from(challenge, 'utf8'), privateKey).toString('base64url'),
  };
}

describeWithInfra('agent enrollment atomic claims', () => {
  const db = createDb(DATABASE_URL!);
  const redis = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_enroll_race_${suffix}`;
  const agentId = `agt_enroll_race_${suffix}`;
  const ticketJti = `ent_enroll_race_${suffix}`;
  const secondTicketJti = `ent_enroll_race_second_${suffix}`;
  const ticketKey = `stack:enroll_ticket_burned:${ticketJti}`;
  const secondTicketKey = `stack:enroll_ticket_burned:${secondTicketJti}`;
  const agentService = new AgentService(new AgentRepository(db));

  async function buildApp(options: {
    redis?: RedisLike;
    audit?: Pick<AuditService, 'write'>;
  } = {}) {
    const app = Fastify({ logger: false });
    app.setErrorHandler(errorHandler);
    registerAgentRoutes(app, {
      db,
      redis: options.redis ?? redis,
      signer: {
        async verifyEnrollmentTicket(token: string) {
          return {
            operator_id: operatorId,
            member_id: null,
            agent_id: agentId,
            machine_label: 'race-test',
            jti: token === 'enrollment-ticket-2' ? secondTicketJti : ticketJti,
            exp: Math.floor(Date.now() / 1000) + 300,
          };
        },
      },
      entitlements: fakeEntitlements(),
      operator: {
        async getById() {
          return {
            id: operatorId,
            email: `${operatorId}@test.invalid`,
            tier: 'free',
            status: 'active',
            is_admin: false,
            is_platform_staff: false,
            is_partner: false,
            stripe_customer_id: null,
          };
        },
      },
      agent: agentService,
      passport: { revokeAllForAgent: async () => ({ revoked_count: 0 }) },
      securityEvent: { record: async () => ({}) },
      audit: options.audit ?? new AuditService(db),
    } as unknown as Services);
    await app.ready();
    return app;
  }

  async function issueChallenge(ticket = 'enrollment-ticket') {
    const app = await buildApp();
    try {
      const response = await app.inject({
        method: 'POST',
        url: `/v1/agents/${agentId}/enrollment-challenge`,
        headers: { authorization: `Bearer ${ticket}` },
      });
      expect(response.statusCode).toBe(200);
      return response.json<{ challenge_id: string; challenge: string }>();
    } finally {
      await app.close();
    }
  }

  async function readAgent() {
    return db.query.agents.findFirst({ where: eq(agents.id, agentId) });
  }

  beforeAll(async () => {
    await redis.connect();
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${suffix}`,
    });
    await db.insert(agents).values({
      id: agentId,
      operator_id: operatorId,
      name: `enrollment-race-${suffix}`,
      key_mode: 'customer_managed',
    });
  });

  beforeEach(async () => {
    await redis.del(ticketKey, secondTicketKey);
    const keys = await redis.keys(`stack:enroll:${agentId}:*`);
    if (keys.length > 0) await redis.del(...keys);
    await db.update(agents).set({ pubkey: null, enrolled_at: null }).where(eq(agents.id, agentId));
    await db.delete(auditLog).where(and(
      eq(auditLog.operator_id, operatorId),
      eq(auditLog.action, 'agent.enroll'),
    ));
  });

  afterAll(async () => {
    await redis.del(ticketKey, secondTicketKey);
    const keys = await redis.keys(`stack:enroll:${agentId}:*`);
    if (keys.length > 0) await redis.del(...keys);
    await db.delete(auditLog).where(eq(auditLog.operator_id, operatorId));
    await db.delete(agents).where(eq(agents.id, agentId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await redis.quit();
  });

  it('lets only one concurrent request consume one ticket and one challenge', async () => {
    const { challenge_id: challengeId, challenge } = await issueChallenge();
    const first = keyPairForChallenge(challenge);
    const second = keyPairForChallenge(challenge);
    const waitForBurnReads = twoPartyBarrier();
    const waitForChallengeReads = twoPartyBarrier();
    const challengeKey = `stack:enroll:${agentId}:${challengeId}`;
    const raceRedis = redisProxy(redis, {
      get: async (...args: unknown[]) => {
        const key = String(args[0]);
        if (key === ticketKey) await waitForBurnReads();
        if (key === challengeKey) await waitForChallengeReads();
        return redis.get(key);
      },
    });
    const app = await buildApp({ redis: raceRedis });

    try {
      const submit = (pair: ReturnType<typeof keyPairForChallenge>) => app.inject({
        method: 'POST',
        url: `/v1/agents/${agentId}/enroll`,
        headers: { authorization: 'Bearer enrollment-ticket' },
        payload: {
          public_key: pair.publicJwk,
          challenge_id: challengeId,
          signed_challenge: pair.signature,
        },
      });
      const responses = await Promise.all([submit(first), submit(second)]);
      expect(responses.filter((response) => response.statusCode === 200)).toHaveLength(1);

      const stored = await readAgent();
      expect([first.publicJwk.x, second.publicJwk.x]).toContain(stored?.pubkey?.x);
      expect(await redis.get(ticketKey)).not.toBeNull();
      expect(await redis.get(challengeKey)).toBeNull();

      const rows = await db.select({ entry_id: auditLog.entry_id }).from(auditLog).where(and(
        eq(auditLog.operator_id, operatorId),
        eq(auditLog.action, 'agent.enroll'),
      ));
      expect(rows).toHaveLength(1);
    } finally {
      await app.close();
    }
  });

  it('serializes two valid tickets so only one first enrollment key wins', async () => {
    const firstChallenge = await issueChallenge();
    const secondChallenge = await issueChallenge('enrollment-ticket-2');
    const first = keyPairForChallenge(firstChallenge.challenge);
    const second = keyPairForChallenge(secondChallenge.challenge);
    const firstChallengeKey = `stack:enroll:${agentId}:${firstChallenge.challenge_id}`;
    const secondChallengeKey = `stack:enroll:${agentId}:${secondChallenge.challenge_id}`;
    const waitForChallengeReads = twoPartyBarrier();
    const raceRedis = redisProxy(redis, {
      get: async (...args: unknown[]) => {
        const key = String(args[0]);
        if (key === firstChallengeKey || key === secondChallengeKey) {
          await waitForChallengeReads();
        }
        return redis.get(key);
      },
    });
    const app = await buildApp({ redis: raceRedis });

    try {
      const submit = (
        ticket: string,
        challenge: typeof firstChallenge,
        pair: ReturnType<typeof keyPairForChallenge>,
      ) => app.inject({
        method: 'POST',
        url: `/v1/agents/${agentId}/enroll`,
        headers: { authorization: `Bearer ${ticket}` },
        payload: {
          public_key: pair.publicJwk,
          challenge_id: challenge.challenge_id,
          signed_challenge: pair.signature,
        },
      });
      const responses = await Promise.all([
        submit('enrollment-ticket', firstChallenge, first),
        submit('enrollment-ticket-2', secondChallenge, second),
      ]);
      expect(responses.map((response) => response.statusCode).sort()).toEqual([200, 409]);
      expect(responses.find((response) => response.statusCode === 409)?.json()).toMatchObject({
        error: { message: 'Enrollment request is invalid or expired' },
      });

      const stored = await readAgent();
      expect([first.publicJwk.x, second.publicJwk.x]).toContain(stored?.pubkey?.x);
      const ticketClaims = await redis.mget(ticketKey, secondTicketKey);
      expect(ticketClaims.filter((value) => value !== null)).toHaveLength(1);
      const challenges = await redis.mget(firstChallengeKey, secondChallengeKey);
      expect(challenges.filter((value) => value !== null)).toHaveLength(1);

      const rows = await db.select({ entry_id: auditLog.entry_id }).from(auditLog).where(and(
        eq(auditLog.operator_id, operatorId),
        eq(auditLog.action, 'agent.enroll'),
      ));
      expect(rows).toHaveLength(1);
    } finally {
      await app.close();
    }
  });

  it('rolls back the key and keeps the ticket reusable when required audit fails', async () => {
    const { challenge_id: challengeId, challenge } = await issueChallenge();
    const pair = keyPairForChallenge(challenge);
    const challengeKey = `stack:enroll:${agentId}:${challengeId}`;
    const app = await buildApp({
      audit: { write: async () => { throw new Error('audit unavailable'); } } as never,
    });

    try {
      const response = await app.inject({
        method: 'POST',
        url: `/v1/agents/${agentId}/enroll`,
        headers: { authorization: 'Bearer enrollment-ticket' },
        payload: {
          public_key: pair.publicJwk,
          challenge_id: challengeId,
          signed_challenge: pair.signature,
        },
      });
      expect(response.statusCode).toBe(503);
      expect((await readAgent())?.pubkey).toBeNull();
      expect(await redis.get(ticketKey)).toBeNull();
      expect(await redis.get(challengeKey)).not.toBeNull();
    } finally {
      await app.close();
    }
  });

  it('does not mutate the key when the ticket claim store fails', async () => {
    const { challenge_id: challengeId, challenge } = await issueChallenge();
    const pair = keyPairForChallenge(challenge);
    const challengeKey = `stack:enroll:${agentId}:${challengeId}`;
    const failingRedis = redisProxy(redis, {
      set: async (...args: unknown[]) => {
        if (String(args[0]) === ticketKey) throw new Error('redis unavailable');
        return (redis.set as (...inner: unknown[]) => unknown)(...args);
      },
    });
    const app = await buildApp({ redis: failingRedis });

    try {
      const response = await app.inject({
        method: 'POST',
        url: `/v1/agents/${agentId}/enroll`,
        headers: { authorization: 'Bearer enrollment-ticket' },
        payload: {
          public_key: pair.publicJwk,
          challenge_id: challengeId,
          signed_challenge: pair.signature,
        },
      });
      expect(response.statusCode).toBe(503);
      expect((await readAgent())?.pubkey).toBeNull();
      expect(await redis.get(ticketKey)).toBeNull();
      expect(await redis.get(challengeKey)).not.toBeNull();
    } finally {
      await app.close();
    }
  });

  it('releases its ticket claim when the challenge claim store fails', async () => {
    const { challenge_id: challengeId, challenge } = await issueChallenge();
    const pair = keyPairForChallenge(challenge);
    const challengeKey = `stack:enroll:${agentId}:${challengeId}`;
    const failingRedis = redisProxy(redis, {
      eval: async (...args: unknown[]) => {
        if (String(args[0]).includes("redis.call('PTTL'")) {
          throw new Error('redis unavailable');
        }
        return (redis.eval as (...inner: unknown[]) => unknown)(...args);
      },
    });
    const app = await buildApp({ redis: failingRedis });

    try {
      const response = await app.inject({
        method: 'POST',
        url: `/v1/agents/${agentId}/enroll`,
        headers: { authorization: 'Bearer enrollment-ticket' },
        payload: {
          public_key: pair.publicJwk,
          challenge_id: challengeId,
          signed_challenge: pair.signature,
        },
      });
      expect(response.statusCode).toBe(503);
      expect((await readAgent())?.pubkey).toBeNull();
      expect(await redis.get(ticketKey)).toBeNull();
      expect(await redis.get(challengeKey)).not.toBeNull();
    } finally {
      await app.close();
    }
  });
});
