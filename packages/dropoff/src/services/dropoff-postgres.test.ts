import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import {
  agents,
  createDb,
  dropoffRecipients,
  dropoffs,
  DropoffAlreadyCollectedError,
  ForbiddenError,
  NotFoundError,
  missions,
  operators,
  passportClaims,
  passports,
  type Database,
} from '@stack/shared';
import { DropoffRepository } from '../repositories/dropoff-repo.js';
import { DropoffService, type DropoffEncryptor } from './dropoff-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

function postgresCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  if ('code' in error && typeof error.code === 'string') return error.code;
  if ('cause' in error) return postgresCode(error.cause);
  return undefined;
}

async function rejectionCode(operation: Promise<unknown>): Promise<string | undefined> {
  try {
    await operation;
    return undefined;
  } catch (error) {
    return postgresCode(error);
  }
}

describeWithDb('drop-off PostgreSQL lifecycle races', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_dropoff_race_${suffix}`;
  const fromAgentId = `agt_dropoff_from_${suffix}`;
  const toAgentId = `agt_dropoff_to_${suffix}`;
  const secondAgentId = `agt_dropoff_second_${suffix}`;
  const thirdAgentId = `agt_dropoff_third_${suffix}`;
  const outsiderAgentId = `agt_dropoff_outsider_${suffix}`;
  const otherOperatorId = `op_dropoff_other_${suffix}`;
  const foreignAgentId = `agt_dropoff_foreign_${suffix}`;
  const passportId = `pas_dropoff_race_${suffix}`;
  const claimId = `pc_dropoff_race_${suffix}`;
  const missionId = `ms_dropoff_race_${suffix}`;
  let db: Database;
  let service: DropoffService;

  const crypto: DropoffEncryptor = {
    async encrypt(plaintext) {
      return { ciphertext: `encrypted:${plaintext}`, keyRef: 'test' };
    },
    async decrypt(ciphertext) {
      return ciphertext.replace(/^encrypted:/, '');
    },
  };

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    service = new DropoffService(new DropoffRepository(db), crypto);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(operators).values({
      id: otherOperatorId,
      email: `${otherOperatorId}@test.invalid`,
      api_key_hash: `hash_${otherOperatorId}`,
    });
    await db.insert(agents).values([
      { id: fromAgentId, operator_id: operatorId, name: 'Drop-off race producer' },
      { id: toAgentId, operator_id: operatorId, name: 'Drop-off race consumer' },
      { id: secondAgentId, operator_id: operatorId, name: 'Drop-off race second consumer' },
      { id: thirdAgentId, operator_id: operatorId, name: 'Drop-off race third consumer' },
      { id: outsiderAgentId, operator_id: operatorId, name: 'Drop-off race bystander' },
      { id: foreignAgentId, operator_id: otherOperatorId, name: 'Another customer agent' },
    ]);
    await db.insert(passports).values({
      jti: passportId,
      operator_id: operatorId,
      agent_id: fromAgentId,
      session_id: `ses_dropoff_race_${suffix}`,
      expires_at: new Date(Date.now() + 600_000),
      mission_ids: [missionId],
    });
    await db.insert(passportClaims).values({
      claim_id: claimId,
      passport_id: passportId,
      operator_id: operatorId,
      type: 'mission',
      body_json: { type: 'mission', mission_id: missionId },
      claim_hash: `hash_${claimId}`,
      signature: 'test-signature',
    });
    await db.insert(missions).values({
      mission_id: missionId,
      claim_id: claimId,
      operator_id: operatorId,
      passport_jti: passportId,
      intent_summary: 'Drop-off lifecycle race verification',
      expires_at: new Date(Date.now() + 600_000),
    });
  });

  beforeEach(async () => {
    await db.delete(dropoffs).where(eq(dropoffs.operator_id, operatorId));
    await db.update(missions).set({
      max_dropoff_bytes: null,
      expires_at: new Date(Date.now() + 600_000),
      revoked_at: null,
      completed_at: null,
    }).where(eq(missions.mission_id, missionId));
  });

  afterAll(async () => {
    await db.delete(dropoffs).where(eq(dropoffs.operator_id, operatorId)).catch(() => undefined);
    await db.delete(missions).where(eq(missions.mission_id, missionId)).catch(() => undefined);
    await db.delete(passportClaims).where(eq(passportClaims.claim_id, claimId)).catch(() => undefined);
    await db.delete(passports).where(eq(passports.jti, passportId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, otherOperatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, otherOperatorId)).catch(() => undefined);
  });

  async function createGroupDropoff(named: string[] = [toAgentId, secondAgentId, thirdAgentId]) {
    return service.create(operatorId, {
      from_agent: fromAgentId,
      to_agents: named,
      schema: { type: 'object' },
      ttl_seconds: 60,
      on_expire: 'notify',
    });
  }

  describe('a drop-off for several of the customer\'s agents', () => {
    it('names every agent, lets each see it and keeps everyone else out', async () => {
      const created = await createGroupDropoff();
      expect(created.to_agent_ids).toEqual([toAgentId, secondAgentId, thirdAgentId]);
      expect(created.to_agent_id).toBe(toAgentId);
      await service.deposit(created.id, operatorId, fromAgentId, { value: 'for-the-team' });

      for (const agent of [toAgentId, secondAgentId, thirdAgentId]) {
        await expect(service.getStatus(created.id, operatorId, agent)).resolves.toMatchObject({
          to_agents: [toAgentId, secondAgentId, thirdAgentId],
          collected_by: null,
        });
        expect((await service.listForOperator(operatorId, agent)).map((d) => d.id)).toContain(created.id);
        expect((await service.listPendingForAgent(agent)).map((d) => d.id)).toContain(created.id);
      }
      await expect(service.getStatus(created.id, operatorId, outsiderAgentId)).rejects.toBeInstanceOf(NotFoundError);
      await expect(service.collect(created.id, operatorId, outsiderAgentId)).rejects.toBeInstanceOf(NotFoundError);
      expect((await service.listForOperator(operatorId, outsiderAgentId)).map((d) => d.id)).not.toContain(created.id);
    });

    it('refuses a group that names an agent of another customer, as a missing agent, and creates nothing', async () => {
      const before = await db.select().from(dropoffs).where(eq(dropoffs.operator_id, operatorId));
      await expect(createGroupDropoff([toAgentId, foreignAgentId])).rejects.toBeInstanceOf(NotFoundError);
      await expect(createGroupDropoff([toAgentId, 'agt_does_not_exist'])).rejects.toBeInstanceOf(NotFoundError);
      const after = await db.select().from(dropoffs).where(eq(dropoffs.operator_id, operatorId));
      expect(after).toHaveLength(before.length);
      // The other customer's agent cannot be reached from this one either way round.
      await expect(service.create(otherOperatorId, {
        from_agent: foreignAgentId,
        to_agents: [toAgentId],
        schema: { type: 'object' },
        ttl_seconds: 60,
        on_expire: 'notify',
      })).rejects.toBeInstanceOf(NotFoundError);
    });

    it('lets exactly one of ten parallel collects take it and tells the others who did', async () => {
      const created = await createGroupDropoff();
      await service.deposit(created.id, operatorId, fromAgentId, { value: 'taken-once' });
      const collectors = [toAgentId, secondAgentId, thirdAgentId];

      const results = await Promise.allSettled(
        Array.from({ length: 10 }, (_, index) => service.collect(created.id, operatorId, collectors[index % 3]!)),
      );

      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(9);
      const rows = await db.select().from(dropoffRecipients).where(eq(dropoffRecipients.dropoff_id, created.id));
      const winners = rows.filter((row) => row.collected_at !== null);
      expect(winners).toHaveLength(1);
      const winner = winners[0]!.agent_id;
      for (const failure of rejected) {
        expect(failure.reason).toBeInstanceOf(DropoffAlreadyCollectedError);
        const error = failure.reason as DropoffAlreadyCollectedError;
        expect(error.details).toMatchObject({ collected_by: { agent_id: winner } });
        expect(error.message).toContain(winner);
      }
      const [stored] = await db.select().from(dropoffs).where(eq(dropoffs.id, created.id));
      expect(stored).toMatchObject({ status: 'collected', payload_encrypted: null });
      await expect(service.getStatus(created.id, operatorId, secondAgentId))
        .resolves.toMatchObject({ status: 'collected', collected_by: winner });
    });

    it('lets the database itself record only one collector', async () => {
      const created = await createGroupDropoff();
      await db.update(dropoffRecipients).set({ collected_at: new Date() })
        .where(and(eq(dropoffRecipients.dropoff_id, created.id), eq(dropoffRecipients.agent_id, toAgentId)));
      expect(await rejectionCode(
        db.update(dropoffRecipients).set({ collected_at: new Date() })
          .where(and(eq(dropoffRecipients.dropoff_id, created.id), eq(dropoffRecipients.agent_id, secondAgentId))),
      )).toBe('23505');
    });

    it('purges the payload on collect as a one-agent drop-off does', async () => {
      const created = await createGroupDropoff();
      await service.deposit(created.id, operatorId, fromAgentId, { value: 'purged' });
      await expect(service.collect(created.id, operatorId, secondAgentId)).resolves.toEqual({ value: 'purged' });
      const [stored] = await db.select().from(dropoffs).where(eq(dropoffs.id, created.id));
      expect(stored?.payload_encrypted).toBeNull();
      await expect(service.collect(created.id, operatorId, toAgentId)).rejects.toMatchObject({
        code: 'DROPOFF_ALREADY_COLLECTED',
        details: { collected_by: { agent_id: secondAgentId, name: 'Drop-off race second consumer' } },
      });
    });

    it('refuses a group that names its own sender or an agent twice', async () => {
      await expect(createGroupDropoff([toAgentId, fromAgentId])).rejects.toThrow(/own sender/);
      await expect(createGroupDropoff([toAgentId, toAgentId])).rejects.toThrow(/more than once/);
    });

    it('still serves a drop-off made before recipients were recorded, for its one named agent', async () => {
      const id = `dpo_legacy_${suffix}`;
      await db.insert(dropoffs).values({
        id, operator_id: operatorId, from_agent_id: fromAgentId, to_agent_id: toAgentId,
        schema: { type: 'object' }, expires_at: new Date(Date.now() + 60_000),
      });
      await service.deposit(id, operatorId, fromAgentId, { value: 'legacy' });
      await expect(service.getStatus(id, operatorId, toAgentId)).resolves.toMatchObject({ to_agents: [toAgentId] });
      await expect(service.getStatus(id, operatorId, secondAgentId)).rejects.toBeInstanceOf(NotFoundError);
      await expect(service.collect(id, operatorId, toAgentId)).resolves.toEqual({ value: 'legacy' });
      await expect(service.getStatus(id, operatorId, toAgentId)).resolves.toMatchObject({ collected_by: toAgentId });
    });
  });

  async function createDropoff() {
    return service.create(operatorId, {
      from_agent: fromAgentId,
      to_agent: toAgentId,
      schema: { type: 'object' },
      ttl_seconds: 60,
      on_expire: 'notify',
    });
  }

  it('serializes deposits on one mission so only one can consume the remaining byte cap', async () => {
    const payload = { value: 'one-cap-sized-deposit' };
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload)).byteLength;
    await db.update(missions).set({ max_dropoff_bytes: payloadBytes })
      .where(eq(missions.mission_id, missionId));
    const [first, second] = await Promise.all([createDropoff(), createDropoff()]);

    const results = await Promise.allSettled([
      service.deposit(first.id, operatorId, fromAgentId, payload, missionId),
      service.deposit(second.id, operatorId, fromAgentId, payload, missionId),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect(results.find((result) => result.status === 'rejected'))
      .toMatchObject({ reason: expect.any(ForbiddenError) });

    const rows = await db.select().from(dropoffs).where(eq(dropoffs.operator_id, operatorId));
    expect(rows.filter((candidate) => candidate.status === 'deposited')).toHaveLength(1);
    expect(rows.reduce((sum, candidate) => sum + candidate.deposited_bytes, 0)).toBe(payloadBytes);
    expect(rows.find((candidate) => candidate.status === 'created')).toMatchObject({
      mission_id: null,
      deposited_bytes: 0,
      payload_encrypted: null,
    });
  });

  it('permits exactly one concurrent collector and atomically purges the envelope', async () => {
    const created = await createDropoff();
    const deposited = await service.deposit(
      created.id,
      operatorId,
      fromAgentId,
      { value: 'collect-once' },
    );

    const results = await Promise.allSettled([
      service.collect(created.id, operatorId, toAgentId),
      service.collect(created.id, operatorId, toAgentId),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.find((result) => result.status === 'rejected'))
      .toMatchObject({ reason: expect.any(DropoffAlreadyCollectedError) });
    const [stored] = await db.select().from(dropoffs).where(eq(dropoffs.id, created.id));
    expect(stored).toMatchObject({
      status: 'collected',
      payload_encrypted: null,
      deposited_bytes: deposited.deposited_bytes,
    });
  });

  it('rolls collection and purge back when the enclosing audit transaction fails', async () => {
    const created = await createDropoff();
    await service.deposit(created.id, operatorId, fromAgentId, { value: 'audit-bound-collect' });

    await expect(db.transaction(async (transaction) => {
      await service.collect(created.id, operatorId, toAgentId, transaction);
      throw new Error('synthetic audit write failure');
    })).rejects.toThrow('synthetic audit write failure');

    const [afterRollback] = await db.select().from(dropoffs).where(eq(dropoffs.id, created.id));
    expect(afterRollback?.status).toBe('deposited');
    expect(afterRollback?.payload_encrypted).not.toBeNull();
    await expect(service.collect(created.id, operatorId, toAgentId))
      .resolves.toEqual({ value: 'audit-bound-collect' });
  });

  it('lets concurrent worker sweeps claim an overdue envelope only once', async () => {
    const created = await createDropoff();
    await service.deposit(created.id, operatorId, fromAgentId, { value: 'expire-once' });
    await db.update(dropoffs).set({ expires_at: new Date(Date.now() - 1_000) })
      .where(eq(dropoffs.id, created.id));

    const results = await Promise.all([
      service.expireOverdue(undefined, 10),
      service.expireOverdue(undefined, 10),
    ]);

    const claimedIds = results.flat().map((candidate) => candidate.id);
    // A developer database can contain other overdue fixtures. Every claimed
    // row must still be unique across the two workers, and ours exactly once.
    expect(new Set(claimedIds).size).toBe(claimedIds.length);
    expect(claimedIds.filter((id) => id === created.id)).toHaveLength(1);
    const [stored] = await db.select().from(dropoffs).where(eq(dropoffs.id, created.id));
    expect(stored).toMatchObject({ status: 'expired', payload_encrypted: null });
  });

  it('rolls expiry and purge back when the enclosing worker audit transaction fails', async () => {
    const created = await createDropoff();
    await service.deposit(created.id, operatorId, fromAgentId, { value: 'audit-bound-expiry' });
    await db.update(dropoffs).set({ expires_at: new Date(Date.now() - 1_000) })
      .where(eq(dropoffs.id, created.id));

    await expect(db.transaction(async (transaction) => {
      const claimed = await service.expireOverdue(transaction, 100);
      expect(claimed.some((candidate) => candidate.id === created.id)).toBe(true);
      throw new Error('synthetic worker audit write failure');
    })).rejects.toThrow('synthetic worker audit write failure');

    const [afterRollback] = await db.select().from(dropoffs).where(eq(dropoffs.id, created.id));
    expect(afterRollback?.status).toBe('deposited');
    expect(afterRollback?.payload_encrypted).not.toBeNull();
    const retry = await service.expireOverdue(undefined, 100);
    expect(retry.some((candidate) => candidate.id === created.id)).toBe(true);
    const [afterRetry] = await db.select().from(dropoffs).where(eq(dropoffs.id, created.id));
    expect(afterRetry).toMatchObject({ status: 'expired', payload_encrypted: null });
  });

  it('rejects terminal-state rewrites and retained-byte tampering in the database', async () => {
    const created = await createDropoff();
    const deposited = await service.deposit(created.id, operatorId, fromAgentId, { value: 'immutable' });
    await service.collect(created.id, operatorId, toAgentId);

    expect(await rejectionCode(
      db.update(dropoffs).set({ status: 'deposited' }).where(eq(dropoffs.id, created.id)),
    )).toBe('23514');
    expect(await rejectionCode(
      db.update(dropoffs).set({ deposited_bytes: deposited.deposited_bytes + 1 })
        .where(eq(dropoffs.id, created.id)),
    )).toBe('55000');
  });
});
