// A retired agent does not hold its name: a failed setup, or a deleted agent, leaves the name free to register again, and
// the retired agent keeps its real name in the history. The name is unique among the agents that are not revoked.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { ConflictError, agents, createDb, operators, type Database } from '@stack/shared';
import { AgentRepository } from './agent-repo.js';
import { AgentService } from '../services/agent-service.js';
import { resolveVaultFixtureDatabaseUrl } from '../test/dedicated-test-database.js';

const fixtureUrl = resolveVaultFixtureDatabaseUrl();

describe.runIf(Boolean(fixtureUrl))('an agent name after the agent is retired', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_name_reuse_${suffix}`;
  let db: Database;
  let repo: AgentRepository;
  let service: AgentService;

  beforeAll(async () => {
    db = createDb(fixtureUrl!);
    repo = new AgentRepository(db);
    service = new AgentService(repo);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@example.test`, api_key_hash: `hash_${operatorId}` });
  });

  afterAll(async () => {
    await db.delete(agents).where(eq(agents.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await (db as unknown as { $client: { end: (o: { timeout: number }) => Promise<void> } }).$client.end({ timeout: 5 });
  });

  it('is found while the agent is live, and not once it is retired, which frees the name and keeps the retired agent\'s own', async () => {
    const first = await service.register(operatorId, 'enterprise', { name: 'grocery-bot' });
    expect(await repo.findByOperatorAndName(operatorId, 'grocery-bot')).toMatchObject({ id: first.id });
    await expect(service.assertCanRegister(operatorId, 'enterprise', 'grocery-bot')).rejects.toMatchObject({ statusCode: 409 });

    await service.delete(first.id, operatorId);
    expect(await repo.findByOperatorAndName(operatorId, 'grocery-bot')).toBeUndefined();
    await expect(service.assertCanRegister(operatorId, 'enterprise', 'grocery-bot')).resolves.toBeUndefined();

    const second = await service.register(operatorId, 'enterprise', { name: 'grocery-bot' });
    expect(second.id).not.toBe(first.id);
    // The retired agent is still there, retired, under its real name.
    expect(await repo.findById(first.id)).toMatchObject({ status: 'revoked', name: 'grocery-bot' });
  });

  it('frees a name that was revoked before this change, under its plain name', async () => {
    await db.insert(agents).values({ id: `agt_old_${suffix}`, operator_id: operatorId, name: 'long-gone-bot', status: 'revoked' });
    await expect(service.register(operatorId, 'enterprise', { name: 'long-gone-bot' })).resolves.toMatchObject({ name: 'long-gone-bot', status: 'active' });
  });

  it('retires an agent more than once under the same name without a clash, each keeping its name', async () => {
    const ids: string[] = [];
    for (let round = 0; round < 3; round += 1) {
      const agent = await service.register(operatorId, 'enterprise', { name: 'again-bot' });
      ids.push(agent.id);
      await service.delete(agent.id, operatorId);
    }
    expect(await repo.findByOperatorAndName(operatorId, 'again-bot')).toBeUndefined();
    for (const id of ids) expect(await repo.findById(id)).toMatchObject({ name: 'again-bot', status: 'revoked' });
  });

  it('answers two requests for one new name at once with one agent and a 409, never a server error', async () => {
    const outcomes = await Promise.allSettled(
      Array.from({ length: 6 }, () => service.register(operatorId, 'enterprise', { name: 'racing-bot' })),
    );
    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
    for (const outcome of outcomes) {
      if (outcome.status === 'rejected') expect(outcome.reason).toBeInstanceOf(ConflictError);
    }
    expect(await db.select().from(agents).where(eq(agents.name, 'racing-bot'))).toHaveLength(1);
  });
});
