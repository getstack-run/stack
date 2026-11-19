import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, operators, passportClaims, securityEvents, type Database } from '@stack/shared';
import { PassportClaimsRepository } from './passport-claims-repo.js';
import { SecurityEventRepository } from './security-event-repo.js';
import { resolveVaultFixtureDatabaseUrl } from '../test/dedicated-test-database.js';

// Only the dedicated test database: these fixtures write and delete rows.
const DATABASE_URL = resolveVaultFixtureDatabaseUrl();
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('what an agent has seen across Missions, and counting a repeated event', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_seen_${suffix}`;
  const agentId = `agt_seen_${suffix}`;
  const otherAgent = `agt_other_${suffix}`;
  let db: Database;
  let claims: PassportClaimsRepository;
  let events: SecurityEventRepository;
  let n = 0;

  const observe = (agent: string, mission: string, entities: string[], issuedAt: number) =>
    db.insert(passportClaims).values({
      claim_id: `pc_seen_${suffix}_${n++}`,
      operator_id: operatorId,
      type: 'entity_observation',
      body_json: { type: 'entity_observation', entities, agent_id: agent, source_service: 'custom_grocer', mission_ref: mission },
      claim_hash: `hash_seen_${suffix}_${n}`,
      signature: 'fixture-signature',
      issued_at_ms: issuedAt,
    });

  const event = async (overrides: Partial<typeof securityEvents.$inferInsert> = {}) => {
    const row = await events.create({
      id: `sev_seen_${suffix}_${n++}`,
      operator_id: operatorId,
      agent_id: agentId,
      signal_type: 'credential_outside_scope',
      severity: 'warning',
      message: 'refused',
      metadata: { request_path: '/v1/admin/reset/1' },
      ...overrides,
    });
    return row.id;
  };

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    claims = new PassportClaimsRepository(db);
    events = new SecurityEventRepository(db);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@example.test`, api_key_hash: `hash_${operatorId}` });
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(securityEvents).where(eq(securityEvents.operator_id, operatorId));
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await db.$client.end();
  });

  it('reads every entity an agent met in any of its Missions, once, and nothing of another agent', async () => {
    const now = Date.now();
    await observe(agentId, 'ms_one', ['a.example', 'b.example'], now - 3000);
    await observe(agentId, 'ms_two', ['b.example', 'c.example'], now - 2000);
    await observe(otherAgent, 'ms_three', ['secret.example'], now - 1000);
    const seen = await claims.findObservedEntitiesForAgent({ operatorId, agentId });
    expect(seen.sort()).toEqual(['a.example', 'b.example', 'c.example']);
    expect(await claims.findObservedEntitiesForAgent({ operatorId: `${operatorId}_x`, agentId })).toEqual([]);
  });

  it('still knows an entity that was only the request\'s own URL: the counterparty check reads it with the rest', async () => {
    const own = `agt_own_${suffix}`;
    await db.insert(passportClaims).values({
      claim_id: `pc_seen_${suffix}_own`, operator_id: operatorId, type: 'entity_observation',
      body_json: { type: 'entity_observation', entities: ['h:read', 'h:sent'], request_entities: ['h:sent'], agent_id: own, source_service: 'openai', mission_ref: 'ms_own' },
      claim_hash: `hash_seen_${suffix}_own`, signature: 'fixture-signature', issued_at_ms: Date.now(),
    });
    expect((await claims.findObservedEntitiesForAgent({ operatorId, agentId: own })).sort()).toEqual(['h:read', 'h:sent']);
  });

  it('keeps to the newest observations, so a long-running agent costs a bounded read', async () => {
    const now = Date.now();
    await observe(agentId, 'ms_late', ['newest.example'], now + 1000);
    const seen = await claims.findObservedEntitiesForAgent({ operatorId, agentId, limit: 1 });
    expect(seen).toEqual(['newest.example']);
  });

  it('counts a repeat on the event the first one made, in one statement, and starts from one', async () => {
    const id = await event();
    await Promise.all([events.addRepeat(id, operatorId), events.addRepeat(id, operatorId), events.addRepeat(id, operatorId)]);
    const row = await events.findById(id);
    expect(row!.metadata).toMatchObject({ request_path: '/v1/admin/reset/1', repeat_count: 4 });
    expect(typeof (row!.metadata as Record<string, unknown>)['last_repeat_at']).toBe('string');
  });

  it('leaves a resolved event and another customer\'s event as they were', async () => {
    const resolved = await event({ resolved: true, resolved_by: 'operator:x' });
    await events.addRepeat(resolved, operatorId);
    expect((await events.findById(resolved))!.metadata).toEqual({ request_path: '/v1/admin/reset/1' });
    const open = await event();
    await events.addRepeat(open, `${operatorId}_other`);
    expect((await events.findById(open))!.metadata).toEqual({ request_path: '/v1/admin/reset/1' });
  });

  it('resolves one agent\'s open warnings and info in one statement and leaves its criticals and other agents alone', async () => {
    const warning = await event({ signal_type: 'undeclared_target' });
    const info = await event({ signal_type: 'pii_below_threshold', severity: 'info' });
    const critical = await event({ signal_type: 'prompt_injection', severity: 'critical' });
    const elsewhere = await event({ agent_id: otherAgent });
    const done = await events.resolveOpenForAgent(operatorId, agentId, 'operator:op', ['info', 'warning']);
    const ids = done.map((row) => row.id);
    expect(ids).toContain(warning);
    expect(ids).toContain(info);
    expect(ids).not.toContain(critical);
    expect(ids).not.toContain(elsewhere);
    expect((await events.findById(warning))!).toMatchObject({ resolved: true, resolved_by: 'operator:op' });
    expect((await events.findById(critical))!.resolved).toBe(false);
    expect((await events.findById(elsewhere))!.resolved).toBe(false);
    // Already resolved events are not resolved again.
    expect(await events.resolveOpenForAgent(operatorId, agentId, 'operator:op', ['info', 'warning'])).toEqual([]);
  });

  it('reads an agent\'s events since a time, and none from before it', async () => {
    const since = `agt_since_${suffix}`;
    const id = await event({ agent_id: since });
    const all = await events.findByAgent(since, new Date(Date.now() - 60_000));
    expect(all.map((row) => row.id)).toEqual([id]);
    expect(await events.findByAgent(since, new Date(Date.now() + 60_000))).toEqual([]);
  });
});
