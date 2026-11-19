import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { agents, createDb, dropoffs, operators } from '@stack/shared';
import { DropoffRepository } from './dropoff-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDatabase = DATABASE_URL ? describe : describe.skip;

describeWithDatabase('a drop-off remembers where its content came from', () => {
  const suffix = Math.random().toString(36).slice(2, 10);
  const operatorId = `op_dprov_${suffix}`;
  const fromAgent = `agt_dprov_from_${suffix}`;
  const toAgent = `agt_dprov_to_${suffix}`;
  const db = createDb(DATABASE_URL!);
  const repo = new DropoffRepository(db);
  const provenance = {
    v: 1, method: 'mission_observations', mission_id: 'ms_x', sources: ['mercury'],
    entity_sources: { abc: ['mercury'] }, fingerprint_sources: { def: ['mercury'] }, unattributed: { entities: 0, fingerprints: 0 },
  };

  const create = (id: string) => repo.create({
    id, operator_id: operatorId, from_agent_id: fromAgent, to_agent_id: toAgent, schema: { type: 'object' },
    status: 'created', expires_at: new Date(Date.now() + 3_600_000),
  });
  const deposit = (id: string) => db.transaction((tx) => repo.deposit(id, operatorId, 'hash', 'envelope', 10, null, 2, tx, provenance));

  beforeAll(async () => {
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@example.test`, api_key_hash: `hash_${operatorId}` });
    await db.insert(agents).values([
      { id: fromAgent, operator_id: operatorId, name: 'from' },
      { id: toAgent, operator_id: operatorId, name: 'to' },
    ]);
  });

  afterAll(async () => {
    await db.delete(dropoffs).where(eq(dropoffs.operator_id, operatorId));
    await db.delete(agents).where(eq(agents.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await db.$client.end({ timeout: 5 });
  });

  it('stores the provenance at deposit', async () => {
    await create(`dof_prov_a_${suffix}`);
    const row = await deposit(`dof_prov_a_${suffix}`);
    expect(row?.provenance).toEqual(provenance);
  });

  it('keeps the source list and drops the digest maps when the payload is collected', async () => {
    await create(`dof_prov_b_${suffix}`);
    await deposit(`dof_prov_b_${suffix}`);
    const collected = await db.transaction((tx) => repo.collect(`dof_prov_b_${suffix}`, operatorId, tx));
    expect(collected?.payload_encrypted).toBeNull();
    expect(collected?.provenance).toEqual({ ...provenance, entity_sources: undefined, fingerprint_sources: undefined });
    expect(collected?.provenance).not.toHaveProperty('entity_sources');
    expect(collected?.provenance).not.toHaveProperty('fingerprint_sources');
  });

  it('does the same when an active drop-off is expired by hand, and leaves a row with no provenance null', async () => {
    await create(`dof_prov_c_${suffix}`);
    await deposit(`dof_prov_c_${suffix}`);
    const expired = await db.transaction((tx) => repo.expireActive(`dof_prov_c_${suffix}`, operatorId, tx));
    expect(expired?.provenance).not.toHaveProperty('entity_sources');
    expect(expired?.provenance).toMatchObject({ sources: ['mercury'] });

    await create(`dof_prov_d_${suffix}`);
    const none = await db.transaction((tx) => repo.deposit(`dof_prov_d_${suffix}`, operatorId, 'hash', 'envelope', 10, null, 2, tx));
    const collected = await db.transaction((tx) => repo.collect(`dof_prov_d_${suffix}`, operatorId, tx));
    expect(none?.provenance).toBeNull();
    expect(collected?.provenance).toBeNull();
  });
});
