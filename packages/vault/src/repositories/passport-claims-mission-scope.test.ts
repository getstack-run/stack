import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  agents,
  createDb,
  operators,
  passportClaims,
  passports,
  type Database,
} from '@stack/shared';
import { PassportClaimsRepository } from './passport-claims-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('PassportClaimsRepository.findInMissionScope PostgreSQL query', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_scope_${suffix}`;
  const agentId = `agt_scope_${suffix}`;
  const passportId = `ppt_scope_${suffix}`;
  const missionId = `ms_scope_${suffix}`;
  let db: Database;
  let repo: PassportClaimsRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new PassportClaimsRepository(db);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(agents).values({ id: agentId, operator_id: operatorId, name: 'Scope test' });
    await db.insert(passports).values({
      jti: passportId,
      operator_id: operatorId,
      agent_id: agentId,
      session_id: `ses_${suffix}`,
      expires_at: new Date(Date.now() + 60_000),
      mission_ids: [missionId],
    });
    await db.insert(passportClaims).values([
      {
        claim_id: `pc_scope_inside_${suffix}`,
        passport_id: passportId,
        operator_id: operatorId,
        type: 'intent_claim',
        body_json: { type: 'intent_claim' },
        claim_hash: `hash_inside_${suffix}`,
        signature: 'sig',
        issued_at_ms: 250,
      },
      {
        claim_id: `pc_scope_outside_${suffix}`,
        passport_id: passportId,
        operator_id: operatorId,
        type: 'intent_claim',
        body_json: { type: 'intent_claim' },
        claim_hash: `hash_outside_${suffix}`,
        signature: 'sig',
        issued_at_ms: 100,
      },
      {
        claim_id: `pc_scope_direct_${suffix}`,
        passport_id: null,
        operator_id: operatorId,
        type: 'operator_review',
        body_json: { type: 'operator_review', mission_ref: missionId },
        claim_hash: `hash_direct_${suffix}`,
        signature: 'sig',
        issued_at_ms: 100,
      },
    ]);
  });

  afterAll(async () => {
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('executes the unbounded source query and includes direct plus passport mission claims', async () => {
    const rows = await repo.findInMissionScope(missionId, operatorId);
    expect(rows.map((row) => row.claim_id)).toEqual([
      `pc_scope_direct_${suffix}`,
      `pc_scope_outside_${suffix}`,
      `pc_scope_inside_${suffix}`,
    ]);
  });

  it('executes the bounded replay query and bounds only the passport mission branch', async () => {
    const rows = await repo.findInMissionScope(missionId, operatorId, 200, 300);
    expect(rows.map((row) => row.claim_id)).toEqual([
      `pc_scope_direct_${suffix}`,
      `pc_scope_inside_${suffix}`,
    ]);
  });
});
