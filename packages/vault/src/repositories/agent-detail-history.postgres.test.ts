import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { agents, createDb, intentApprovals, missions, operators, passportClaims, passports, type Database } from '@stack/shared';
import { MissionRepository } from './mission-repo.js';
import { IntentApprovalRepository } from './intent-approval-repo.js';
import { PassportClaimsRepository } from './passport-claims-repo.js';

const databaseUrl = process.env['DATABASE_URL'];
const withDb = databaseUrl ? describe : describe.skip;

withDb('agent detail history SQL filtering', () => {
  const suffix = Math.random().toString(36).slice(2);
  const op = `op_history_${suffix}`;
  const foreign = `op_foreign_${suffix}`;
  const agent = `agt_history_${suffix}`;
  const other = `agt_other_${suffix}`;
  const foreignAgent = `agt_foreign_${suffix}`;
  const passport = `pas_history_${suffix}`;
  const claim = `pc_history_${suffix}`;
  const ownIds = Array.from({ length: 65 }, (_, n) => `ms_${suffix}_${String(n).padStart(3, '0')}`);
  const otherIds = Array.from({ length: 70 }, (_, n) => `ms_other_${suffix}_${n}`);
  let db: Database;
  let repo: MissionRepository;
  let approvals: IntentApprovalRepository;

  beforeAll(async () => {
    db = createDb(databaseUrl!);
    repo = new MissionRepository(db);
    approvals = new IntentApprovalRepository(db);
    await db.insert(operators).values([op, foreign].map((id) => ({ id, email: `${id}@test.invalid`, api_key_hash: id })));
    await db.insert(agents).values([
      { id: agent, operator_id: op, name: 'History' },
      { id: other, operator_id: op, name: 'Other' },
      { id: foreignAgent, operator_id: foreign, name: 'Foreign' },
    ]);
    await db.insert(passports).values([
      { jti: passport, operator_id: op, agent_id: agent, session_id: suffix,
        expires_at: new Date('2020-01-01'), revoked_at: new Date('2020-01-01'), mission_ids: ownIds },
      { jti: `${passport}_other`, operator_id: op, agent_id: other, session_id: suffix,
        expires_at: new Date('2030-01-01'), mission_ids: otherIds },
      // A malformed cross-operator association must not establish membership.
      { jti: `${passport}_foreign`, operator_id: foreign, agent_id: foreignAgent, session_id: suffix,
        expires_at: new Date('2030-01-01'), mission_ids: ownIds },
    ]);
    await db.insert(passportClaims).values({ claim_id: claim, passport_id: passport, operator_id: op,
      type: 'mission', body_json: {}, claim_hash: suffix, signature: 'test' });
    await db.insert(passportClaims).values(Array.from({ length: 135 }, (_, n) => ({
      claim_id: `${claim}_${n}`, passport_id: passport, operator_id: op,
      type: n < 45 ? 'dossier' : 'intent_claim', body_json: { mission_ref: ownIds[0] },
      issued_at_ms: Date.UTC(2026, 0, 1, 0, n), claim_hash: `${suffix}_${n}`, signature: 'test',
    })));
    await db.insert(missions).values([...ownIds, ...otherIds, `ms_baseline_${suffix}`].map((id, n) => ({
      mission_id: id, claim_id: claim, operator_id: op, intent_summary: id,
      // Only this baseline pointer connects the last row to the target agent.
      passport_jti: passport,
      started_at: new Date(Date.UTC(2026, 0, 1, 0, n)), expires_at: new Date('2030-01-01'),
      ...(n < 65 && n % 3 === 1 ? { completed_at: new Date('2026-03-01'), terminal_state: 'completed_successful' } : {}),
      ...(n < 65 && n % 3 === 2 ? { revoked_at: new Date('2026-03-01'), terminal_state: 'revoked_operator_clean' } : {}),
    })));
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(intentApprovals).where(eq(intentApprovals.operator_id, op));
    await db.delete(missions).where(eq(missions.operator_id, op));
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, op));
    await db.delete(passports).where(eq(passports.operator_id, op));
    await db.delete(passports).where(eq(passports.operator_id, foreign));
    await db.delete(agents).where(eq(agents.operator_id, op));
    await db.delete(agents).where(eq(agents.operator_id, foreign));
    await db.delete(operators).where(eq(operators.id, op));
    await db.delete(operators).where(eq(operators.id, foreign));
  });

  it('filters before pagination, preserving revoked/expired Passport relationships without duplicates', async () => {
    const first = await repo.listByOperator(op, { agentId: agent, limit: 50 });
    const second = await repo.listByOperator(op, { agentId: agent, limit: 50, page: 2 });
    expect(first).toHaveLength(50);
    expect(second).toHaveLength(15);
    expect(new Set([...first, ...second].map((row) => row.mission_id))).toEqual(new Set(ownIds));
    expect(await repo.countByOperator(op, undefined, agent)).toBe(65);
    expect(await repo.countByOperator(op, 'completed', agent)).toBe(22);
    expect(await repo.countByOperator(op, 'revoked', agent)).toBe(21);
    expect(await repo.countByOperator(op, 'active', agent)).toBe(22);
    expect(await repo.countByOperator(op, undefined, foreignAgent)).toBe(0);
    expect(await repo.hasAgent(ownIds[0]!, op, agent)).toBe(true);
    expect(await repo.hasAgent(otherIds[0]!, op, agent)).toBe(false);
    expect(await repo.hasAgent(ownIds[0]!, foreign, foreignAgent)).toBe(false);
  });

  it('returns historical mission Passports with operator and optional agent filters', async () => {
    const result = await repo.listPassports(op, ownIds[0]!, { agentId: agent, limit: 1 });
    expect(result.total).toBe(1);
    expect(result.items[0]?.jti).toBe(passport);
    expect(result.items[0]?.revoked_at).not.toBeNull();
    expect((await repo.listPassports(op, ownIds[0]!, { agentId: foreignAgent })).total).toBe(0);
  });

  it('bounds mission activity and dossier records inside the SQL query', async () => {
    const claims = new PassportClaimsRepository(db);
    const first = await claims.findInMissionScope(ownIds[0]!, op, 0, Date.now(), { page: 1, limit: 20 });
    const second = await claims.findInMissionScope(ownIds[0]!, op, 0, Date.now(), { page: 2, limit: 20 });
    expect(first).toHaveLength(21);
    expect(second).toHaveLength(21);
    expect(first[20]?.claim_id).toBe(second[0]?.claim_id);
    const dossiers = await claims.findActiveByTypeAndMissionRef('dossier', ownIds[0]!, op, { page: 3, limit: 20 });
    expect(dossiers).toHaveLength(5);
    expect(await claims.findActiveByTypeAndMissionRef('dossier', ownIds[0]!, foreign, { page: 1, limit: 20 })).toHaveLength(0);
  });

  it('filters pending approvals before pagination and counts the same agent', async () => {
    await db.insert(intentApprovals).values(Array.from({ length: 135 }, (_, n) => ({
      id: `ia_${suffix}_${String(n).padStart(3, '0')}`, operator_id: op, agent_id: n < 65 ? agent : other,
      passport_jti: passport, intent_claim_id: `${claim}_${n}`, status: 'pending',
      requested_at: new Date(Date.UTC(2026, 0, 1, 0, n)), expires_at: new Date('2030-01-01'),
    }))).catch((error: { cause?: Error }) => { throw error.cause ?? error; });
    const first = await approvals.listByOperator(op, { agentId: agent, status: 'pending', limit: 50 });
    const second = await approvals.listByOperator(op, { agentId: agent, status: 'pending', limit: 50, page: 2 });
    expect(first).toHaveLength(50);
    expect(second).toHaveLength(15);
    expect([...first, ...second].every((row) => row.agent_id === agent)).toBe(true);
    expect(await approvals.countByOperator(op, 'pending', agent)).toBe(65);
    expect(await approvals.countByOperator(foreign, 'pending', agent)).toBe(0);
  });
});
