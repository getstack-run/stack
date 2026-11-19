import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq, inArray } from 'drizzle-orm';
import {
  agents,
  createDb,
  operators,
  passports,
  type Database,
} from '@stack/shared';
import { AgentRepository } from './agent-repo.js';
import { PassportRepository } from './passport-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'] ?? process.env['STACK_TEST_DATABASE_URL'];

describe.skipIf(!DATABASE_URL)('PassportRepository agent block transaction', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_block_${suffix}`;
  const agentId = `agt_block_${suffix}`;
  const childAgentId = `agt_block_child_${suffix}`;
  const unrelatedAgentId = `agt_block_other_${suffix}`;
  const rootJti = `ppt_block_root_${suffix}`;
  const childJti = `ppt_block_child_${suffix}`;
  const grandchildJti = `ppt_block_grandchild_${suffix}`;
  const unrelatedJti = `ppt_block_other_${suffix}`;
  const expiredJti = `ppt_block_expired_${suffix}`;
  const alreadyRevokedJti = `ppt_block_revoked_${suffix}`;
  let db: Database;
  let passportRepo: PassportRepository;
  let agentRepo: AgentRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    passportRepo = new PassportRepository(db);
    agentRepo = new AgentRepository(db);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(agents).values([
      { id: agentId, operator_id: operatorId, name: 'Blocked root' },
      { id: childAgentId, operator_id: operatorId, name: 'Delegated child' },
      { id: unrelatedAgentId, operator_id: operatorId, name: 'Unrelated agent' },
    ]);
    const future = new Date(Date.now() + 60_000);
    await db.insert(passports).values([
      { jti: rootJti, operator_id: operatorId, agent_id: agentId, session_id: `ses_root_${suffix}`, expires_at: future },
      { jti: childJti, operator_id: operatorId, agent_id: childAgentId, session_id: `ses_root_${suffix}`, parent_passport_id: rootJti, delegation_depth: 1, expires_at: future },
      { jti: grandchildJti, operator_id: operatorId, agent_id: childAgentId, session_id: `ses_root_${suffix}`, parent_passport_id: childJti, delegation_depth: 2, expires_at: future },
      { jti: unrelatedJti, operator_id: operatorId, agent_id: unrelatedAgentId, session_id: `ses_other_${suffix}`, expires_at: future },
      { jti: expiredJti, operator_id: operatorId, agent_id: agentId, session_id: `ses_expired_${suffix}`, expires_at: new Date(Date.now() - 1_000) },
      { jti: alreadyRevokedJti, operator_id: operatorId, agent_id: agentId, session_id: `ses_revoked_${suffix}`, expires_at: future, revoked_at: new Date(Date.now() - 1_000), revoked_reason: 'earlier' },
    ]);
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('revokes live and expired refreshable roots plus descendants while preserving unrelated passports', async () => {
    const blockedAt = new Date();
    const revoked = await passportRepo.blockAgentAndRevokeChain({
      operatorId,
      agentId,
      reason: 'Incident review',
      blockedAt,
    });

    expect(new Set(revoked.map((passport) => passport.jti))).toEqual(new Set([
      rootJti,
      childJti,
      grandchildJti,
      expiredJti,
    ]));
    const blockedAgent = await agentRepo.findById(agentId);
    expect(blockedAgent?.passport_blocked).toBe(true);
    expect(blockedAgent?.passport_blocked_reason).toBe('Incident review');

    const rows = await db.select().from(passports).where(inArray(passports.jti, [
      rootJti,
      childJti,
      grandchildJti,
      unrelatedJti,
      expiredJti,
      alreadyRevokedJti,
    ]));
    const byId = new Map(rows.map((row) => [row.jti, row]));
    expect(byId.get(rootJti)?.revoked_reason).toBe('Incident review');
    expect(byId.get(childJti)?.revoked_reason).toBe('Incident review');
    expect(byId.get(grandchildJti)?.revoked_reason).toBe('Incident review');
    expect(byId.get(unrelatedJti)?.revoked_at).toBeNull();
    expect(byId.get(expiredJti)?.revoked_at).toBeInstanceOf(Date);
    expect(byId.get(alreadyRevokedJti)?.revoked_reason).toBe('earlier');
  });

  it('unblocking permits future issuance state without reviving revoked passports', async () => {
    await agentRepo.update(agentId, {
      passport_blocked: false,
      passport_blocked_reason: null,
      passport_blocked_at: null,
    });

    const unblockedAgent = await agentRepo.findById(agentId);
    const rows = await db.select().from(passports).where(inArray(passports.jti, [rootJti, childJti, grandchildJti]));
    expect(unblockedAgent?.passport_blocked).toBe(false);
    expect(rows.every((passport) => passport.revoked_at instanceof Date)).toBe(true);
  });
});
