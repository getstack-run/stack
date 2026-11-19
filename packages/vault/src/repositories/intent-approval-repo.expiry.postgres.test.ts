import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  agents,
  createDb,
  intentApprovals,
  operators,
  passportClaims,
  passports,
  type Database,
} from '@stack/shared';
import { IntentApprovalRepository } from './intent-approval-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

// Pending approvals past their time become expired once, returned to the one sweep that moved each, so the agent
// waiting on it is told exactly once however many machines sweep.
describeWithDb('expiring intent approvals in PostgreSQL', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_approval_expiry_${suffix}`;
  const agentId = `agt_approval_expiry_${suffix}`;
  const passportId = `pas_approval_expiry_${suffix}`;
  const claimId = `pc_approval_expiry_${suffix}`;
  const due = `ia_due_${suffix}`;
  const notDue = `ia_not_due_${suffix}`;
  const decided = `ia_decided_${suffix}`;
  let db: Database;
  let repo: IntentApprovalRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new IntentApprovalRepository(db);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` });
    await db.insert(agents).values({ id: agentId, operator_id: operatorId, name: 'Approval expiry' });
    await db.insert(passports).values({
      jti: passportId, operator_id: operatorId, agent_id: agentId, session_id: `ses_${suffix}`, expires_at: new Date(Date.now() + 600_000),
    });
    await db.insert(passportClaims).values({
      claim_id: claimId, passport_id: passportId, operator_id: operatorId, type: 'intent_claim',
      body_json: { type: 'intent_claim' }, claim_hash: `hash_${claimId}`, signature: 'test-signature',
    });
    const row = (id: string, status: string, expiresAt: Date) => ({
      id, operator_id: operatorId, agent_id: agentId, passport_jti: passportId, intent_claim_id: claimId, status, expires_at: expiresAt,
    });
    await db.insert(intentApprovals).values([
      row(due, 'pending', new Date(Date.now() - 1_000)),
      row(notDue, 'pending', new Date(Date.now() + 600_000)),
      row(decided, 'approved', new Date(Date.now() - 1_000)),
    ]);
  });

  afterAll(async () => {
    await db.delete(intentApprovals).where(eq(intentApprovals.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passportClaims).where(eq(passportClaims.claim_id, claimId)).catch(() => undefined);
    await db.delete(passports).where(eq(passports.jti, passportId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.id, agentId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('moves each due pending approval once, whatever sweeps at the same time', async () => {
    const now = new Date();
    const sweeps = await Promise.all([repo.expirePending(now, 500), repo.expirePending(now, 500), repo.expirePending(now, 500)]);
    const mine = sweeps.flat().filter((row) => row.operator_id === operatorId);
    expect(mine).toEqual([{ id: due, operator_id: operatorId, agent_id: agentId, fleet_policy_id: null }]);
    expect((await repo.findById(due))?.status).toBe('expired');
    expect((await repo.findById(notDue))?.status).toBe('pending');
    expect((await repo.findById(decided))?.status).toBe('approved');
  });
});
