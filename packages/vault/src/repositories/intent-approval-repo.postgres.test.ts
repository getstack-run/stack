import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  agents,
  createDb,
  fleetPolicies,
  intentApprovals,
  missions,
  operators,
  passportClaims,
  passports,
  type Database,
} from '@stack/shared';
import { IntentApprovalRepository } from './intent-approval-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('intent approval reservation ownership in PostgreSQL', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_approval_owner_${suffix}`;
  const agentId = `agt_approval_owner_${suffix}`;
  const passportId = `pas_approval_owner_${suffix}`;
  const claimId = `pc_approval_owner_${suffix}`;
  const approvalId = `ia_approval_owner_${suffix}`;
  const firstOwner = 'a'.repeat(64);
  const secondOwner = 'b'.repeat(64);
  let db: Database;
  let repo: IntentApprovalRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new IntentApprovalRepository(db);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(agents).values({ id: agentId, operator_id: operatorId, name: 'Approval owner' });
    await db.insert(passports).values({
      jti: passportId,
      operator_id: operatorId,
      agent_id: agentId,
      session_id: `ses_${suffix}`,
      expires_at: new Date(Date.now() + 600_000),
    });
    await db.insert(passportClaims).values({
      claim_id: claimId,
      passport_id: passportId,
      operator_id: operatorId,
      type: 'intent_claim',
      body_json: { type: 'intent_claim' },
      claim_hash: `hash_${claimId}`,
      signature: 'test-signature',
    });
    await db.insert(intentApprovals).values({
      id: approvalId,
      operator_id: operatorId,
      agent_id: agentId,
      passport_jti: passportId,
      intent_claim_id: claimId,
      status: 'approved',
      expires_at: new Date(Date.now() + 600_000),
    });
  });

  afterAll(async () => {
    await db.delete(intentApprovals).where(eq(intentApprovals.operator_id, operatorId)).catch(() => undefined);
    await db.delete(missions).where(eq(missions.operator_id, operatorId)).catch(() => undefined);
    await db.delete(fleetPolicies).where(eq(fleetPolicies.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passportClaims).where(eq(passportClaims.claim_id, claimId)).catch(() => undefined);
    await db.delete(passports).where(eq(passports.jti, passportId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.id, agentId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('lets one owner reserve, and only that owner release or consume', async () => {
    const reservations = await Promise.all([
      repo.markReserved(approvalId, firstOwner),
      repo.markReserved(approvalId, secondOwner),
    ]);
    expect(reservations.filter(Boolean)).toHaveLength(1);

    const row = await repo.findById(approvalId);
    const winner = row?.consuming_owner_hash;
    const loser = winner === firstOwner ? secondOwner : firstOwner;
    expect([firstOwner, secondOwner]).toContain(winner);
    await expect(repo.releaseReservation(approvalId, loser)).resolves.toBe(false);
    await expect(repo.releaseReservation(approvalId, winner!)).resolves.toBe(true);
    await expect(repo.releaseReservation(approvalId, winner!)).resolves.toBe(false);

    await expect(repo.markReserved(approvalId, winner!)).resolves.toBe(true);
    await expect(repo.markConsumed(approvalId, loser)).resolves.toBe(false);
    await expect(repo.markConsumed(approvalId, winner!)).resolves.toBe(true);
    // Replay is recognized by ApprovalGateService; it cannot consume again.
    await expect(repo.markConsumed(approvalId, winner!)).resolves.toBe(false);
    const consumed = await repo.findById(approvalId);
    expect(consumed?.status).toBe('consumed');
    expect(consumed?.consuming_owner_hash).toBe(winner);
    await expect(repo.markConsumed(approvalId, loser)).resolves.toBe(false);
    await expect(repo.releaseReservation(approvalId, winner!)).resolves.toBe(false);
  });

  const pending = async (id: string, expiresInMs: number, extra: Record<string, unknown> = {}) => {
    await db.insert(intentApprovals).values({
      id, operator_id: operatorId, agent_id: agentId, passport_jti: passportId, intent_claim_id: claimId,
      status: 'pending', expires_at: new Date(Date.now() + expiresInMs), ...extra,
    });
  };

  it('gives an approval its own use window from the decision, and never approves a pending one past its time', async () => {
    await pending(`${approvalId}_w`, 30_000);
    const now = new Date();
    const useUntil = new Date(now.getTime() + 3_600_000);
    const approved = await repo.markDecided(`${approvalId}_w`, 'approved', { now, useUntil });
    expect(approved?.status).toBe('approved');
    expect(approved?.expires_at.toISOString()).toBe(useUntil.toISOString());

    await pending(`${approvalId}_late`, -1_000);
    await expect(repo.markDecided(`${approvalId}_late`, 'approved', { useUntil })).resolves.toBeNull();
    expect((await repo.findById(`${approvalId}_late`))?.status).toBe('pending');
  });

  it('sweeps pending approvals past their time to expired, and leaves the rest', async () => {
    await pending(`${approvalId}_old`, -5_000);
    await pending(`${approvalId}_live`, 600_000);
    expect(await repo.sweepExpired()).toBeGreaterThanOrEqual(1);
    expect((await repo.findById(`${approvalId}_old`))?.status).toBe('expired');
    expect((await repo.findById(`${approvalId}_live`))?.status).toBe('pending');
  });

  it('opens a fleet review again on the same operation key once it expired, and returns a live one as it is', async () => {
    const key = 'c'.repeat(64);
    const policyId = `flp_${suffix}`;
    const missionId = `ms_fleet_${suffix}`;
    await db.insert(fleetPolicies).values({ id: policyId, operator_id: operatorId, root_agent_id: agentId, revision: 1 });
    await db.insert(missions).values({
      mission_id: missionId, claim_id: claimId, operator_id: operatorId, intent_summary: 'Fleet review',
      expires_at: new Date(Date.now() + 600_000),
    });
    const review = (id: string, expiresInMs: number) => ({
      id, operator_id: operatorId, agent_id: agentId, passport_jti: passportId, intent_claim_id: claimId,
      status: 'pending', expires_at: new Date(Date.now() + expiresInMs), fleet_review_key: key,
      fleet_policy_id: policyId, fleet_policy_revision: 1, fleet_mission_id: missionId, fleet_request_hash: 'd'.repeat(64),
    });
    const first = await repo.insertFleetReview(review(`${approvalId}_f1`, -1_000));
    expect(first.created).toBe(true);
    const again = await repo.insertFleetReview(review(`${approvalId}_f2`, 600_000));
    expect(again).toMatchObject({ created: true, row: { id: `${approvalId}_f1`, status: 'pending' } });
    expect(again.row.expires_at.getTime()).toBeGreaterThan(Date.now());
    const live = await repo.insertFleetReview(review(`${approvalId}_f3`, 600_000));
    expect(live).toMatchObject({ created: false, row: { id: `${approvalId}_f1` } });
  });
});
