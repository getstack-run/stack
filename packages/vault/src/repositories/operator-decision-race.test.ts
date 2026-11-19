import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  agents,
  ConflictError,
  createDb,
  missions,
  NotFoundError,
  operators,
  passportCheckouts,
  passportClaims,
  passportReviews,
  passports,
  securityEvents,
  type Database,
} from '@stack/shared';
import { OperatorDecisionRepository } from './operator-decision-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('OperatorDecisionRepository stale-state and rollback invariants', () => {
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_odec_race_${suffix}`;
  const agentId = `agt_odec_race_${suffix}`;
  const passportId = `ppt_odec_race_${suffix}`;
  const missionId = `ms_odec_race_${suffix}`;
  const missionClaimId = `pc_odec_race_${suffix}`;
  const checkoutId = `cout_odec_race_${suffix}`;
  const eventId = `sevt_odec_race_${suffix}`;
  let db: Database;
  let repo: OperatorDecisionRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new OperatorDecisionRepository(db);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.insert(agents).values({ id: agentId, operator_id: operatorId, name: 'Decision race test' });
    await db.insert(passports).values({
      jti: passportId,
      operator_id: operatorId,
      agent_id: agentId,
      session_id: `ses_${suffix}`,
      expires_at: new Date(Date.now() + 60_000),
      mission_ids: [missionId],
    });
    await db.insert(passportClaims).values({
      claim_id: missionClaimId,
      passport_id: passportId,
      operator_id: operatorId,
      type: 'mission',
      body_json: { type: 'mission', mission_id: missionId },
      claim_hash: `hash_${missionClaimId}`,
      signature: 'sig',
    });
    await db.insert(missions).values({
      mission_id: missionId,
      claim_id: missionClaimId,
      operator_id: operatorId,
      intent_summary: 'Race test',
      expires_at: new Date(Date.now() + 60_000),
    });
    await db.insert(passportCheckouts).values({
      id: checkoutId,
      passport_jti: passportId,
      operator_id: operatorId,
      mission_id: missionId,
      review_status: 'flagged',
    });
    await db.insert(securityEvents).values({
      id: eventId,
      operator_id: operatorId,
      mission_id: missionId,
      agent_id: agentId,
      signal_type: 'scope_drift',
      message: 'Race test event',
    });
  });

  beforeEach(async () => {
    await db.delete(passportReviews).where(eq(passportReviews.operator_id, operatorId));
    await db.update(passportCheckouts).set({ review_status: 'flagged', reviewed_at: null })
      .where(eq(passportCheckouts.id, checkoutId));
    await db.update(securityEvents).set({ resolved: false, resolved_by: null, resolved_at: null })
      .where(eq(securityEvents.id, eventId));
    await db.update(passports).set({ revoked_at: null, revoked_reason: null })
      .where(eq(passports.jti, passportId));
    await db.update(agents).set({
      passport_blocked: false,
      passport_blocked_reason: null,
      passport_blocked_at: null,
    }).where(eq(agents.id, agentId));
  });

  afterAll(async () => {
    await db.delete(passportReviews).where(eq(passportReviews.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passportCheckouts).where(eq(passportCheckouts.operator_id, operatorId)).catch(() => undefined);
    await db.delete(securityEvents).where(eq(securityEvents.operator_id, operatorId)).catch(() => undefined);
    await db.delete(missions).where(eq(missions.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passports).where(eq(passports.operator_id, operatorId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('rejects a checkout effect when a legacy decision changed the eligible state', async () => {
    const [source] = await repo.findCheckoutSources([checkoutId]);
    await db.update(passportCheckouts).set({ review_status: 'clean' })
      .where(eq(passportCheckouts.id, checkoutId));
    await expect(repo.transaction(({ decisions }) => decisions.applyCheckoutEffect({
      decisionId: `odec_${suffix}`,
      operatorId,
      action: 'checkout_blocked',
      sources: [source!],
      decidedAt: new Date(),
    }))).rejects.toBeInstanceOf(ConflictError);
    expect(await db.select().from(passportReviews).where(eq(passportReviews.checkout_id, checkoutId)))
      .toHaveLength(0);
  });

  it('rolls back checkout resolution when the target agent update finds no row', async () => {
    const [source] = await repo.findCheckoutSources([checkoutId]);
    await expect(repo.transaction(({ decisions }) => decisions.applyCheckoutEffect({
      decisionId: `odec_${suffix}`,
      operatorId,
      action: 'checkout_blocked',
      sources: [{ ...source!, agent_id: `agt_missing_${suffix}` }],
      decidedAt: new Date(),
    }))).rejects.toBeInstanceOf(NotFoundError);
    const [checkout] = await db.select().from(passportCheckouts).where(eq(passportCheckouts.id, checkoutId));
    expect(checkout?.review_status).toBe('flagged');
    expect(await db.select().from(passportReviews).where(eq(passportReviews.checkout_id, checkoutId)))
      .toHaveLength(0);
  });

  it('blocks the agent and revokes its active passport in the checkout transaction', async () => {
    const [source] = await repo.findCheckoutSources([checkoutId]);
    const revoked = await repo.transaction(({ decisions }) => decisions.applyCheckoutEffect({
      decisionId: `odec_block_${suffix}`,
      operatorId,
      action: 'checkout_blocked',
      sources: [source!],
      decidedAt: new Date(),
    }));

    const [blockedAgent] = await db.select().from(agents).where(eq(agents.id, agentId));
    const [revokedPassport] = await db.select().from(passports).where(eq(passports.jti, passportId));
    expect(blockedAgent?.passport_blocked).toBe(true);
    expect(revokedPassport?.revoked_at).toBeInstanceOf(Date);
    expect(revoked.map((passport) => passport.jti)).toEqual([passportId]);
  });

  it('rejects a security effect after another resolver changed the event state', async () => {
    const [source] = await repo.findSecurityEventSources([eventId]);
    await db.update(securityEvents).set({ resolved: true }).where(eq(securityEvents.id, eventId));
    await expect(repo.transaction(({ decisions }) => decisions.applySecurityEventEffect({
      operatorId,
      action: 'security_events_dismissed',
      sources: [source!],
      resolvedBy: `operator:${operatorId}`,
      decidedAt: new Date(),
    }))).rejects.toBeInstanceOf(ConflictError);
  });

  it('rolls back event resolution when agent suspension finds no target row', async () => {
    const [source] = await repo.findSecurityEventSources([eventId]);
    await expect(repo.transaction(({ decisions }) => decisions.applySecurityEventEffect({
      operatorId,
      action: 'agent_suspended',
      sources: [{ ...source!, agent_id: `agt_missing_${suffix}` }],
      resolvedBy: `operator:${operatorId}`,
      decidedAt: new Date(),
    }))).rejects.toBeInstanceOf(NotFoundError);
    const [event] = await db.select().from(securityEvents).where(eq(securityEvents.id, eventId));
    expect(event?.resolved).toBe(false);
  });
});
