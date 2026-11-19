import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import {
  agents,
  createDb,
  missions,
  operators,
  passportClaims,
  startOfDayIn,
  type DecisionReachedEvent,
  type Database,
} from '@stack/shared';
import { MissionRepository } from '../../repositories/mission-repo.js';
import type { PassportClaimsRepository } from '../../repositories/passport-claims-repo.js';
import { resolveVaultFixtureDatabaseUrl } from '../../test/dedicated-test-database.js';
import { MissionService, missionReviewId } from '../mission-service.js';
import type { MissionAuditInput, MissionPausedEvent } from './types.js';

// What a Mission's caps do when one is reached (10.5 of the plan of 2 November): pause the Mission for its owner's
// review (the default for every cap), refuse only the action, or end the Mission; the owner's review raises the limit,
// lets it continue or closes it, and the agent the Mission was opened for hears the decision. A money cap may be one day
// in the Mission's own time zone. The owner's pre-approval of making orders is stored on the Mission.

const DATABASE_URL = resolveVaultFixtureDatabaseUrl();
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb("a Mission's caps, its pause and the owner's review", () => {
  let db: Database;
  const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
  const operatorId = `op_caps_${suffix}`;
  const otherOperatorId = `op_caps_other_${suffix}`;
  const agentId = `agt_caps_${suffix}`;
  let claimSeq = 0;
  const payloads: Array<Record<string, unknown>> = [];
  const paused: MissionPausedEvent[] = [];
  const decisions: DecisionReachedEvent[] = [];
  const audits: MissionAuditInput[] = [];
  const spendCalls: unknown[][] = [];
  let spent = 0;
  let service: MissionService;

  const claimRegistry = {
    async registerClaim(
      input: { operatorId: string; payload: Record<string, unknown> },
      options: { persistence?: Pick<PassportClaimsRepository, 'insert'> } = {},
    ) {
      claimSeq += 1;
      const claimId = `pc_caps_${suffix}_${claimSeq}`;
      payloads.push(input.payload);
      await options.persistence!.insert({
        claim_id: claimId, operator_id: input.operatorId, type: 'mission', body_json: input.payload,
        claim_hash: `hash_${suffix}_${claimSeq}`, signature: 'fixture', envelope_cose: 'fixture',
      });
      return { claimId };
    },
  };

  /** Seed one intent claim under a Mission, so a cap of one action is reached. */
  const seedIntent = async (missionId: string) => {
    claimSeq += 1;
    await db.insert(passportClaims).values({
      claim_id: `pc_caps_intent_${suffix}_${claimSeq}`, operator_id: operatorId, type: 'intent_claim',
      body_json: { intent_type: 'http_call', target: 'slack', mission_ref: missionId },
      claim_hash: `hash_intent_${suffix}_${claimSeq}`, signature: 'fixture',
    });
  };

  const open = (extra: Parameters<MissionService['open']>[0] extends infer T ? Partial<T> : never = {}) =>
    service.open({ operatorId, assignedAgentId: agentId, intent_summary: 'caps', intent_services: ['slack'], ...extra });

  const gate = (missionId: string) => service.checkGate({ missionId, requestedService: 'slack' });

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    for (const id of [operatorId, otherOperatorId]) {
      await db.insert(operators).values({ id, email: `${id}@example.test`, api_key_hash: `hash_${id}` });
    }
    await db.insert(agents).values({ id: agentId, operator_id: operatorId, name: `caps-${suffix}` });
    service = new MissionService({
      repo: new MissionRepository(db),
      claimRegistry: claimRegistry as never,
      audit: { write: async (input) => { audits.push(input); return 'aud'; } },
      onPaused: async (event) => { paused.push(event); },
      onDecision: async (event) => { decisions.push(event); },
      missionSpend: {
        async spentCents(...args: unknown[]) { spendCalls.push(args); return spent; },
        async governedByAccountBudget() { return false; },
      },
    });
  });

  afterAll(async () => {
    await db.delete(missions).where(eq(missions.operator_id, operatorId)).catch(() => undefined);
    await db.delete(passportClaims).where(eq(passportClaims.operator_id, operatorId)).catch(() => undefined);
    await db.delete(agents).where(eq(agents.operator_id, operatorId)).catch(() => undefined);
    for (const id of [operatorId, otherOperatorId]) await db.delete(operators).where(eq(operators.id, id)).catch(() => undefined);
    await (db as unknown as { $client: { end(o: { timeout: number }): Promise<void> } }).$client.end({ timeout: 5 });
  });

  it('opens with every cap pausing by default, the money cap of the whole Mission in UTC, and no allowance; the claim names no behaviour', async () => {
    const { mission_id } = await open({ max_actions: 3 });
    const view = (await service.findById(mission_id))!;
    expect(view).toMatchObject({
      cap_behavior: {}, coverage_cap_period: 'mission', cap_time_zone: 'UTC',
      paused_at: null, paused_cap: null, paused_service: null, making_orders_up_to_cents: null,
    });
    expect(payloads.at(-1)!['cap_behavior']).toEqual({});
  });

  it('keeps what a Mission set at open on the row, never in the signed claim, and refuses a time zone that is not one', async () => {
    const { mission_id } = await open({
      coverage_cap_cents: 500, coverage_cap_period: 'day', cap_time_zone: 'America/New_York',
      cap_behavior: { coverage_cap_cents: 'end_mission', max_actions: 'refuse_action' }, making_orders_up_to_cents: 2_500,
    });
    expect(await service.findById(mission_id)).toMatchObject({
      coverage_cap_period: 'day', cap_time_zone: 'America/New_York', making_orders_up_to_cents: 2_500,
      cap_behavior: { coverage_cap_cents: 'end_mission', max_actions: 'refuse_action' },
    });
    expect(payloads.at(-1)!['cap_behavior']).toEqual({});
    await expect(open({ cap_time_zone: 'Mars/Olympus' })).rejects.toMatchObject({ statusCode: 400 });
  });

  it('pauses the Mission at a cap that pauses it, once however many calls reach it, and refuses everything under it after', async () => {
    paused.length = 0;
    const { mission_id } = await open({ max_actions: 1 });
    await seedIntent(mission_id);
    const verdict = await gate(mission_id);
    expect(verdict).toMatchObject({ allowed: false, reason: 'cap_max_actions', capBehavior: 'pause' });

    await Promise.all(Array.from({ length: 10 }, () => service.applyCapBehavior(mission_id, 'max_actions', 'pause')));
    expect(paused).toEqual([{ operatorId, missionId: mission_id, agentId, cap: 'max_actions', service: null }]);
    expect(audits.filter((a) => a.action === 'mission.paused')).toHaveLength(1);

    const view = (await service.findById(mission_id))!;
    expect(view.paused_at).toBeInstanceOf(Date);
    expect(view.paused_cap).toBe('max_actions');
    expect(view.completed_at).toBeNull();
    expect(view.revoked_at).toBeNull();
    expect(await gate(mission_id)).toMatchObject({ allowed: false, reason: 'mission_paused' });
    expect((await service.listByOperator(operatorId, { status: 'paused' })).items.map((m) => m.mission_id)).toContain(mission_id);
  });

  it('pauses one Mission and leaves the operator\'s others running', async () => {
    const one = await open({ max_actions: 1 });
    const two = await open({ max_actions: 5 });
    await seedIntent(one.mission_id);
    await service.applyCapBehavior(one.mission_id, 'max_actions', 'pause');
    expect(await gate(one.mission_id)).toMatchObject({ reason: 'mission_paused' });
    expect(await gate(two.mission_id)).toMatchObject({ allowed: true });
  });

  it('raise: the owner sets a higher limit of the cap that paused it, the Mission goes on, and its agent hears "raised"', async () => {
    decisions.length = 0;
    const { mission_id } = await open({ max_actions: 1 });
    await seedIntent(mission_id);
    await service.applyCapBehavior(mission_id, 'max_actions', 'pause');
    const pausedAt = (await service.findById(mission_id))!.paused_at!;

    await expect(service.review(mission_id, { operatorId, decision: 'raise', limit: 1 })).rejects.toMatchObject({ statusCode: 400 });
    const result = await service.review(mission_id, { operatorId, decision: 'raise', limit: 4 });
    expect(result).toMatchObject({ result: 'raised', mission: { max_actions: 4, paused_at: null, paused_cap: null } });
    expect(decisions).toEqual([{ operatorId, agentId, kind: 'mission_review', itemId: missionReviewId(mission_id, pausedAt), result: 'raised' }]);
    expect(await gate(mission_id)).toMatchObject({ allowed: true });
    // A second decision of the same review changes nothing.
    await expect(service.review(mission_id, { operatorId, decision: 'continue' })).rejects.toMatchObject({ code: 'MISSION_NOT_PAUSED' });
  });

  it('raise of a per-service cap raises that service\'s limit only', async () => {
    const { mission_id } = await open({ max_actions_per_service: { slack: 1, github: 9 } });
    await seedIntent(mission_id);
    expect(await gate(mission_id)).toMatchObject({ reason: 'cap_max_actions_per_service', capService: 'slack' });
    await service.applyCapBehavior(mission_id, 'max_actions_per_service', 'pause', 'slack');
    expect((await service.findById(mission_id))!.paused_service).toBe('slack');
    const result = await service.review(mission_id, { operatorId, decision: 'raise', limit: 3 });
    expect(result.mission.max_actions_per_service).toEqual({ slack: 3, github: 9 });
  });

  it('continue: the Mission goes on with its limits as they were, so the cap pauses it again, and each pause is a review of its own', async () => {
    decisions.length = 0;
    const { mission_id } = await open({ max_actions: 1 });
    await seedIntent(mission_id);
    await service.applyCapBehavior(mission_id, 'max_actions', 'pause');
    const first = (await service.findById(mission_id))!.paused_at!;
    expect(await service.review(mission_id, { operatorId, decision: 'continue' })).toMatchObject({ result: 'continued', mission: { max_actions: 1 } });
    expect(await gate(mission_id)).toMatchObject({ reason: 'cap_max_actions', capBehavior: 'pause' });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await service.applyCapBehavior(mission_id, 'max_actions', 'pause');
    const second = (await service.findById(mission_id))!.paused_at!;
    await service.review(mission_id, { operatorId, decision: 'continue' });
    expect(decisions.map((d) => d.itemId)).toEqual([missionReviewId(mission_id, first), missionReviewId(mission_id, second)]);
    expect(new Set(decisions.map((d) => d.itemId)).size).toBe(2);
  });

  it('close: the Mission ends as cap breached and its agent hears "closed"', async () => {
    decisions.length = 0;
    const { mission_id } = await open({ max_actions: 1 });
    await seedIntent(mission_id);
    await service.applyCapBehavior(mission_id, 'max_actions', 'pause');
    expect(await service.review(mission_id, { operatorId, decision: 'close' })).toMatchObject({
      result: 'closed', mission: { terminal_state: 'completed_cap_breached' },
    });
    expect(decisions.map((d) => d.result)).toEqual(['closed']);
    expect(await gate(mission_id)).toMatchObject({ reason: 'mission_completed' });
  });

  it('refuses a review of a Mission that is not paused, and hides another operator\'s', async () => {
    const { mission_id } = await open({ max_actions: 5 });
    await expect(service.review(mission_id, { operatorId, decision: 'continue' })).rejects.toMatchObject({ code: 'MISSION_NOT_PAUSED', statusCode: 409 });
    await expect(service.review(mission_id, { operatorId: otherOperatorId, decision: 'continue' })).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('end_mission ends the Mission as cap breached; refuse_action changes nothing', async () => {
    const ended = await open({ max_actions: 1, cap_behavior: { max_actions: 'end_mission' } });
    await seedIntent(ended.mission_id);
    const verdict = await gate(ended.mission_id);
    expect(verdict).toMatchObject({ allowed: false, capBehavior: 'end_mission' });
    await service.applyCapBehavior(ended.mission_id, 'max_actions', 'end_mission');
    expect(await service.findById(ended.mission_id)).toMatchObject({ terminal_state: 'completed_cap_breached', paused_at: null });

    const refused = await open({ max_actions: 1, cap_behavior: { max_actions: 'refuse_action' } });
    await seedIntent(refused.mission_id);
    expect(await gate(refused.mission_id)).toMatchObject({ allowed: false, capBehavior: 'refuse_action' });
    await service.applyCapBehavior(refused.mission_id, 'max_actions', 'refuse_action');
    expect(await service.findById(refused.mission_id)).toMatchObject({ paused_at: null, completed_at: null, revoked_at: null });
  });

  it('a money cap of one day counts from the last midnight of the Mission\'s time zone; a cap of the Mission counts all of it', async () => {
    const day = await open({ coverage_cap_cents: 1_000, coverage_cap_period: 'day', cap_time_zone: 'Asia/Tokyo' });
    spendCalls.length = 0;
    spent = 400;
    expect(await gate(day.mission_id)).toMatchObject({ allowed: true });
    const [, , before, since] = spendCalls[0] as [string, string, Date | undefined, Date];
    expect(before).toBeUndefined();
    expect(since.getTime()).toBe(startOfDayIn(new Date(), 'Asia/Tokyo').getTime());
    expect(await service.getCapUsage(day.mission_id)).toMatchObject({ coverage_cents: { used: 400, limit: 1_000, period: 'day' } });

    const whole = await open({ coverage_cap_cents: 1_000 });
    spendCalls.length = 0;
    spent = 1_000;
    expect(await gate(whole.mission_id)).toMatchObject({ allowed: false, reason: 'cap_coverage_cap_cents', capBehavior: 'pause' });
    expect(spendCalls[0]).toEqual([operatorId, whole.mission_id]);
    spent = 0;
  });

  it('a spend the money cap refused at the ledger takes the cap\'s behaviour: pause by default', async () => {
    const { mission_id } = await open({ coverage_cap_cents: 100 });
    expect(await service.spendCapReached(mission_id)).toBe('pause');
    expect(await service.findById(mission_id)).toMatchObject({ paused_cap: 'coverage_cap_cents' });
    const ends = await open({ coverage_cap_cents: 100, cap_behavior: { coverage_cap_cents: 'end_mission' } });
    expect(await service.spendCapReached(ends.mission_id)).toBe('end_mission');
    expect(await service.findById(ends.mission_id)).toMatchObject({ terminal_state: 'completed_cap_breached' });
    expect(await service.spendCapReached(ends.mission_id)).toBeNull();
  });

  it('the owner sets the making allowance on a running Mission; an ended or another operator\'s Mission refuses', async () => {
    const { mission_id } = await open({});
    expect(await service.setMakingAllowance(mission_id, operatorId, 7_500)).toMatchObject({ making_orders_up_to_cents: 7_500 });
    expect(await service.setMakingAllowance(mission_id, operatorId, null)).toMatchObject({ making_orders_up_to_cents: null });
    await expect(service.setMakingAllowance(mission_id, otherOperatorId, 10)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await service.complete(mission_id, {});
    await expect(service.setMakingAllowance(mission_id, operatorId, 10)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('tells nobody when the decision hook fails, and the decision stands', async () => {
    const failing = new MissionService({
      repo: new MissionRepository(db),
      claimRegistry: claimRegistry as never,
      onDecision: vi.fn(async () => { throw new Error('wake store down'); }),
    });
    const { mission_id } = await failing.open({ operatorId, assignedAgentId: agentId, intent_summary: 'caps', max_actions: 1 });
    await seedIntent(mission_id);
    await failing.applyCapBehavior(mission_id, 'max_actions', 'pause');
    await expect(failing.review(mission_id, { operatorId, decision: 'continue' })).resolves.toMatchObject({ result: 'continued' });
  });
});
