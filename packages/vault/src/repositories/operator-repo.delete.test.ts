import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { eq, sql } from 'drizzle-orm';
import {
  createDb,
  type Database,
  ConflictError,
  operators,
  auditLog,
  twinRuns,
  inboundWebhookReceipts,
  fleetPolicies,
  fleetPolicyRevisions,
  fleetMemberships,
  fleetMissions,
  fleetOperations,
  fleetMissionStarts,
  operatorPiiConfig,
  usageDaily,
  usageDailyByAction,
  usageMonthlyAllowances,
  operatorEmailChanges,
  operatorEmailDeliveryJobs,
  auditArchiveSegments,
  operatorErasureJobs,
  magicLinkTokens,
  authorityPrincipals,
  authorityProofs,
  authorityBindings,
  authorityPresentations,
  receiverTransactionReceipts,
  authorityIdempotencyKeys,
  controlSockets,
  controlDecisions,
  controlEventOutbox,
  controlPolicies,
  controlPolicyRevisions,
  controlReviews,
  connectLinks,
  ssoVerifiedDomains,
} from '@stack/shared';
import { OperatorRepository } from './operator-repo.js';
import { OPERATOR_DELETE_SLOTS, type OperatorDeleteStep } from './operator-delete-steps.js';
import {
  ENGINE_OPERATOR_FOREIGN_KEYS,
  SEEDED_DB_TIMEOUT_MS,
  countEngineRowsOfVictim,
  createDeleteFixture,
  hasKeysOutsideTheEngine,
  operatorForeignKeys,
  seedEngineFixtures,
  tearDownEngineFixtures,
} from './operator-delete.test-support.js';

/**
 * GDPR Art. 17 — operator hard-delete of the engine's own tables, against a REAL Postgres.
 *
 * This test exists because the bug it pins is a foreign-key bug, and a
 * fake-`db` unit test (the convention for the other repo tests in this
 * directory) cannot observe a foreign-key violation. The only honest proof
 * is seeding every table that references `operators.id` — directly or
 * transitively — and watching the transaction either commit or roll back.
 *
 * It seeds the engine's tables only and deletes through a repository with no
 * steps, which is what an install has. STACK's hosted deployment adds tables of
 * its own and deletes them in steps of its own; the same deletion over both is
 * proved by the hosted build's own test.
 *
 * Requires a migrated test database and Redis.
 * Run it with:
 *   cd packages/vault && DATABASE_URL=postgresql://<user>:<password>@localhost:5432/<database> pnpm test
 */

const DATABASE_URL = process.env.DATABASE_URL ?? process.env.STACK_TEST_DATABASE_URL;

if (!DATABASE_URL) {
  // Loud, not silent: a skipped GDPR test reads like a passing one otherwise.
  console.warn(
    '\n[operator-repo.delete.test] SKIPPED — no DATABASE_URL. ' +
      'This suite is the only proof that account deletion works; ' +
      'start the dev stack and re-run before trusting a green suite.\n',
  );
}

const fixture = createDeleteFixture();
const { RUN, VICTIM, PUBLISHER, PARTNER } = fixture;

describe.skipIf(!DATABASE_URL)('OperatorRepository.deleteById (GDPR Art. 17)', () => {
  let db: Database;
  let repo: OperatorRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new OperatorRepository(db);
    await seedEngineFixtures(db, fixture);
  }, SEEDED_DB_TIMEOUT_MS);

  afterAll(async () => {
    await tearDownEngineFixtures(db, repo, fixture);
  }, SEEDED_DB_TIMEOUT_MS);

  it('seeded a row in every engine table that references the operator', async () => {
    // Guards the test itself: if a future schema adds an FK to operators.id
    // and the seed does not cover it, this assertion tells you before the
    // delete quietly "passes" against an under-seeded fixture.
    const found = await operatorForeignKeys(db);
    const covered = new Set(found);
    // Every key the engine's seed is written for is really there ...
    expect(ENGINE_OPERATOR_FOREIGN_KEYS.filter((key) => !covered.has(key))).toEqual([]);
    // ... and on a database that has only the engine's tables there is no other one. (Beside the hosted deployment's
    // tables the same check over both lists is the hosted test's.)
    if (!hasKeysOutsideTheEngine(found)) {
      expect([...found].sort()).toEqual([...ENGINE_OPERATOR_FOREIGN_KEYS].sort());
    }
    expect(covered).toContain('admin_actions.target_operator_id');
    expect(covered).toContain('passport_claims.operator_id');
    expect(covered).toContain('magic_link_tokens.operator_id');
    expect(covered).toContain('operator_email_delivery_jobs.operator_id');
    expect(covered).toContain('operator_decisions.operator_id');
    expect(covered).toContain('services.operator_id');
    expect(covered).toContain('proxy_operations.operator_id');
    expect(covered).toContain('proxy_operation_replacement_acknowledgements.operator_id');
    expect(covered).toContain('proxy_accounting_receipts.operator_id');
    expect(covered).toContain('fleet_policies.operator_id');
    expect(covered).toContain('fleet_memberships.operator_id');
    expect(covered).toContain('fleet_missions.operator_id');
    expect(covered).toContain('fleet_operations.operator_id');
    expect(covered).toContain('fleet_mission_starts.operator_id');

    const [pii, usage, usageDetail, usageAllowance, emailChange, emailDelivery, archiveSegment, erasureJob, magicLinks] =
      await Promise.all([
        db.select().from(operatorPiiConfig).where(eq(operatorPiiConfig.operator_id, VICTIM)),
        db.select().from(usageDaily).where(eq(usageDaily.operator_id, VICTIM)),
        db.select().from(usageDailyByAction).where(eq(usageDailyByAction.operator_id, VICTIM)),
        db.select().from(usageMonthlyAllowances).where(eq(usageMonthlyAllowances.operator_id, VICTIM)),
        db.select().from(operatorEmailChanges).where(eq(operatorEmailChanges.operator_id, VICTIM)),
        db.select().from(operatorEmailDeliveryJobs).where(eq(operatorEmailDeliveryJobs.operator_id, VICTIM)),
        db.select().from(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, VICTIM)),
        db.select().from(operatorErasureJobs).where(eq(operatorErasureJobs.operator_id, VICTIM)),
        db.select().from(magicLinkTokens).where(eq(magicLinkTokens.operator_id, VICTIM)),
      ]);
    expect(pii).toHaveLength(1);
    expect(usage).toHaveLength(1);
    expect(usageDetail).toHaveLength(1);
    expect(usageAllowance).toHaveLength(1);
    expect(emailChange).toHaveLength(1);
    expect(emailDelivery).toHaveLength(1);
    expect(archiveSegment).toHaveLength(1);
    expect(erasureJob).toHaveLength(1);
    expect(magicLinks).toHaveLength(1);
    for (const table of [fleetPolicies, fleetMemberships, fleetMissions, fleetOperations, fleetMissionStarts]) {
      const rows = await db.select().from(table).where(eq(table.operator_id, VICTIM));
      expect(rows).toHaveLength(1);
    }

    const authorityRows = await db.execute(sql`
      SELECT
        (SELECT count(*) FROM authority_principals WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_receivers WHERE managed_by_operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_profile_versions WHERE owner_operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_proofs WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_proof_dependencies WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_bindings WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_binding_proofs WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_uses WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_approval_requests WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_approval_decisions WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_presentations WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM receiver_transaction_receipts WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM passport_authority_bindings WHERE operator_id = ${VICTIM})
        + (SELECT count(*) FROM authority_idempotency_keys WHERE operator_id = ${VICTIM}) AS total
    `);
    expect(Number((authorityRows[0] as { total: string }).total)).toBe(17);

    // Connect links add 1: the link carries its owner and cascades with it.
    expect(covered).toContain('connect_links.operator_id');
    expect(await db.select().from(connectLinks).where(eq(connectLinks.operator_id, VICTIM))).toHaveLength(1);
    // The control socket adds 3: the customer's socket, its decisions and its event outbox.
    for (const table of ['control_sockets', 'control_decisions', 'control_event_outbox']) {
      expect(covered).toContain(`${table}.operator_id`);
    }
    for (const table of [controlSockets, controlDecisions, controlEventOutbox]) {
      expect(await db.select().from(table).where(eq(table.operator_id, VICTIM))).toHaveLength(1);
    }
    // Single sign-on's verified domains add 1: the account's claimed e-mail domains go with it.
    expect(covered).toContain('sso_verified_domains.operator_id');
    expect(await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.operator_id, VICTIM))).toHaveLength(1);
    // Policies add 3: the customer's policies, their revisions and the actions they held.
    for (const table of ['control_policies', 'control_policy_revisions', 'control_reviews']) {
      expect(covered).toContain(`${table}.operator_id`);
    }
    for (const table of [controlPolicies, controlPolicyRevisions, controlReviews]) {
      expect(await db.select().from(table).where(eq(table.operator_id, VICTIM))).toHaveLength(1);
    }
  });

  it('rejects every partial erasure and terminal presentation with retained request ciphertext', async () => {
    const fixtureId = fixture.id;
    await expect(db.update(authorityPrincipals).set({
      status: 'erased', erased_at: new Date(),
    }).where(eq(authorityPrincipals.id, fixtureId('prn')))).rejects.toThrow();
    await expect(db.update(authorityProofs).set({
      status: 'erased', erased_at: new Date(), native_evidence_encrypted: null,
      normalized_facts_encrypted: null,
    }).where(eq(authorityProofs.id, fixtureId('prf_identity')))).rejects.toThrow();
    await expect(db.update(authorityBindings).set({
      status: 'erased',
    }).where(eq(authorityBindings.id, fixtureId('abn')))).rejects.toThrow();
    await expect(db.update(authorityPresentations).set({
      status: 'accepted',
    }).where(eq(authorityPresentations.id, fixtureId('prs')))).rejects.toThrow();
    await expect(db.update(receiverTransactionReceipts).set({
      erased_at: new Date(), native_receipt_encrypted: null,
    }).where(eq(receiverTransactionReceipts.id, fixtureId('rtr')))).rejects.toThrow();
    await expect(db.update(authorityIdempotencyKeys).set({
      workflow_phase: 'erased',
    }).where(eq(authorityIdempotencyKeys.id, fixtureId('aik')))).rejects.toThrow();
  });

  it('runs a deployment\'s steps at their named points, in order, inside the erasure\'s own transaction', async () => {
    const own = `op_del_steps_${RUN}`;
    await db.insert(operators).values({ id: own, email: `steps+${RUN}@example.invalid`, api_key_hash: `hash_steps_${RUN}` });
    const ran: string[] = [];
    const steps: OperatorDeleteStep[] = [...OPERATOR_DELETE_SLOTS].reverse().map((slot) => ({
      slot,
      async run(tx, operatorId) {
        // The operator is still there until the very last statement, and the step sees the same transaction.
        const [row] = await tx.select({ id: operators.id }).from(operators).where(eq(operators.id, operatorId));
        ran.push(`${slot}:${row ? 'present' : 'gone'}`);
      },
    }));
    const withSteps = new OperatorRepository(db, { deleteSteps: () => steps });
    await withSteps.deleteById(own);
    expect(ran).toEqual(OPERATOR_DELETE_SLOTS.map((slot) => `${slot}:present`));
    expect(await db.select().from(operators).where(eq(operators.id, own))).toHaveLength(0);
  });

  it('rolls the whole erasure back when a step fails', async () => {
    const own = `op_del_rollback_${RUN}`;
    await db.insert(operators).values({ id: own, email: `rollback+${RUN}@example.invalid`, api_key_hash: `hash_rollback_${RUN}` });
    const failing: OperatorDeleteStep = {
      slot: 'beforeLlmUsage',
      async run() {
        throw new Error('a step of the deployment failed');
      },
    };
    const withFailing = new OperatorRepository(db, { deleteSteps: () => [failing] });
    await expect(withFailing.deleteById(own)).rejects.toThrow('a step of the deployment failed');
    expect(await db.select().from(operators).where(eq(operators.id, own))).toHaveLength(1);
    // Nothing was written to the list of erased accounts either: the erasure did not happen.
    const erased = (await db.execute(sql`SELECT * FROM erased_operators WHERE operator_id = ${own}`)) as unknown as unknown[];
    expect(erased).toHaveLength(0);
    await repo.deleteById(own);
  });

  it('deletes an operator that has data in every engine table that references it', async () => {
    await expect(repo.deleteById(VICTIM)).resolves.not.toThrow();

    const remaining = await db.select().from(operators).where(eq(operators.id, VICTIM));
    expect(remaining).toHaveLength(0);
    for (const table of [fleetPolicies, fleetMemberships, fleetMissions, fleetOperations, fleetMissionStarts]) {
      const rows = await db.select().from(table).where(eq(table.operator_id, VICTIM));
      expect(rows).toHaveLength(0);
    }
    expect(await db.select().from(fleetPolicyRevisions)
      .where(eq(fleetPolicyRevisions.policy_id, `flp_del_${RUN}`))).toHaveLength(0);
  }, SEEDED_DB_TIMEOUT_MS);

  it('leaves no orphan rows in any engine table keyed on the deleted operator', async () => {
    expect(await countEngineRowsOfVictim(db, fixture)).toBe(0);
  });

  it('records the erasure on the list of erased accounts, with the operator id and nothing else', async () => {
    // The list is what lets a restore from an older snapshot erase the account again: it is written in the same
    // transaction as the delete, and it is the one table about the operator that survives it.
    const rows = (await db.execute(sql`SELECT * FROM erased_operators WHERE operator_id = ${VICTIM}`)) as unknown as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(Object.keys(rows[0]!).sort()).toEqual(['erased_at', 'operator_id']);
  });

  it('sweeps rows keyed on the operator that have no FK to catch them', async () => {
    // audit_log, twin_runs and inbound_webhook_receipts carry the operator's
    // data but would NOT have blocked the delete. Regression guard: they must
    // be swept deliberately, not left as orphans.
    const audit = await db.select().from(auditLog).where(eq(auditLog.operator_id, VICTIM));
    expect(audit).toHaveLength(0);

    const twins = await db
      .select()
      .from(twinRuns)
      .where(eq(twinRuns.real_passport_jti, `pas_del_${RUN}`));
    expect(twins).toHaveLength(0);

    const receipts = await db
      .select()
      .from(inboundWebhookReceipts)
      .where(eq(inboundWebhookReceipts.webhook_id, `iwh_del_${RUN}`));
    expect(receipts).toHaveLength(0);
  });

  it("does not touch another operator's audit chain", async () => {
    const chain = await db.select().from(auditLog).where(eq(auditLog.operator_id, PUBLISHER));
    expect(chain).toHaveLength(1);
  });

  it('refuses to delete a partner that still has child tenants', async () => {
    await expect(repo.deleteById(PARTNER)).rejects.toBeInstanceOf(ConflictError);
    // And the partner is still there — the guard aborts before any deletion.
    const still = await db.select().from(operators).where(eq(operators.id, PARTNER));
    expect(still).toHaveLength(1);
  });
});
