import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { AUDIT_RETENTION_DAYS, auditLog, createDb, operators, passportClaims, securityEvents } from '@stack/shared';
import { AuditService, PassportClaimsRepository, SecurityEventRepository } from '@stack/vault';
import { isDedicatedStackTestDatabase } from './test/dedicated-test-database.js';
import { createOwnDatabase, type OwnDatabase } from './test/own-database.js';

/**
 * The record is kept a year for every account, whatever tier its row carries: the audit log, the security events and
 * the signed claims. The prunes delete across every account, so this suite runs on a database of its own.
 */

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = isDedicatedStackTestDatabase(DATABASE_URL) ? describe : describe.skip;
const DAY_MS = 86_400_000;
const TIERS = ['free', 'developer', 'pro', 'business', 'enterprise'] as const;

describeWithDb('the retention prunes', () => {
  let own: OwnDatabase;
  let db: ReturnType<typeof createDb>;

  beforeAll(async () => {
    own = await createOwnDatabase(DATABASE_URL, 'retention');
    db = createDb(own.url);
    for (const tier of TIERS) {
      await db.insert(operators).values({ id: `op_ret_${tier}`, email: `${tier}@retention.invalid`, api_key_hash: `hash_${tier}`, tier });
    }
  }, 120_000);

  afterAll(async () => {
    await (db as unknown as { $client: { end(o: { timeout: number }): Promise<void> } } | undefined)?.$client.end({ timeout: 5 });
    await own?.drop();
  });

  /** One row of each table for the operator, the given number of days old. */
  async function seed(operatorId: string, ageDays: number, tag: string) {
    const at = new Date(Date.now() - ageDays * DAY_MS);
    await db.insert(auditLog).values({
      entry_id: `ae_${tag}`, trace_id: `tr_${tag}`, span_id: `sp_${tag}`, timestamp: at.getTime(), operator_id: operatorId,
      agent_id: 'agt_none', passport_jti: 'none', layer: 'system', action: 'retention.test', outcome: 'success',
      prev_entry_hash: '', entry_hash: `h_${tag}`, hash_version: 2, claim_binding_status: 'not_applicable',
    });
    await db.insert(securityEvents).values({
      id: `se_${tag}`, operator_id: operatorId, agent_id: 'agt_none', signal_type: 'retention_test', severity: 'info',
      message: 'retention test', created_at: at,
    } as typeof securityEvents.$inferInsert);
    await db.insert(passportClaims).values({
      claim_id: `pc_${tag}`, type: 'mission', body_json: {}, claim_hash: `ch_${tag}`, signature: 'sig', attached_at: at,
      operator_id: operatorId,
    } as typeof passportClaims.$inferInsert);
  }

  async function kept(tag: string) {
    const [audit] = await db.select({ id: auditLog.entry_id }).from(auditLog).where(eq(auditLog.entry_id, `ae_${tag}`));
    const [event] = await db.select({ id: securityEvents.id }).from(securityEvents).where(eq(securityEvents.id, `se_${tag}`));
    const [claim] = await db.select({ id: passportClaims.claim_id }).from(passportClaims).where(eq(passportClaims.claim_id, `pc_${tag}`));
    return { audit: Boolean(audit), event: Boolean(event), claim: Boolean(claim) };
  }

  it('keeps a year of record for every tier and deletes what is older', async () => {
    for (const tier of TIERS) {
      // Younger than a year.
      await seed(`op_ret_${tier}`, 100, `young_${tier}`);
      // Older than a year.
      await seed(`op_ret_${tier}`, AUDIT_RETENTION_DAYS + 5, `old_${tier}`);
    }

    await new AuditService(db).pruneExpired(AUDIT_RETENTION_DAYS);
    await new SecurityEventRepository(db).pruneExpired(AUDIT_RETENTION_DAYS);
    await new PassportClaimsRepository(db).pruneExpired(AUDIT_RETENTION_DAYS, 'op_stack_system');

    for (const tier of TIERS) {
      expect(await kept(`young_${tier}`), tier).toEqual({ audit: true, event: true, claim: true });
      expect(await kept(`old_${tier}`), tier).toEqual({ audit: false, event: false, claim: false });
    }
  });

  it('keeps an account\'s negotiated longer window for its audit log', async () => {
    await db.update(operators).set({ audit_retention_days_override: 800 }).where(eq(operators.id, 'op_ret_enterprise'));
    await seed('op_ret_enterprise', 500, 'negotiated');
    await new AuditService(db).pruneExpired(AUDIT_RETENTION_DAYS);
    expect((await kept('negotiated')).audit).toBe(true);
  });
});
