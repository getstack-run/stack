import { afterAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { auditLog, createDb, operators } from '@stack/shared';
import { AuditService } from './audit-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('AuditService caller transaction', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_audit_tx_${suffix}`;

  afterAll(async () => {
    await db.delete(auditLog).where(eq(auditLog.operator_id, operatorId)).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('rolls the audit entry back with the caller transaction', async () => {
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `hash_${operatorId}`,
    });
    const audit = new AuditService(db);

    await expect(db.transaction(async (tx) => {
      await (audit.write as unknown as (
        input: Parameters<AuditService['write']>[0],
        transaction: typeof tx,
      ) => Promise<string>)({
        ctx: {
          trace_id: `tr_${suffix}`,
          span_id: `sp_${suffix}`,
          operator_id: operatorId,
          agent_id: 'system',
          passport_jti: 'none',
        },
        layer: 'vault',
        action: 'test.atomic',
        outcome: 'success',
      }, tx);
      throw new Error('rollback_probe');
    })).rejects.toThrow('rollback_probe');

    expect(await db.select().from(auditLog).where(eq(auditLog.operator_id, operatorId)))
      .toHaveLength(0);
  });
});
