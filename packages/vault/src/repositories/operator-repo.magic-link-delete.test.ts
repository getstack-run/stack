import { afterAll, describe, expect, it } from 'vitest';
import { eq, sql } from 'drizzle-orm';
import { createDb, operators } from '@stack/shared';
import { OperatorRepository } from './operator-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

function postgresCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  if ('code' in error && typeof error.code === 'string') return error.code;
  if ('cause' in error) return postgresCode(error.cause);
  return undefined;
}

describeWithDb('OperatorRepository magic-link erasure', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_magic_delete_${suffix}`;
  const storedEmail = `Mixed.Delete.${suffix}@Example.Test`;
  const normalizedEmail = storedEmail.trim().toLowerCase();
  const legacyEmail = `  ${storedEmail.toUpperCase()}  `;
  const linkedId = `mlt_linked_${suffix}`;
  const legacyId = `mlt_legacy_${suffix}`;
  const otherId = `mlt_other_${suffix}`;
  const lateId = `mlt_late_${suffix}`;

  afterAll(async () => {
    await db.execute(sql`
      DELETE FROM magic_link_tokens
      WHERE id IN (${linkedId}, ${legacyId}, ${otherId}, ${lateId})
    `).catch(() => undefined);
    await db.delete(operators).where(eq(operators.id, operatorId)).catch(() => undefined);
  });

  it('deletes linked and legacy email tokens and rejects a late operator insert', async () => {
    await db.insert(operators).values({
      id: operatorId,
      email: storedEmail,
      api_key_hash: `hash_${operatorId}`,
    });
    await db.execute(sql`
      INSERT INTO magic_link_tokens
        (id, email, token_hash, intent, operator_id, used, expires_at)
      VALUES
        (${linkedId}, ${normalizedEmail}, ${`hash_${linkedId}`}, 'login', ${operatorId}, false, clock_timestamp() + interval '1 hour'),
        (${legacyId}, ${legacyEmail}, ${`hash_${legacyId}`}, 'login', NULL, false, clock_timestamp() + interval '1 hour'),
        (${otherId}, ${`other_${normalizedEmail}`}, ${`hash_${otherId}`}, 'login', NULL, false, clock_timestamp() + interval '1 hour')
    `);

    await new OperatorRepository(db).deleteById(operatorId);

    const matching = await db.execute(sql`
      SELECT id FROM magic_link_tokens
      WHERE id IN (${linkedId}, ${legacyId})
    `) as unknown as Array<{ id: string }>;
    expect(matching).toHaveLength(0);
    const unrelated = await db.execute(sql`
      SELECT id FROM magic_link_tokens WHERE id = ${otherId}
    `) as unknown as Array<{ id: string }>;
    expect(unrelated).toEqual([{ id: otherId }]);

    let lateErrorCode: string | undefined;
    try {
      await db.execute(sql`
        INSERT INTO magic_link_tokens
          (id, email, token_hash, intent, operator_id, used, expires_at)
        VALUES
          (${lateId}, ${normalizedEmail}, ${`hash_${lateId}`}, 'login', ${operatorId}, false, clock_timestamp() + interval '1 hour')
      `);
    } catch (error) {
      lateErrorCode = postgresCode(error);
    }
    expect(lateErrorCode).toBe('23503');
  });
});
