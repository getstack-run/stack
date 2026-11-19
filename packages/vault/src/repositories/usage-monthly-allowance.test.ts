import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, operators, usageMonthlyAllowances } from '@stack/shared';
import { OperatorRepository } from './operator-repo.js';
import { UsageRepository } from './usage-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('monthly action allowance history', () => {
  const db = createDb(DATABASE_URL!);
  const run = Math.random().toString(36).slice(2);
  const operatorA = `op_allowance_a_${run}`;
  const operatorB = `op_allowance_b_${run}`;
  const usage = new UsageRepository(db);
  const engineRepo = new OperatorRepository(db);

  beforeAll(async () => {
    await db.insert(operators).values([
      {
        id: operatorA,
        email: `${operatorA}@example.test`,
        api_key_hash: `hash_${operatorA}`,
      },
      {
        id: operatorB,
        email: `${operatorB}@example.test`,
        api_key_hash: `hash_${operatorB}`,
      },
    ]);
  });

  afterAll(async () => {
    await db.delete(operators).where(eq(operators.id, operatorA));
    await db.delete(operators).where(eq(operators.id, operatorB));
  });

  it('snapshots no limit when the deployment names none, as an engine alone does', async () => {
    const month = new Date().toISOString().slice(0, 7) + '-01';

    await engineRepo.updateTier(operatorB, 'developer');
    await expect(usage.getMonthlyActionAllowance(operatorB, month)).resolves.toEqual({
      month,
      tier: 'developer',
      actions_limit: null,
    });
  });

  it('reads a saved closed month only for its operator', async () => {
    await db.insert(usageMonthlyAllowances).values({
      operator_id: operatorA,
      month: '2026-07-01',
      tier: 'pro',
      actions_limit: 1_500_000,
    });

    await expect(usage.getMonthlyActionAllowance(operatorA, '2026-07-01')).resolves.toEqual({
      month: '2026-07-01',
      tier: 'pro',
      actions_limit: 1_500_000,
    });
    await expect(usage.getMonthlyActionAllowance(operatorB, '2026-07-01')).resolves.toBeNull();
  });
});
