import { hashApiKey, ids, operators, type Database } from '@stack/shared';
import type { OperatorRepository } from '@stack/vault';
import { ne } from 'drizzle-orm';

/**
 * A self-managed install has no plans, no meter and no bill. Everything that
 * reads a plan reads `enterprise` (the contract plan: never refused for
 * payment, never charged, controls included, no allowance), and the licence
 * key gates the enterprise features by itself, so a plan can never stand in
 * for it. Every operator is moved to that plan at boot, and operators the
 * install creates start on it (`createSelfManagedOperator`).
 *
 * Returns how many operators it moved.
 */
export async function ensureSelfManagedPlan(db: Database, operatorRepo: OperatorRepository): Promise<number> {
  const rows = await db
    .select({ id: operators.id })
    .from(operators)
    .where(ne(operators.tier, 'enterprise'));
  // `updateTier` also re-snapshots the month's allowance for the new plan.
  for (const row of rows) await operatorRepo.updateTier(row.id, 'enterprise');
  if (rows.length > 0) console.log(`[self-managed] Moved ${rows.length} operator(s) to the install's contract plan.`);
  return rows.length;
}

/**
 * Create an operator on a self-managed install and return its API key, shown
 * once: only its hash is stored. An install has no sign-up page, so this is how
 * its first operator (the owner) and any further ones come to exist.
 */
export async function createSelfManagedOperator(
  db: Database,
  input: { email: string },
): Promise<{ operatorId: string; apiKey: string }> {
  const email = input.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('A valid email address is required');
  const apiKey = ids.apiKey();
  const operatorId = ids.operator();
  await db.insert(operators).values({
    id: operatorId,
    email,
    api_key_hash: hashApiKey(apiKey),
    tier: 'enterprise',
    claimed_at: new Date(),
  });
  return { operatorId, apiKey };
}

/**
 * Refuse, at boot, the settings a self-managed production install cannot run
 * safely without, so the failure is one clear line at start and not a 500 on
 * the first request.
 */
export function assertSelfManagedBoot(env: Record<string, string | undefined>): void {
  if (env['NODE_ENV'] !== 'production') return;
  const pepper = env['API_KEY_PEPPER'] ?? '';
  if (Buffer.byteLength(pepper, 'utf8') < 32) {
    throw new Error('[BOOT] API_KEY_PEPPER must be at least 32 bytes (generate one with: openssl rand -hex 32)');
  }
}
