import { eq, and, isNull, sql } from 'drizzle-orm';
import { type Database, operatorSigningKeys } from '@stack/shared';

/**
 * operator_signing_keys repo. Part of the Signed Primitive epic.
 *
 * History-keyed table — one row per (operator_id, kid). On rotation the
 * prior row's retired_at is stamped; the row is NOT deleted. Verification
 * of historical claims keeps working because the operator's JWKS endpoint
 * (apps api src routes operator jwks.ts lands in) keeps
 * serving retired-but-not-revoked kids alongside the active one.
 *
 * revoked_at is reserved for emergency key compromise — when set, the
 * kid is removed from the JWKS and any claim signed under it stops
 * verifying. Don't conflate with retired_at.
 *
 * The dogfood operator (op_stack_system) should NEVER have a row here;
 * its claims keep signing under the deployment key stack-passport-v1.
 * The carve-out is asserted at the service layer + at the wiring layer
 * (apps/api/src/config/wiring/crypto-and-signing.ts), mirroring the CMEK 3-layer pattern.
 */
export class OperatorSigningKeyRepository {
  constructor(private db: Database) {}

  async insert(data: typeof operatorSigningKeys.$inferInsert) {
    const [row] = await this.db.insert(operatorSigningKeys).values(data).returning();
    return row!;
  }

  /**
   * The single active key for an operator: not retired, not revoked.
   * Returns undefined if no key exists yet (lazy generation path).
   */
  async findActiveByOperator(operatorId: string) {
    return this.db.query.operatorSigningKeys.findFirst({
      where: and(
        eq(operatorSigningKeys.operator_id, operatorId),
        isNull(operatorSigningKeys.retired_at),
        isNull(operatorSigningKeys.revoked_at),
      ),
    });
  }

  /**
   * All non-revoked keys for an operator — active + retired. Sorted by
   * created_at ascending so JWKS readers see the historical order. Used
   * by the operator JWKS endpoint and by the kid-prefix resolver.
   */
  async findAllByOperatorForJwks(operatorId: string) {
    return this.db.query.operatorSigningKeys.findMany({
      where: and(
        eq(operatorSigningKeys.operator_id, operatorId),
        isNull(operatorSigningKeys.revoked_at),
      ),
      orderBy: (k, { asc }) => [asc(k.created_at)],
    });
  }

  async findByKid(kid: string) {
    return this.db.query.operatorSigningKeys.findFirst({
      where: eq(operatorSigningKeys.kid, kid),
    });
  }

  /**
   * Find the highest version number ever issued for an operator (active,
   * retired, or revoked). Used by rotate() to pick the next kid suffix.
   * Returns 0 if no rows exist.
   */
  async findMaxVersion(operatorId: string): Promise<number> {
    const rows = await this.db.execute<{ max_version: number | null }>(sql`
      SELECT MAX(CAST(SUBSTRING(kid FROM ':claim:v([0-9]+)$') AS INTEGER)) AS max_version
      FROM operator_signing_keys
      WHERE operator_id = ${operatorId}
    `);
    const v = (rows as unknown as { max_version: number | null }[])[0]?.max_version;
    return v ?? 0;
  }

  /**
   * Stamp retired_at on a kid. Used by rotate() to retire the previous
   * active key after the new one is inserted in the same transaction.
   * Idempotent — re-retiring is a no-op (the partial index excludes
   * already-retired rows).
   */
  async markRetired(kid: string, when: Date = new Date()) {
    await this.db
      .update(operatorSigningKeys)
      .set({ retired_at: when })
      .where(and(eq(operatorSigningKeys.kid, kid), isNull(operatorSigningKeys.retired_at)));
  }

  /**
   * Emergency-only: stamp revoked_at on a kid. Removes it from the JWKS
   * and any claim signed under it stops verifying. Reserved for key
   * compromise; routine rotation uses markRetired instead.
   */
  async markRevoked(kid: string, when: Date = new Date()) {
    await this.db
      .update(operatorSigningKeys)
      .set({ revoked_at: when })
      .where(eq(operatorSigningKeys.kid, kid));
  }
}
