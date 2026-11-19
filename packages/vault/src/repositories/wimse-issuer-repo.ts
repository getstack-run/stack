import { eq, and } from 'drizzle-orm';
import type { JWK } from 'jose';
import { type Database, wimseIssuers } from '@stack/shared';
import type { WimseJwksPersistor } from '../identity/wimse-wit-validator.js';

/**
 * wimse_issuers repo + WimseJwksPersistor implementation. Mirrors the
 * SpiffeTrustDomainRepository shape and dual role: CRUD for the
 * dashboard / route layer, plus JWKS last-known-good durability for
 * the WIT validator.
 */
export class WimseIssuerRepository implements WimseJwksPersistor {
  constructor(private db: Database) {}

  // ── CRUD ────────────────────────────────────────────────────────

  async create(data: typeof wimseIssuers.$inferInsert) {
    const [row] = await this.db.insert(wimseIssuers).values(data).returning();
    return row!;
  }

  async findById(id: string) {
    return this.db.query.wimseIssuers.findFirst({
      where: eq(wimseIssuers.id, id),
    });
  }

  async findByOperatorAndIssuerUri(operatorId: string, issuerUri: string) {
    return this.db.query.wimseIssuers.findFirst({
      where: and(
        eq(wimseIssuers.operator_id, operatorId),
        eq(wimseIssuers.issuer_uri, issuerUri),
      ),
    });
  }

  /**
   * Find every active config matching an issuer URI across operators.
   * The /v1/workload/wit route uses this to enumerate candidates for an
   * incoming WIT — multiple operators may share the same issuer (e.g.
   * a SaaS workload-issuance vendor) and the workload_id_mapping_policy
   * disambiguates ownership.
   */
  async findActiveByIssuerUri(issuerUri: string) {
    return this.db.query.wimseIssuers.findMany({
      where: and(
        eq(wimseIssuers.issuer_uri, issuerUri),
        eq(wimseIssuers.active, true),
      ),
    });
  }

  async listByOperator(operatorId: string) {
    return this.db.query.wimseIssuers.findMany({
      where: eq(wimseIssuers.operator_id, operatorId),
    });
  }

  async update(id: string, data: Partial<typeof wimseIssuers.$inferInsert>) {
    const [row] = await this.db
      .update(wimseIssuers)
      .set({ ...data, updated_at: new Date() })
      .where(eq(wimseIssuers.id, id))
      .returning();
    return row;
  }

  async delete(id: string) {
    const [row] = await this.db
      .delete(wimseIssuers)
      .where(eq(wimseIssuers.id, id))
      .returning();
    return row;
  }

  // ── WimseJwksPersistor ────────────────────────────────────────────

  async persistLastKnownGood(
    issuerId: string,
    jwks: { keys: JWK[] },
    fetchedAt: Date,
  ): Promise<void> {
    await this.db
      .update(wimseIssuers)
      .set({
        jwks_cached_jwks_json: jwks,
        jwks_cached_at: fetchedAt,
        updated_at: new Date(),
      })
      .where(eq(wimseIssuers.id, issuerId));
  }
}
