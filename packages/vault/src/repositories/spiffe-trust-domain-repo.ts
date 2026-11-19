import { eq, and } from 'drizzle-orm';
import type { JWK } from 'jose';
import { type Database, spiffeTrustDomains } from '@stack/shared';
import type { JwksPersistor } from '../identity/spiffe-svid-validator.js';

/**
 * spiffe_trust_domains repo + JwksPersistor implementation.
 *
 * Two roles in one class:
 *
 *   1. CRUD operations the dashboard / route layer use to manage
 *      operator-configured trust domains (jwks_uri, audience pin,
 *      SPIFFE-ID-to-agent mapping policy).
 *
 *   2. JwksPersistor — the SPIFFE SVID validator (P1.3) calls
 *      `persistLastKnownGood(id, jwks, fetchedAt)` after every
 *      successful upstream fetch, writing the JWKS into the
 *      `jwks_cached_jwks_json` column. That column is the durability
 *      tier for fail-open: when Redis is gone AND upstream is
 *      unreachable, the row's last-known-good JWKS keeps SVID
 *      validation working until Redis or upstream recover.
 */
export class SpiffeTrustDomainRepository implements JwksPersistor {
  constructor(private db: Database) {}

  // ── CRUD ────────────────────────────────────────────────────────

  async create(data: typeof spiffeTrustDomains.$inferInsert) {
    const [row] = await this.db.insert(spiffeTrustDomains).values(data).returning();
    return row!;
  }

  async findById(id: string) {
    return this.db.query.spiffeTrustDomains.findFirst({
      where: eq(spiffeTrustDomains.id, id),
    });
  }

  /**
   * Find one operator-scoped config by trust_domain. The unique index
   * on (operator_id, trust_domain) guarantees at most one match.
   */
  async findByOperatorAndTrustDomain(operatorId: string, trustDomain: string) {
    return this.db.query.spiffeTrustDomains.findFirst({
      where: and(
        eq(spiffeTrustDomains.operator_id, operatorId),
        eq(spiffeTrustDomains.trust_domain, trustDomain),
      ),
    });
  }

  /**
   * Find every active config matching a trust_domain across operators.
   * The workload route uses this to enumerate candidate configs for an
   * incoming SVID — a SPIFFE ID's trust_domain may match multiple
   * operators' rows, and the SPIFFE-ID-to-agent map disambiguates which
   * one owns the workload.
   */
  async findActiveByTrustDomain(trustDomain: string) {
    return this.db.query.spiffeTrustDomains.findMany({
      where: and(
        eq(spiffeTrustDomains.trust_domain, trustDomain),
        eq(spiffeTrustDomains.active, true),
      ),
    });
  }

  async listByOperator(operatorId: string) {
    return this.db.query.spiffeTrustDomains.findMany({
      where: eq(spiffeTrustDomains.operator_id, operatorId),
    });
  }

  async update(id: string, data: Partial<typeof spiffeTrustDomains.$inferInsert>) {
    const [row] = await this.db
      .update(spiffeTrustDomains)
      .set({ ...data, updated_at: new Date() })
      .where(eq(spiffeTrustDomains.id, id))
      .returning();
    return row;
  }

  async delete(id: string) {
    const [row] = await this.db
      .delete(spiffeTrustDomains)
      .where(eq(spiffeTrustDomains.id, id))
      .returning();
    return row;
  }

  // ── JwksPersistor ────────────────────────────────────────────────

  /**
   * Write the latest successfully-fetched JWKS to the row's
   * jwks_cached_jwks_json column. Validator failures here are
   * non-fatal (the validator wraps the call in try/catch), so this
   * method is best-effort durability. Idempotent: a stale or duplicate
   * fetch just overwrites the same row.
   */
  async persistLastKnownGood(
    trustDomainId: string,
    jwks: { keys: JWK[] },
    fetchedAt: Date,
  ): Promise<void> {
    await this.db
      .update(spiffeTrustDomains)
      .set({
        jwks_cached_jwks_json: jwks,
        jwks_cached_at: fetchedAt,
        updated_at: new Date(),
      })
      .where(eq(spiffeTrustDomains.id, trustDomainId));
  }
}
