import { eq, and } from 'drizzle-orm';
import type { JWK } from 'jose';
import { type Database, oidcIdpConfigs } from '@stack/shared';

/**
 * oidc_idp_configs repo. CRUD for per-operator OIDC IdP configuration
 * plus a JWKS last-known-good persistor used by OidcIdpProvider's
 * fail-open path when both Redis cache and upstream JWKS are
 * unreachable.
 */
export class OidcIdpConfigRepository {
  constructor(private db: Database) {}

  async create(data: typeof oidcIdpConfigs.$inferInsert) {
    const [row] = await this.db.insert(oidcIdpConfigs).values(data).returning();
    return row!;
  }

  async findById(id: string) {
    return this.db.query.oidcIdpConfigs.findFirst({
      where: eq(oidcIdpConfigs.id, id),
    });
  }

  /**
   * Resolve /login/sso/<slug> to a config. Requires the connection to be
   * active AND to have login switched on — the slug alone must never be
   * enough to start a login against a half-configured or disabled IdP.
   */
  async findBySsoSlug(slug: string) {
    return this.db.query.oidcIdpConfigs.findFirst({
      where: and(
        eq(oidcIdpConfigs.sso_slug, slug),
        eq(oidcIdpConfigs.active, true),
        eq(oidcIdpConfigs.sso_login_enabled, true),
      ),
    });
  }

  /**
   * One OIDC IdP per operator in v1 (unique index on operator_id).
   * Returns the active config or null.
   */
  async findActiveByOperator(operatorId: string) {
    return this.db.query.oidcIdpConfigs.findFirst({
      where: and(eq(oidcIdpConfigs.operator_id, operatorId), eq(oidcIdpConfigs.active, true)),
    });
  }

  async update(id: string, data: Partial<typeof oidcIdpConfigs.$inferInsert>) {
    const [row] = await this.db
      .update(oidcIdpConfigs)
      .set({ ...data, updated_at: new Date() })
      .where(eq(oidcIdpConfigs.id, id))
      .returning();
    return row;
  }

  async delete(id: string) {
    const [row] = await this.db.delete(oidcIdpConfigs).where(eq(oidcIdpConfigs.id, id)).returning();
    return row;
  }

  /**
   * Best-effort durability for the last successfully-fetched JWKS.
   * Called by OidcIdpProvider after every successful upstream fetch.
   * Failures here are non-fatal — the provider wraps in try/catch.
   */
  async persistLastKnownGoodJwks(
    configId: string,
    jwks: { keys: JWK[] },
    fetchedAt: Date,
  ): Promise<void> {
    await this.db
      .update(oidcIdpConfigs)
      .set({
        jwks_cached_jwks_json: jwks,
        jwks_cached_at: fetchedAt,
        updated_at: new Date(),
      })
      .where(eq(oidcIdpConfigs.id, configId));
  }
}
