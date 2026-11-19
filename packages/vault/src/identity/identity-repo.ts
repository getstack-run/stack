import { eq, and, isNull, gt, asc, sql } from 'drizzle-orm';
import {
  type Database,
  identityClaims,
  identityProviders,
  serviceIdentityRequirements,
} from '@stack/shared';

export class IdentityRepository {
  constructor(private db: Database) {}

  // ── Identity Providers ───────────────────────────────────────────

  async listActiveProviders() {
    return this.db.query.identityProviders.findMany({
      where: eq(identityProviders.active, true),
    });
  }

  async findProviderByKey(providerKey: string) {
    return this.db.query.identityProviders.findFirst({
      where: eq(identityProviders.provider_key, providerKey),
    });
  }

  // ── Identity Claims ──────────────────────────────────────────────

  async createClaim(data: typeof identityClaims.$inferInsert) {
    const [row] = await this.db.insert(identityClaims).values(data).returning();
    return row!;
  }

  /**
   * link an identity_claims row to its paired
   * operator-scoped identity_claim envelope in passport_claims.
   * Idempotent on null; never clobbers an existing link.
   */
  async linkClaim(identityClaimRowId: string, envelopeClaimId: string): Promise<void> {
    await this.db
      .update(identityClaims)
      .set({ claim_id: envelopeClaimId })
      .where(
        and(
          eq(identityClaims.id, identityClaimRowId),
          isNull(identityClaims.claim_id),
        ),
      );
  }

  async findClaimById(id: string) {
    return this.db.query.identityClaims.findFirst({
      where: eq(identityClaims.id, id),
    });
  }

  /** Get operator's valid claims: not revoked, not expired */
  async findValidClaims(operatorId: string) {
    return this.db.query.identityClaims.findMany({
      where: and(
        eq(identityClaims.operator_id, operatorId),
        isNull(identityClaims.revoked_at),
        gt(identityClaims.expires_at, new Date()),
      ),
    });
  }

  async findClaimsByOperator(operatorId: string) {
    return this.db.query.identityClaims.findMany({
      where: eq(identityClaims.operator_id, operatorId),
    });
  }

  /**
   * Count L2 (identity-layer) claims for this operator, ignoring revoked ones.
   * Used to gate the "first L2 verification is free" billing rule — if the
   * caller has ever completed an L2 before (even if it later expired), they
   * pay for subsequent ones.
   */
  async countLifetimeL2ClaimsForOperator(operatorId: string): Promise<number> {
    const rows = await this.db
      .select({ id: identityClaims.id })
      .from(identityClaims)
      .where(
        and(
          eq(identityClaims.operator_id, operatorId),
          eq(identityClaims.layer, 'identity'),
        ),
      );
    return rows.length;
  }

  async revokeClaim(id: string) {
    const [row] = await this.db
      .update(identityClaims)
      .set({ revoked_at: new Date() })
      .where(eq(identityClaims.id, id))
      .returning();
    return row;
  }

  /**
   * Delete a claim entirely — GDPR right to erasure.
   * Removes PII permanently, not just soft-delete via revoked_at.
   */
  async deleteClaim(id: string) {
    await this.db
      .delete(identityClaims)
      .where(eq(identityClaims.id, id));
  }

  // ── Service Identity Requirements ────────────────────────────────
  //
  // every read/write/delete is scoped by operator_id. A row is
  // the requiring OPERATOR's own identity gate on a service — never
  // global-catalog state. The enforcement path (passport-service.verify)
  // calls findRequirementsByService with the verifying passport's
  // operator_id, so one tenant never enforces (or reads, or deletes)
  // another tenant's policy.

  async findRequirementsByService(operatorId: string, serviceId: string) {
    return this.db.query.serviceIdentityRequirements.findMany({
      where: and(
        eq(serviceIdentityRequirements.operator_id, operatorId),
        eq(serviceIdentityRequirements.service_id, serviceId),
      ),
      orderBy: [
        asc(serviceIdentityRequirements.layer),
        asc(serviceIdentityRequirements.requires_claim),
        asc(serviceIdentityRequirements.id),
      ],
    });
  }

  async replaceRequirements(
    operatorId: string,
    serviceId: string,
    requirement: typeof serviceIdentityRequirements.$inferInsert | null,
  ) {
    return this.db.transaction(async (tx) => {
      const lockKey = `${operatorId}:${serviceId}`;
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))`);
      await tx.delete(serviceIdentityRequirements).where(
        and(
          eq(serviceIdentityRequirements.operator_id, operatorId),
          eq(serviceIdentityRequirements.service_id, serviceId),
        ),
      );
      if (requirement === null) return [];
      const [row] = await tx.insert(serviceIdentityRequirements).values({
        ...requirement,
        operator_id: operatorId,
        service_id: serviceId,
      }).returning();
      return [row!];
    });
  }

  async upsertRequirement(data: typeof serviceIdentityRequirements.$inferInsert) {
    return this.db.transaction(async (tx) => {
      const lockKey = `${data.operator_id}:${data.service_id}`;
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))`);
      const [row] = await tx
        .insert(serviceIdentityRequirements)
        .values(data)
        // Stable conflict target: repeated sets for the same
        // (operator, service, layer, claim) update in place. The pre-fix
        // target was the always-fresh `id`, so every POST inserted a new
        // row and requirements accumulated with no cleanup path.
        .onConflictDoUpdate({
          target: [
            serviceIdentityRequirements.operator_id,
            serviceIdentityRequirements.service_id,
            serviceIdentityRequirements.layer,
            serviceIdentityRequirements.requires_claim,
          ],
          set: {
            minimum_assurance: data.minimum_assurance,
            accepted_providers: data.accepted_providers,
            required_scopes: data.required_scopes,
            requires_pii: data.requires_pii,
            lawful_basis: data.lawful_basis,
          },
        })
        .returning();
      return row!;
    });
  }

  async deleteRequirement(operatorId: string, serviceId: string, id: string) {
    await this.db.transaction(async (tx) => {
      const lockKey = `${operatorId}:${serviceId}`;
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))`);
      await tx
        .delete(serviceIdentityRequirements)
        .where(
          and(
            eq(serviceIdentityRequirements.operator_id, operatorId),
            eq(serviceIdentityRequirements.service_id, serviceId),
            eq(serviceIdentityRequirements.id, id),
          ),
        );
    });
  }
}
