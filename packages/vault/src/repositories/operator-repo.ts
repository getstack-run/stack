import { eq, inArray, and, or, isNotNull, sql } from 'drizzle-orm';
import {
  type Database,
  operators,
  agents,
  serviceConnections,
  serviceConfigurations,
  serviceIdentityRequirements,
  agentServiceGrants,
  passports,
  passportClaims,
  passportCheckpoints,
  passportCheckouts,
  passportReviews,
  dropoffs,
  identityClaims,
  identityVerificationSessions,
  teamMembers,
  operatorOauthApps,
  llmUsage,
  securityEvents,
  notificationChannels,
  notificationDestinations,
  oauthClients,
  oauthAuthorizationCodes,
  oauthRefreshTokens,
  oauthDeviceCodes,
  adminActions,
  partnerGrants,
  intentApprovals,
  missions,
  twinRuns,
  auditLog,
  usageDaily,
  usageMonthlyAllowances,
  operatorEmailChanges,
  magicLinkTokens,
  authorityIdempotencyKeys,
  receiverTransactionReceipts,
  authorityPresentations,
  authorityApprovalDecisions,
  authorityApprovalRequests,
  authorityUses,
  passportAuthorityBindings,
  authorityBindingProofs,
  authorityBindings,
  authorityProofDependencies,
  authorityProofs,
  authorityReceiverKeys,
  authorityProfileVersions,
  authorityReceivers,
  authorityPrincipals,
  proxyOperations,
  fleetPolicies,
  fleetPolicyRevisions,
  fleetMemberships,
  fleetMissions,
  fleetOperations,
  fleetMissionStarts,
  ConflictError,
  OperatorTier,
  LimitOverrides,
  erasedOperators,
} from '@stack/shared';
// The tier's limits are STACK's hosted plans; the engine's snapshot of them leaves with the entitlements seam.
import type { OperatorDeleteSlot, OperatorRepositoryOptions } from './operator-delete-steps.js';

export type DbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export type OperatorBillingSnapshot = {
  id: string;
  row_version: string;
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  tier: string;
  cmek_status: string;
};

export type OperatorBillingUpdate = {
  stripe_customer_id?: string;
  stripe_subscription_id?: string | null;
  billing_period_start?: Date | null;
  billing_period_end?: Date | null;
  purchased_seats?: number;
  tier?: string;
};

export class OperatorRepository {
  constructor(
    private db: Database,
    private readonly options: OperatorRepositoryOptions = {},
  ) {}

  private monthlyActionLimit(tier: OperatorTier, overrides: LimitOverrides | null): number {
    return this.options.monthlyActionLimit?.(tier, overrides) ?? Infinity;
  }

  /** Runs the steps a deployment put at a named point of an erasure; the engine alone has none. */
  private async runSteps(tx: DbTransaction, operatorId: string, slot: OperatorDeleteSlot): Promise<void> {
    for (const step of this.options.deleteSteps?.() ?? []) {
      if (step.slot === slot) await step.run(tx, operatorId);
    }
  }

  async findById(id: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor.select().from(operators).where(eq(operators.id, id)).limit(1);
    return row;
  }

  async findByIdForUpdate(id: string, transaction: DbTransaction) {
    const [row] = await transaction
      .select()
      .from(operators)
      .where(eq(operators.id, id))
      .for('update')
      .limit(1);
    return row;
  }

  async findBillingSnapshot(
    id: string,
    transaction?: DbTransaction,
    lockForUpdate = false,
  ): Promise<OperatorBillingSnapshot | undefined> {
    const executor = transaction ?? this.db;
    const query = executor
      .select({
        id: operators.id,
        row_version: sql<string>`xmin::text`,
        stripe_customer_id: operators.stripe_customer_id,
        stripe_subscription_id: operators.stripe_subscription_id,
        tier: operators.tier,
        cmek_status: operators.cmek_status,
      })
      .from(operators)
      .where(eq(operators.id, id));
    const [row] = lockForUpdate ? await query.for('update').limit(1) : await query.limit(1);
    if (!row) return undefined;
    return { ...row, row_version: String(row.row_version) };
  }

  async findByEmail(email: string) {
    return this.db.query.operators.findFirst({
      where: eq(operators.email, email),
    });
  }

  async findByApiKeyHash(hash: string) {
    return this.db.query.operators.findFirst({
      where: eq(operators.api_key_hash, hash),
    });
  }

  /**
   * Upgrade a stored api_key_hash in place.
   * Guarded on the OLD hash so a concurrent rotation can't be clobbered:
   * if the row's hash already changed, this no-ops.
   */
  async updateApiKeyHash(id: string, oldHash: string, newHash: string): Promise<void> {
    await this.db
      .update(operators)
      .set({ api_key_hash: newHash })
      .where(and(eq(operators.id, id), eq(operators.api_key_hash, oldHash)));
  }

  // ─── partner-tenancy ──────────────────────────────────────

  /**
   * Insert a new child operator under a partner. Used by
   * PartnerTenantService.createTenant; never called directly by the
   * dashboard signup path (which has its own email-verified flow).
   *
   * Caller is responsible for: id generation, api_key_hash computation,
   * synthesising a unique placeholder email, and verifying the
   * (parent_operator_id, external_customer_id) tuple is unique (the DB
   * has a partial unique index on it but the caller should fail-fast
   * with a friendlier error).
   */
  async insertChild(
    input: {
      id: string;
      email: string;
      api_key_hash: string;
      parent_operator_id: string;
      external_customer_id: string | null;
      tier?: string;
    },
    transaction?: DbTransaction,
  ) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .insert(operators)
      .values({
        id: input.id,
        email: input.email,
        api_key_hash: input.api_key_hash,
        parent_operator_id: input.parent_operator_id,
        external_customer_id: input.external_customer_id,
        tier: input.tier ?? 'free',
        is_partner: false, // children are never partners themselves
        is_admin: false,
        is_platform_staff: false,
      })
      .returning();
    if (!row) throw new Error('operators: insertChild returned no row');
    return row;
  }

  /**
   * List children of a partner. Returns the operator rows only — caller
   * (PartnerTenantService) joins aggregate counters and audit metadata
   * separately. NEVER returns audit content via this method.
   */
  async listChildren(parentOperatorId: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    return executor
      .select()
      .from(operators)
      .where(eq(operators.parent_operator_id, parentOperatorId));
  }

  /**
   * Find a single child operator scoped by parent. Returns null when
   * the child doesn't exist OR doesn't belong to this partner. Caller
   * surfaces 404 on null to avoid enumeration of foreign tenant ids.
   */
  async findChildScoped(childId: string, parentOperatorId: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .select()
      .from(operators)
      .where(and(eq(operators.id, childId), eq(operators.parent_operator_id, parentOperatorId)))
      .limit(1);
    return row;
  }

  /** Replace a child's API key hash: the key it had stops working at once. Scoped by parent. */
  async replaceChildApiKey(childId: string, parentOperatorId: string, apiKeyHash: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .update(operators)
      .set({ api_key_hash: apiKeyHash, updated_at: new Date() })
      .where(and(eq(operators.id, childId), eq(operators.parent_operator_id, parentOperatorId)))
      .returning({ id: operators.id });
    if (!row) throw new Error('operators: replaceChildApiKey matched no child');
  }

  /**
   * Soft-revoke a child operator. Sets status='deleted' + deleted_at;
   * does NOT cascade-delete owned data (audit chain remains intact for
   * the retention window). Cascade-revoke of webhooks happens at the
   * service layer.
   */
  async revokeChild(childId: string, parentOperatorId: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .update(operators)
      .set({ status: 'deleted', deleted_at: new Date(), updated_at: new Date() })
      .where(
        and(
          eq(operators.id, childId),
          eq(operators.parent_operator_id, parentOperatorId),
          eq(operators.status, 'active'),
        ),
      )
      .returning({ id: operators.id });
    return row !== undefined;
  }

  async updateTier(id: string, tier: string) {
    return this.updateStripeIds(id, { tier });
  }

  /**
   * Set a billing account's negotiated limits (null = tier defaults) and
   * re-snapshot the current month's action allowance so usage reports the
   * limit that is being enforced. Refuses tenants: a tenant draws from its
   * partner's limits and cannot hold its own (CHECK in migration 0092).
   */
  async setLimitOverrides(id: string, overrides: LimitOverrides | null) {
    return this.db.transaction(async (tx) => {
      const [current] = await tx.select().from(operators).where(eq(operators.id, id)).for('update');
      if (!current) return undefined;
      if (current.parent_operator_id) {
        throw new ConflictError("A tenant draws from its partner's limits and cannot hold its own");
      }
      const now = new Date();
      const [row] = await tx
        .update(operators)
        .set({ limit_overrides: overrides, updated_at: now })
        .where(eq(operators.id, id))
        .returning();
      if (!row) return row;
      const tier = OperatorTier.safeParse(row.tier);
      if (tier.success) {
        const limit = this.monthlyActionLimit(tier.data, overrides);
        const actionsLimit = limit === Infinity ? null : limit;
        const month = now.toISOString().slice(0, 7) + '-01';
        await tx
          .insert(usageMonthlyAllowances)
          .values({ operator_id: id, month, tier: tier.data, actions_limit: actionsLimit, updated_at: now })
          .onConflictDoUpdate({
            target: [usageMonthlyAllowances.operator_id, usageMonthlyAllowances.month],
            set: { tier: tier.data, actions_limit: actionsLimit, updated_at: now },
          });
      }
      return { previous: current.limit_overrides ?? null, row };
    });
  }

  /**
   * Staff-only partner flag and provider allowlist. A tenant can never be a
   * partner (partners are one level deep).
   */
  async setPartner(id: string, input: { isPartner: boolean; providers: string[] | null }) {
    return this.db.transaction(async (tx) => {
      const [current] = await tx.select().from(operators).where(eq(operators.id, id)).for('update');
      if (!current) return undefined;
      if (current.parent_operator_id && input.isPartner) {
        throw new ConflictError('A tenant cannot be a partner');
      }
      const [row] = await tx
        .update(operators)
        .set({ is_partner: input.isPartner, partner_providers: input.providers, updated_at: new Date() })
        .where(eq(operators.id, id))
        .returning();
      return row ? {
        previous: { is_partner: current.is_partner, partner_providers: current.partner_providers ?? null },
        row,
      } : undefined;
    });
  }

  /**
   * GDPR Art. 17 hard delete of an operator account and everything that
   * references it.
   *
   * ─── Why this method is long ──────────────────────────────────────────
   * Some foreign keys reference `operators.id` without ON DELETE CASCADE.
   * The self-referential `parent_operator_id` uses ON DELETE RESTRICT. Only
   * CASCADE and SET NULL links clean themselves up, so a
   * bare `DELETE FROM operators` — or a partial child sweep — raises a
   * foreign-key violation and rolls the whole transaction back. The previous
   * implementation deleted 13 child tables and missed the rest, which means
   * deletion failed outright for any operator that had ever used the
   * product (an OAuth refresh token, a notification destination, a
   * security event, or a checkout was enough). This method is the
   * exhaustive version, ordered children-before-parents.
   *
   * ─── Rules encoded below ──────────────────────────────────────────────
   * 1. CASCADE FKs get NO explicit delete — Postgres handles them when the
   *    `operators` row goes. They are listed in the "cascade-only" comment
   *    at the bottom so a future reader can tell "absent" from "forgotten".
   *    EXCEPTION: a cascading table that itself holds a NO ACTION FK into a
   *    table we delete EARLIER must be deleted explicitly, because its
   *    cascade only fires at the very end. That applies to `missions`
   *    (→ passport_claims), and to the tables a deployment adds, which its
   *    own delete steps handle.
   * 2. Rows owned by OTHER operators that point INTO this operator's rows
   *    are handled explicitly — nulled out when the pointer is nullable and
   *    the row is someone else's record to keep, deleted when the row is
   *    only meaningful while ours exists.
   * 3. Some cascading tables also need explicit deletion for privacy or
   *    dependency order. The per-table comments explain each exception.
   *
   * Throws ConflictError when the operator is a partner with child tenants
   * (`operators.parent_operator_id` is ON DELETE RESTRICT). Fail loudly:
   * silently orphaning or cascading someone else's tenants is worse than
   * refusing.
   */
  async deleteById(id: string, transaction?: DbTransaction) {
    const deleteInTransaction = async (tx: DbTransaction) => {
      const [operator] = await tx
        .select({ email: operators.email })
        .from(operators)
        .where(eq(operators.id, id))
        .for('update');
      const normalizedEmail = operator?.email.trim().toLowerCase();

      // ── Guard: child tenants block the delete (FK is ON DELETE RESTRICT).
      // Deleting a partner would either orphan or silently destroy child
      // operators that are their own data subjects. The caller must revoke
      // / delete the children first.
      const children = await tx
        .select({ id: operators.id })
        .from(operators)
        .where(eq(operators.parent_operator_id, id));
      if (children.length > 0) {
        throw new ConflictError(
          `Operator ${id} still has ${children.length} child tenant(s) ` +
            `(${children.map((c) => c.id).join(', ')}). Delete or revoke them ` +
            `before deleting the parent.`,
        );
      }

      // ── Collect the id sets we need for the transitive sweeps. Every
      // subsequent `inArray` is guarded on a non-empty list because drizzle
      // emits invalid SQL for `IN ()`.
      // Allow only this transaction's account-erasure path through the
      // immutable authority profile/binding DELETE guards. This setting is
      // transaction-local, and each trigger compares it to the row owner.
      await tx.execute(sql`select set_config('stack.operator_erasure_id', ${id}, true)`);

      const [agentRows, connectionRows, passportRows, memberRows, clientRows] = await Promise.all([
        tx.select({ id: agents.id }).from(agents).where(eq(agents.operator_id, id)),
        tx
          .select({ id: serviceConnections.id })
          .from(serviceConnections)
          .where(eq(serviceConnections.operator_id, id)),
        tx.select({ jti: passports.jti }).from(passports).where(eq(passports.operator_id, id)),
        tx.select({ id: teamMembers.id }).from(teamMembers).where(eq(teamMembers.operator_id, id)),
        tx
          .select({ id: oauthClients.id })
          .from(oauthClients)
          .where(eq(oauthClients.operator_id, id)),
      ]);

      const agentIds = agentRows.map((r) => r.id);
      const connectionIds = connectionRows.map((r) => r.id);
      const passportJtis = passportRows.map((r) => r.jti);
      const memberIds = memberRows.map((r) => r.id);
      const clientIds = clientRows.map((r) => r.id);

      // Rows of a deployment's own tables that point at this operator are deleted by its steps, at the
      // named points below (`operatorDeleteSteps`), in the order the engine's own statements need.
      await this.runSteps(tx, id, 'beforePlatformEdges');

      // ─── platform / partner edges ─────────────────────────────

      // Linked tokens cascade. Legacy pre-FK tokens can have no operator id,
      // so delete every challenge for the locked operator's normalized email.
      await tx
        .delete(magicLinkTokens)
        .where(
          or(
            eq(magicLinkTokens.operator_id, id),
            normalizedEmail
              ? sql`lower(trim(${magicLinkTokens.email})) = ${normalizedEmail}`
              : undefined,
          ),
        );

      // Both this operator's own staff actions AND platform-staff actions
      // TAKEN AGAINST them: the latter carry the operator's id plus a free-
      // text reason that can name them, so Art. 17 covers both directions.
      // The target FK cascades, but admin_operator_id does not. Delete both
      // directions explicitly so the action text is erased before the row.
      await tx
        .delete(adminActions)
        .where(or(eq(adminActions.admin_operator_id, id), eq(adminActions.target_operator_id, id)));

      // Grants where we are either side. Deleting the user's account ends
      // every partner's authority over it; deleting a partner ends its
      // authority over every user.
      await tx
        .delete(partnerGrants)
        .where(
          or(eq(partnerGrants.partner_operator_id, id), eq(partnerGrants.user_operator_id, id)),
        );

      // ─── OAuth 2.1 (codes/tokens → clients) ───────────────────
      //
      // Codes and tokens can hang off our operator_id, off a client we
      // registered, or off one of our team members — all three NO ACTION.
      await tx
        .delete(oauthAuthorizationCodes)
        .where(
          or(
            eq(oauthAuthorizationCodes.operator_id, id),
            clientIds.length > 0
              ? inArray(oauthAuthorizationCodes.client_id, clientIds)
              : undefined,
            memberIds.length > 0
              ? inArray(oauthAuthorizationCodes.member_id, memberIds)
              : undefined,
          ),
        );
      await tx
        .delete(oauthRefreshTokens)
        .where(
          or(
            eq(oauthRefreshTokens.operator_id, id),
            clientIds.length > 0 ? inArray(oauthRefreshTokens.client_id, clientIds) : undefined,
            memberIds.length > 0 ? inArray(oauthRefreshTokens.member_id, memberIds) : undefined,
          ),
        );
      await tx
        .delete(oauthDeviceCodes)
        .where(
          or(
            eq(oauthDeviceCodes.operator_id, id),
            clientIds.length > 0 ? inArray(oauthDeviceCodes.client_id, clientIds) : undefined,
            memberIds.length > 0 ? inArray(oauthDeviceCodes.member_id, memberIds) : undefined,
          ),
        );
      // Self-registered DCR clients carry operator_id = NULL and are NOT
      // ours to delete — the `eq` predicate skips them by construction.
      await tx.delete(oauthClients).where(eq(oauthClients.operator_id, id));

      // ─── notifications ────────────────────────────────────────
      // notification_channel_verifications cascades from both channels and
      // destinations, so it needs no explicit delete.
      await tx.delete(notificationChannels).where(eq(notificationChannels.operator_id, id));
      await tx.delete(notificationDestinations).where(eq(notificationDestinations.operator_id, id));

      // ─── accountability + claims graph ────────────────────────
      //
      // Order is load-bearing:
      //   passport_reviews → passport_checkouts (NOT NULL FK)
      //   intent_approvals + missions → passport_claims (NO ACTION FK)
      //   passport_claims → passports (cascade, but see below)
      await tx.delete(passportReviews).where(eq(passportReviews.operator_id, id));
      await tx.delete(passportCheckouts).where(eq(passportCheckouts.operator_id, id));
      await tx.delete(passportCheckpoints).where(eq(passportCheckpoints.operator_id, id));
      // Fleet rows retain references to Missions, agents, policies, claims,
      // and proxy operations. Remove the operator's graph leaf-to-root before
      // any of those parents. Do not sweep another operator's rows by policy
      // ID; an inconsistent cross-tenant edge must fail the transaction.
      await tx.delete(fleetOperations).where(eq(fleetOperations.operator_id, id));
      await tx.delete(fleetMissions).where(eq(fleetMissions.operator_id, id));
      await tx.delete(fleetMissionStarts).where(eq(fleetMissionStarts.operator_id, id));
      await tx.delete(fleetMemberships).where(eq(fleetMemberships.operator_id, id));
      // Proxy attempts cascade from these rows. Delete before approvals,
      // authority uses, passports and connections because each operation
      // binds all four in the same tenant.
      await tx.delete(proxyOperations).where(eq(proxyOperations.operator_id, id));
      await tx.delete(intentApprovals).where(eq(intentApprovals.operator_id, id));
      await tx.delete(fleetPolicyRevisions).where(sql`${fleetPolicyRevisions.policy_id} in (
        select ${fleetPolicies.id} from ${fleetPolicies}
        where ${fleetPolicies.operator_id} = ${id}
      )`);
      await tx.delete(fleetPolicies).where(eq(fleetPolicies.operator_id, id));
      // Authority artifacts retain signed-claim, Mission, Passport, agent,
      // identity, receiver-key, profile, and service-connection references.
      // Remove the graph leaf-to-root before deleting those shared parents.
      await tx
        .delete(receiverTransactionReceipts)
        .where(eq(receiverTransactionReceipts.operator_id, id));
      await tx.delete(authorityPresentations).where(eq(authorityPresentations.operator_id, id));
      await tx
        .delete(authorityApprovalDecisions)
        .where(eq(authorityApprovalDecisions.operator_id, id));
      await tx
        .delete(authorityApprovalRequests)
        .where(eq(authorityApprovalRequests.operator_id, id));
      await tx.delete(authorityUses).where(eq(authorityUses.operator_id, id));
      await tx
        .delete(passportAuthorityBindings)
        .where(eq(passportAuthorityBindings.operator_id, id));
      await tx.delete(authorityBindingProofs).where(eq(authorityBindingProofs.operator_id, id));
      await tx.delete(authorityBindings).where(eq(authorityBindings.operator_id, id));
      await tx
        .delete(authorityProofDependencies)
        .where(eq(authorityProofDependencies.operator_id, id));
      await tx.delete(authorityProofs).where(eq(authorityProofs.operator_id, id));
      await tx.delete(authorityReceiverKeys).where(sql`${authorityReceiverKeys.receiver_id} in (
        select ${authorityReceivers.id} from ${authorityReceivers}
        where ${authorityReceivers.managed_by_operator_id} = ${id}
      )`);
      await tx
        .update(authorityReceivers)
        .set({ current_profile_version_id: null })
        .where(eq(authorityReceivers.managed_by_operator_id, id));
      await tx
        .delete(authorityProfileVersions)
        .where(eq(authorityProfileVersions.owner_operator_id, id));
      await tx.delete(authorityReceivers).where(eq(authorityReceivers.managed_by_operator_id, id));
      await tx.delete(authorityPrincipals).where(eq(authorityPrincipals.operator_id, id));
      await tx.delete(authorityIdempotencyKeys).where(eq(authorityIdempotencyKeys.operator_id, id));
      await this.runSteps(tx, id, 'afterAuthorityGraph');

      // Mission-bound security events use a composite NO ACTION FK to
      // missions. Remove them before missions so account erasure cannot be
      // blocked by a durable Home-source attribution row.
      await tx.delete(securityEvents).where(eq(securityEvents.operator_id, id));
      // A drop-off deposited under a Mission holds the same kind of key to missions (its recipients go with it, by
      // cascade); the sweep further down also takes the ones that name this operator's agents from another account.
      await tx.delete(dropoffs).where(eq(dropoffs.operator_id, id));
      // `missions` cascades on operator_id, but it holds a NO ACTION FK into
      // passport_claims which we delete two statements from now — so its
      // cascade would fire too late. Explicit delete required.
      await tx.delete(missions).where(eq(missions.operator_id, id));
      // twin_runs now cascades with missions. This explicit JTI sweep also
      // covers legacy rows whose mission reference predates the NOT VALID FK.
      if (passportJtis.length > 0) {
        await tx
          .delete(twinRuns)
          .where(
            or(
              inArray(twinRuns.real_passport_jti, passportJtis),
              inArray(twinRuns.twin_passport_jti, passportJtis),
            ),
          );
      }
      // passport_claims rows now cascade by passport or non-null operator_id.
      // The explicit sweep keeps the erasure boundary visible and removes
      // envelope-shaped rows before their signing keys disappear. Their
      // `subject` URI embeds the operator id and the COSE envelope is signed
      // under the operator's key — squarely personal data.
      await tx.delete(passportClaims).where(eq(passportClaims.operator_id, id));
      await tx.delete(passports).where(eq(passports.operator_id, id));

      // Exact billing allocations point at holds, LLM rows and machine rows: a deployment's steps delete them first.
      await this.runSteps(tx, id, 'beforeLlmUsage');
      await tx.delete(llmUsage).where(eq(llmUsage.operator_id, id));
      await this.runSteps(tx, id, 'afterLlmUsage');

      // ─── services + agents graph ──────────────────────────────
      if (agentIds.length > 0 || connectionIds.length > 0) {
        await tx
          .delete(agentServiceGrants)
          .where(
            or(
              agentIds.length > 0 ? inArray(agentServiceGrants.agent_id, agentIds) : undefined,
              connectionIds.length > 0
                ? inArray(agentServiceGrants.service_connection_id, connectionIds)
                : undefined,
            ),
          );
      }
      await tx
        .delete(dropoffs)
        .where(
          or(
            eq(dropoffs.operator_id, id),
            agentIds.length > 0 ? inArray(dropoffs.from_agent_id, agentIds) : undefined,
            agentIds.length > 0 ? inArray(dropoffs.to_agent_id, agentIds) : undefined,
          ),
        );
      await tx.delete(serviceConnections).where(eq(serviceConnections.operator_id, id));
      await tx.delete(serviceConfigurations).where(eq(serviceConfigurations.operator_id, id));
      await tx
        .delete(serviceIdentityRequirements)
        .where(eq(serviceIdentityRequirements.operator_id, id));
      await tx.delete(identityClaims).where(eq(identityClaims.operator_id, id));
      await tx
        .delete(identityVerificationSessions)
        .where(eq(identityVerificationSessions.operator_id, id));
      await tx.delete(operatorOauthApps).where(eq(operatorOauthApps.operator_id, id));
      await tx.delete(usageDaily).where(eq(usageDaily.operator_id, id));
      await tx.delete(operatorEmailChanges).where(eq(operatorEmailChanges.operator_id, id));
      // team_members must follow service_connections + the OAuth sweep —
      // both carry nullable member_id FKs with NO ACTION.
      await tx.delete(teamMembers).where(eq(teamMembers.operator_id, id));
      // inbound_webhooks.agent_id is ON DELETE SET NULL, so agents can go
      // before the webhook rows cascade with the operator.
      await tx.delete(agents).where(eq(agents.operator_id, id));

      // ─── the audit chain ──────────────────────────────────────
      //
      // DELIBERATE, NARROW EXCEPTION to the append-only invariant of the
      // audit log (hash-chained: INSERT only, no UPDATE/DELETE).
      //
      // Why deleting is the right call, not a shortcut:
      //  - audit_log rows carry operator_id, agent_id, passport_jti, action
      //    and free-text error_message. That is personal data of an
      //    identified account holder; Art. 17(1) applies and none of the
      //    Art. 17(3) exceptions fit. There is no statutory retention duty
      //    on a product telemetry/evidence chain (unlike the accounting
      //    records in payout ledgers, which is exactly
      //    why those are severed rather than deleted above).
      //  - The chain is PER-OPERATOR (AuditService.write scopes it by
      //    operator_id alone): cross-tenant chain linking is
      //    structurally impossible. So removing this operator's rows cannot
      //    break any other tenant's chain — the blast radius is exactly the
      //    account being erased.
      //  - The append-only rule governs the RUNTIME write path (no in-place
      //    edits, no selective redaction, so tamper-evidence holds while the
      //    account lives). Executing a lawful erasure once, at account
      //    close, in the same transaction that removes the account itself,
      //    is a different operation from mutating a live chain.
      //  - Keeping it would make the product's "hard-deleted immediately"
      //    promise false.
      //
      // CONSEQUENCES, stated rather than hidden:
      //  - Irreversible. The operator's evidence packs can no longer be
      //    reproduced or re-verified after this runs.
      //  - Any external chain-head anchor already published for this
      //    operator (external_anchors, which cascades away here, plus the
      //    public commits in the anchor registry) becomes unverifiable —
      //    there is no longer a chain to replay against it. The published
      //    artifacts are bare hashes, so nothing leaks, but a third party
      //    holding one can no longer confirm it.
      //  - Migration 0045 adds a NOT VALID ON DELETE CASCADE FK from new
      //    audit rows to operators. This explicit sweep keeps the erasure
      //    boundary visible. The cascade is the final concurrency guard for
      //    a valid audit insert that races this sweep. Legacy orphans remain
      //    untouched. If retention is ever decided to win, this statement,
      //    the FK, and the public erasure promise must change together.
      await tx.delete(auditLog).where(eq(auditLog.operator_id, id));

      // ─── the operator row ────────────────────────────────────
      //
      // Deleting this cascades the remaining CASCADE children, none of which
      // hold a NO ACTION FK into anything
      // already deleted above:
      //   audit_archive_segments, cmek_migrations, external_anchors,
      //   governance_approvals,
      //   inbound_webhooks (→ inbound_webhook_receipts), llm_usage,
      //   oidc_idp_configs, operator_detector_config,
      //   operator_erasure_jobs, operator_pii_config, operator_signing_keys,
      //   spiffe_trust_domains, sso_verified_domains,
      //   wimse_issuers.
      // Adding explicit deletes for those would be redundant, so they are
      // named here instead — "absent" vs "forgotten" must stay legible.
      await tx.delete(operators).where(eq(operators.id, id));

      // The record that this account was erased, in the same transaction: an erased account whose row is not here
      // cannot be told from one that never existed, so a restore from an older snapshot could not delete it again.
      await tx.insert(erasedOperators).values({ operator_id: id }).onConflictDoNothing();
    };
    if (transaction) return deleteInTransaction(transaction);
    return this.db.transaction(deleteInTransaction);
  }

  async updateIdentitySettings(
    id: string,
    data: {
      identity_claim_ttl?: string;
      identity_claim_inheritance?: string;
      identity_auto_revoke?: boolean;
    },
  ) {
    const [row] = await this.db
      .update(operators)
      .set({ ...data, updated_at: new Date() })
      .where(eq(operators.id, id))
      .returning();
    return row;
  }

  async updateStripeIds(id: string, data: OperatorBillingUpdate, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    if (data.tier === undefined) {
      const [row] = await executor
        .update(operators)
        .set({ ...data, updated_at: new Date() })
        .where(eq(operators.id, id))
        .returning();
      return row;
    }

    const parsedTier = OperatorTier.safeParse(data.tier);
    if (!parsedTier.success) throw new Error(`Invalid operator tier: ${data.tier}`);
    const tier = parsedTier.data;
    const now = new Date();
    const month = now.toISOString().slice(0, 7) + '-01';

    const update = async (tx: DbTransaction) => {
      const [row] = await tx
        .update(operators)
        .set({ ...data, tier, updated_at: now })
        .where(eq(operators.id, id))
        .returning();
      if (!row) return row;

      // Snapshot the allowance this account actually has: the tier default
      // with any negotiated override on top. An unreadable override is
      // snapshotted as the tier default rather than failing the tier write.
      const overrides = LimitOverrides.safeParse(row.limit_overrides ?? {});
      const configuredLimit = this.monthlyActionLimit(tier, overrides.success ? overrides.data : null);
      const actionsLimit = configuredLimit === Infinity ? null : configuredLimit;
      await tx
        .insert(usageMonthlyAllowances)
        .values({
          operator_id: id,
          month,
          tier,
          actions_limit: actionsLimit,
          updated_at: now,
        })
        .onConflictDoUpdate({
          target: [usageMonthlyAllowances.operator_id, usageMonthlyAllowances.month],
          set: {
            tier,
            actions_limit: actionsLimit,
            updated_at: now,
          },
        });
      return row;
    };
    return transaction ? update(transaction) : this.db.transaction(update);
  }

  // ─── CMEK (migration 0034) ──────────────────────────────────────────

  /**
   * Return the operator's CMEK state in the shape the KmsService resolver
   * expects. Returns status='none' if the operator row is missing — fail-
   * open here is safe because the operator_id came from auth and the row
   * would have been missing for unrelated reasons.
   */
  async getCmekState(id: string): Promise<{
    keyArn: string | null;
    status: 'none' | 'migrating' | 'active' | 'revoking' | 'revoked';
  }> {
    const row = await this.db.query.operators.findFirst({
      where: eq(operators.id, id),
      columns: { cmek_key_arn: true, cmek_status: true },
    });
    if (!row) return { keyArn: null, status: 'none' };
    return {
      keyArn: row.cmek_key_arn,
      status: row.cmek_status as 'none' | 'migrating' | 'active' | 'revoking' | 'revoked',
    };
  }

  async setCmekConfig(
    id: string,
    data: {
      cmek_key_arn?: string | null;
      cmek_status?: 'none' | 'migrating' | 'active' | 'revoking' | 'revoked';
      cmek_activated_at?: Date | null;
    },
    transaction?: DbTransaction,
  ) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .update(operators)
      .set({ ...data, updated_at: new Date() })
      .where(eq(operators.id, id))
      .returning();
    return row;
  }

  /**
   * Find operators whose CMEK status is one of the supplied values. Used by
   * the migration worker to discover work — typically called with
   * `['migrating', 'revoking']` to pick up operators that need backfill.
   * isNotNull(cmek_key_arn) is a defensive filter: a 'none' row should
   * never carry an arn, but the constraint allows historical revoked rows
   * to keep their arn so we don't accidentally process a no-arn operator.
   */
  async findByCmekStatus(
    statuses: Array<'none' | 'migrating' | 'active' | 'revoking' | 'revoked'>,
  ) {
    if (statuses.length === 0) return [];
    return this.db
      .select()
      .from(operators)
      .where(and(inArray(operators.cmek_status, statuses), isNotNull(operators.cmek_key_arn)));
  }
}
