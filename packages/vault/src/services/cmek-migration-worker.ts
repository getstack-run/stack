import { eq, sql } from 'drizzle-orm';
import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import { safeErrorSummary } from '@stack/shared';
import {
  type Database,
  serviceConnections,
  identityClaims,
  oidcIdpConfigs,
  operatorOauthApps,
  inboundWebhooks,
  notificationDestinations,
  notificationChannels,
  proxyOperations,
  missionOutputs,
  intentApprovals,
} from '@stack/shared';
import type { KmsService } from '../crypto/kms.js';
import { openDownstreamSecret, webhookSecretContext } from './inbound-webhook-secret.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import type { CmekMigrationRepository, CmekMigrationRow, MigrationDirection } from '../repositories/cmek-migration-repo.js';
import { CMEK_LONG_LIVED_STORES } from './cmek-service.js';
import { ServiceRepository } from '../repositories/service-repo.js';

const PAGE_SIZE = 100;

/**
 * A store of ciphertext a deployment adds to the engine's. The migration row of
 * the store names it; the step re-encrypts one operator's rows of it and marks
 * the row's progress (running, bumped, completed) like the engine's own do.
 */
export interface CmekMigrationStep {
  table: string;
  migrate(
    operatorId: string,
    row: CmekMigrationRow,
    context: { db: Database; kms: KmsService; migrationRepo: CmekMigrationRepository },
  ): Promise<void>;
}

/**
 * Per-store backfill plan. For each long-lived ciphertext column the worker
 * needs to know how to (a) find rows belonging to an operator, (b) decrypt
 * existing rows (envelope path vs direct-encrypt), (c) re-encrypt under the
 * target key (the resolver picks it from operator status), (d) write back.
 *
 * KmsService.encrypt() routes through the per-operator CMEK resolver
 * automatically based on operator.cmek_status:
 *   - migrating  → customer key (new writes target the customer key so
 *                  the worker's verifier can prove zero rows under the
 *                  source key before flipping to 'active')
 *   - revoking   → platform default key (worker re-encrypts customer-keyed
 *                  rows back to the platform key)
 *   - active     → customer key
 *   - none/revoked → platform key
 *
 * So the worker does NOT pick a key explicitly. It decrypts under whatever
 * the envelope's keyRef says (or AWS-KMS-infers for direct-encrypt rows),
 * then re-encrypts and KmsService picks the right target.
 *
 * Identity claims rows + identity provider sessions + skills + drop-offs
 * all use the envelope path. Skill invocations and notification webhook
 * secrets use encryptDirect.
 * dropoff_packages and a deployment's per-call stores are EPHEMERAL and handled at toggle
 * time (auto-completed in CmekService.enable/disable); only the 8 long-
 * lived stores are backfilled by the worker.
 */
export class CmekMigrationWorker {
  constructor(
    private deps: {
      db: Database;
      kms: KmsService;
      operatorRepo: OperatorRepository;
      migrationRepo: CmekMigrationRepository;
      stackSystemOperatorId: string;
      /** Redis publish hook so peer machines invalidate their per-operator
       * cache when an operator's status flips. */
      publishCmekUpdated?: (operatorId: string) => Promise<void> | void;
      /** Redis SETNX-lock primitive so two worker machines don't both
       * process the same (operator, table) row. Returns true if lock
       * was acquired. */
      acquireLock?: (key: string, ttlSeconds: number) => Promise<boolean>;
      releaseLock?: (key: string) => Promise<void>;
      /** Stores of ciphertext the deployment adds to the engine's (its skills). */
      extraSteps?: readonly CmekMigrationStep[];
    },
  ) {}

  /** Every store the backfill covers: the engine's, then the deployment's. */
  private longLivedStores(): readonly string[] {
    return [...CMEK_LONG_LIVED_STORES, ...(this.deps.extraSteps ?? []).map((step) => step.table)];
  }

  /**
   * Run one tick of CMEK migration work across all operators that need it.
   * Designed to be called from a polling worker on a 10-second cadence;
   * each tick processes one batch per (operator, table) and returns. The
   * next tick picks up where it left off.
   */
  async tick(): Promise<void> {
    const ops = await this.deps.operatorRepo.findByCmekStatus(['migrating', 'revoking']);
    for (const op of ops) {
      // Defense in depth — operator_id was asserted at toggle-on time, but
      // we re-assert here so a direct DB mutation or a future code path
      // that bypasses CmekService.enable doesn't slip the dogfood operator
      // into a customer-managed key.
      if (this.deps.stackSystemOperatorId && op.id === this.deps.stackSystemOperatorId) {
        console.warn('[CMEK] refusing to migrate op_stack_system as dogfood carve-out:', op.cmek_status);
        continue;
      }
      try {
        await this.processOperator(op.id, (op.cmek_status as 'migrating' | 'revoking'));
      } catch (err) {
        console.error('[CMEK] operator tick failed:', op.id, safeErrorSummary(err));
      }
    }
  }

  private async processOperator(operatorId: string, status: 'migrating' | 'revoking'): Promise<void> {
    const direction: MigrationDirection = status === 'migrating' ? 'enable' : 'disable';
    const rows = await this.deps.migrationRepo.listByOperatorAndDirection(operatorId, direction);
    // A deployment can add an encrypted store while a migration is running.
    // Its ciphertext must participate before the operator can leave migration.
    const stores = this.longLivedStores();
    if (rows.length > 0) {
      for (const table of stores) {
        if (!rows.some(row => row.table_name === table)) {
          rows.push(await this.deps.migrationRepo.upsertPending(`cmkm_${randomUUID().replaceAll('-', '')}`, operatorId, direction, table));
        }
      }
    }

    // Process each LONG_LIVED store. Ephemeral stores are auto-completed in
    // CmekService.enable/disable; we skip them here.
    for (const row of rows) {
      if (row.status === 'completed' || row.status === 'failed') continue;
      if (!stores.includes(row.table_name)) continue;

      const lockKey = `cmek_migration:lock:${operatorId}:${row.table_name}:${direction}`;
      const got = this.deps.acquireLock ? await this.deps.acquireLock(lockKey, 600) : true;
      if (!got) continue; // another worker machine holds it

      try {
        await this.processTable(operatorId, row);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await this.deps.migrationRepo.markFailed(row.id, msg);
        console.error('[CMEK] migration failed:', row.id, row.table_name, safeErrorSummary(err));
      } finally {
        if (this.deps.releaseLock) await this.deps.releaseLock(lockKey);
      }
    }

    // If every long-lived row is completed, flip operator status.
    const final = await this.deps.migrationRepo.listByOperatorAndDirection(operatorId, direction);
    const longLivedOnly = final.filter((r) => stores.includes(r.table_name));
    const allDone = longLivedOnly.length === stores.length && longLivedOnly.every((r) => r.status === 'completed');
    if (!allDone) return;

    if (direction === 'enable') {
      await this.deps.operatorRepo.setCmekConfig(operatorId, {
        cmek_status: 'active',
        cmek_activated_at: new Date(),
      });
    } else {
      await this.deps.operatorRepo.setCmekConfig(operatorId, {
        cmek_status: 'none',
        cmek_key_arn: null,
        cmek_activated_at: null,
      });
    }
    await this.deps.publishCmekUpdated?.(operatorId);
    console.log(`[CMEK] operator ${operatorId} migration ${direction} complete — status flipped`);
  }

  private async processTable(operatorId: string, row: CmekMigrationRow): Promise<void> {
    // Per-table dispatcher. Each migrator knows its column shape +
    // EncryptionContext layout (matching what chunk 3.5 set at write time).
    switch (row.table_name) {
      case 'service_connections':
        return this.migrateServiceConnections(operatorId, row);
      case 'identity_claims':
        return this.migrateIdentityClaims(operatorId, row);
      case 'oidc_idp_configs':
        return this.migrateOidcIdpConfigs(operatorId, row);
      case 'operator_oauth_apps':
        return this.migrateOperatorOauthApps(operatorId, row);
      case 'inbound_webhooks':
        return this.migrateInboundWebhooks(operatorId, row);
      case 'notification_destinations':
        return this.migrateNotificationDestinations(operatorId, row);
      case 'notification_channels':
        return this.migrateNotificationChannels(operatorId, row);
      case 'proxy_operations':
        return this.migrateProxyOperations(operatorId, row);
      case 'mission_outputs':
        return this.migrateMissionOutputs(operatorId, row);
      case 'intent_approvals':
        return this.migrateFleetReviews(operatorId, row);
      case 'identity_providers':
        // Legacy: removed from CMEK_LONG_LIVED_STORES in chunk 7. A
        // CmekMigrationRow for `identity_providers` could still exist
        // for any operator that enabled CMEK before that cleanup;
        // mark such rows completed (zero rows to migrate — the column
        // is global STACK-system state, not per-operator).
        await this.deps.migrationRepo.markRunning(row.id, 0);
        await this.deps.migrationRepo.markCompleted(row.id);
        return;
      default: {
        const step = this.deps.extraSteps?.find((candidate) => candidate.table === row.table_name);
        if (!step) throw new Error(`[CMEK] no migrator wired for table ${row.table_name}`);
        return step.migrate(operatorId, row, {
          db: this.deps.db,
          kms: this.deps.kms,
          migrationRepo: this.deps.migrationRepo,
        });
      }
    }
  }

  // ─── Per-store migrators ────────────────────────────────────────────

  private async migrateFleetReviews(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const condition = sql`${intentApprovals.operator_id} = ${operatorId} and ${intentApprovals.fleet_review_encrypted} is not null`;
    const countRows = await this.deps.db.select({ count: sql<number>`count(*)::int` }).from(intentApprovals).where(condition);
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);
    let offset = 0;
    while (true) {
      const rows = await this.deps.db.select().from(intentApprovals).where(condition).orderBy(intentApprovals.id).limit(PAGE_SIZE).offset(offset);
      if (rows.length === 0) break;
      for (const row of rows) {
        if (!row.fleet_review_key || !row.fleet_review_encrypted) throw new Error('Invalid input');
        const context = { operator_id: operatorId, store: 'fleet_review', review_key: row.fleet_review_key };
        const plaintext = await this.deps.kms.decrypt(row.fleet_review_encrypted, context);
        const encrypted = await this.deps.kms.encrypt(plaintext, context);
        await this.deps.db.update(intentApprovals).set({ fleet_review_encrypted: encrypted.ciphertext, fleet_review_key_ref: encrypted.keyRef })
          .where(eq(intentApprovals.id, row.id));
      }
      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  private async migrateMissionOutputs(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const countRows = await this.deps.db.select({ count: sql<number>`count(*)::int` }).from(missionOutputs)
      .where(eq(missionOutputs.operator_id, operatorId));
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);
    let offset = 0;
    while (true) {
      const rows = await this.deps.db.select().from(missionOutputs)
        .where(eq(missionOutputs.operator_id, operatorId)).orderBy(missionOutputs.mission_id).limit(PAGE_SIZE).offset(offset);
      if (rows.length === 0) break;
      for (const row of rows) {
        const context = { operator_id: operatorId, mission_id: row.mission_id, store: 'mission_output' };
        const plaintext = await this.deps.kms.decrypt(row.output_encrypted, context);
        const encrypted = await this.deps.kms.encrypt(plaintext, context);
        await this.deps.db.update(missionOutputs).set({ output_encrypted: encrypted.ciphertext, key_ref: encrypted.keyRef })
          .where(eq(missionOutputs.mission_id, row.mission_id));
      }
      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  private async migrateProxyOperations(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const countRows = await this.deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(proxyOperations)
      .where(eq(proxyOperations.operator_id, operatorId));
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);

    let offset = 0;
    while (true) {
      const rows = await this.deps.db.select({
        id: proxyOperations.id,
        prepared_request_encrypted: proxyOperations.prepared_request_encrypted,
        scope_descriptor_encrypted: proxyOperations.scope_descriptor_encrypted,
        response_encrypted: proxyOperations.response_encrypted,
        post_response_context_encrypted: proxyOperations.post_response_context_encrypted,
      }).from(proxyOperations)
        .where(eq(proxyOperations.operator_id, operatorId))
        .limit(PAGE_SIZE)
        .offset(offset);
      if (rows.length === 0) break;

      for (const r of rows) {
        const update: {
          prepared_request_encrypted?: string;
          prepared_request_key_ref?: string;
          scope_descriptor_encrypted?: string;
          scope_descriptor_key_ref?: string;
          response_encrypted?: string;
          response_key_ref?: string;
          response_ciphertext_bytes?: number;
          capacity_reserved_bytes?: number;
          capacity_used_bytes?: number;
          post_response_context_encrypted?: string;
          post_response_context_key_ref?: string;
        } = {};
        if (r.prepared_request_encrypted) {
          const ctx = {
            operator_id: operatorId,
            proxy_operation_id: r.id,
            envelope_version: '1',
            purpose: 'proxy_prepared_request',
          };
          const plain = await this.deps.kms.decrypt(r.prepared_request_encrypted, ctx);
          const encrypted = await this.deps.kms.encrypt(plain, ctx);
          update.prepared_request_encrypted = encrypted.ciphertext;
          update.prepared_request_key_ref = encrypted.keyRef;
        }
        if (r.response_encrypted) {
          const ctx = {
            operator_id: operatorId,
            proxy_operation_id: r.id,
            envelope_version: '1',
            purpose: 'proxy_final_response',
          };
          const plain = await this.deps.kms.decrypt(r.response_encrypted, ctx);
          const encrypted = await this.deps.kms.encrypt(plain, ctx);
          update.response_encrypted = encrypted.ciphertext;
          update.response_key_ref = encrypted.keyRef;
          const ciphertextBytes = Buffer.byteLength(encrypted.ciphertext, 'utf8');
          update.response_ciphertext_bytes = ciphertextBytes;
          update.capacity_reserved_bytes = ciphertextBytes;
          update.capacity_used_bytes = ciphertextBytes;
        }
        if (r.scope_descriptor_encrypted) {
          const ctx = {
            operator_id: operatorId,
            proxy_operation_id: r.id,
            envelope_version: '1',
            purpose: 'proxy_scope_descriptor',
          };
          const plain = await this.deps.kms.decrypt(r.scope_descriptor_encrypted, ctx);
          const encrypted = await this.deps.kms.encrypt(plain, ctx);
          update.scope_descriptor_encrypted = encrypted.ciphertext;
          update.scope_descriptor_key_ref = encrypted.keyRef;
        }
        if (r.post_response_context_encrypted) {
          const ctx = {
            operator_id: operatorId,
            proxy_operation_id: r.id,
            envelope_version: '1',
            purpose: 'proxy_post_response_work',
          };
          const plain = await this.deps.kms.decrypt(r.post_response_context_encrypted, ctx);
          const encrypted = await this.deps.kms.encrypt(plain, ctx);
          update.post_response_context_encrypted = encrypted.ciphertext;
          update.post_response_context_key_ref = encrypted.keyRef;
        }
        if (Object.keys(update).length > 0) {
          await this.deps.db.update(proxyOperations).set(update).where(eq(proxyOperations.id, r.id));
        }
      }

      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  private async migrateServiceConnections(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const countRows = await this.deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(serviceConnections)
      .where(eq(serviceConnections.operator_id, operatorId));
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);

    let offset = 0;
    while (true) {
      const rows = await this.deps.db
        .select({
          id: serviceConnections.id,
          provider: serviceConnections.provider,
          credential_encrypted: serviceConnections.credential_encrypted,
        })
        .from(serviceConnections)
        .where(eq(serviceConnections.operator_id, operatorId))
        .limit(PAGE_SIZE)
        .offset(offset);
      if (rows.length === 0) break;

      for (const r of rows) {
        await new ServiceRepository(this.deps.db).withCredentialLock(r.id, operatorId, async (current, tx) => {
          // OAuth rotation owns the same row lock. Re-read only after acquiring it.
          if (!current) return;
          const ctx = { operator_id: operatorId, provider: current.provider };
          const plaintext = await this.deps.kms.decrypt(current.credential_encrypted, ctx);
          const { ciphertext } = await this.deps.kms.encrypt(plaintext, ctx);
          await tx.update(serviceConnections).set({ credential_encrypted: ciphertext }).where(eq(serviceConnections.id, current.id));
        });
      }

      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  private async migrateIdentityClaims(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const countRows = await this.deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(identityClaims)
      .where(eq(identityClaims.operator_id, operatorId));
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);

    let offset = 0;
    while (true) {
      const rows = await this.deps.db
        .select({
          id: identityClaims.id,
          assertion_encrypted: identityClaims.assertion_encrypted,
          payload_encrypted: identityClaims.payload_encrypted,
        })
        .from(identityClaims)
        .where(eq(identityClaims.operator_id, operatorId))
        .limit(PAGE_SIZE)
        .offset(offset);
      if (rows.length === 0) break;

      for (const r of rows) {
        const update: { assertion_encrypted?: string; payload_encrypted?: string } = {};

        // assertion_encrypted is always present.
        const assertionCtx = { operator_id: operatorId, store: 'identity_claim_assertion' };
        const assertionPlain = await this.deps.kms.decrypt(r.assertion_encrypted, assertionCtx);
        const { ciphertext: assertionCt } = await this.deps.kms.encrypt(assertionPlain, assertionCtx);
        update.assertion_encrypted = assertionCt;

        // payload_encrypted only for L2 PII claims.
        if (r.payload_encrypted) {
          const piiCtx = { operator_id: operatorId, store: 'identity_claim_pii' };
          const piiPlain = await this.deps.kms.decrypt(r.payload_encrypted, piiCtx);
          const { ciphertext: piiCt } = await this.deps.kms.encrypt(piiPlain, piiCtx);
          update.payload_encrypted = piiCt;
        }

        // identity_claims has no updated_at column (immutable except for
        // revoked_at) — so we just update the ciphertext columns. The
        // re-encryption is a content-preserving rewrite, not a semantic
        // change, so the "updated" timestamp gap is intentional.
        await this.deps.db
          .update(identityClaims)
          .set(update)
          .where(eq(identityClaims.id, r.id));
      }

      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  private async migrateOidcIdpConfigs(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const countRows = await this.deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(oidcIdpConfigs)
      .where(eq(oidcIdpConfigs.operator_id, operatorId));
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);

    let offset = 0;
    while (true) {
      const rows = await this.deps.db
        .select({
          id: oidcIdpConfigs.id,
          client_secret_encrypted: oidcIdpConfigs.client_secret_encrypted,
        })
        .from(oidcIdpConfigs)
        .where(eq(oidcIdpConfigs.operator_id, operatorId))
        .limit(PAGE_SIZE)
        .offset(offset);
      if (rows.length === 0) break;

      for (const r of rows) {
        const ctx = { operator_id: operatorId, provider: 'oidc' };
        const plaintext = await this.deps.kms.decrypt(r.client_secret_encrypted, ctx);
        const { ciphertext } = await this.deps.kms.encrypt(plaintext, ctx);
        await this.deps.db
          .update(oidcIdpConfigs)
          .set({ client_secret_encrypted: ciphertext, updated_at: new Date() })
          .where(eq(oidcIdpConfigs.id, r.id));
      }

      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  private async migrateOperatorOauthApps(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const countRows = await this.deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(operatorOauthApps)
      .where(eq(operatorOauthApps.operator_id, operatorId));
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);

    let offset = 0;
    while (true) {
      const rows = await this.deps.db
        .select({
          id: operatorOauthApps.id,
          provider: operatorOauthApps.provider,
          client_secret_encrypted: operatorOauthApps.client_secret_encrypted,
        })
        .from(operatorOauthApps)
        .where(eq(operatorOauthApps.operator_id, operatorId))
        .limit(PAGE_SIZE)
        .offset(offset);
      if (rows.length === 0) break;

      for (const r of rows) {
        const ctx = { operator_id: operatorId, provider: r.provider, kind: 'oauth_app' };
        const plaintext = await this.deps.kms.decrypt(r.client_secret_encrypted, ctx);
        const { ciphertext } = await this.deps.kms.encrypt(plaintext, ctx);
        await this.deps.db
          .update(operatorOauthApps)
          .set({ client_secret_encrypted: ciphertext, updated_at: new Date() })
          .where(eq(operatorOauthApps.id, r.id));
      }

      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  // hardening — inbound_webhooks.webhook_secret_encrypted, its previous secret and the incoming provider secret.
  // Distinct from the other migrators in that the secrets are stored via
  // KmsService.encryptDirect (DIRECT_WRAP_MAGIC base64-encoded), not the
  // envelope path. AAD is {operator_id, webhook_id, purpose} — re-encryption MUST use the same AAD or
  // the receiver's decrypt path fails. The downstream secret's purpose is `inbound_webhook_downstream_secret`
  // for every row made since the keys were separated and `inbound_webhook_secret` for rows made before; a row
  // is opened under whichever it carries and written back under that one (`openDownstreamSecret`), and a row
  // that opens under neither stops the migration with its error rather than being overwritten.
  // `provider_signing_secret_encrypted` is sealed under `inbound_provider_signing_secret`.
  private async migrateInboundWebhooks(operatorId: string, mrow: CmekMigrationRow): Promise<void> {
    const countRows = await this.deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(inboundWebhooks)
      .where(eq(inboundWebhooks.operator_id, operatorId));
    await this.deps.migrationRepo.markRunning(mrow.id, countRows[0]?.count ?? 0);

    let offset = 0;
    while (true) {
      const rows = await this.deps.db
        .select({
          id: inboundWebhooks.id,
          webhook_secret_encrypted: inboundWebhooks.webhook_secret_encrypted,
          webhook_secret_previous_encrypted: inboundWebhooks.webhook_secret_previous_encrypted,
          provider_signing_secret_encrypted: inboundWebhooks.provider_signing_secret_encrypted,
        })
        .from(inboundWebhooks)
        .where(eq(inboundWebhooks.operator_id, operatorId))
        .limit(PAGE_SIZE)
        .offset(offset);
      if (rows.length === 0) break;

      for (const r of rows) {
        const current = await openDownstreamSecret(this.deps.kms, {
          operatorId,
          webhookId: r.id,
          sealed: r.webhook_secret_encrypted,
          allowLegacy: true,
        });
        const reWrapped = await this.deps.kms.encryptDirect(current.plain, {
          operatorId,
          context: webhookSecretContext(operatorId, r.id, current.purpose),
        });
        await this.deps.db
          .update(inboundWebhooks)
          .set({ webhook_secret_encrypted: reWrapped.toString('base64') })
          .where(eq(inboundWebhooks.id, r.id));
        // The downstream secret a rotation replaced is still a live secret for 24 hours.
        if (r.webhook_secret_previous_encrypted) {
          const previous = await openDownstreamSecret(this.deps.kms, {
            operatorId,
            webhookId: r.id,
            sealed: r.webhook_secret_previous_encrypted,
            allowLegacy: true,
          });
          const rewrappedPrevious = await this.deps.kms.encryptDirect(previous.plain, {
            operatorId,
            context: webhookSecretContext(operatorId, r.id, previous.purpose),
          });
          await this.deps.db
            .update(inboundWebhooks)
            .set({ webhook_secret_previous_encrypted: rewrappedPrevious.toString('base64') })
            .where(eq(inboundWebhooks.id, r.id));
        }
        // The secret the provider signs its deliveries with, kept for a row that has one.
        if (r.provider_signing_secret_encrypted) {
          const providerContext = { operator_id: operatorId, webhook_id: r.id, purpose: 'inbound_provider_signing_secret' };
          const provider = await this.deps.kms.decryptDirect(Buffer.from(r.provider_signing_secret_encrypted, 'base64'), {
            operatorId,
            expectedContext: providerContext,
          });
          const rewrappedProvider = await this.deps.kms.encryptDirect(provider, { operatorId, context: providerContext });
          await this.deps.db
            .update(inboundWebhooks)
            .set({ provider_signing_secret_encrypted: rewrappedProvider.toString('base64') })
            .where(eq(inboundWebhooks.id, r.id));
        }
      }

      await this.deps.migrationRepo.bumpProgress(mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(mrow.id);
  }

  private async migrateNotificationDestinations(
    operatorId: string,
    mrow: CmekMigrationRow,
  ): Promise<void> {
    await this.migrateNotificationSecrets({
      operatorId,
      mrow,
      table: notificationDestinations,
      purpose: 'notification_destination_webhook_secret',
    });
  }

  private async migrateNotificationChannels(
    operatorId: string,
    mrow: CmekMigrationRow,
  ): Promise<void> {
    await this.migrateNotificationSecrets({
      operatorId,
      mrow,
      table: notificationChannels,
      purpose: 'notification_channel_webhook_secret',
    });
  }

  private async migrateNotificationSecrets(args: {
    operatorId: string;
    mrow: CmekMigrationRow;
    table: typeof notificationDestinations | typeof notificationChannels;
    purpose: 'notification_destination_webhook_secret' | 'notification_channel_webhook_secret';
  }): Promise<void> {
    const countRows = await this.deps.db
      .select({ count: sql<number>`count(*)::int` })
      .from(args.table)
      .where(
        sql`${args.table.operator_id} = ${args.operatorId} and ${args.table.webhook_secret_encrypted} is not null`,
      );
    await this.deps.migrationRepo.markRunning(args.mrow.id, countRows[0]?.count ?? 0);

    let offset = 0;
    while (true) {
      const rows = await this.deps.db
        .select({
          id: args.table.id,
          webhook_secret_encrypted: args.table.webhook_secret_encrypted,
        })
        .from(args.table)
        .where(
          sql`${args.table.operator_id} = ${args.operatorId} and ${args.table.webhook_secret_encrypted} is not null`,
        )
        .limit(PAGE_SIZE)
        .offset(offset);
      if (rows.length === 0) break;

      for (const row of rows) {
        if (!row.webhook_secret_encrypted) continue;
        const context = {
          operator_id: args.operatorId,
          notification_resource_id: row.id,
          purpose: args.purpose,
        };
        const plaintext = await this.deps.kms.decryptDirect(
          Buffer.from(row.webhook_secret_encrypted, 'base64'),
          { operatorId: args.operatorId, expectedContext: context },
        );
        const encrypted = await this.deps.kms.encryptDirect(plaintext, {
          operatorId: args.operatorId,
          context,
        });
        await this.deps.db
          .update(args.table)
          .set({ webhook_secret_encrypted: encrypted.toString('base64') })
          .where(eq(args.table.id, row.id));
        // A destination keeps the secret a rotation replaced for 24 hours; it moves to the new key too.
        if (args.table === notificationDestinations) {
          const [held] = await this.deps.db
            .select({ previous: notificationDestinations.webhook_secret_previous_encrypted })
            .from(notificationDestinations)
            .where(eq(notificationDestinations.id, row.id));
          if (held?.previous) {
            const previous = await this.deps.kms.decryptDirect(Buffer.from(held.previous, 'base64'), {
              operatorId: args.operatorId,
              expectedContext: context,
            });
            const rewrapped = await this.deps.kms.encryptDirect(previous, { operatorId: args.operatorId, context });
            await this.deps.db
              .update(notificationDestinations)
              .set({ webhook_secret_previous_encrypted: rewrapped.toString('base64') })
              .where(eq(notificationDestinations.id, row.id));
          }
        }
      }

      await this.deps.migrationRepo.bumpProgress(args.mrow.id, rows.length);
      if (rows.length < PAGE_SIZE) break;
      offset += rows.length;
    }
    await this.deps.migrationRepo.markCompleted(args.mrow.id);
  }
}
