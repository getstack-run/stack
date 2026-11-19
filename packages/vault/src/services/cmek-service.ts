import { randomBytes } from 'node:crypto';
import {
  CmekConfigurationError,
  CmekRevokedError,
  NotConfiguredError,
  NotFoundError,
} from '@stack/shared';
import type { KmsService } from '../crypto/kms.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import type {
  CmekMigrationRepository,
  CmekMigrationRow,
} from '../repositories/cmek-migration-repo.js';

/**
 * Tables that hold operator-owned ciphertext. The migration worker iterates
 * this list on both enable + disable. Some of them (dropoff_packages, and the
 * per-call stores a deployment adds) are ephemeral — short-TTL or per-call rows that age
 * out naturally. We do NOT backfill those; new writes go to the target key
 * via the KmsService resolver, old rows expire under the old key.
 *
 * The remaining long-lived stores must be eagerly re-encrypted so the
 * verifier can prove zero rows remain under the source key before flipping
 * status to 'active' (on enable) or 'none' (on disable).
 *
 * Source of truth: packages/shared/src/db/schema/ grep for `_encrypted`.
 * If a new ciphertext column lands, ADD IT HERE — silent omission is a
 * security regression because the new column would never get re-encrypted.
 */
export const CMEK_LONG_LIVED_STORES = [
  'service_connections', // credential_encrypted
  'identity_claims', // assertion_encrypted + payload_encrypted
  'oidc_idp_configs', // client_secret_encrypted
  'operator_oauth_apps', // client_secret_encrypted
  'inbound_webhooks', // webhook_secret_encrypted, webhook_secret_previous_encrypted, provider_signing_secret_encrypted
  'notification_destinations', // webhook_secret_encrypted
  'notification_channels', // legacy inline webhook_secret_encrypted
  'proxy_operations', // prepared_request_encrypted + response_encrypted (24h replay)
  'mission_outputs',
  'intent_approvals', // encrypted exact fleet review request
] as const;
// Note: `identity_providers.provider_data` IS encrypted but holds
// STACK-system catalog state (provider config seeded at install), NOT
// per-operator data. It stays under the platform key and is deliberately
// not in this list.

export const CMEK_EPHEMERAL_STORES = [
  'dropoff_packages', // payload_encrypted (TTL 30m-24h)
  'oauth_refresh_tokens', // replacement_token_encrypted (60s retry window)
] as const;

export type CmekStore =
  | (typeof CMEK_LONG_LIVED_STORES)[number]
  | (typeof CMEK_EPHEMERAL_STORES)[number];

export type CmekStatusSnapshot = {
  status: 'none' | 'migrating' | 'active' | 'revoking' | 'revoked';
  keyArn: string | null;
  activatedAt: Date | null;
  migrations: CmekMigrationRow[];
};

export interface CmekServiceDeps {
  operatorRepo: OperatorRepository;
  migrationRepo: CmekMigrationRepository;
  kms: KmsService;
  /**
   * The dogfood operator's ID (env STACK_SYSTEM_OPERATOR_ID). Empty string in
   * dev mode disables the carve-out. CMEK must NEVER bind to this operator
   * — STACK's own credentials don't get held hostage by a customer revoke.
   */
  stackSystemOperatorId: string;
  /**
   * Optional pub/sub publish hook so config changes propagate to other API
   * machines + the worker. Channel: `stack:cmek-updated`. Payload is the
   * operator_id. If omitted (e.g. in tests), the in-process cache stays
   * coherent only within this process.
   */
  publishCmekUpdated?: (operatorId: string) => Promise<void> | void;
  /** Stores of ciphertext the deployment adds to the engine's (its skills): seeded and migrated like the rest. */
  extraLongLivedStores?: readonly string[];
  /** Ephemeral stores (per-call rows that age out) the deployment adds to the engine's. */
  extraEphemeralStores?: readonly string[];
}

const ARN_PATTERN = /^arn:aws:kms:[a-z0-9-]+:\d{12}:key\/[a-f0-9-]{36}$/i;
const ALIAS_PATTERN = /^arn:aws:kms:[a-z0-9-]+:\d{12}:alias\/[A-Za-z0-9/_-]+$/i;

function isValidKmsArn(arn: string): boolean {
  return ARN_PATTERN.test(arn) || ALIAS_PATTERN.test(arn);
}

export class CmekService {
  constructor(private deps: CmekServiceDeps) {}

  /** The engine's ephemeral stores, then the deployment's. */
  private ephemeralStores(): readonly string[] {
    return [...CMEK_EPHEMERAL_STORES, ...(this.deps.extraEphemeralStores ?? [])];
  }

  /** The engine's long-lived stores, then the deployment's. */
  private longLivedStores(): readonly string[] {
    return [...CMEK_LONG_LIVED_STORES, ...(this.deps.extraLongLivedStores ?? [])];
  }

  /**
   * Enable CMEK for an operator.
   *
   * Validates:
   *  - operator exists (any account may use its own key; no plan gates it)
   *  - operator is NOT op_stack_system (dogfood carve-out)
   *  - keyArn looks like a valid AWS KMS ARN (or alias ARN)
   *  - the IAM grant actually works: smokeTestCustomerKey() does a real
   *    GenerateDataKey + Decrypt round-trip BEFORE we commit anything
   *
   * On success: writes cmek_key_arn + cmek_status='migrating', seeds the
   * migration rows for both long-lived + ephemeral stores (the ephemeral
   * rows go straight to 'completed' since there's no backfill work), and
   * publishes a cache-invalidation event so other API machines pick up
   * the new state on their next encrypt/decrypt call.
   *
   * After this returns, the worker process picks up the pending rows and
   * runs the backfill. The dashboard polls getStatus() for progress.
   */
  async enable(operatorId: string, keyArn: string): Promise<CmekStatusSnapshot> {
    if (this.deps.stackSystemOperatorId && operatorId === this.deps.stackSystemOperatorId) {
      // Dogfood carve-out. STACK's own credentials never end up under a
      // customer KEK. This is the same operator that holds the dogfood
      // provider credentials under op_stack_system.
      throw new CmekConfigurationError(
        'The platform operator cannot use customer-managed encryption.',
        { operator_id: operatorId },
      );
    }

    // A deployment that holds its own key file has no key service a customer
    // could grant access to. (`=== false`: a bare test double has no flag.)
    if (this.deps.kms.supportsCustomerKeys === false) {
      throw new NotConfiguredError('Customer-managed encryption keys (this deployment wraps keys with its own key file)');
    }

    const op = await this.deps.operatorRepo.findById(operatorId);
    if (!op) throw new NotFoundError('Operator', operatorId);

    if (op.cmek_status !== 'none' && op.cmek_status !== 'revoked') {
      throw new CmekConfigurationError(
        `CMEK already configured (status=${op.cmek_status}). Disable it first.`,
        { current_status: op.cmek_status },
      );
    }

    if (!isValidKmsArn(keyArn)) {
      throw new CmekConfigurationError(
        'Key ARN must be a full AWS KMS key ARN (arn:aws:kms:REGION:ACCOUNT:key/UUID) or alias ARN.',
        { provided: keyArn },
      );
    }

    // Smoke-test BEFORE we commit anything to the DB. If the customer's
    // IAM grant isn't wired, surface that as 400 with a clear message,
    // not as a half-committed migrating state.
    try {
      await this.deps.kms.smokeTestCustomerKey(keyArn, operatorId);
    } catch (err) {
      if (err instanceof CmekRevokedError) {
        throw new CmekConfigurationError(
          'STACK cannot call AWS KMS with the provided key. Check the IAM grant on your CMK allows kms:GenerateDataKey + kms:Decrypt for the STACK principal.',
          { key_arn: keyArn },
        );
      }
      const message = err instanceof Error ? err.message : String(err);
      throw new CmekConfigurationError(
        `Smoke test against the provided KMS key failed: ${message}`,
        {
          key_arn: keyArn,
        },
      );
    }

    // All gates passed. Commit + seed migration rows.
    await this.deps.operatorRepo.setCmekConfig(operatorId, {
      cmek_key_arn: keyArn,
      cmek_status: 'migrating',
      cmek_activated_at: null,
    });

    for (const table of this.longLivedStores()) {
      const id = `cmkm_${randomBytes(12).toString('base64url')}`;
      await this.deps.migrationRepo.upsertPending(id, operatorId, 'enable', table);
    }
    // Ephemeral stores: mark completed straight away — the worker doesn't
    // backfill them. New writes go through KmsService with status='migrating'
    // and target the customer key; existing rows expire under the old key.
    for (const table of this.ephemeralStores()) {
      const id = `cmkm_${randomBytes(12).toString('base64url')}`;
      await this.deps.migrationRepo.upsertPending(id, operatorId, 'enable', table);
      await this.deps.migrationRepo.markRunning(id, 0);
      await this.deps.migrationRepo.markCompleted(id);
    }

    await this.deps.publishCmekUpdated?.(operatorId);
    return this.getStatus(operatorId);
  }

  /**
   * Disable CMEK for an operator — flips to 'revoking' status, seeds reverse
   * migration rows. The worker re-encrypts long-lived rows back to the
   * platform default key; ephemeral rows naturally age out under the
   * customer key. On worker completion, status flips to 'none'.
   */
  async disable(operatorId: string): Promise<CmekStatusSnapshot> {
    const op = await this.deps.operatorRepo.findById(operatorId);
    if (!op) throw new NotFoundError('Operator', operatorId);

    if (op.cmek_status === 'none') {
      throw new CmekConfigurationError('CMEK is not configured for this operator.', {
        current_status: op.cmek_status,
      });
    }

    // 'revoked' → still let them disable; the worker will re-encrypt rows
    // it can still reach (those written under the platform key during the
    // migration window). Rows under the revoked customer key will fail to
    // decrypt and the worker will mark those migration rows 'failed' with
    // a CMEK_REVOKED error — visible in the dashboard for the operator to
    // either restore the grant + retry disable, or accept the data loss.
    await this.deps.operatorRepo.setCmekConfig(operatorId, {
      cmek_status: 'revoking',
    });

    // Clear stale enable-direction migration rows so they don't conflict
    // with the reverse direction (the unique index is on direction+table,
    // so 'disable' rows are separate, but old 'enable' rows leftover from
    // a previous cycle would confuse the dashboard).
    const enableRows = await this.deps.migrationRepo.listByOperatorAndDirection(
      operatorId,
      'enable',
    );
    if (enableRows.length > 0) {
      await this.deps.migrationRepo.deleteByOperator(operatorId);
    }

    for (const table of this.longLivedStores()) {
      const id = `cmkm_${randomBytes(12).toString('base64url')}`;
      await this.deps.migrationRepo.upsertPending(id, operatorId, 'disable', table);
    }
    for (const table of this.ephemeralStores()) {
      const id = `cmkm_${randomBytes(12).toString('base64url')}`;
      await this.deps.migrationRepo.upsertPending(id, operatorId, 'disable', table);
      await this.deps.migrationRepo.markRunning(id, 0);
      await this.deps.migrationRepo.markCompleted(id);
    }

    await this.deps.publishCmekUpdated?.(operatorId);
    return this.getStatus(operatorId);
  }

  /**
   * Status snapshot for the dashboard. Includes the per-table migration
   * progress so the UI can render a progress bar.
   */
  async getStatus(operatorId: string): Promise<CmekStatusSnapshot> {
    const op = await this.deps.operatorRepo.findById(operatorId);
    if (!op) throw new NotFoundError('Operator', operatorId);
    const migrations = await this.deps.migrationRepo.listByOperator(operatorId);
    return {
      status: (op.cmek_status ?? 'none') as CmekStatusSnapshot['status'],
      keyArn: op.cmek_key_arn ?? null,
      activatedAt: op.cmek_activated_at,
      migrations,
    };
  }

  /**
   * Called when a CmekRevokedError propagates from anywhere in the system
   * (proxy, drop-off, identity, skill invocation). Flips status to 'revoked'
   * so subsequent encrypt() calls fail-fast without hitting KMS again, and
   * publishes a cache-invalidation event so every API machine sees the new
   * state on its next request.
   *
   * Idempotent: re-recording an already-revoked operator is a no-op.
   */
  async recordRevoked(operatorId: string, _keyArn?: string): Promise<void> {
    const op = await this.deps.operatorRepo.findById(operatorId);
    if (!op) return;
    if (op.cmek_status === 'revoked') return;
    await this.deps.operatorRepo.setCmekConfig(operatorId, { cmek_status: 'revoked' });
    await this.deps.publishCmekUpdated?.(operatorId);
  }
}
