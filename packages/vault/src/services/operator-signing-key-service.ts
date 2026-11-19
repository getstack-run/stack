/**
 * Per-operator signing-key service. of the Signed Primitive
 * epic. Issues + caches + rotates the EdDSA keypair each tenant operator
 * uses to sign COSE_Sign1 claim envelopes via ClaimRegistryService.
 *
 * Architecture summary:
 *   - One active keypair per non-system operator. Lazy-generated on
 *     first claim attempt.
 *   - Private key KMS-wrapped at rest via KmsService.encryptDirect with
 *     AAD {operator_id, kid, purpose: 'claim_signing'}.
 *   - Public JWK stored alongside in the row for the JWKS endpoint and
 *     the kid-prefix resolver to read without an extra KMS Decrypt.
 *   - In-memory cache Map<operator_id, ClaimSigner>. Cache-miss = one
 *     KMS Decrypt to unwrap the private JWK. Evicted on rotation.
 *   - Rotation appends a new row at v+1, stamps retired_at on the prior.
 *     Old kid stays in JWKS so historical claims keep verifying.
 *
 * Dogfood carve-out: op_stack_system MUST NOT have a row here. Its claims
 * sign under the deployment key (kid stack-passport-v1) via the wiring
 * layer in apps/api/src/config/services.ts. ensureKeyForOperator throws
 * for the system operator as defense-in-depth.
 *
 * Redis pub/sub for cache eviction lives at the wiring layer (Phase
 * 3.5.5 / 3.5.6). The service exposes evictSigner(operator_id) for the
 * subscriber to call; the rotate() method exposes a hook so the caller
 * can publish to stack:signing-key-rotated after the DB write.
 */
import { generateKeyPair, exportJWK, importJWK, type JWK } from 'jose';
import type { Redis } from 'ioredis';
import { ClaimSigner } from '../crypto/claim-signer.js';
import type { KmsService } from '../crypto/kms.js';
import type { OperatorSigningKeyRepository } from '../repositories/operator-signing-key-repo.js';

export interface OperatorSigningKeyServiceDeps {
  repo: OperatorSigningKeyRepository;
  kms: KmsService;
  /**
   * The dogfood operator id. ensureKeyForOperator throws when called
   * with this id. Empty string disables the carve-out (test / dev).
   */
  systemOperatorId: string;
  /**
   * Optional Redis handle for cross-machine cache eviction on rotation.
   * When set, `rotate()` publishes the operator_id on `stack:signing-key-rotated`
   * after the DB write completes. Peer machines subscribed to that channel
   * call `evictSigner(operator_id)` to drop their cached ClaimSigner so
   * the next `getSigner` call rebuilds with the new active kid.
   * Tests pass undefined.
   */
  redis?: Redis;
}

export const SIGNING_KEY_ROTATED_CHANNEL = 'stack:signing-key-rotated';

export class OperatorSigningKeyService {
  private cache = new Map<string, ClaimSigner>();

  constructor(private readonly deps: OperatorSigningKeyServiceDeps) {}

  /**
   * Generate-if-absent. Returns the active kid for the operator.
   * Idempotent — re-calling for an operator with an active key is
   * a cheap DB lookup.
   *
   * Throws if called for the system operator (carve-out).
   */
  async ensureKeyForOperator(operatorId: string): Promise<string> {
    this.assertNotSystemOperator(operatorId);
    const existing = await this.deps.repo.findActiveByOperator(operatorId);
    if (existing) return existing.kid;
    return this.generateAndStoreKey(operatorId, 1);
  }

  /**
   * Returns the ClaimSigner for an operator's currently-active key.
   * Cached in-memory; cache-miss triggers one DB read + one KMS Decrypt.
   *
   * Throws if called for the system operator (carve-out).
   */
  async getSigner(operatorId: string): Promise<ClaimSigner> {
    this.assertNotSystemOperator(operatorId);
    const cached = this.cache.get(operatorId);
    if (cached) return cached;

    // Ensure-or-create the active key, then load it.
    await this.ensureKeyForOperator(operatorId);
    const row = await this.deps.repo.findActiveByOperator(operatorId);
    if (!row) {
      throw new Error(`[OperatorSigningKeyService] no active key for ${operatorId} after ensure`);
    }

    const privateJwk = await this.unwrapPrivateJwk(operatorId, row.kid, row.private_key_wrapped);
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid: row.kid });
    this.cache.set(operatorId, signer);
    return signer;
  }

  /**
   * Returns the JWKS array for an operator: active + retired-not-revoked
   * keys, sorted by created_at ascending. Each entry carries the kid and
   * the public JWK fields. Consumed by /v1/operators/:id/jwks.json
   * and by the kid-prefix resolver in ClaimRegistryService.
   *
   * Returns empty array if no keys exist for the operator (caller decides
   * 404 vs 200-with-empty-list).
   */
  async getPublicJwksForOperator(operatorId: string): Promise<Array<JWK & { kid: string; not_after: number | null }>> {
    const rows = await this.deps.repo.findAllByOperatorForJwks(operatorId);
    return rows.map((r) => ({
      ...(r.public_jwk as JWK),
      kid: r.kid,
      alg: 'EdDSA',
      use: 'sig',
      not_before: r.active_from.getTime(),
      not_after: r.retired_at ? r.retired_at.getTime() : null,
    }));
  }

  /**
   * Rotate the operator's active key. Inserts a new row at version+1,
   * stamps retired_at on the prior, evicts the in-process cache. Returns
   * the (new, retired) kid pair. Caller is responsible for publishing
   * to stack:signing-key-rotated for cross-machine cache eviction.
   *
   * Throws if called for the system operator (carve-out).
   */
  async rotate(operatorId: string): Promise<{ newKid: string; retiredKid: string | null }> {
    this.assertNotSystemOperator(operatorId);

    const prior = await this.deps.repo.findActiveByOperator(operatorId);
    const maxVersion = await this.deps.repo.findMaxVersion(operatorId);
    const newKid = await this.generateAndStoreKey(operatorId, maxVersion + 1);

    if (prior) {
      await this.deps.repo.markRetired(prior.kid);
    }

    this.evictSigner(operatorId);
    if (this.deps.redis) {
      // Fire-and-forget; subscriber-side evictSigner is idempotent so a
      // dropped pub/sub doesn't break correctness (the next getSigner call
      // would still see the old cached signer until eviction or process
      // restart — old kid stays valid for verify, just slightly stale).
      await this.deps.redis.publish(SIGNING_KEY_ROTATED_CHANNEL, operatorId);
    }
    return { newKid, retiredKid: prior?.kid ?? null };
  }

  /**
   * Drop the cached ClaimSigner for an operator. Next getSigner() call
   * rebuilds from the DB. Called by the Redis subscriber
   * when a peer machine published a rotation, AND by rotate() itself
   * on the originating machine.
   */
  evictSigner(operatorId: string): void {
    this.cache.delete(operatorId);
  }

  /**
   * Drop every cached signer. Used by tests; not wired in prod.
   */
  evictAll(): void {
    this.cache.clear();
  }

  // ── Private helpers ─────────────────────────────────────────────

  private assertNotSystemOperator(operatorId: string): void {
    if (this.deps.systemOperatorId && operatorId === this.deps.systemOperatorId) {
      throw new Error(
        `[OperatorSigningKeyService] refusing operation for system operator ${operatorId} — ` +
          'system claims sign under the deployment key (kid stack-passport-v1) via the wiring ' +
          'layer in apps/api/src/config/services.ts.',
      );
    }
  }

  private async generateAndStoreKey(operatorId: string, version: number): Promise<string> {
    const kid = `${operatorId}:claim:v${version}`;
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    const privateJwk = await exportJWK(privateKey);
    const publicJwk = await exportJWK(publicKey);

    const wrappedBuf = await this.deps.kms.encryptDirect(Buffer.from(JSON.stringify(privateJwk), 'utf8'), {
      operatorId,
      context: {
        operator_id: operatorId,
        kid,
        purpose: 'claim_signing',
      },
    });
    const wrappedBase64 = wrappedBuf.toString('base64');

    await this.deps.repo.insert({
      kid,
      operator_id: operatorId,
      private_key_wrapped: wrappedBase64,
      public_jwk: publicJwk as Record<string, unknown>,
    });
    return kid;
  }

  private async unwrapPrivateJwk(operatorId: string, kid: string, wrappedBase64: string): Promise<JWK> {
    const wrappedBuf = Buffer.from(wrappedBase64, 'base64');
    const plainBuf = await this.deps.kms.decryptDirect(wrappedBuf, {
      operatorId,
      expectedContext: {
        operator_id: operatorId,
        kid,
        purpose: 'claim_signing',
      },
    });
    const jwk = JSON.parse(plainBuf.toString('utf8')) as JWK;
    // Validate the JWK by importing it; throws on shape mismatch.
    await importJWK(jwk, 'EdDSA');
    return jwk;
  }
}
