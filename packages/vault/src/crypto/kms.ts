import { CmekRevokedError } from '@stack/shared';
import { AwsKeyProvider, parseKmsRegion } from './aws-key-provider.js';
import type { EncryptionContext, KeyProvider } from './key-provider.js';

export { parseKmsRegion };
export type { EncryptionContext };

/**
 * Per-operator CMEK status as resolved at encrypt/decrypt time.
 * Mirrors the operators.cmek_status column added in migration 0034.
 */
export type CmekStatus = 'none' | 'migrating' | 'active' | 'revoking' | 'revoked';

export interface OperatorCmekState {
  keyArn: string | null;
  status: CmekStatus;
}

export type ResolveOperatorKey = (operatorId: string) => Promise<OperatorCmekState>;

export interface OperatorKeyHandlers {
  /** Resolves the per-operator CMEK state (status + keyArn). */
  resolve: ResolveOperatorKey;
  /**
   * Called when a KMS Encrypt or Decrypt throws AccessDeniedException — i.e.
   * the customer has revoked our IAM grant on their CMK — BEFORE the KmsService
   * rethrows as CmekRevokedError. Lets the caller evict its per-operator
   * resolver cache so the next request after a revoke does not sit on a stale
   * 5-minute-cached `active` state and route to the same revoked key again.
   */
  evict?: (operatorId: string) => void;
  /**
   * Called when decryptDirect succeeds via the no-context fallback path AFTER
   * the with-context attempt failed with InvalidCiphertextException. Indicates
   * a legacy (pre-CMEK-AAD) row was redeemed. Telemetry signal — new (post-3.5)
   * rows hitting this callback would mean the forward-only AAD rule was
   * violated somewhere. Caller typically wires this to a Sentry breadcrumb so
   * we can watch the redemption rate trend to zero.
   */
  onLegacyFallback?: (info: { operatorId?: string; hasExpectedContext: boolean }) => void;
}

export interface KmsConfig {
  /**
   * Who wraps and unwraps. Omitted, STACK's hosted deployment is assumed:
   * AWS KMS in `region`. A deployment with its own key service or key file
   * passes a provider.
   */
  provider?: KeyProvider;
  /** AWS region of the default key. Required unless a provider is given. */
  region?: string;
  /**
   * STACK platform default key. Used when:
   *  - the call has no operator_id context (system-scoped ciphertext)
   *  - the operator's CMEK status is 'none'
   *  - the operator's CMEK status is 'revoking' (we're migrating back to platform)
   *  - the operator is op_stack_system (dogfood carve-out — never use a customer key)
   */
  defaultKeyId: string;
  /**
   * The dogfood operator's ID — when present, encrypt routes for this operator
   * short-circuit to the platform key BEFORE the resolver is consulted, even
   * if a resolver is configured. Defense-in-depth against any callsite that
   * reaches `kms.encrypt` for `op_stack_system` without going through
   * `CmekService.enable` (which has its own carve-out gate at the service
   * layer). Empty / unset means no short-circuit — fine in tests + dev.
   */
  stackSystemOperatorId?: string;
  /**
   * Resolves the per-operator CMEK state. Implementations are expected to
   * cache (e.g. 5-min TTL with Redis pub/sub invalidation on `stack:cmek-updated`).
   * If omitted, every call uses the default key — useful in dev/test.
   */
  resolveOperatorKey?: ResolveOperatorKey;
}

interface Envelope {
  /** Envelope version — absent/1 means no context, 2 means context-bound. */
  v?: number;
  iv: string;
  authTag: string;
  data: string;
  encryptedDataKey: string;
  ctx?: EncryptionContext;
  /**
   * The reference the provider needs to route the unwrap of
   * `encryptedDataKey` back to the key that wrapped it. For AWS KMS it is the
   * full key ARN, because a client is bound to one region and the region is in
   * the ARN. Absent on pre-Path-B (pre-2026-05-14) envelopes — those were
   * always written by a single-region client (eu-north-1 in prod) so decrypt
   * falls back to the provider's default.
   *
   * Only written when the provider says the key id is routable (a full ARN).
   * Bare-UUID platform keys, and every key of a local provider, leave it absent.
   */
  keyRef?: string;
}

/**
 * Direct-encrypt wrapper. AWS KMS Encrypt returns opaque ciphertext bytes
 * with no region in them. To route Decrypt to the right regional endpoint
 * we prepend a tiny wrapper carrying the wrapping key's ARN. Only used
 * when the provider names a routable key reference — platform-key (bare UUID)
 * direct encrypts stay raw, matching the legacy shape.
 *
 *   [ 0xDC 0xCE 0x4B 0x4D ][ keyRef_len uint16 BE ][ keyRef utf-8 ][ raw KMS blob ]
 *      ^ magic prefix ^
 *
 * 4-byte magic collision against a raw KMS blob is ~1/2^32. AWS KMS blobs
 * in practice start with `0x01` (their internal version byte); we picked a
 * sentinel that does not collide with that prefix and would not collide
 * with any plausible future KMS version byte either.
 */
const DIRECT_WRAP_MAGIC = Buffer.from([0xdc, 0xce, 0x4b, 0x4d]);

function wrapDirectBlob(rawBlob: Buffer, keyRef: string): Buffer {
  const keyRefBytes = Buffer.from(keyRef, 'utf8');
  if (keyRefBytes.length > 0xffff) {
    throw new Error('KMS keyRef exceeds 65535 bytes — refusing to wrap');
  }
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(keyRefBytes.length, 0);
  return Buffer.concat([DIRECT_WRAP_MAGIC, lenBuf, keyRefBytes, rawBlob]);
}

interface UnwrappedDirect {
  keyRef: string | null;
  rawBlob: Buffer;
}

function unwrapDirectBlob(blob: Buffer): UnwrappedDirect {
  if (blob.length < DIRECT_WRAP_MAGIC.length + 2) {
    return { keyRef: null, rawBlob: blob };
  }
  for (let i = 0; i < DIRECT_WRAP_MAGIC.length; i++) {
    if (blob[i] !== DIRECT_WRAP_MAGIC[i]) {
      return { keyRef: null, rawBlob: blob };
    }
  }
  const keyRefLen = blob.readUInt16BE(DIRECT_WRAP_MAGIC.length);
  const headerEnd = DIRECT_WRAP_MAGIC.length + 2 + keyRefLen;
  if (blob.length < headerEnd) {
    return { keyRef: null, rawBlob: blob };
  }
  const keyRef = blob
    .slice(DIRECT_WRAP_MAGIC.length + 2, headerEnd)
    .toString('utf8');
  const rawBlob = blob.slice(headerEnd);
  return { keyRef, rawBlob };
}

function contextsMatch(a: EncryptionContext, b: EncryptionContext): boolean {
  const aKeys = Object.keys(a).sort();
  const bKeys = Object.keys(b).sort();
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every((k, i) => bKeys[i] === k && a[k] === b[k]);
}

export class KmsService {
  private readonly provider: KeyProvider;
  private defaultKeyId: string;
  private stackSystemOperatorId?: string;
  private resolveOperatorKey?: ResolveOperatorKey;
  private evictCache?: (operatorId: string) => void;
  private onLegacyFallback?: (info: { operatorId?: string; hasExpectedContext: boolean }) => void;

  constructor(config: KmsConfig) {
    if (config.provider) {
      this.provider = config.provider;
    } else if (config.region) {
      this.provider = new AwsKeyProvider({ region: config.region });
    } else {
      throw new Error('KmsService needs a key provider or an AWS region');
    }
    this.defaultKeyId = config.defaultKeyId;
    this.stackSystemOperatorId = config.stackSystemOperatorId || undefined;
    this.resolveOperatorKey = config.resolveOperatorKey;
  }

  /** Which provider wraps this deployment's keys. For startup logs and health output. */
  get providerKind(): KeyProvider['kind'] {
    return this.provider.kind;
  }

  /** Whether an operator may bring a key of their own (CMEK). False on a local key file. */
  get supportsCustomerKeys(): boolean {
    return this.provider.supportsCustomerKeys;
  }

  /**
   * Late-wire per-operator key handlers. Used by the API + worker bootstraps
   * after operatorRepo + a cache (and optional Sentry hook) exist.
   *
   * Replaces the older `setResolveOperatorKey` so all callbacks ride a single
   * setter and new hooks can be added without growing the surface area.
   */
  setOperatorKeyHandlers(handlers: OperatorKeyHandlers): void {
    this.resolveOperatorKey = handlers.resolve;
    this.evictCache = handlers.evict;
    this.onLegacyFallback = handlers.onLegacyFallback;
  }

  /**
   * Resolve which KMS key to use for an outgoing Encrypt/GenerateDataKey,
   * honouring the per-operator CMEK status when context carries operator_id.
   *
   * Status semantics:
   *  - none:      default key (no CMEK configured)
   *  - migrating: customer key (new writes go to customer key so backfill
   *               can verify zero rows under the old keyRef)
   *  - active:    customer key
   *  - revoking:  default key (new writes go back to platform key; backfill
   *               re-encrypts existing customer-keyed rows)
   *  - revoked:   throw CmekRevokedError — writing new ciphertext we can
   *               never read is worse than failing the request.
   */
  private async resolveEncryptKey(context?: EncryptionContext): Promise<string> {
    if (!this.resolveOperatorKey || !context?.operator_id) return this.defaultKeyId;
    // Dogfood carve-out, asserted at the resolver layer so the carve-out at
    // CmekService.enable + CmekMigrationWorker.tick is not the only line of
    // defense. If anything ever reaches `kms.encrypt` for the dogfood operator
    // via a path that bypasses those services, the platform key stays in use.
    if (this.stackSystemOperatorId && context.operator_id === this.stackSystemOperatorId) {
      return this.defaultKeyId;
    }
    const state = await this.resolveOperatorKey(context.operator_id);
    switch (state.status) {
      case 'active':
      case 'migrating':
        return state.keyArn ?? this.defaultKeyId;
      case 'revoked':
        throw new CmekRevokedError(context.operator_id, state.keyArn ?? undefined);
      case 'revoking':
      case 'none':
      default:
        return this.defaultKeyId;
    }
  }

  /**
   * Encrypt credential using KMS envelope encryption.
   * If `context` is provided it is bound into both the KMS EncryptionContext
   * (protecting the data key unwrap) and the local AES-GCM AAD (protecting
   * the payload). The context is stored in the envelope so decrypt can re-bind it.
   *
   * If context carries operator_id and a CMEK resolver is configured, the
   * outgoing data key is generated under the customer's CMK instead of the
   * platform default. The envelope's keyRef records which key was used so
   * decrypt() works regardless of the operator's current CMEK status.
   */
  async encrypt(
    plaintext: string,
    context?: EncryptionContext,
  ): Promise<{ ciphertext: string; keyRef: string }> {
    const keyId = await this.resolveEncryptKey(context);
    let dataKey: { plaintext: Buffer; wrapped: Buffer };
    try {
      dataKey = await this.provider.generateDataKey({
        keyId,
        ...(context ? { context } : {}),
      });
    } catch (err) {
      if (
        this.provider.classify(err) === 'access_denied'
        && context?.operator_id
        && keyId !== this.defaultKeyId
      ) {
        this.evictCache?.(context.operator_id);
        throw new CmekRevokedError(context.operator_id, keyId);
      }
      throw err;
    }

    const { createCipheriv, randomBytes } = await import('node:crypto');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', dataKey.plaintext, iv);
    if (context) {
      cipher.setAAD(Buffer.from(canonicalize(context), 'utf8'));
    }
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Embed keyRef in the envelope only when the provider can route by it:
    // bare UUIDs (the platform default key id in prod today) have no region
    // to encode, and decrypt routes them to the default-region client.
    const keyRef = this.provider.routableKeyRef(keyId);
    const envelope: Envelope = {
      v: context ? 2 : 1,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      data: encrypted.toString('base64'),
      encryptedDataKey: dataKey.wrapped.toString('base64'),
      ...(context ? { ctx: context } : {}),
      ...(keyRef ? { keyRef } : {}),
    };

    return {
      ciphertext: Buffer.from(JSON.stringify(envelope)).toString('base64'),
      keyRef: keyId,
    };
  }

  /**
   * Decrypt credential. If the envelope was encrypted with a context, the caller
   * MUST supply a matching expected context; mismatches throw. Legacy envelopes
   * without a context decrypt unchanged so existing rows keep working.
   *
   * If KMS returns AccessDeniedException the customer has revoked our IAM
   * grant on their CMK — throw CmekRevokedError so the caller fail-closes
   * with 503 and the operator gets surfaced a remediation path.
   */
  async decrypt(ciphertext: string, expectedContext?: EncryptionContext): Promise<string> {
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString('utf8')) as Envelope;

    const envelopeCtx = envelope.ctx;
    if (envelopeCtx) {
      if (!expectedContext) {
        throw new Error('KMS decrypt: envelope is context-bound but no expected context supplied');
      }
      if (!contextsMatch(envelopeCtx, expectedContext)) {
        throw new Error('KMS decrypt: envelope context does not match caller expectation');
      }
    }

    // The unwrap names no key: AWS KMS derives it from the ciphertext
    // metadata itself, so a service configured with `defaultKeyId=KEY_B` can
    // decrypt blobs that were encrypted under `KEY_A` as long as IAM allows
    // it. Passing this.defaultKeyId explicitly would fail when the envelope
    // was written under a different key (platform-key rotation, per-operator
    // CMEK keys, etc.). The envelope's keyRef is only a routing hint (the
    // region of the wrapping key), never a key choice.
    let dataKey: Buffer;
    try {
      dataKey = await this.provider.unwrapDataKey({
        wrapped: Buffer.from(envelope.encryptedDataKey, 'base64'),
        ...(envelopeCtx ? { context: envelopeCtx } : {}),
        ...(envelope.keyRef ? { keyRef: envelope.keyRef } : {}),
      });
    } catch (err) {
      if (this.provider.classify(err) === 'access_denied' && envelopeCtx?.operator_id) {
        this.evictCache?.(envelopeCtx.operator_id);
        throw new CmekRevokedError(envelopeCtx.operator_id);
      }
      throw err;
    }

    const { createDecipheriv } = await import('node:crypto');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      dataKey,
      Buffer.from(envelope.iv, 'base64'),
    );
    if (envelopeCtx) {
      decipher.setAAD(Buffer.from(canonicalize(envelopeCtx), 'utf8'));
    }
    decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(envelope.data, 'base64')),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Direct KMS encrypt for small data (e.g., signing key material, skill
   * invocation input/output buffers).
   *
   * If `operatorId` is supplied, the per-operator CMEK resolver routes the
   * outgoing Encrypt under the customer's key when CMEK is active. Omitting
   * it (the default) pins to the platform key — that's what STACK-scoped
   * material like passport signing-key wraps should use.
   *
   * The encryption context is honoured (same shape as the envelope path), so
   * AAD-bound direct-encrypts are possible for callers that want the
   * row-level tamper-evidence.
   */
  async encryptDirect(plaintext: Buffer, opts?: { operatorId?: string; context?: EncryptionContext }): Promise<Buffer> {
    let keyId = this.defaultKeyId;
    if (opts?.operatorId && this.resolveOperatorKey) {
      keyId = await this.resolveEncryptKey({ operator_id: opts.operatorId, ...(opts.context ?? {}) });
    }
    try {
      const rawBlob = await this.provider.wrap({
        keyId,
        plaintext,
        ...(opts?.context ? { context: opts.context } : {}),
      });
      // Wrap with the keyRef only when the provider can route by it: it gives
      // decryptDirect the region to route to. Bare-UUID platform keys emit raw
      // bytes, matching the pre-Path-B shape so existing rows continue to
      // round-trip unchanged.
      const keyRef = this.provider.routableKeyRef(keyId);
      return keyRef ? wrapDirectBlob(rawBlob, keyRef) : rawBlob;
    } catch (err) {
      if (
        this.provider.classify(err) === 'access_denied'
        && opts?.operatorId
        && keyId !== this.defaultKeyId
      ) {
        this.evictCache?.(opts.operatorId);
        throw new CmekRevokedError(opts.operatorId, keyId);
      }
      throw err;
    }
  }

  /**
   * Decrypt a direct-encrypt blob (no envelope). The unwrap names no key: KMS
   * derives it from the ciphertext — safe under platform-key rotation
   * and per-operator CMEK.
   *
   * Unlike the envelope path, direct-encrypt does NOT embed its
   * EncryptionContext in the ciphertext. AWS KMS Decrypt is strict: pass
   * the same context that was used at encrypt time or it fails with
   * InvalidCiphertextException. Pre-CMEK rows were encryptDirect'd with
   * no context; post-CMEK rows are encryptDirect'd with operator_id +
   * store context. The caller cannot tell from the ciphertext bytes
   * which shape a given row is.
   *
   * So: try with `expectedContext` first; on context-mismatch failure,
   * retry without context (legacy shape). The dual-try is removable once
   * the migration worker has re-encrypted every legacy row.
   *
   * AccessDeniedException → CmekRevokedError when the caller identifies
   * the operator so the upstream handler can fail-close with 503.
   */
  async decryptDirect(ciphertext: Buffer, opts?: { operatorId?: string; expectedContext?: EncryptionContext }): Promise<Buffer> {
    // Path B wrapper: peel the keyRef out if present, leaving just the
    // raw blob for the unwrap. Wrapper absent → legacy shape, route to the
    // default (pre-Path-B writes were single-region).
    const { keyRef, rawBlob } = unwrapDirectBlob(ciphertext);
    const tryDecrypt = (withContext: boolean): Promise<Buffer> =>
      this.provider.unwrap({
        blob: rawBlob,
        ...(withContext && opts?.expectedContext ? { context: opts.expectedContext } : {}),
        ...(keyRef ? { keyRef } : {}),
      });

    try {
      // Path A: try with expectedContext (new CMEK-aware rows).
      if (opts?.expectedContext) return await tryDecrypt(true);
      return await tryDecrypt(false);
    } catch (err) {
      const failure = this.provider.classify(err);
      if (failure === 'access_denied' && opts?.operatorId) {
        this.evictCache?.(opts.operatorId);
        throw new CmekRevokedError(opts.operatorId);
      }
      // Path B fallback: the row was encryptDirect'd before CMEK landed
      // (no EncryptionContext at encrypt time). Retry without context.
      // A context-mismatch failure is what KMS throws when the context
      // shape mismatches; any other failure is not a signal to retry.
      if (opts?.expectedContext && failure === 'context_mismatch') {
        let result: Buffer;
        try {
          result = await tryDecrypt(false);
        } catch (fallbackErr) {
          if (this.provider.classify(fallbackErr) === 'access_denied' && opts?.operatorId) {
            this.evictCache?.(opts.operatorId);
            throw new CmekRevokedError(opts.operatorId);
          }
          throw fallbackErr;
        }
        // Legacy row redeemed. Signal telemetry so we can watch the
        // redemption rate decay to zero as the worker drains old rows.
        // New (post-3.5) rows hitting this path is a bug signal.
        this.onLegacyFallback?.({
          operatorId: opts.operatorId,
          hasExpectedContext: !!opts.expectedContext,
        });
        return result;
      }
      throw err;
    }
  }

  /**
   * Smoke-test a customer's CMK ARN by encrypting + decrypting a probe value
   * under it directly. Used by CmekService.enable() to prove the IAM grant
   * works BEFORE we flip the operator into the migrating status — the worst
   * shape is half-committing to a CMK we can't actually call.
   *
   * Returns nothing on success; throws CmekRevokedError on AccessDenied,
   * a generic Error otherwise. Caller should map to CmekConfigurationError.
   */
  async smokeTestCustomerKey(keyArn: string, operatorId: string): Promise<void> {
    try {
      await this.provider.smokeTestCustomerKey(keyArn, operatorId);
    } catch (err) {
      if (this.provider.classify(err) === 'access_denied') {
        // Smoke-test runs at enable time, before the cache holds anything
        // CMEK-shaped, but evict for symmetry: a `none` state cached just
        // before a failed enable would otherwise outlive the failure.
        this.evictCache?.(operatorId);
        throw new CmekRevokedError(operatorId, keyArn);
      }
      throw err;
    }
  }
}

function canonicalize(ctx: EncryptionContext): string {
  return JSON.stringify(
    Object.keys(ctx)
      .sort()
      .reduce<Record<string, string>>((acc, k) => {
        acc[k] = ctx[k]!;
        return acc;
      }, {}),
  );
}
