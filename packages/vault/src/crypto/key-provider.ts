/**
 * The service that wraps and unwraps STACK's keys.
 *
 * `KmsService` owns what is STACK's own: the envelope format, the encryption
 * context bound into every ciphertext, per-operator customer-managed keys and
 * the legacy fallbacks. It holds no key material and calls no cloud. Every
 * wrap and unwrap goes through a `KeyProvider`: AWS KMS for STACK's hosted
 * deployment (`AwsKeyProvider`), or a key-encryption key read from a file or
 * the environment for an install that runs on its own infrastructure
 * (`LocalKeyProvider`).
 *
 * A provider wraps bytes under an identified key and a context. It never sees
 * an operator's plaintext credentials: the envelope's data key is generated
 * and unwrapped here, and the payload is encrypted locally with AES-GCM.
 */

/**
 * Context bound into a wrap as AAD / KMS EncryptionContext. Typically
 * `{operator_id, connection_id}`, so a ciphertext cannot be moved between rows
 * without the unwrap failing.
 */
export type EncryptionContext = Record<string, string>;

/** What a provider failure means to `KmsService`, whatever the provider's own error looks like. */
export type KeyFailure =
  /** The key's owner has withdrawn access, or the key is gone or disabled. */
  | 'access_denied'
  /** The unwrap failed in a way a wrong or missing context explains. */
  | 'context_mismatch'
  | 'other';

export interface KeyProvider {
  readonly kind: 'aws-kms' | 'local';
  /**
   * Can a customer bring a key of their own (per-operator CMEK)? Only a
   * provider that talks to a key service the customer also has an account with
   * can.
   */
  readonly supportsCustomerKeys: boolean;
  /** Mint a 256-bit data key and return it plain and wrapped under `keyId`. */
  generateDataKey(input: {
    keyId: string;
    context?: EncryptionContext;
  }): Promise<{ plaintext: Buffer; wrapped: Buffer }>;
  /** Unwrap a data key `generateDataKey` produced. `keyRef` is the reference stored beside it, if any. */
  unwrapDataKey(input: {
    wrapped: Buffer;
    context?: EncryptionContext;
    keyRef?: string;
  }): Promise<Buffer>;
  /** Wrap a small secret directly under `keyId` (signing keys, buffers). */
  wrap(input: {
    keyId: string;
    plaintext: Buffer;
    context?: EncryptionContext;
  }): Promise<Buffer>;
  /** Unwrap what `wrap` produced. */
  unwrap(input: {
    blob: Buffer;
    context?: EncryptionContext;
    keyRef?: string;
  }): Promise<Buffer>;
  /**
   * A reference to store beside a wrap when the provider needs one to route
   * the unwrap back (an AWS key ARN carries its region); null when the key id
   * alone is enough.
   */
  routableKeyRef(keyId: string): string | null;
  /** Read a provider failure into one of the cases `KmsService` acts on. */
  classify(err: unknown): KeyFailure;
  /** Prove a customer's key works before anything is committed to it. */
  smokeTestCustomerKey(keyArn: string, operatorId: string): Promise<void>;
}
