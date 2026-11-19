import {
  KMSClient,
  EncryptCommand,
  DecryptCommand,
  GenerateDataKeyCommand,
} from '@aws-sdk/client-kms';
import type { EncryptionContext, KeyFailure, KeyProvider } from './key-provider.js';

/**
 * Parses the region out of an AWS KMS key identifier. Accepts full key ARNs
 * and alias ARNs. Returns null for bare UUIDs (the platform default key id
 * shape in prod today) or anything that doesn't match the ARN form. Region
 * is lower-cased to canonicalise.
 *
 * Used to route Encrypt/GenerateDataKey/Decrypt commands to the right
 * regional KMS endpoint. Path B (2026-05-14): cross-region customer keys.
 */
export function parseKmsRegion(keyIdOrArn: string): string | null {
  const m = /^arn:aws:kms:([a-z0-9-]+):/i.exec(keyIdOrArn);
  return m ? m[1]!.toLowerCase() : null;
}

/**
 * KMS Decrypt throws InvalidCiphertextException both when the ciphertext is
 * corrupt AND when the EncryptionContext doesn't match what was used at
 * encrypt time. We can't tell those apart from the error alone, but the
 * decryptDirect dual-try path only triggers the fallback when the caller
 * explicitly supplied a context — corrupt ciphertext failures still bubble
 * up after the second attempt.
 */
function isContextMismatch(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { name?: string; __type?: string; Code?: string };
  return (
    e.name === 'InvalidCiphertextException' ||
    e.__type === 'InvalidCiphertextException' ||
    e.Code === 'InvalidCiphertextException'
  );
}

function isAccessDenied(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { name?: string; Code?: string; __type?: string };
  return (
    e.name === 'AccessDeniedException' ||
    e.Code === 'AccessDeniedException' ||
    e.__type === 'AccessDeniedException' ||
    // KMS also throws KMSAccessDeniedException for some operations
    e.name === 'KMSAccessDeniedException' ||
    e.name === 'NotFoundException' ||      // key deleted on the customer side
    e.name === 'DisabledException' ||      // key disabled on the customer side
    e.name === 'KeyUnavailableException'   // key in a region we can't reach
  );
}

/**
 * AWS KMS. An SDK client is bound to a single region, so the provider keeps
 * one per region and routes each call to the region in the key's ARN. The
 * default-region client is seeded eagerly so the common path (the platform key
 * in its home region) takes no map-miss penalty.
 */
export class AwsKeyProvider implements KeyProvider {
  readonly kind = 'aws-kms' as const;
  readonly supportsCustomerKeys = true;
  private readonly clients = new Map<string, KMSClient>();

  constructor(private readonly config: { region: string }) {
    this.clients.set(config.region, new KMSClient({ region: config.region }));
  }

  /**
   * The client for a region, built on first use. A null region is the
   * legacy/platform-key path, where the key id is a bare UUID and the region
   * is the one this provider was configured with.
   */
  private getClient(region: string | null | undefined): KMSClient {
    const r = region ?? this.config.region;
    let c = this.clients.get(r);
    if (!c) {
      c = new KMSClient({ region: r });
      this.clients.set(r, c);
    }
    return c;
  }

  routableKeyRef(keyId: string): string | null {
    return parseKmsRegion(keyId) ? keyId : null;
  }

  async generateDataKey(input: {
    keyId: string;
    context?: EncryptionContext;
  }): Promise<{ plaintext: Buffer; wrapped: Buffer }> {
    const res = await this.getClient(parseKmsRegion(input.keyId)).send(
      new GenerateDataKeyCommand({
        KeyId: input.keyId,
        KeySpec: 'AES_256',
        ...(input.context ? { EncryptionContext: input.context } : {}),
      }),
    );
    if (!res.Plaintext || !res.CiphertextBlob) {
      throw new Error('KMS GenerateDataKey failed');
    }
    return { plaintext: Buffer.from(res.Plaintext), wrapped: Buffer.from(res.CiphertextBlob) };
  }

  async unwrapDataKey(input: {
    wrapped: Buffer;
    context?: EncryptionContext;
    keyRef?: string;
  }): Promise<Buffer> {
    // KeyId is omitted on Decrypt: AWS KMS derives the key from the ciphertext
    // metadata itself, so a service configured with one default key can
    // decrypt blobs written under another as long as IAM allows it.
    // Envelopes with no keyRef were written by a single-region client, so the
    // default region is right for them.
    const region = input.keyRef ? parseKmsRegion(input.keyRef) : null;
    const res = await this.getClient(region).send(
      new DecryptCommand({
        CiphertextBlob: input.wrapped,
        ...(input.context ? { EncryptionContext: input.context } : {}),
      }),
    );
    if (!res.Plaintext) throw new Error('KMS Decrypt failed');
    return Buffer.from(res.Plaintext);
  }

  async wrap(input: {
    keyId: string;
    plaintext: Buffer;
    context?: EncryptionContext;
  }): Promise<Buffer> {
    const res = await this.getClient(parseKmsRegion(input.keyId)).send(
      new EncryptCommand({
        KeyId: input.keyId,
        Plaintext: input.plaintext,
        ...(input.context ? { EncryptionContext: input.context } : {}),
      }),
    );
    if (!res.CiphertextBlob) throw new Error('KMS Encrypt failed');
    return Buffer.from(res.CiphertextBlob);
  }

  async unwrap(input: {
    blob: Buffer;
    context?: EncryptionContext;
    keyRef?: string;
  }): Promise<Buffer> {
    const region = input.keyRef ? parseKmsRegion(input.keyRef) : null;
    const res = await this.getClient(region).send(
      new DecryptCommand({
        CiphertextBlob: input.blob,
        ...(input.context ? { EncryptionContext: input.context } : {}),
      }),
    );
    if (!res.Plaintext) throw new Error('KMS Decrypt failed');
    return Buffer.from(res.Plaintext);
  }

  classify(err: unknown): KeyFailure {
    if (isAccessDenied(err)) return 'access_denied';
    if (isContextMismatch(err)) return 'context_mismatch';
    return 'other';
  }

  /**
   * Smoke-test a customer's CMK ARN by minting and unwrapping a data key under
   * it. Customer keys may live in any region; both calls go to the region in
   * the ARN (placeholder strings used in tests fall back to the default).
   */
  async smokeTestCustomerKey(keyArn: string, operatorId: string): Promise<void> {
    const client = this.getClient(parseKmsRegion(keyArn));
    const context = { operator_id: operatorId, probe: 'cmek-smoke-test' };
    const gdk = await client.send(
      new GenerateDataKeyCommand({ KeyId: keyArn, KeySpec: 'AES_256', EncryptionContext: context }),
    );
    if (!gdk.Plaintext || !gdk.CiphertextBlob) {
      throw new Error('GenerateDataKey returned empty');
    }
    const dk = await client.send(
      new DecryptCommand({ CiphertextBlob: gdk.CiphertextBlob, EncryptionContext: context }),
    );
    if (!dk.Plaintext) throw new Error('Decrypt returned empty');
    // Compare key material to confirm the round-trip is intact.
    if (!Buffer.from(dk.Plaintext).equals(Buffer.from(gdk.Plaintext))) {
      throw new Error('Decrypt plaintext did not match GenerateDataKey plaintext');
    }
  }
}
