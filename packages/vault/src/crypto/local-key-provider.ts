import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import type { EncryptionContext, KeyFailure, KeyProvider } from './key-provider.js';

/**
 * A key-encryption key (KEK) the install holds itself, for a deployment that
 * has no cloud key service: a 32-byte key in a file (a mounted secret, a file
 * on an encrypted volume) or in an environment variable.
 *
 * It is a real wrap, not the base64 stand-in of local development, and it is
 * the only local provider production accepts. Every wrap is AES-256-GCM under
 * the KEK with the encryption context as additional authenticated data, so a
 * ciphertext moved to another row fails to unwrap exactly as it does under AWS
 * KMS.
 *
 * Several keys may be configured. The first wraps; every one unwraps, so a
 * rotation is: put the new key first, keep the old below it, re-wrap (or let
 * the old key's data age out), then drop the old one. A wrapped blob names its
 * key by a short fingerprint, never the key.
 *
 * Wire format: `4C 4B 01` | key fingerprint (4 bytes) | iv (12) | tag (16) | ciphertext.
 */

const MAGIC = Buffer.from([0x4c, 0x4b, 0x01]);
const IV_BYTES = 12;
const TAG_BYTES = 16;
const FINGERPRINT_BYTES = 4;
const KEY_BYTES = 32;
const HEADER_BYTES = MAGIC.length + FINGERPRINT_BYTES + IV_BYTES + TAG_BYTES;

/** Why a local unwrap failed. The wording never includes key material. */
export class LocalKeyError extends Error {
  constructor(
    readonly reason: 'malformed' | 'unknown_key' | 'authentication_failed',
    message: string,
  ) {
    super(message);
    this.name = 'LocalKeyError';
  }
}

function fingerprint(key: Buffer): Buffer {
  return createHash('sha256').update('stack-local-kek-v1').update(key).digest().subarray(0, FINGERPRINT_BYTES);
}

function canonicalAad(context: EncryptionContext | undefined): Buffer {
  if (!context) return Buffer.alloc(0);
  const sorted = Object.keys(context)
    .sort()
    .reduce<Record<string, string>>((acc, k) => {
      acc[k] = context[k]!;
      return acc;
    }, {});
  return Buffer.from(JSON.stringify(sorted), 'utf8');
}

/** A key decoded from hex or base64 must be exactly 32 bytes and not a single repeated byte. */
export function parseKeyEncryptionKey(text: string): Buffer {
  const value = text.trim();
  let key: Buffer | undefined;
  if (/^[0-9a-fA-F]{64}$/.test(value)) key = Buffer.from(value, 'hex');
  else if (/^[A-Za-z0-9+/_-]{43}=?$/.test(value)) key = Buffer.from(value, 'base64');
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('[BOOT] A key-encryption key must be 32 bytes, written as 64 hex characters or base64');
  }
  if (key.every((byte) => byte === key[0])) {
    throw new Error('[BOOT] The key-encryption key is not random: it is one byte repeated');
  }
  return key;
}

/** One key per non-empty line (or comma), `#` starts a comment. The first is the active key. */
export function parseKeyList(text: string): Buffer[] {
  const keys = text
    .split(/[\r\n,]+/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter((line) => line.length > 0)
    .map(parseKeyEncryptionKey);
  if (keys.length === 0) throw new Error('[BOOT] No key-encryption key found');
  const seen = new Set<string>();
  for (const key of keys) {
    const id = fingerprint(key).toString('hex');
    if (seen.has(id)) throw new Error('[BOOT] The same key-encryption key is listed twice');
    seen.add(id);
  }
  return keys;
}

export interface LocalKeySource {
  /** Path of a file holding the key or keys. */
  file?: string;
  /** The key or keys inline (an environment variable). */
  inline?: string;
}

/**
 * Read the keys from their source. A file wins over an inline value only when
 * the inline one is absent: configuring both is refused, because it would make
 * the active key depend on which is read first.
 */
export function loadLocalKeys(
  source: LocalKeySource,
  warn: (message: string) => void = (m) => console.warn(m),
): Buffer[] {
  const file = source.file?.trim();
  const inline = source.inline?.trim();
  if (file && inline) {
    throw new Error('[BOOT] Set the key-encryption key as a file or as a value, not both');
  }
  if (file) {
    let text: string;
    try {
      const mode = statSync(file).mode;
      if (process.platform !== 'win32' && (mode & 0o077) !== 0) {
        warn('[SECURITY] The key encryption key file is readable by other users.');
      }
      text = readFileSync(file, 'utf8');
    } catch {
      throw new Error('[BOOT] The key-encryption key file cannot be read');
    }
    return parseKeyList(text);
  }
  if (inline) return parseKeyList(inline);
  throw new Error('[BOOT] A key-encryption key is required: set STACK_KEY_FILE or STACK_KEY_ENCRYPTION_KEY');
}

export class LocalKeyProvider implements KeyProvider {
  readonly kind = 'local' as const;
  readonly supportsCustomerKeys = false;
  private readonly keys: Array<{ key: Buffer; id: Buffer }>;

  constructor(keys: Buffer[]) {
    if (keys.length === 0) throw new Error('[BOOT] A key-encryption key is required');
    for (const key of keys) {
      if (key.length !== KEY_BYTES) throw new Error('[BOOT] A key-encryption key must be 32 bytes');
    }
    this.keys = keys.map((key) => ({ key: Buffer.from(key), id: fingerprint(key) }));
  }

  static fromSource(source: LocalKeySource): LocalKeyProvider {
    return new LocalKeyProvider(loadLocalKeys(source));
  }

  /** Fingerprints of the keys this provider can unwrap, active first. For startup logs and doctor output. */
  fingerprints(): string[] {
    return this.keys.map((k) => k.id.toString('hex'));
  }

  routableKeyRef(): null {
    return null;
  }

  private seal(plaintext: Buffer, context: EncryptionContext | undefined): Buffer {
    const active = this.keys[0]!;
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', active.key, iv);
    cipher.setAAD(canonicalAad(context));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([MAGIC, active.id, iv, cipher.getAuthTag(), body]);
  }

  private open(blob: Buffer, context: EncryptionContext | undefined): Buffer {
    if (blob.length < HEADER_BYTES || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw new LocalKeyError('malformed', 'Wrapped value is not a local key-encryption key blob');
    }
    const id = blob.subarray(MAGIC.length, MAGIC.length + FINGERPRINT_BYTES);
    const entry = this.keys.find((k) => k.id.equals(id));
    if (!entry) {
      throw new LocalKeyError('unknown_key', 'No configured key-encryption key wrapped this value');
    }
    const ivStart = MAGIC.length + FINGERPRINT_BYTES;
    const iv = blob.subarray(ivStart, ivStart + IV_BYTES);
    const tag = blob.subarray(ivStart + IV_BYTES, ivStart + IV_BYTES + TAG_BYTES);
    const body = blob.subarray(HEADER_BYTES);
    try {
      const decipher = createDecipheriv('aes-256-gcm', entry.key, iv);
      decipher.setAAD(canonicalAad(context));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]);
    } catch {
      // GCM cannot say whether the context, the bytes or the key was wrong.
      throw new LocalKeyError('authentication_failed', 'Wrapped value failed authentication');
    }
  }

  async generateDataKey(input: {
    keyId: string;
    context?: EncryptionContext;
  }): Promise<{ plaintext: Buffer; wrapped: Buffer }> {
    const plaintext = randomBytes(KEY_BYTES);
    return { plaintext, wrapped: this.seal(plaintext, input.context) };
  }

  async unwrapDataKey(input: { wrapped: Buffer; context?: EncryptionContext }): Promise<Buffer> {
    return this.open(input.wrapped, input.context);
  }

  async wrap(input: { keyId: string; plaintext: Buffer; context?: EncryptionContext }): Promise<Buffer> {
    return this.seal(input.plaintext, input.context);
  }

  async unwrap(input: { blob: Buffer; context?: EncryptionContext }): Promise<Buffer> {
    return this.open(input.blob, input.context);
  }

  classify(err: unknown): KeyFailure {
    if (err instanceof LocalKeyError && err.reason === 'authentication_failed') return 'context_mismatch';
    return 'other';
  }

  async smokeTestCustomerKey(): Promise<void> {
    throw new Error('Customer-managed keys need AWS KMS; this install holds its own key-encryption key');
  }
}
