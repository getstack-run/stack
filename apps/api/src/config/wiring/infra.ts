import {
  createDb,
  observeRedisClient,
  REDIS_COMMAND_TIMEOUT_MS,
  REDIS_CONNECT_TIMEOUT_MS,
  waitForRedis,
  type Database,
} from '@stack/shared';
import { KmsService, selectKeyProvider } from '@stack/vault';
import type { RedisOptions } from 'ioredis';
import { env } from '../env.js';

/** How many PINGs a one-shot command (a script, the install's command line) tries before it gives up: about fifteen seconds of waiting. */
export const ONE_SHOT_REDIS_ATTEMPTS = 5;

/** `overrides` is for tests (a fast retry strategy, a short connect timeout); the server passes none. */
export async function createRedis(url: string, overrides: Partial<RedisOptions> = {}) {
  const { Redis } = await import('ioredis');
  // A command gives up after two reconnect attempts instead of the library's
  // twenty, so a Redis outage answers callers with a retriable 503 in seconds
  // rather than holding every request open.
  // A command also gives up after REDIS_COMMAND_TIMEOUT_MS: a socket that is open
  // and never answers does not reconnect, so the retry cap alone would hold every
  // authenticated request for as long as the socket stays silent. The timeout is a
  // `Command timed out` the error handler answers 503 (fail closed, retriable).
  // No command on this client blocks, so the cap cannot cut a legitimate wait.
  const redis = new Redis(url, {
    maxRetriesPerRequest: 2,
    commandTimeout: REDIS_COMMAND_TIMEOUT_MS,
    connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
    ...overrides,
  });
  // Without a listener ioredis prints every reconnect failure, with the driver's
  // text, for as long as an outage lasts; keep one safe line per half minute, on
  // this client and on every subscriber copied from it.
  return observeRedisClient(redis);
}

export type RedisClient = Awaited<ReturnType<typeof createRedis>>;

/**
 * `createRedis`, then wait until Redis answers a PING before anything else uses
 * it. The boot opens pub/sub subscribers next, and a `subscribe` has no command
 * timeout, so against a Redis that accepts the socket and never answers it would
 * hold the boot for ever with nothing logged. The PING is capped by the client's
 * command timeout: each attempt ends, is logged and is retried with backoff, so
 * the boot waits visibly and goes on the moment Redis answers. A server does not
 * exit (`maxAttempts` unset): a machine that exits is restarted only a few times
 * before it is left stopped. A one-shot command passes a cap and fails instead.
 */
export async function connectRedis(
  url: string,
  options: { overrides?: Partial<RedisOptions>; sleep?: (ms: number) => Promise<void>; maxAttempts?: number } = {},
): Promise<RedisClient> {
  const redis = await createRedis(url, options.overrides);
  try {
    await waitForRedis(redis, options.sleep, options.maxAttempts);
  } catch (err) {
    redis.disconnect();
    throw err;
  }
  return redis;
}

export interface Infrastructure {
  /**
   * The wiring is typed against the full schema until its callers are switched to the seams. On the
   * engine entry the handle knows the engine's tables only; nothing there builds a repository that
   * queries a hosted table relationally.
   */
  db: Database;
  redis: RedisClient;
  kms: KmsService;
}

/**
 * Opens the database handle, Redis and KMS. Boot refuses here when KMS is not
 * configured: production never starts on the dev KMS. A deployment with tables
 * of its own passes its schema (the engine's merged with its own), so
 * relational queries on those tables work.
 */
export async function createInfrastructure(
  schema?: Record<string, unknown>,
  options: { redisAttempts?: number } = {},
): Promise<Infrastructure> {
  if (!env.DATABASE_URL) throw new Error('[BOOT] DATABASE_URL is required');
  const db = (schema ? createDb(env.DATABASE_URL, schema) : createDb(env.DATABASE_URL)) as unknown as Database;
  const redis = await connectRedis(env.REDIS_URL, options.redisAttempts === undefined ? {} : { maxAttempts: options.redisAttempts });

  const kms = createConfiguredKms({
    nodeEnv: env.NODE_ENV,
    awsRegion: env.AWS_REGION,
    awsKmsKeyId: env.AWS_KMS_KEY_ID,
    stackSystemOperatorId: env.STACK_SYSTEM_OPERATOR_ID,
    allowInsecureDevKms: process.env['STACK_ALLOW_INSECURE_DEV_KMS'] === 'true',
    keyProvider: process.env['STACK_KEY_PROVIDER'],
    keyFile: process.env['STACK_KEY_FILE'],
    keyEncryptionKey: process.env['STACK_KEY_ENCRYPTION_KEY'],
  });

  return { db, redis, kms };
}

interface ConfiguredKmsInput {
  nodeEnv: string;
  awsRegion: string;
  awsKmsKeyId: string;
  stackSystemOperatorId: string;
  allowInsecureDevKms: boolean;
  /** `aws-kms` or `local`; chosen from what is configured when omitted. */
  keyProvider?: string | undefined;
  /** A file holding the key-encryption key(s) of a deployment with no cloud key service. */
  keyFile?: string | undefined;
  keyEncryptionKey?: string | undefined;
}

/**
 * Who wraps this deployment's keys: AWS KMS, or a key-encryption key the
 * install holds (a file or a value). With neither, production refuses and
 * development needs the explicit opt-in to the base64 stand-in. The stand-in
 * is never a way to run production, whatever else is set.
 */
export function createConfiguredKms(input: ConfiguredKmsInput): KmsService {
  const selection = selectKeyProvider({
    awsRegion: input.awsRegion,
    awsKmsKeyId: input.awsKmsKeyId,
    stackSystemOperatorId: input.stackSystemOperatorId,
    keyProvider: input.keyProvider,
    keyFile: input.keyFile,
    keyEncryptionKey: input.keyEncryptionKey,
  });
  if (selection.kind !== 'none') return new KmsService(selection.config);
  if (input.nodeEnv === 'production') {
    throw new Error(
      '[BOOT] AWS_KMS_KEY_ID is required in production, or a key-encryption key (STACK_KEY_FILE or STACK_KEY_ENCRYPTION_KEY)',
    );
  }
  if (!input.allowInsecureDevKms) {
    throw new Error(
      '[BOOT] Local dev KMS is insecure. Set STACK_ALLOW_INSECURE_DEV_KMS=true to opt in explicitly.',
    );
  }
  console.warn(
    '[SECURITY] Insecure local KMS opt-in active:', 'credentials are not encrypted',
  );
  return createDevKms();
}

/** Dev-only mock KMS that uses base64 (no encryption). NEVER use in production. */
function createDevKms(): KmsService {
  return {
    async encrypt(plaintext: string) {
      return {
        ciphertext: Buffer.from(plaintext).toString('base64'),
        keyRef: 'dev-key',
      };
    },
    async decrypt(ciphertext: string) {
      return Buffer.from(ciphertext, 'base64').toString('utf8');
    },
    async encryptDirect(plaintext: Buffer) {
      return plaintext;
    },
    async decryptDirect(ciphertext: Buffer) {
      return ciphertext;
    },
    async smokeTestCustomerKey() {
      // Dev mode: pretend the customer's key works. CMEK is a no-op in
      // dev because the underlying mock doesn't encrypt anyway.
    },
    setOperatorKeyHandlers() {
      // No-op in dev — the mock doesn't route on operator_id, doesn't
      // need cache eviction (no cache), and never goes down the legacy
      // fallback path (no real KMS to throw context mismatch).
    },
  } as unknown as KmsService;
}
