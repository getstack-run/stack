import type { KmsConfig } from './kms.js';
import { LocalKeyProvider, loadLocalKeys } from './local-key-provider.js';

/**
 * What the process environment says about who wraps this deployment's keys.
 * The API and the worker read the same variables and must agree, so the
 * decision is made here once.
 *
 *   STACK_KEY_PROVIDER         `aws-kms` or `local`; chosen from what is set when omitted
 *   AWS_KMS_KEY_ID, AWS_REGION the platform key (AWS KMS)
 *   STACK_KEY_FILE             path of a file holding the key-encryption key(s)
 *   STACK_KEY_ENCRYPTION_KEY   the key-encryption key(s) inline (64 hex characters or base64)
 */
export interface KeyProviderEnv {
  awsRegion?: string | undefined;
  awsKmsKeyId?: string | undefined;
  stackSystemOperatorId?: string | undefined;
  keyProvider?: string | undefined;
  keyFile?: string | undefined;
  keyEncryptionKey?: string | undefined;
}

export type KeyProviderSelection =
  | { kind: 'aws-kms'; config: KmsConfig }
  | { kind: 'local'; config: KmsConfig; provider: LocalKeyProvider }
  /** Nothing configured: the caller decides (development may use its stand-in, production refuses). */
  | { kind: 'none' };

/** The label a local provider's default key goes by. Never an AWS key id. */
export const LOCAL_DEFAULT_KEY_ID = 'local-kek';

export function keyProviderEnvFrom(env: Record<string, string | undefined>): KeyProviderEnv {
  return {
    awsRegion: env['AWS_REGION'],
    awsKmsKeyId: env['AWS_KMS_KEY_ID'],
    stackSystemOperatorId: env['STACK_SYSTEM_OPERATOR_ID'],
    keyProvider: env['STACK_KEY_PROVIDER'],
    keyFile: env['STACK_KEY_FILE'],
    keyEncryptionKey: env['STACK_KEY_ENCRYPTION_KEY'],
  };
}

/**
 * Pick the provider. Refuses configurations that leave the choice ambiguous
 * (an AWS key and a key file both present with no explicit choice) or half
 * made (a provider named, its key missing), so a deployment never wraps
 * under a key its operator did not mean.
 */
export function selectKeyProvider(env: KeyProviderEnv): KeyProviderSelection {
  const named = env.keyProvider?.trim() || undefined;
  if (named && named !== 'aws-kms' && named !== 'local') {
    throw new Error('[BOOT] STACK_KEY_PROVIDER must be "aws-kms" or "local"');
  }
  const explicit = named as 'aws-kms' | 'local' | undefined;
  const hasAws = Boolean(env.awsKmsKeyId);
  const hasLocal = Boolean(env.keyFile?.trim() || env.keyEncryptionKey?.trim());
  if (hasAws && hasLocal && !explicit) {
    throw new Error(
      '[BOOT] Both AWS_KMS_KEY_ID and a local key-encryption key are set; name the one to use with STACK_KEY_PROVIDER',
    );
  }
  const kind = explicit ?? (hasAws ? 'aws-kms' : hasLocal ? 'local' : undefined);
  if (!kind) return { kind: 'none' };

  if (kind === 'aws-kms') {
    if (!env.awsKmsKeyId) throw new Error('[BOOT] STACK_KEY_PROVIDER=aws-kms needs AWS_KMS_KEY_ID');
    if (!env.awsRegion || !env.stackSystemOperatorId) {
      throw new Error('[BOOT] Production KMS configuration is incomplete');
    }
    return {
      kind,
      config: {
        region: env.awsRegion,
        defaultKeyId: env.awsKmsKeyId,
        stackSystemOperatorId: env.stackSystemOperatorId,
      },
    };
  }

  const provider = new LocalKeyProvider(
    loadLocalKeys({
      ...(env.keyFile?.trim() ? { file: env.keyFile } : {}),
      ...(env.keyEncryptionKey?.trim() ? { inline: env.keyEncryptionKey } : {}),
    }),
  );
  return {
    kind,
    provider,
    config: {
      provider,
      defaultKeyId: LOCAL_DEFAULT_KEY_ID,
      // A local deployment has no dogfood operator whose data must stay under
      // a platform key: every key is the one key.
      ...(env.stackSystemOperatorId ? { stackSystemOperatorId: env.stackSystemOperatorId } : {}),
    },
  };
}
