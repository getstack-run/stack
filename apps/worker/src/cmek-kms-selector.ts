import type { KmsConfig } from '@stack/vault';

export type CmekKmsSelection =
  | { kind: 'real'; config: KmsConfig }
  | { kind: 'skip'; reason: string };

export type WorkerCmekEnv = {
  AWS_REGION?: string | undefined;
  AWS_KMS_KEY_ID?: string | undefined;
  STACK_SYSTEM_OPERATOR_ID?: string | undefined;
  NODE_ENV?: string | undefined;
  STACK_KEY_PROVIDER?: string | undefined;
  STACK_KEY_FILE?: string | undefined;
  STACK_KEY_ENCRYPTION_KEY?: string | undefined;
};

/** True when this deployment wraps keys with a key-encryption key it holds itself. */
export function usesLocalKeyProvider(env: WorkerCmekEnv): boolean {
  if (env.STACK_KEY_PROVIDER === 'local') return true;
  if (env.STACK_KEY_PROVIDER === 'aws-kms') return false;
  return !env.AWS_KMS_KEY_ID && Boolean(env.STACK_KEY_FILE?.trim() || env.STACK_KEY_ENCRYPTION_KEY?.trim());
}

/**
 * Decide the worker's CMEK KMS posture from env vars.
 *
 * Three outcomes:
 *  - `real`  — AWS_REGION + AWS_KMS_KEY_ID both set. Worker runs the CMEK
 *              migration tick under the real AWS KMS client.
 *  - `skip`  — AWS env missing AND NODE_ENV is not production. Worker boots,
 *              but the CMEK migration tick is disabled. Local-dev / test path.
 *  - `throw` — AWS env missing AND NODE_ENV is production. Hard-fail boot.
 *
 * Why hard-fail in prod: silently falling back to a base64 dev encryptor
 * for migration re-encrypt writes would re-encrypt customer ciphertext as
 * plaintext-base64. That is a confidentiality regression we cannot ship
 * even briefly. The right shape is "no CMEK tick at all" rather than "CMEK
 * tick with a broken encryptor"; refusing to boot makes the configuration
 * gap visible at deploy time instead of silently after the first migrating
 * operator lands.
 */
export function chooseCmekKmsForWorker(env: WorkerCmekEnv): CmekKmsSelection {
  // A key file has no customer key service behind it, so there is no
  // customer-managed key to migrate to or from: nothing for the tick to do.
  if (usesLocalKeyProvider(env)) {
    return {
      kind: 'skip',
      reason: 'local key-encryption key in use; customer-managed keys are not available, CMEK migration tick disabled.',
    };
  }
  const region = env.AWS_REGION;
  const keyId = env.AWS_KMS_KEY_ID;

  if (region && keyId) {
    return {
      kind: 'real',
      config: {
        region,
        defaultKeyId: keyId,
        stackSystemOperatorId: env.STACK_SYSTEM_OPERATOR_ID || undefined,
      },
    };
  }

  if (env.NODE_ENV === 'production') {
    throw new Error(
      'STACK Worker boot: CMEK migration tick requires AWS_REGION + AWS_KMS_KEY_ID ' +
        'in production. Without them the tick would re-encrypt customer ciphertext ' +
        'under a base64 mock — a confidentiality regression. Set both env vars, or ' +
        'unset NODE_ENV=production to skip the tick for local/dev runs. ' +
        `Present: AWS_REGION=${region ? 'yes' : 'no'} AWS_KMS_KEY_ID=${keyId ? 'yes' : 'no'}.`,
    );
  }

  return {
    kind: 'skip',
    reason: 'AWS_REGION + AWS_KMS_KEY_ID not set; CMEK migration tick disabled (dev mode).',
  };
}
