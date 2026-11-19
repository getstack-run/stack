import { KmsService, keyProviderEnvFrom, selectKeyProvider } from '@stack/vault';
import { usesLocalKeyProvider } from './cmek-kms-selector.js';

/**
 * The key service behind the worker's signing and vault credential reads: the
 * one the API wraps with, chosen by the same variables.
 *
 *   - a key-encryption key file or value (self-managed): the local provider;
 *   - `AWS_KMS_KEY_ID` (STACK's hosted deployment): AWS KMS, in `AWS_REGION`
 *     (eu-north-1 when unset, as it always was here);
 *   - neither: the caller's stand-in, which production never reaches because
 *     the CMEK selection and the signing boot refuse first.
 */
export function createDeploymentKms(
  fallback: KmsService,
  stackSystemOperatorId: string,
  env: NodeJS.ProcessEnv = process.env,
): KmsService {
  if (usesLocalKeyProvider(env)) {
    const selection = selectKeyProvider({
      ...keyProviderEnvFrom(env),
      stackSystemOperatorId,
    });
    if (selection.kind === 'none') return fallback;
    return new KmsService(selection.config);
  }
  if (env['AWS_KMS_KEY_ID']) {
    return new KmsService({
      region: env['AWS_REGION'] ?? 'eu-north-1',
      defaultKeyId: env['AWS_KMS_KEY_ID'],
      stackSystemOperatorId,
    });
  }
  return fallback;
}
