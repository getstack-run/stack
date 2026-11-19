import { readFileSync } from 'node:fs';
import type { KmsService } from './kms.js';

export interface SigningKeySourceInput {
  /** `SESSION_SIGNING_KEY_WRAPPED`: the PEM wrapped by the key service, base64. */
  wrapped?: string | undefined;
  /** `SESSION_SIGNING_KEY_FILE`: path of a file holding the PEM (a mounted secret). */
  file?: string | undefined;
  /** `SESSION_SIGNING_KEY`: the PEM itself. */
  plaintext?: string | undefined;
  kms: Pick<KmsService, 'decryptDirect'>;
  systemOperatorId: string;
  /**
   * May the key be read from a plain file? True for an install that holds its
   * own keys. STACK's hosted deployment keeps its key wrapped under AWS KMS and
   * refuses a key file, so a stray file can never become its signing key.
   */
  allowFile: boolean;
}

/**
 * Where the deployment's signing key (EdDSA, PEM) comes from, in order of
 * preference: wrapped by the key service, a file, the environment. Returns
 * undefined when none is set; the caller decides whether that is a development
 * convenience (an ephemeral key) or a boot refusal.
 *
 * The wrapped form is bound to `{operator_id, purpose: 'passport_signing'}`,
 * so it cannot be unwrapped as anything else.
 */
export async function resolveSigningKeyPem(input: SigningKeySourceInput): Promise<string | undefined> {
  if (input.wrapped) {
    const pem = await input.kms.decryptDirect(Buffer.from(input.wrapped, 'base64'), {
      operatorId: input.systemOperatorId,
      expectedContext: {
        operator_id: input.systemOperatorId,
        purpose: 'passport_signing',
      },
    });
    return pem.toString('utf8');
  }
  const file = input.file?.trim();
  if (file) {
    if (!input.allowFile) {
      throw new Error('[BOOT] SESSION_SIGNING_KEY_FILE is only accepted by a self-managed deployment');
    }
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      throw new Error('[BOOT] The signing key file cannot be read');
    }
    if (!text.includes('PRIVATE KEY')) {
      throw new Error('[BOOT] The signing key file does not hold a PEM private key');
    }
    return text;
  }
  if (input.plaintext) return input.plaintext;
  return undefined;
}
