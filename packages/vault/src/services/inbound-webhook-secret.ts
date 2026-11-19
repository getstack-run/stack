// The two purposes an inbound webhook's downstream signing secret has been sealed under.
//
// Rows made before downstream and incoming keys were separated hold their secret under
// `inbound_webhook_secret`; every row made since holds it under `inbound_webhook_downstream_secret`. Both kinds
// are in production, so anything that reads or moves the secret asks for the current purpose first and the
// earlier one second, and writes it back under the purpose it was found under: the sealing authenticates the
// purpose, so a secret is never read under the wrong one and never silently re-purposed.

import { CmekRevokedError } from '@stack/shared';
import type { KmsService } from '../crypto/kms.js';

export const DOWNSTREAM_SECRET_PURPOSE = 'inbound_webhook_downstream_secret';
export const LEGACY_WEBHOOK_SECRET_PURPOSE = 'inbound_webhook_secret';

export type WebhookSecretPurpose = typeof DOWNSTREAM_SECRET_PURPOSE | typeof LEGACY_WEBHOOK_SECRET_PURPOSE;

export function webhookSecretContext(operatorId: string, webhookId: string, purpose: WebhookSecretPurpose) {
  return { operator_id: operatorId, webhook_id: webhookId, purpose };
}

/**
 * Opens a sealed downstream secret under the current purpose and, when `allowLegacy`, under the earlier one.
 * Any failure to open under the current purpose leads to the earlier one (the key service's own errors do not
 * say which kind of mismatch they are), except a revoked customer key, which ends the attempt. When neither
 * opens, the first error is the one thrown.
 */
export async function openDownstreamSecret(
  kms: Pick<KmsService, 'decryptDirect'>,
  args: { operatorId: string; webhookId: string; sealed: string; allowLegacy: boolean },
): Promise<{ plain: Buffer; purpose: WebhookSecretPurpose }> {
  const wrapped = Buffer.from(args.sealed, 'base64');
  const open = async (purpose: WebhookSecretPurpose) => ({
    plain: await kms.decryptDirect(wrapped, {
      operatorId: args.operatorId,
      expectedContext: webhookSecretContext(args.operatorId, args.webhookId, purpose),
    }),
    purpose,
  });
  try {
    return await open(DOWNSTREAM_SECRET_PURPOSE);
  } catch (firstError) {
    if (!args.allowLegacy || firstError instanceof CmekRevokedError) throw firstError;
    try {
      return await open(LEGACY_WEBHOOK_SECRET_PURPOSE);
    } catch {
      throw firstError;
    }
  }
}
