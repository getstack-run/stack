// The fixed Stripe read target used to reconcile an uncertain outcome. It decrypts the prepared
// request only to bind the provider marker and account, never a response body or credential.

import { ProxyOperationId } from '@stack/shared';
import { metadataFrom } from './replay.js';
import {
  type PreparedProxyRequest,
  type StripeReconciliationTarget,
  type ProxyOperationDeps,
} from './types.js';
import { constantTimeHexEqual, preparedAad, sha256 } from './envelope.js';

/**
 * Internal-only target for the fixed Stripe read adapter. This decrypts no
 * response body and returns no credential. Route authorization must already
 * have established a current owner/admin dashboard session.
 */
export async function readStripeReconciliationTarget(deps: ProxyOperationDeps, input: {
  operatorId: string;
  operationKey: string;
  allowedConnections?: readonly string[];
  now?: Date;
}): Promise<StripeReconciliationTarget | null> {
  if (!ProxyOperationId.safeParse(input.operationKey).success) return null;
  const operationKeyHash = sha256(input.operationKey);
  const operation = await deps.repository.findVisibleByOperationKey(
    input.operatorId,
    operationKeyHash,
    input.allowedConnections,
  );
  const now = input.now ?? new Date();
  if (!operation || !['outcome_unknown', 'response_received'].includes(operation.delivery_state)
    || operation.adapter_kind !== 'stripe'
    || operation.provider !== 'stripe'
    || operation.method !== 'POST'
    || !operation.prepared_request_encrypted
    || operation.prepared_request_readable_until <= now
    || operation.replay_state === 'erased') return null;
  const plaintext = await deps.kms.decrypt(
    operation.prepared_request_encrypted,
    preparedAad(input.operatorId, operation.id),
  );
  const prepared = JSON.parse(plaintext) as PreparedProxyRequest;
  let url: URL;
  try { url = new URL(prepared.finalUrl); } catch { return null; }
  if (prepared.version !== 1 || prepared.service !== 'stripe'
    || prepared.method !== 'POST'
    || url.origin !== 'https://api.stripe.com'
    || url.pathname !== '/v1/refunds'
    || prepared.requestHash !== operation.request_hash) return null;
  const stripeAccount = prepared.headers['stripe-account'] ?? null;
  const accountBinding = stripeAccount ?? 'credential-owner';
  if (!operation.provider_account_hash
    || !constantTimeHexEqual(operation.provider_account_hash, sha256(accountBinding))) return null;
  return {
    metadata: metadataFrom(operation),
    operationKeyHash,
    providerMarker: `stack_${operationKeyHash}`,
    stripeAccount,
  };
}
