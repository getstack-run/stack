import { createHash } from 'node:crypto';

/**
 * The receipt handle for a white-label tenant's proxy operation, filed under
 * its partner's billing account.
 *
 * Receipts are unique per (billing account, handle). Two tenants of one
 * partner may legitimately reuse the same client handle, so the handle is
 * bound to the acting tenant before it reaches the partner's ledger. The
 * digest is base64url SHA-256 (43 chars), inside the 22–256 base64url shape
 * every proxy operation key must have, and stable across retries.
 */
export function pooledAccountingKey(actingOperatorId: string, operationKey: string): string {
  return createHash('sha256')
    .update(`stack:pooled-proxy-accounting:v1\0${actingOperatorId}\0${operationKey}`)
    .digest('base64url');
}
