// Post-response work lease: claim one stored operation and decrypt its work context, releasing the
// lease for retry if the stored context is invalid.

import { randomBytes } from 'node:crypto';
import { canonicalize, evidenceUrl } from '@stack/shared';
import {
  type ProxyPostResponseContext,
  type ClaimedProxyPostResponseWork,
  type ProxyOperationDeps,
} from './types.js';
import {
  ENVELOPE_VERSION,
  OWNER_LEASE_MS,
  postResponseRetryAt,
  postResponseAad,
  sha256,
} from './envelope.js';

export async function claimPostResponseWork(
  deps: ProxyOperationDeps,
  operationId?: string,
): Promise<ClaimedProxyPostResponseWork | null> {
  const token = randomBytes(32).toString('base64url');
  const operation = await deps.repository.claimPostResponseWork({
    ownerHash: sha256(token),
    leaseExpiresAt: new Date(Date.now() + OWNER_LEASE_MS),
    operationId,
  });
  if (!operation?.post_response_context_encrypted) return null;
  try {
    const plaintext = await deps.kms.decrypt(
      operation.post_response_context_encrypted,
      postResponseAad(operation.operator_id, operation.id),
    );
    const context = JSON.parse(plaintext) as ProxyPostResponseContext;
    if (context.version !== ENVELOPE_VERSION || !context.audit || !context.action) {
      throw new Error('Stored proxy post-response context is invalid');
    }
    return { operation, token, context };
  } catch (error) {
    await deps.repository.releasePostResponseWork({
      operatorId: operation.operator_id,
      operationId: operation.id,
      ownerHash: sha256(token),
      retryAt: postResponseRetryAt(operation.post_response_attempts),
    }).catch(() => false);
    throw error;
  }
}

/**
 * A context stored before the signed records stopped carrying a query string still names the full URL the agent sent.
 * This rewrites each queued one (the encrypted context is read, its `originalUrl` put in evidence form, and the hash of
 * the parameters taken over the same form, as the intent claim states them) so nothing is left at rest that the records
 * would not show. Idempotent: a context already in evidence form is left as it is. Work someone is processing is left
 * alone (it clears its context when it completes), and a context that cannot be read is counted and left.
 */
export async function redactQueuedPostResponseContexts(
  deps: ProxyOperationDeps,
  options: { batch?: number } = {},
): Promise<{ scanned: number; redacted: number; unreadable: number }> {
  const batch = options.batch ?? 200;
  const result = { scanned: 0, redacted: 0, unreadable: 0 };
  let afterId: string | undefined;
  for (;;) {
    const rows = await deps.repository.listQueuedPostResponseContexts({ ...(afterId ? { afterId } : {}), limit: batch });
    if (rows.length === 0) return result;
    for (const row of rows) {
      afterId = row.id;
      result.scanned += 1;
      const stored = row.post_response_context_encrypted;
      if (!stored) continue;
      try {
        const aad = postResponseAad(row.operator_id, row.id);
        const context = JSON.parse(await deps.kms.decrypt(stored, aad)) as ProxyPostResponseContext;
        const original = context.action?.originalUrl;
        if (typeof original !== 'string') continue;
        const evidence = evidenceUrl(original) ?? '';
        if (evidence === original) continue;
        context.action.originalUrl = evidence;
        context.action.parametersHash = rehashedParameters(context.action, original, evidence);
        const encrypted = await deps.kms.encrypt(canonicalize(context), aad);
        const replaced = await deps.repository.replacePostResponseContext({
          operatorId: row.operator_id,
          operationId: row.id,
          expectedCiphertext: stored,
          ciphertext: encrypted.ciphertext,
          keyRef: encrypted.keyRef,
        });
        if (replaced) result.redacted += 1;
      } catch {
        result.unreadable += 1;
      }
    }
    if (rows.length < batch) return result;
  }
}

/** The parameters hash over the URL's evidence form, when the stored hash was over its full form (else it is kept). */
function rehashedParameters(
  action: ProxyPostResponseContext['action'],
  original: string,
  evidence: string,
): string {
  const over = (url: string, body: unknown) =>
    sha256(JSON.stringify({ service: action.service, method: action.method, url, body }));
  // The context keeps an absent body as null; the hash was taken over whichever the call had.
  for (const body of [action.originalBody, action.originalBody === null ? undefined : action.originalBody]) {
    if (over(original, body) === action.parametersHash) return over(evidence, body);
  }
  return action.parametersHash;
}
