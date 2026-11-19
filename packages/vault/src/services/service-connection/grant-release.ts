import { parseCredentialObject } from '../credential-fields.js';
import type { CredentialFields } from '../oauth-token-lifecycle.js';
import type { ServiceConnectionContext } from './context.js';
import { sharesAppGrant } from './shared-grant.js';

/**
 * Hands the credential of a connection that was just closed, or marked for
 * reconnecting, to the deployment's `grantDropped` hook. Best effort: the
 * connection is already closed in its own transaction, so a failure here (the
 * KMS, the provider) never fails the caller and never reaches it. It is not
 * silent: the connection's id and provider are logged and reported (never the
 * credential or what the provider said), and an operator can end the grant at
 * the provider later. Never rejects.
 */
export async function releaseGrant(
  ctx: ServiceConnectionContext,
  conn: { id: string; operator_id: string; provider: string; scopes: readonly string[]; credential_encrypted: string },
): Promise<void> {
  if (!ctx.hooks.grantDropped) return;
  try {
    const credential = parseCredentialObject<CredentialFields>(
      await ctx.decryptCredential(conn.operator_id, conn.id, conn.credential_encrypted, conn.provider),
    );
    const binding = credential?.oauth_app_binding;
    if (credential) {
      await ctx.hooks.grantDropped(
        { id: conn.id, provider: conn.provider, scopes: conn.scopes },
        credential,
        { sharesGrant: async () => binding ? sharesAppGrant(ctx, conn.operator_id, binding, conn.id) : false },
      );
    }
  } catch {
    console.warn(
      '[service-connection] grant could not be ended at the provider:', conn.id, conn.provider, 'An operator can end the grant there.',
    );
    try {
      ctx.hooks.grantReleaseFailed?.({ connectionId: conn.id, provider: conn.provider });
    } catch {
      // Reporting never fails the caller either.
    }
  }
}
