import { parseCredentialObject } from '../credential-fields.js';
import type { CredentialFields } from '../oauth-token-lifecycle.js';
import type { ServiceConnectionContext } from './context.js';

/** The app a grant was made through, as a connection's binding names it (the client id only as its digest). */
export interface GrantApp {
  owner_id: string;
  provider: string;
  client_id_hash: string;
}

/**
 * Whether the operator holds another live connection, still within what its
 * app may ask for, made through the same app. A provider that ends a grant by
 * revoking one refresh token may end it for the whole person and app, so such
 * a connection's token would stop working too; the caller leaves the grant
 * alone and the customer is asked to disconnect instead. Which person a grant
 * belongs to is not recorded, so two connections of one app count as sharing.
 * Fails closed: a connection that cannot be read counts as sharing, because
 * ending a grant is the step that cannot be undone.
 */
export async function sharesAppGrant(
  ctx: ServiceConnectionContext,
  operatorId: string,
  app: GrantApp,
  exceptConnectionId?: string,
): Promise<boolean> {
  for (const other of await ctx.serviceRepo.findConnectionsByOperator(operatorId)) {
    if (other.id === exceptConnectionId || !other.oauth_managed || !other.credential_encrypted) continue;
    // A Slack or Jira connection cannot stand on a Google grant: not read, so the check costs a KMS call for the
    // handful of connections of the app's own family and for no other.
    if (ctx.hooks.oauthAppServes && !ctx.hooks.oauthAppServes(app.provider, other.provider)) continue;
    let binding: CredentialFields['oauth_app_binding'];
    try {
      binding = parseCredentialObject<CredentialFields>(
        await ctx.decryptCredential(other.operator_id, other.id, other.credential_encrypted, other.provider),
      )?.oauth_app_binding;
    } catch {
      return true;
    }
    if (!binding || binding.owner_id !== app.owner_id || binding.provider !== app.provider
      || binding.client_id_hash !== app.client_id_hash) continue;
    if (ctx.hooks.oauthAppScopesExceeded?.(binding, other.provider, other.scopes) === true) continue;
    return true;
  }
  return false;
}
