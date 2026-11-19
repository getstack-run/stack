import { ConflictError } from '@stack/shared';
import {
  maybeRefreshAccessToken,
  maybeFetchClientCredentialsToken,
  type CredentialFields,
  credentialExpiresAt,
  OAuthLifecycleError,
  type ReconnectReason,
  tenantTokenUrl,
} from '../oauth-token-lifecycle.js';
import { parseCredentialObject } from '../credential-fields.js';
import type { ServiceConnectionContext } from './context.js';
import { releaseGrant } from './grant-release.js';
import { markReconnectRequired, notifyReconnectRequired } from './reconnect.js';

/** The connection columns OAuth renewal reads. */
export interface RenewableConnection {
  id: string;
  operator_id: string;
  provider: string;
  service_id: string;
  credential_version: number;
  oauth_managed?: boolean;
  /** The scopes the connection records. Absent: only what the lock re-reads is checked against the app. */
  scopes?: readonly string[];
}

/**
 * Why a connection's app no longer lets it renew, when it does not: the app is
 * one that is no longer run, or one whose allowed scopes do not cover what the
 * connection holds. Both end as the same reconnect-required state.
 */
function appReconnectReason(
  ctx: ServiceConnectionContext,
  binding: CredentialFields['oauth_app_binding'],
  provider: string,
  scopes: readonly string[] | undefined,
): ReconnectReason | null {
  if (!binding) return null;
  if (ctx.hooks.oauthAppRetired?.(binding) === true) return 'stack_oauth_app_retired';
  if (scopes && ctx.hooks.oauthAppScopesExceeded?.(binding, provider, scopes) === true) return 'oauth_app_scopes_narrowed';
  return null;
}

/**
 * Apply the OAuth lifecycle (refresh-token rotation, client_credentials grant)
 * to a decrypted credential before it is handed to the proxy or a caller. A
 * no-op for non-OAuth credentials and for tokens that are still fresh.
 *
 * With `requirePinnedPersistence`, the connection must still be at the
 * credential version the caller pinned, and a refresh that cannot durably
 * advance the version fails closed.
 */
export async function applyTokenLifecycle(
  ctx: ServiceConnectionContext,
  decrypted: string,
  conn: RenewableConnection,
  requirePinnedPersistence = false,
): Promise<{ credential: string; credentialVersion: number }> {
  const initial = parseCredentialObject<CredentialFields>(decrypted);
  if (!initial) {
    return { credential: decrypted, credentialVersion: conn.credential_version };
  }
  // A connection made through an app that no longer lets it renew never skips
  // this path, whatever its token's state: it is marked for reconnecting on
  // first use, so a token that never expires cannot keep it looking connected.
  const retired = appReconnectReason(ctx, initial.oauth_app_binding, conn.provider, conn.scopes) !== null;
  const refreshable = initial.refresh_token || (initial.client_id && initial.client_secret);
  const expiry = credentialExpiresAt(initial);
  if (!retired) {
    if (!refreshable && !(initial.access_token && expiry !== null && expiry <= Date.now())) {
      return { credential: decrypted, credentialVersion: conn.credential_version };
    }
    if (initial.access_token && expiry !== null && expiry > Date.now() + 60_000) {
      return { credential: decrypted, credentialVersion: conn.credential_version };
    }
  }

  // Resolve app metadata before opening the transaction. A pool full of
  // rotation waiters must not starve the lock holder of a second DB connection.
  let resolvedClient: { clientId: string; clientSecret: string; tenant?: string } | undefined;
  let clientError: unknown;
  if (initial.refresh_token && initial.oauth_app_binding && !retired) {
    try {
      if (!conn.oauth_managed) throw new OAuthLifecycleError(true);
      const service = await ctx.serviceRepo.findAccessibleServiceById(
        conn.service_id,
        conn.operator_id,
      );
      resolvedClient = await ctx.hooks.oauthClientResolver(conn.operator_id, initial, {
        serviceId: conn.service_id,
        provider: conn.provider,
        tokenUrl: service?.oauth_token_url ?? '',
      });
    } catch (error) {
      clientError = error;
    }
  }

  const outcome = await ctx.serviceRepo.withCredentialLock(
    conn.id,
    conn.operator_id,
    async (current, tx) => {
      if (
        !current ||
        current.status !== 'active' ||
        (requirePinnedPersistence && current.credential_version !== conn.credential_version)
      ) {
        throw new ConflictError('Service connection changed after proxy policy evaluation');
      }
      // Unlike the pre-lock read above, this does not check the shape: the row
      // was re-read under the lock, and a credential that stopped being JSON
      // between the two reads must surface as an error, not as a skipped renewal.
      const fields = JSON.parse(
        await ctx.decryptCredential(
          current.operator_id,
          current.id,
          current.credential_encrypted,
          current.provider,
        ),
      ) as CredentialFields;
      const service = await ctx.serviceRepo.findAccessibleServiceById(
        current.service_id,
        current.operator_id,
        tx,
      );
      let version = current.credential_version;
      try {
        const retryKey = `oauth_retry:${current.operator_id}:${current.id}:${version}`;
        if (ctx.redis && (await ctx.redis.get(retryKey))) throw new OAuthLifecycleError();
        const deps = {
          persistRefreshed: async (
            _id: string,
            _operator: string,
            _provider: string,
            next: CredentialFields,
            expiresAt: Date,
          ) => {
            const { ciphertext, keyRef } = await ctx.kms.encrypt(JSON.stringify(next), {
              operator_id: current.operator_id,
              provider: current.provider,
            });
            // A provider may narrow consent. Never widen the local connection ceiling.
            const returnedScopes =
              typeof next.scope === 'string' ? new Set(next.scope.split(/[ ,]+/)) : null;
            const scopes = returnedScopes
              ? current.scopes.filter((scope) => returnedScopes.has(scope))
              : current.scopes;
            const updated = await ctx.serviceRepo.replaceCredential(
              current.id,
              current.operator_id,
              version,
              {
                credential_encrypted: ciphertext,
                credential_ref: keyRef,
                expires_at: expiresAt,
                scopes,
              },
              tx,
            );
            if (!updated)
              throw new ConflictError('Credential changed while its OAuth token was being refreshed');
            version = updated.credential_version;
          },
        };
        const args = {
          fields,
          connectionId: current.id,
          operatorId: current.operator_id,
          provider: current.provider,
          deps,
        };
        let next = fields;
        // Re-read under the lock: the binding is the one the credential holds now.
        const appReason = appReconnectReason(ctx, fields.oauth_app_binding, current.provider, current.scopes);
        if (appReason) throw new OAuthLifecycleError(true, appReason);
        if (fields.refresh_token) {
          const expiry = credentialExpiresAt(fields);
          const needsRefresh = expiry === null || expiry <= Date.now() + 60_000;
          let client: { clientId: string; clientSecret: string; tenant?: string } | undefined;
          if (needsRefresh && fields.oauth_app_binding) {
            if (!current.oauth_managed) throw new OAuthLifecycleError(true);
            if (
              fields.oauth_app_binding.token_url !== (service?.oauth_token_url ?? '') ||
              fields.oauth_app_binding.service_id !== current.service_id ||
              fields.oauth_app_binding.connection_provider !== current.provider
            ) {
              throw new OAuthLifecycleError(true);
            }
            if (
              JSON.stringify(fields.oauth_app_binding) !== JSON.stringify(initial.oauth_app_binding)
            ) {
              throw new ConflictError('Service connection changed after proxy policy evaluation');
            }
            if (clientError) throw clientError;
            if (!resolvedClient) throw new OAuthLifecycleError(true);
            client = resolvedClient;
          }
          const tokenUrl =
            current.provider === 'figma'
              ? 'https://api.figma.com/v1/oauth/refresh'
              : tenantTokenUrl(service?.oauth_token_url ?? '', client?.tenant);
          next = await maybeRefreshAccessToken({
            ...args,
            ...(client ? { clientId: client.clientId, clientSecret: client.clientSecret } : {}),
            oauthTokenUrl: tokenUrl,
          });
        } else if (fields.client_id && fields.client_secret) {
          next = await maybeFetchClientCredentialsToken({
            ...args,
            defaultTokenUrl: service?.oauth_token_url ?? '',
          });
        } else {
          throw new OAuthLifecycleError(true);
        }
        return { credential: JSON.stringify(next), credentialVersion: version };
      } catch (error) {
        if (error instanceof OAuthLifecycleError && error.reconnectRequired) {
          // Return the error so the transaction COMMITS the terminal state.
          const eventId = await markReconnectRequired(ctx, current, tx, error.reason);
          return { error, connection: current, eventId };
        }
        if (ctx.redis) {
          // Non-secret backoff metadata only. An outage must not make every
          // waiting worker call the provider or request fresh consent.
          await ctx.redis.set(
            `oauth_retry:${current.operator_id}:${current.id}:${version}`,
            '1',
            'EX',
            30,
            'NX',
          );
        }
        throw error;
      }
    },
  );
  if (outcome.error) {
    await notifyReconnectRequired(ctx, conn, outcome, outcome.error.reason);
    // A grant the app's allowed scopes do not cover is ended at the provider, not left to be used by anyone with the
    // token. Not awaited: the caller is told to reconnect at once, whatever the provider is doing (the release is
    // bounded by its own timeout, never rejects, and logs and reports a failure).
    if (outcome.error.reason === 'oauth_app_scopes_narrowed') void releaseGrant(ctx, outcome.connection);
    throw outcome.error;
  }
  return outcome;
}
