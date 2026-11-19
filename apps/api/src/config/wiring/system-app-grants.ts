import * as Sentry from '@sentry/node';
import type { ServiceConnectionHooks } from '@stack/vault';

/**
 * The hooks that end a grant at the provider, and report one that could not be ended. They exist only where the
 * deployment ends grants at all (`revokeSystemAppGrant`): an install has none, so the connection service finds neither
 * hook and a disconnect decrypts no credential for a hook that would do nothing.
 *
 * Every closed connection's grant is ended, with its refresh token (its access token when there is no refresh token),
 * unless the operator holds another live connection through the same app. STACK connects each Google service apart, but
 * they share one Google grant, so revoking one token ends them all: the last connection out revokes, and an earlier
 * one only has its stored credential closed. A revocation that fails never undoes the disconnect: the connection
 * service logs and reports it by connection id and provider, never the token.
 */
export function systemAppGrantHooks(deps: {
  revokeSystemAppGrant?: (appProvider: string, refreshToken: string) => Promise<void>;
}): Pick<ServiceConnectionHooks, 'grantDropped' | 'grantReleaseFailed'> {
  const { revokeSystemAppGrant } = deps;
  if (!revokeSystemAppGrant) return {};
  return {
    grantDropped: async (connection, credential, context) => {
      const binding = credential.oauth_app_binding;
      const token = credential.refresh_token ?? credential.access_token;
      if (!binding || !token) return;
      if (await context.sharesGrant()) {
        console.warn(
          '[service-connection] grant left at the provider:', connection.id, connection.provider, 'shares its app with a live connection',
        );
        return;
      }
      await revokeSystemAppGrant(binding.provider, token);
    },
    grantReleaseFailed: ({ connectionId, provider }) => {
      // The report names the connection; it carries nothing of the credential or of what the provider said.
      Sentry.captureMessage('service connection: a provider grant could not be ended', {
        level: 'error',
        extra: { connectionId, provider },
      });
    },
  };
}
