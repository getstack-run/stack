import { FORWARDED_CLIENT_HEADER, retryAfterSeconds } from '@stack/mcp-server';
import type { AuthContext } from './types.js';

/**
 * Validate the bearer before the MCP server registers any tools.
 *
 * A 401 or 403 means that the credential cannot authorize this session.
 * An upstream or malformed response means that STACK cannot prove the
 * credential valid. That path returns 503 so a server fault never starts a
 * new login ceremony or gets mislabeled as a bad user credential. It carries
 * the wait the API named (its Retry-After header or retry_after_seconds, else
 * 5 seconds, clamped to 1 through 300) so the 503 can say when to retry.
 *
 * `forwardedClient` is the signed `x-stack-forwarded-client` value naming the end client this call is made for, when
 * there is one, so the API's request allowance counts that client and not this server's address.
 */
export async function resolveAuthContext(
  apiUrl: string,
  apiKey: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  forwardedClient?: string,
): Promise<AuthContext> {
  let response: Response;
  try {
    response = await fetchImpl(`${apiUrl}/v1/auth/context`, {
      headers: { Authorization: `Bearer ${apiKey}`, ...(forwardedClient ? { [FORWARDED_CLIENT_HEADER]: forwardedClient } : {}) },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return unavailable();
  }

  if (response.status === 401 || response.status === 403) {
    return { status: 'invalid' };
  }
  if (response.status === 402) {
    // A good credential on an account with no platform subscription: the same 402 the API gives, not a fault.
    return { status: 'subscription_required', body: await response.json().catch(() => undefined) };
  }
  if (!response.ok) {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = undefined;
    }
    return unavailable(retryAfterSeconds(response.headers.get('retry-after'), body));
  }

  try {
    const context = (await response.json()) as {
      principal?: { type?: unknown; id?: unknown };
      is_platform_staff?: unknown;
      oauth_resource?: unknown;
    };
    const principalType = context.principal?.type;
    const principalId = context.principal?.id;
    if (
      (principalType !== 'operator' && principalType !== 'member' && principalType !== 'agent')
      || typeof principalId !== 'string'
      || principalId.length === 0
      || typeof context.is_platform_staff !== 'boolean'
      || (context.oauth_resource !== undefined && typeof context.oauth_resource !== 'string')
    ) {
      return unavailable();
    }
    return {
      status: 'valid',
      principalFingerprint: `${principalType}:${principalId}`,
      isPlatformStaff: context.is_platform_staff,
      ...(typeof context.oauth_resource === 'string' ? { oauthResource: context.oauth_resource } : {}),
    };
  } catch {
    return unavailable();
  }
}

function unavailable(seconds: number = retryAfterSeconds(null)): AuthContext {
  return { status: 'unavailable', retryAfterSeconds: seconds };
}
