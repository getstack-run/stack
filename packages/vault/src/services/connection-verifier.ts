import { CREDENTIAL_TEMPLATES, assertPublicUrl, publicFetch, reconnectMessage, UnsafeUrlError } from '@stack/shared';
import type { CredentialFields } from './oauth-token-lifecycle.js';
import type { ServiceRepository } from '../repositories/service-repo.js';
import { OAuthLifecycleError, oauthClientIdDigest } from './oauth-token-lifecycle.js';
import {
  interpolate,
  parseCredentialObject,
  templateApplies,
  templateFieldsFromCredential,
} from './credential-fields.js';

export interface ConnectionVerificationResult {
  status: 'healthy' | 'unhealthy' | 'unknown';
  message?: string;
  checked_at: string;
}

/**
 * Where the verifier gets the credential it checks. It is the credential the
 * proxy would send, so an OAuth token that has run out is renewed first: a
 * check of an hour-old access token would fail every healthy connection.
 */
export interface VerifiedCredentialSource {
  current(connection: {
    id: string;
    operator_id: string;
    provider: string;
    service_id: string;
    credential_version: number;
    oauth_managed?: boolean;
    scopes?: readonly string[];
    credential_encrypted: string;
  }): Promise<string>;
}

interface ConnectionVerifierDependencies {
  request?: typeof fetch;
  assertPublicUrl?: typeof assertPublicUrl;
  timeoutMs?: number;
}

interface OAuthVerifyEndpoint {
  url: string;
  header: string;
  /**
   * The scopes under which the endpoint answers at all. A token granted none of
   * them is refused by the endpoint however good the token is, so it is checked
   * with `tokenCheck` instead.
   */
  scopes?: readonly string[];
  tokenCheck?: { url: string };
}

// Google answers a token check at this endpoint for any scope. The token
// travels in the request body, never in the URL.
const GOOGLE_TOKEN_CHECK = { url: 'https://oauth2.googleapis.com/tokeninfo' };

// Gmail's profile call needs a read scope; a token that holds none is refused.
const GMAIL_PROFILE_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.compose',
  'https://www.googleapis.com/auth/gmail.metadata',
  'https://mail.google.com/',
] as const;

// OAuth providers with known "me" or "userinfo" endpoints
const OAUTH_VERIFY_ENDPOINTS: Record<string, OAuthVerifyEndpoint> = {
  slack: { url: 'https://slack.com/api/auth.test', header: 'Bearer' },
  github: { url: 'https://api.github.com/user', header: 'Bearer' },
  google_drive: { url: 'https://www.googleapis.com/drive/v3/about?fields=user', header: 'Bearer' },
  gmail: {
    url: 'https://gmail.googleapis.com/gmail/v1/users/me/profile',
    header: 'Bearer',
    scopes: GMAIL_PROFILE_SCOPES,
    tokenCheck: GOOGLE_TOKEN_CHECK,
  },
  notion: { url: 'https://api.notion.com/v1/users/me', header: 'Bearer' },
  linear: { url: 'https://api.linear.app/graphql', header: 'Bearer' },
  discord: { url: 'https://discord.com/api/v10/users/@me', header: 'Bearer' },
  figma: { url: 'https://api.figma.com/v1/me', header: 'Bearer' },
  dropbox: { url: 'https://api.dropboxapi.com/2/users/get_current_account', header: 'Bearer' },
  microsoft: { url: 'https://graph.microsoft.com/v1.0/me', header: 'Bearer' },
  spotify: { url: 'https://api.spotify.com/v1/me', header: 'Bearer' },
  asana: { url: 'https://app.asana.com/api/1.0/users/me', header: 'Bearer' },
};

// Scopes a token can carry that say who signed in, not what was granted.
const IDENTITY_SCOPES: ReadonlySet<string> = new Set([
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
]);

/**
 * What the token check's answer must say beyond "this token is live": that the
 * token was issued to the app the connection was made through (the audience is
 * the app's client id, matched against the hash the binding keeps), and that it
 * carries exactly the scopes the connection records. A live token from another
 * app, or one whose scopes Google narrowed or widened, is not this connection.
 */
function tokenCheckProblem(
  answer: unknown,
  clientIdHash: string | undefined,
  recordedScopes: readonly string[],
): string | null {
  if (typeof answer !== 'object' || answer === null) return 'The token check gave no readable answer';
  const body = answer as Record<string, unknown>;
  // A connection that records no app, or no access, has nothing to compare the answer with: it is not vouched for.
  if (clientIdHash === undefined) return 'This connection records no app it was made through; reconnect it';
  const audience = typeof body['aud'] === 'string' ? body['aud'] : '';
  if (!audience || oauthClientIdDigest(audience) !== clientIdHash) {
    return 'The token was not issued to the app this connection was made through; reconnect it';
  }
  const granted = new Set(
    (typeof body['scope'] === 'string' ? body['scope'].split(/[ ,]+/) : []).filter((scope) => scope && !IDENTITY_SCOPES.has(scope)),
  );
  const recorded = new Set(recordedScopes.filter((scope) => !IDENTITY_SCOPES.has(scope)));
  if (recorded.size === 0) return 'This connection records no access to compare the token with; reconnect it';
  if (granted.size !== recorded.size || [...recorded].some((scope) => !granted.has(scope))) {
    return 'The access Google granted is not the access this connection records; reconnect it';
  }
  return null;
}

export class ConnectionVerifierService {
  private readonly request: typeof fetch;
  private readonly urlGuard: typeof assertPublicUrl;
  private readonly timeoutMs: number;

  constructor(
    private serviceRepo: ServiceRepository,
    private credentials: VerifiedCredentialSource,
    dependencies: ConnectionVerifierDependencies = {},
  ) {
    this.request = dependencies.request ?? publicFetch;
    this.urlGuard = dependencies.assertPublicUrl ?? assertPublicUrl;
    this.timeoutMs = dependencies.timeoutMs ?? 10_000;
  }

  async verify(connectionId: string, operatorId: string): Promise<ConnectionVerificationResult> {
    const conn = await this.serviceRepo.findConnectionById(connectionId);
    if (!conn || conn.operator_id !== operatorId || conn.status !== 'active') {
      return { status: 'unknown', message: 'Connection not found or inactive', checked_at: new Date().toISOString() };
    }

    const now = new Date().toISOString();
    let decrypted: string;
    try {
      decrypted = await this.credentials.current(conn);
    } catch (error) {
      if (!(error instanceof OAuthLifecycleError)) throw error;
      await this.serviceRepo.updateConnectionVerification(connectionId, 'unhealthy');
      return {
        status: 'unhealthy',
        message: error.reason
          ? reconnectMessage(error.reason)
          : error.reconnectRequired
            ? 'The provider no longer honours this connection; reconnect it'
            : 'The provider could not renew this connection just now; try again shortly',
        checked_at: now,
      };
    }

    // Try template-based verification first
    const templateKey = conn.provider.replace(/^custom_/, '');
    const template = CREDENTIAL_TEMPLATES[templateKey];

    const stored = parseCredentialObject<Record<string, string>>(decrypted);
    if (
      template?.verification_url &&
      templateApplies(template, { fields: stored ?? {}, structured: stored !== null })
    ) {
      const result = await this.verifyWithTemplate(template, decrypted);
      await this.serviceRepo.updateConnectionVerification(connectionId, result.status);
      return { ...result, checked_at: now };
    }

    // Try OAuth "me" endpoint verification
    const oauthEndpoint = OAUTH_VERIFY_ENDPOINTS[conn.provider];
    if (oauthEndpoint) {
      const result = await this.verifyOAuth(oauthEndpoint, decrypted, conn.scopes ?? []);
      await this.serviceRepo.updateConnectionVerification(connectionId, result.status);
      return { ...result, checked_at: now };
    }

    await this.serviceRepo.updateConnectionVerification(connectionId, 'unknown');
    return { status: 'unknown', message: 'No verification method available for this provider', checked_at: now };
  }

  private async verifyWithTemplate(
    template: typeof CREDENTIAL_TEMPLATES[string],
    encryptedValue: string,
  ): Promise<Omit<ConnectionVerificationResult, 'checked_at'>> {
    // A single string credential maps onto the template's first required field.
    const fields = templateFieldsFromCredential(encryptedValue, template.fields);

    const url = interpolate(template.verification_url!, fields);
    const headers: Record<string, string> = {};
    if (template.verification_headers) {
      for (const [key, value] of Object.entries(template.verification_headers)) {
        headers[key] = interpolate(value, fields);
      }
    }

    // Handle special Basic auth pattern
    for (const [key, value] of Object.entries(headers)) {
      const basicMatch = value.match(/^Basic \{\{__basic:(\w+):(\w+)\}\}$/);
      if (basicMatch && basicMatch[1] && basicMatch[2]) {
        const user = fields[basicMatch[1]] ?? '';
        const pass = fields[basicMatch[2]] ?? '';
        headers[key] = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
      }
    }

    return this.makeVerificationRequest(url, template.verification_method ?? 'GET', headers);
  }

  private async verifyOAuth(
    endpoint: OAuthVerifyEndpoint,
    credential: string,
    recordedScopes: readonly string[],
  ): Promise<Omit<ConnectionVerificationResult, 'checked_at'>> {
    // Hosted OAuth stores the token response as JSON; older connections hold
    // the bare token string. Only the access token is ever sent.
    let token = credential;
    const stored = parseCredentialObject(credential);
    if (stored) {
      const accessToken = stored['access_token'];
      if (typeof accessToken !== 'string' || !accessToken) {
        return { status: 'unhealthy', message: 'Stored credential has no access token' };
      }
      token = accessToken;
      const granted = typeof stored['scope'] === 'string' ? stored['scope'].split(/[ ,]+/) : null;
      if (
        endpoint.scopes && endpoint.tokenCheck && granted &&
        !granted.some((scope) => endpoint.scopes!.includes(scope))
      ) {
        const clientIdHash = (stored['oauth_app_binding'] as CredentialFields['oauth_app_binding'] | undefined)?.client_id_hash;
        return this.makeVerificationRequest(
          endpoint.tokenCheck.url,
          'POST',
          { 'Content-Type': 'application/x-www-form-urlencoded' },
          new URLSearchParams({ access_token: token }).toString(),
          (answer) => tokenCheckProblem(answer, clientIdHash, recordedScopes),
        );
      }
    }
    const headers: Record<string, string> = {
      Authorization: `${endpoint.header} ${token}`,
    };

    // Special case: Notion needs a version header
    if (endpoint.url.includes('notion.com')) {
      headers['Notion-Version'] = '2022-06-28';
    }

    return this.makeVerificationRequest(endpoint.url, 'GET', headers);
  }

  private async makeVerificationRequest(
    url: string,
    method: string,
    headers: Record<string, string>,
    body?: string,
    /** Reads the answer of a call that succeeded; a returned message makes the connection unhealthy. */
    inspect?: (answer: unknown) => string | null,
  ): Promise<Omit<ConnectionVerificationResult, 'checked_at'>> {
    try {
      await this.urlGuard(url, { allowedProtocols: ['https:'] });
    } catch (err) {
      const message = err instanceof UnsafeUrlError ? err.message : 'Invalid URL';
      return { status: 'unhealthy', message: `Refused to verify: ${message}` };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {

      const res = await this.request(url, {
        method,
        headers,
        signal: controller.signal,
        redirect: 'manual',
        // For POST verification (e.g. Linear GraphQL), send a minimal query
        ...(body !== undefined
          ? { body }
          : method === 'POST' ? { body: JSON.stringify({ query: '{ viewer { id } }' }) } : {}),
      });

      if (res.ok) {
        if (inspect) {
          const problem = inspect(await res.json().catch(() => null));
          if (problem) return { status: 'unhealthy', message: problem };
        }
        return { status: 'healthy' };
      }
      if (res.status === 401) {
        return { status: 'unhealthy', message: 'Authentication failed (401)' };
      }
      if (res.status === 403) {
        return { status: 'unhealthy', message: 'Access denied or insufficient permission (403)' };
      }
      return { status: 'unhealthy', message: `API returned ${res.status}` };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      if ((err instanceof DOMException && err.name === 'AbortError') || message.toLowerCase().includes('abort')) {
        return { status: 'unhealthy', message: `Request timed out (${this.timeoutMs}ms)` };
      }
      return { status: 'unhealthy', message: 'Connection request failed' };
    } finally {
      clearTimeout(timeout);
    }
  }
}
