import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  Atlassian,
  Bitbucket,
  Box,
  Coinbase,
  Discord,
  Dropbox,
  Figma,
  GitHub,
  Google,
  Intuit,
  Linear,
  LinkedIn,
  MicrosoftEntraId,
  Notion,
  Reddit,
  Spotify,
  Twitter,
  Zoom,
  generateCodeVerifier,
} from 'arctic';
import {
  ConnectionName,
  assertPublicUrl,
  normalizeAllowedHosts,
  publicFetch,
  StackError,
  type OperatorTier,
} from '@stack/shared';
import type {
  OauthAppService,
  PassportSigner,
  ProviderOAuthStateClaims,
  ServiceConnectionService,
} from '@stack/vault';
import {
  ConnectionPrincipalConflictError,
  OAuthLifecycleError,
  oauthClientIdDigest,
  type CredentialFields,
} from '@stack/vault';

export const PROVIDER_OAUTH_RETURN_TO = {
  connect: '/app/connections',
  services: '/services',
} as const;
export type ProviderOAuthReturnTo = keyof typeof PROVIDER_OAUTH_RETURN_TO;

/**
 * The providers STACK runs an OAuth app of its own for: `slack` (chat approvals
 * and Slack connections) and `google` (the shared parent of every Google
 * service). STACK registers no other app at a third party, so a connection to
 * any other service is made with a key or token, or through the customer's own
 * OAuth app. A system app row for any other provider (left over from the apps
 * STACK used to run) is never used to sign anyone in or to renew a token.
 */
export const SYSTEM_OAUTH_PROVIDERS = ['slack', 'google'] as const;

function isSystemOAuthProvider(provider: string): boolean {
  return (SYSTEM_OAUTH_PROVIDERS as readonly string[]).includes(provider);
}

/**
 * What a deployment's own OAuth app (the one owned by the system operator) may ask a person for, when it is held
 * to a list. Given the provider the app is registered under and the service being connected, it answers the allowed
 * scopes, an empty list when the service may not be connected through that app at all, or null when the app is not
 * limited. An app of the customer's own is never asked about: it requests whatever the service lists. An install
 * has no such list.
 */
export type SystemAppScopes = (appProvider: string, serviceProvider: string) => readonly string[] | null;

/**
 * Services that share one OAuth app. A company's own Google or Microsoft app is
 * entered once, under `google` or `microsoft`, and covers every service below;
 * an app entered under a service's own name wins for that service.
 */
export const SHARED_OAUTH_PARENT: Readonly<Record<string, string>> = {
  gmail: 'google',
  google_drive: 'google',
  google_docs: 'google',
  google_sheets: 'google',
  google_calendar: 'google',
  google_analytics: 'google',
  youtube: 'google',
  outlook: 'microsoft',
  microsoft_teams: 'microsoft',
};

/**
 * A provider connection failed for a reason the dashboard can explain. The
 * lowercase code is the key the connect page maps to its message, so it is
 * part of the wire contract. `return_to` travels in the envelope details so
 * the dashboard knows which page to send the browser back to.
 */
export class ProviderOAuthError extends StackError {
  constructor(
    code: string,
    readonly status: 400 | 401 | 403 | 404 | 409 | 503 = 400,
    readonly returnTo?: ProviderOAuthReturnTo,
  ) {
    super(`Provider connection failed: ${code}`, code, status, returnTo ? { return_to: returnTo } : undefined);
    this.name = 'ProviderOAuthError';
  }

  withReturnTo(returnTo: ProviderOAuthReturnTo): ProviderOAuthError {
    return new ProviderOAuthError(this.code, this.status, returnTo);
  }
}

interface CatalogService {
  id: string;
  provider: string;
  name: string;
  oauth_auth_url: string;
  oauth_token_url: string;
  scopes_available: string[];
  available: boolean;
}

interface ResolvedOAuthApp {
  id: string;
  ownerId: string;
  provider: string;
  clientId: string;
  clientSecret: string;
  /** The directory a single-tenant Microsoft app signs in against. */
  tenant?: string;
}

/**
 * Scopes a provider must be asked for before it returns a refresh token.
 * Microsoft and Atlassian give none without `offline_access`; Google's own
 * parameters are set by its client. Added to the consent request only: the
 * connection's own scopes are the ones the person chose.
 */
const OFFLINE_ACCESS_PROVIDERS: ReadonlySet<string> = new Set(['outlook', 'microsoft_teams', 'jira', 'confluence']);

function consentScopes(provider: string, scopes: string[]): string[] {
  return OFFLINE_ACCESS_PROVIDERS.has(provider) && !scopes.includes('offline_access')
    ? [...scopes, 'offline_access']
    : scopes;
}

interface OAuthClient {
  requiresCodeVerifier: boolean;
  extraAuthParams: Record<string, string>;
  createAuthorizationURL(state: string, scopes: string[], codeVerifier?: string): Promise<URL>;
  validateAuthorizationCode(code: string, codeVerifier?: string): Promise<string | CredentialFields>;
}

interface ProviderOAuthPrincipal {
  operatorId: string;
  operatorTier: OperatorTier;
  memberId?: string;
  memberRole?: string;
  allowedConnections?: string[];
}

interface ProviderOAuthDeps {
  catalog: {
    findByProvider(operatorId: string, provider: string): Promise<CatalogService | undefined>;
    findById(operatorId: string, id: string): Promise<CatalogService | undefined>;
  };
  oauthApps: Pick<OauthAppService, 'getDecrypted' | 'list'>;
  signer: Pick<PassportSigner, 'signProviderOAuthState' | 'verifyProviderOAuthState'>;
  connections: Pick<ServiceConnectionService, 'assertConnectionAccess' | 'assertConnectionPrincipal' | 'connect' | 'sharesAppGrant'>;
  systemOperatorId: string;
  dashboardUrl: string;
  microsoftTenant?: string;
  /** Holds the system operator's own app to a list of scopes. Absent: no app is narrowed. */
  systemAppScopes?: SystemAppScopes;
  /** Ends a grant of the system operator's app at the provider (a refresh token), best effort. Absent: nothing is ended there. */
  revokeGrant?: (appProvider: string, refreshToken: string) => Promise<void>;
  createClient?: typeof createOAuthClient;
  createCodeVerifier?: () => string;
}

export class ProviderOAuthService {
  constructor(private readonly deps: ProviderOAuthDeps) {}

  async authorize(
    principal: ProviderOAuthPrincipal,
    input: {
      provider: string;
      scopes?: string[];
      returnTo: ProviderOAuthReturnTo;
      allowedHosts?: string[];
      /** A connect link this consent completes; carried only inside the signed state. */
      connectLinkId?: string;
      /** What the connection this consent makes is called; carried only inside the signed state. */
      connectionName?: string;
    },
  ): Promise<{ authorizationUrl: string; codeVerifier?: string }> {
    this.assertPrincipal(principal);
    const service = await this.deps.catalog.findByProvider(principal.operatorId, input.provider);
    if (!service || service.provider !== input.provider
      || (!service.available && !(service.oauth_auth_url && service.oauth_token_url))) {
      throw new ProviderOAuthError('service_not_found', 404);
    }

    const allowedHosts = normalizeProviderHosts(input.provider, input.allowedHosts);
    let scopes = selectScopes(service, input.scopes);
    // Refuse before the consent screen: a principal that cannot hold this
    // connection would otherwise consent at the provider and fail on return.
    await this.assertCanConnect(principal, service.provider, input.connectionName);
    const oauthApp = await this.resolveOAuthApp(principal.operatorId, input.provider);
    if (!oauthApp) throw new ProviderOAuthError('provider_not_configured', 503);
    // What is narrowed here is what the claims and the consent URL carry; a customer's own app is never narrowed.
    scopes = scopesForApp(scopes, oauthApp, service.provider, this.deps);

    const redirectUri = `${this.deps.dashboardUrl}/api/oauth/callback`;
    const client = (this.deps.createClient ?? createOAuthClient)(
      input.provider,
      oauthApp.clientId,
      oauthApp.clientSecret,
      redirectUri,
      service.oauth_auth_url,
      service.oauth_token_url,
      oauthApp.tenant ?? this.deps.microsoftTenant ?? 'common',
    );
    const codeVerifier = client.requiresCodeVerifier
      ? (this.deps.createCodeVerifier ?? generateCodeVerifier)()
      : undefined;
    const claims: ProviderOAuthStateClaims = {
      operator_id: principal.operatorId,
      ...(principal.memberId ? { member_id: principal.memberId } : {}),
      service_id: service.id,
      provider: service.provider,
      scopes,
      nonce: randomBytes(16).toString('base64url'),
      return_to: input.returnTo,
      ...(allowedHosts ? { allowed_hosts: allowedHosts } : {}),
      ...(codeVerifier ? { code_verifier_hash: sha256(codeVerifier) } : {}),
      oauth_app_id: oauthApp.id,
      oauth_app_owner_id: oauthApp.ownerId,
      oauth_app_provider: oauthApp.provider,
      oauth_client_id_hash: oauthClientIdDigest(oauthApp.clientId),
      ...(input.connectLinkId ? { connect_link_id: input.connectLinkId } : {}),
      ...(input.connectionName ? { connection_name: input.connectionName } : {}),
    };
    const state = await this.deps.signer.signProviderOAuthState(claims);
    const url = await client.createAuthorizationURL(state, consentScopes(service.provider, scopes), codeVerifier);
    for (const [key, value] of Object.entries(client.extraAuthParams)) url.searchParams.set(key, value);
    return { authorizationUrl: url.toString(), ...(codeVerifier ? { codeVerifier } : {}) };
  }

  async callback(
    principal: ProviderOAuthPrincipal,
    input: { code: string; state: string; codeVerifier?: string },
  ): Promise<{ connectionId: string; provider: string; returnTo: ProviderOAuthReturnTo; connectLinkId?: string }> {
    this.assertPrincipal(principal);
    let claims: ProviderOAuthStateClaims;
    try {
      claims = parseStateClaims(await this.deps.signer.verifyProviderOAuthState(input.state));
    } catch {
      throw new ProviderOAuthError('invalid_state', 401);
    }
    try {
    if (claims.operator_id !== principal.operatorId
      || (claims.member_id ?? null) !== (principal.memberId ?? null)) {
      throw new ProviderOAuthError('session_mismatch', 403);
    }

    const service = await this.deps.catalog.findById(principal.operatorId, claims.service_id);
    if (!service || service.provider !== claims.provider) {
      throw new ProviderOAuthError('service_not_found', 404);
    }
    const oauthApp = await this.resolveBoundOAuthApp(principal.operatorId, claims);
    const redirectUri = `${this.deps.dashboardUrl}/api/oauth/callback`;
    const client = (this.deps.createClient ?? createOAuthClient)(
      claims.provider,
      oauthApp.clientId,
      oauthApp.clientSecret,
      redirectUri,
      service.oauth_auth_url,
      service.oauth_token_url,
      oauthApp.tenant ?? this.deps.microsoftTenant ?? 'common',
    );

    if (client.requiresCodeVerifier) {
      if (!input.codeVerifier || !claims.code_verifier_hash) {
        throw new ProviderOAuthError('missing_code_verifier');
      }
      if (!digestMatches(sha256(input.codeVerifier), claims.code_verifier_hash)) {
        throw new ProviderOAuthError('code_verifier_mismatch', 401);
      }
    } else if (claims.code_verifier_hash !== undefined) {
      throw new ProviderOAuthError('invalid_state', 401);
    }

    // Re-checked here: the account may have changed since consent started.
    await this.assertCanConnect(principal, service.provider, claims.connection_name);

    let accessToken: string | CredentialFields;
    try {
      accessToken = await client.validateAuthorizationCode(input.code, input.codeVerifier);
    } catch {
      throw new ProviderOAuthError('token_exchange_failed', 503);
    }
    if (!accessToken) throw new ProviderOAuthError('token_exchange_failed', 503);

    const granted = typeof accessToken !== 'string' && typeof accessToken.scope === 'string'
      ? claims.scopes.filter(scope => accessToken.scope!.split(/[ ,]+/).includes(scope)) : claims.scopes;
    // An app held to a list is never connected with no access recorded: nothing could show the connection stays within it.
    if (granted.length === 0 && this.deps.systemAppScopes && oauthApp.ownerId === this.deps.systemOperatorId
      && this.deps.systemAppScopes(oauthApp.provider, service.provider) !== null) {
      // The tokens were issued and nothing will hold them: end the grant rather than leave it on the person's account,
      // unless a live connection through the same app may stand on it (ending it could end that one too).
      if (typeof accessToken !== 'string' && accessToken.refresh_token && this.deps.revokeGrant) {
        const sharedWithLiveConnection = await this.deps.connections.sharesAppGrant(principal.operatorId, {
          owner_id: oauthApp.ownerId,
          provider: oauthApp.provider,
          client_id_hash: oauthClientIdDigest(oauthApp.clientId),
        }).catch(() => true);
        if (!sharedWithLiveConnection) {
          await this.deps.revokeGrant(oauthApp.provider, accessToken.refresh_token).catch(() => undefined);
        }
      }
      throw new ProviderOAuthError('invalid_scopes');
    }

    const connection = await this.deps.connections.connect(
      principal.operatorId,
      principal.operatorTier,
      {
        service_id: claims.service_id,
        scopes: granted,
        oauth_token: JSON.stringify({
          ...(typeof accessToken === 'string' ? { access_token: accessToken } : accessToken),
          token_auth_method: ['jira', 'confluence', 'box', 'linear', 'linkedin', 'coinbase'].includes(claims.provider)
            ? 'client_secret_post' : 'client_secret_basic',
        }),
        ...(claims.allowed_hosts ? { allowed_hosts: claims.allowed_hosts } : {}),
        ...(claims.connection_name ? { connection_name: claims.connection_name } : {}),
      },
      principal.memberId,
      principal.memberId,
      { id: oauthApp.id, owner_id: oauthApp.ownerId, provider: oauthApp.provider,
        client_id_hash: oauthClientIdDigest(oauthApp.clientId), service_id: service.id,
        connection_provider: service.provider, token_url: service.oauth_token_url },
    ).catch((error: unknown) => { throw principalConflict(error); });
    return {
      connectionId: connection.id,
      provider: claims.provider,
      returnTo: claims.return_to,
      ...(claims.connect_link_id ? { connectLinkId: claims.connect_link_id } : {}),
    };
    } catch (error) {
      if (error instanceof ProviderOAuthError) throw error.withReturnTo(claims.return_to);
      throw error;
    }
  }

  private async assertCanConnect(principal: ProviderOAuthPrincipal, provider: string, connectionName?: string): Promise<void> {
    try {
      this.deps.connections.assertConnectionAccess(principal.allowedConnections);
    } catch {
      throw new ProviderOAuthError('connection_not_allowed', 403);
    }
    await this.deps.connections
      .assertConnectionPrincipal(principal.operatorId, provider, principal.memberId, connectionName)
      .catch((error: unknown) => { throw principalConflict(error); });
  }

  private assertPrincipal(principal: ProviderOAuthPrincipal): void {
    if (principal.memberRole === 'readonly') throw new ProviderOAuthError('insufficient_permissions', 403);
  }

  /** Renewal must use the exact client that obtained consent, even when a
   * tenant later creates its own app or the shared app is replaced. */
  async resolveRenewalClient(operatorId: string, fields: CredentialFields, connection: {
    serviceId: string; provider: string; tokenUrl: string;
  }): Promise<{
    clientId: string; clientSecret: string; tenant?: string;
  }> {
    const binding = fields.oauth_app_binding;
    if (!binding || (binding.owner_id !== operatorId && binding.owner_id !== this.deps.systemOperatorId)
      || binding.service_id !== connection.serviceId || binding.connection_provider !== connection.provider
      || binding.token_url !== connection.tokenUrl
      || !appServesProvider(binding.provider, binding.connection_provider)) {
      throw new OAuthLifecycleError(true);
    }
    // An app STACK no longer runs renews nothing, whether or not its row is still stored.
    if (this.isRetiredBinding(binding)) throw new OAuthLifecycleError(true, 'stack_oauth_app_retired');
    let app: Awaited<ReturnType<OauthAppService['getDecrypted']>>;
    try { app = await this.deps.oauthApps.getDecrypted(binding.owner_id, binding.provider); }
    catch { throw new OAuthLifecycleError(); }
    if (!app || app.id !== binding.id || !digestMatches(oauthClientIdDigest(app.client_id), binding.client_id_hash)) {
      throw new OAuthLifecycleError(true);
    }
    return { clientId: app.client_id, clientSecret: app.client_secret, ...(app.tenant ? { tenant: app.tenant } : {}) };
  }

  /**
   * Whether a connection's app is one of STACK's own that STACK no longer runs:
   * the binding names the system operator as the owner of an app for a provider
   * outside `SYSTEM_OAUTH_PROVIDERS` (GitHub, Atlassian, Notion, Linear,
   * Discord and Figma used to have one). The stored app row is left as it is.
   */
  isRetiredBinding(binding: { owner_id: string; provider: string }): boolean {
    return this.deps.systemOperatorId !== ''
      && binding.owner_id === this.deps.systemOperatorId
      && !isSystemOAuthProvider(binding.provider);
  }

  /**
   * Whether a connection holds scopes that the app it was made through may no
   * longer ask for: the binding names the system operator's own app, the
   * deployment holds that app to a list, and the connection records a scope
   * outside the list, or records none (a record that is empty cannot be shown
   * to be inside it). A customer's own app is never held to one.
   */
  exceedsAppScopes(
    binding: { owner_id: string; provider: string },
    connectionProvider: string,
    scopes: readonly string[],
  ): boolean {
    if (!this.deps.systemAppScopes || this.deps.systemOperatorId === '' || binding.owner_id !== this.deps.systemOperatorId) return false;
    const allowed = this.deps.systemAppScopes(binding.provider, connectionProvider);
    return allowed !== null && (scopes.length === 0 || scopes.some((scope) => !allowed.includes(scope)));
  }

  /**
   * The scopes STACK's own app will actually request for a service's catalogue row, so the Connect page can say so
   * before a person is sent to a consent screen: the row's `scopes_available` held to the deployment's list. Only a
   * service whose OAuth parent is Google has one; any other service, and an install with no list, answers null. A
   * service the list does not name answers an empty list (STACK's app cannot be used for it at all).
   */
  stackAppScopes(provider: string, scopesAvailable: readonly string[]): string[] | null {
    if (SHARED_OAUTH_PARENT[provider] !== 'google' || !this.deps.systemAppScopes) return null;
    const allowed = this.deps.systemAppScopes('google', provider);
    return allowed === null ? null : scopesAvailable.filter((scope) => allowed.includes(scope));
  }

  /**
   * The (owner, provider) app rows authorize would try for this provider, in
   * order: the operator's own app for the service, the operator's own app for
   * its shared parent (google, microsoft), then STACK's own app for the
   * provider or its parent, which exists only for `SYSTEM_OAUTH_PROVIDERS`.
   * Shared by authorize and availability so they can never disagree.
   */
  appCandidates(operatorId: string, provider: string): Array<{ ownerId: string; provider: string }> {
    const parent = SHARED_OAUTH_PARENT[provider];
    const names = parent ? [provider, parent] : [provider];
    // The system operator's own rows are STACK's apps: only the ones STACK still runs count.
    const isSystem = this.deps.systemOperatorId !== '' && operatorId === this.deps.systemOperatorId;
    const out = names
      .filter((name) => !isSystem || isSystemOAuthProvider(name))
      .map((name) => ({ ownerId: operatorId, provider: name }));
    if (this.deps.systemOperatorId && !isSystem) {
      for (const name of names) {
        if (isSystemOAuthProvider(name)) out.push({ ownerId: this.deps.systemOperatorId, provider: name });
      }
    }
    return out;
  }

  /**
   * Whether this operator would resolve an OAuth app for the provider, read
   * without decrypting any client secret.
   */
  async hasResolvableApp(operatorId: string, provider: string): Promise<boolean> {
    return (await this.appAvailability(operatorId, [provider])).available.includes(provider);
  }

  /**
   * Which of these providers this operator can connect through an OAuth app,
   * and which of those through an app of its own (its own, or its shared
   * parent's). One read of each app list, however many providers are asked.
   */
  async appAvailability(operatorId: string, providers: readonly string[]): Promise<{
    available: string[]; own: string[];
  }> {
    const own = new Set((await this.deps.oauthApps.list(operatorId)).map((app) => app.provider));
    const system = this.deps.systemOperatorId && this.deps.systemOperatorId !== operatorId
      ? new Set((await this.deps.oauthApps.list(this.deps.systemOperatorId)).map((app) => app.provider))
      : own;
    const available: string[] = [];
    const ownApp: string[] = [];
    for (const provider of providers) {
      const candidates = this.appCandidates(operatorId, provider);
      const resolves = candidates.filter((candidate) =>
        (candidate.ownerId === operatorId ? own : system).has(candidate.provider));
      if (resolves.length > 0) available.push(provider);
      if (resolves.some((candidate) => candidate.ownerId === operatorId)) ownApp.push(provider);
    }
    return { available, own: ownApp };
  }

  private async resolveOAuthApp(operatorId: string, provider: string): Promise<ResolvedOAuthApp | null> {
    for (const candidate of this.appCandidates(operatorId, provider)) {
      let app: Awaited<ReturnType<OauthAppService['getDecrypted']>>;
      try {
        app = await this.deps.oauthApps.getDecrypted(candidate.ownerId, candidate.provider);
      } catch {
        // A lookup failure is not evidence that no app exists. Falling through
        // here could send the authorization code to another OAuth client (the
        // customer's own app is tried before STACK's), so the transaction stops.
        throw new ProviderOAuthError('provider_lookup_failed', 503);
      }
      if (app) return toResolvedApp(candidate.ownerId, candidate.provider, app);
    }
    return null;
  }

  private async resolveBoundOAuthApp(
    operatorId: string,
    claims: ProviderOAuthStateClaims,
  ): Promise<ResolvedOAuthApp> {
    if (claims.oauth_app_owner_id !== operatorId
      && claims.oauth_app_owner_id !== this.deps.systemOperatorId) {
      throw new ProviderOAuthError('invalid_state', 401);
    }
    // The app must be one the provider could have been consented through, and a
    // system app one STACK still runs.
    if (!appServesProvider(claims.oauth_app_provider, claims.provider)
      || this.isRetiredBinding({ owner_id: claims.oauth_app_owner_id, provider: claims.oauth_app_provider })) {
      throw new ProviderOAuthError('oauth_app_changed', 409);
    }
    let app: Awaited<ReturnType<OauthAppService['getDecrypted']>>;
    try {
      app = await this.deps.oauthApps.getDecrypted(
        claims.oauth_app_owner_id,
        claims.oauth_app_provider,
      );
    } catch {
      throw new ProviderOAuthError('provider_lookup_failed', 503);
    }
    if (!app) throw new ProviderOAuthError('oauth_app_changed', 409);
    const resolved = toResolvedApp(claims.oauth_app_owner_id, claims.oauth_app_provider, app);
    if (resolved.id !== claims.oauth_app_id
      || !digestMatches(sha256(resolved.clientId), claims.oauth_client_id_hash)) {
      throw new ProviderOAuthError('oauth_app_changed', 409);
    }
    return resolved;
  }
}

function toResolvedApp(
  ownerId: string,
  provider: string,
  app: NonNullable<Awaited<ReturnType<OauthAppService['getDecrypted']>>>,
): ResolvedOAuthApp {
  return {
    id: app.id,
    ownerId,
    provider,
    clientId: app.client_id,
    clientSecret: app.client_secret,
    ...(app.tenant ? { tenant: app.tenant } : {}),
  };
}

/** An app serves a service when it is registered under the service's own name or its shared parent's. */
export function appServesProvider(appProvider: string, serviceProvider: string): boolean {
  return appProvider === serviceProvider || appProvider === SHARED_OAUTH_PARENT[serviceProvider];
}

/** A principal conflict becomes a coded, user-explainable OAuth error. */
function principalConflict(error: unknown): unknown {
  return error instanceof ConnectionPrincipalConflictError
    ? new ProviderOAuthError(error.reason, 409)
    : error;
}

/**
 * The scopes a consent request carries: the ones asked for, held to the deployment's list when the app is its own.
 * A request left with no allowed scope is refused before the person sees a consent screen.
 */
function scopesForApp(
  scopes: string[],
  app: ResolvedOAuthApp,
  serviceProvider: string,
  deps: Pick<ProviderOAuthDeps, 'systemOperatorId' | 'systemAppScopes'>,
): string[] {
  if (!deps.systemAppScopes || app.ownerId !== deps.systemOperatorId) return scopes;
  const allowed = deps.systemAppScopes(app.provider, serviceProvider);
  if (!allowed) return scopes;
  const kept = scopes.filter((scope) => allowed.includes(scope));
  if (kept.length === 0) throw new ProviderOAuthError('invalid_scopes');
  return kept;
}

function selectScopes(service: CatalogService, requested?: string[]): string[] {
  const source = requested && requested.length > 0 ? requested : service.scopes_available;
  const unique = [...new Set(source.filter((scope) => typeof scope === 'string' && scope.length > 0))];
  const available = new Set(service.scopes_available);
  const valid = available.has('*') ? unique : unique.filter((scope) => available.has(scope));
  if (!service.provider.startsWith('custom_') && valid.length === 0) {
    throw new ProviderOAuthError('invalid_scopes');
  }
  return valid;
}

function normalizeProviderHosts(provider: string, hosts?: string[]): string[] | undefined {
  if (!provider.startsWith('custom_')) {
    if (hosts !== undefined) throw new ProviderOAuthError('invalid_allowed_hosts');
    return undefined;
  }
  try {
    const normalized = normalizeAllowedHosts(hosts ?? []);
    if (normalized.length === 0 || normalized.length > 20) throw new Error('invalid host count');
    return normalized;
  } catch {
    throw new ProviderOAuthError('invalid_allowed_hosts');
  }
}

function parseStateClaims(raw: ProviderOAuthStateClaims): ProviderOAuthStateClaims {
  const strings = [
    raw.operator_id, raw.service_id, raw.provider, raw.nonce, raw.oauth_app_id,
    raw.oauth_app_owner_id, raw.oauth_app_provider, raw.oauth_client_id_hash,
  ];
  if (strings.some((value) => typeof value !== 'string' || value.length === 0 || value.length > 512)
    || (raw.member_id !== undefined && (typeof raw.member_id !== 'string' || !raw.member_id))
    || (raw.return_to !== 'connect' && raw.return_to !== 'services')
    || !Array.isArray(raw.scopes)
    || raw.scopes.length > 100
    || raw.scopes.some((scope) => typeof scope !== 'string' || !scope || scope.length > 512)
    || (raw.allowed_hosts !== undefined && !Array.isArray(raw.allowed_hosts))
    || (raw.code_verifier_hash !== undefined && typeof raw.code_verifier_hash !== 'string')
    || (raw.connection_name !== undefined && !ConnectionName.safeParse(raw.connection_name).success)
    || (raw.connect_link_id !== undefined && (typeof raw.connect_link_id !== 'string' || !/^cnl_[A-Za-z0-9_-]{1,64}$/.test(raw.connect_link_id)))) {
    throw new Error('Invalid provider OAuth state');
  }
  const allowedHosts = normalizeProviderHosts(raw.provider, raw.allowed_hosts);
  return { ...raw, ...(allowedHosts ? { allowed_hosts: allowedHosts } : {}) };
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

function digestMatches(actual: string, expected: string): boolean {
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ProviderFactory = (clientId: string, clientSecret: string, redirectUri: string, tenant: string) => any;

const ARCTIC_PROVIDERS: Record<string, ProviderFactory> = {
  discord: (id, secret, uri) => new Discord(id, secret, uri),
  microsoft_teams: (id, secret, uri, tenant) => new MicrosoftEntraId(tenant, id, secret, uri),
  gmail: (id, secret, uri) => new Google(id, secret, uri),
  outlook: (id, secret, uri, tenant) => new MicrosoftEntraId(tenant, id, secret, uri),
  github: (id, secret, uri) => new GitHub(id, secret, uri),
  linear: (id, secret, uri) => new Linear(id, secret, uri),
  jira: (id, secret, uri) => new Atlassian(id, secret, uri),
  notion: (id, secret, uri) => new Notion(id, secret, uri),
  confluence: (id, secret, uri) => new Atlassian(id, secret, uri),
  google_docs: (id, secret, uri) => new Google(id, secret, uri),
  google_sheets: (id, secret, uri) => new Google(id, secret, uri),
  google_drive: (id, secret, uri) => new Google(id, secret, uri),
  dropbox: (id, secret, uri) => new Dropbox(id, secret, uri),
  quickbooks: (id, secret, uri) => new Intuit(id, secret, uri),
  coinbase: (id, secret, uri) => new Coinbase(id, secret, uri),
  google_analytics: (id, secret, uri) => new Google(id, secret, uri),
  google_calendar: (id, secret, uri) => new Google(id, secret, uri),
  twitter: (id, secret, uri) => new Twitter(id, secret, uri),
  linkedin: (id, secret, uri) => new LinkedIn(id, secret, uri),
  reddit: (id, secret, uri) => new Reddit(id, secret, uri),
  figma: (id, secret, uri) => new Figma(id, secret, uri),
  spotify: (id, secret, uri) => new Spotify(id, secret, uri),
  bitbucket: (id, secret, uri) => new Bitbucket(id, secret, uri),
  box: (id, secret, uri) => new Box(id, secret, uri),
  zoom: (id, secret, uri) => new Zoom(id, secret, uri),
};

export function createOAuthClient(
  provider: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string,
  oauthAuthUrl: string,
  oauthTokenUrl: string,
  microsoftTenant = 'common',
  safeFetch: typeof publicFetch = publicFetch,
): OAuthClient {
  const factory = ARCTIC_PROVIDERS[provider];
  if (factory) {
    const arctic = factory(clientId, clientSecret, redirectUri, microsoftTenant);
    const requiresCodeVerifier = arctic.createAuthorizationURL.length >= 3;
    return {
      requiresCodeVerifier,
      extraAuthParams: arctic instanceof Google ? { access_type: 'offline', prompt: 'consent' } : {},
      createAuthorizationURL: async (state, scopes, codeVerifier) => requiresCodeVerifier
        ? arctic.createAuthorizationURL(state, codeVerifier, scopes)
        : arctic.createAuthorizationURL(state, scopes),
      validateAuthorizationCode: async (code, codeVerifier) => {
        const tokens = requiresCodeVerifier
          ? await arctic.validateAuthorizationCode(code, codeVerifier)
          : await arctic.validateAuthorizationCode(code);
        return storedTokenFields(tokens.data);
      },
    };
  }
  return {
    requiresCodeVerifier: false,
    extraAuthParams: {},
    createAuthorizationURL: async (state, scopes) => {
      const url = await assertPublicUrl(oauthAuthUrl, { allowedProtocols: ['https:'] });
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('state', state);
      if (scopes.length > 0) url.searchParams.set('scope', scopes.join(' '));
      return url;
    },
    validateAuthorizationCode: async (code) => {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
      });
      const response = await safeFetch(oauthTokenUrl, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: body.toString(),
        redirect: 'error',
      }, {
        allowedProtocols: ['https:'],
        maxRequestBytes: 16 * 1024,
        maxResponseBytes: 256 * 1024,
        timeoutMs: 10_000,
      });
      if (!response.ok) throw new Error('OAuth token endpoint rejected the authorization code');
      const contentType = response.headers.get('content-type') ?? '';
      const payload = contentType.includes('application/json')
        ? await response.json() as { access_token?: unknown }
        : Object.fromEntries(new URLSearchParams(await response.text())) as { access_token?: unknown };
      if (typeof payload.access_token !== 'string' || !payload.access_token) {
        throw new Error('OAuth token endpoint omitted access token');
      }
      return storedTokenFields(payload);
    },
  };
}

/** Keep only token material and expiry metadata. Provider profiles and ID
 * tokens do not belong in a service connection credential. */
function storedTokenFields(payload: Record<string, unknown>): CredentialFields {
  if (typeof payload.access_token !== 'string' || !payload.access_token) {
    throw new Error('OAuth token endpoint omitted access token');
  }
  const fields: CredentialFields = { access_token: payload.access_token };
  if (typeof payload.refresh_token === 'string' && payload.refresh_token) fields.refresh_token = payload.refresh_token;
  if (typeof payload.scope === 'string') fields.scope = payload.scope;
  if (payload.expires_in !== undefined) {
    const ttl = Number(payload.expires_in);
    if (!Number.isFinite(ttl) || ttl <= 0 || ttl > 315_360_000) throw new Error('OAuth token endpoint omitted access token');
    fields.expires_at = new Date(Date.now() + ttl * 1000).toISOString();
  }
  return fields;
}
