import { createHash, randomBytes } from 'node:crypto';
import {
  importJWK,
  jwtVerify,
  calculateJwkThumbprint,
  decodeProtectedHeader,
  type JWK,
  type JWTPayload,
} from 'jose';
import type { Redis } from 'ioredis';
import type {
  TrustLayer,
  AssuranceLevel,
} from '@stack/shared';
import {
  SSO_CODE_TTL_SECONDS,
  SSO_DISCOVERY_TTL_SECONDS,
  SSO_FETCH_TIMEOUT_SECONDS,
  SSO_ID_TOKEN_CLOCK_TOLERANCE_SECONDS,
  SSO_JWKS_REFETCH_COOLDOWN_SECONDS,
  SSO_STATE_TTL_SECONDS,
  sha256,
  assertPublicUrl,
  publicFetch,
} from '@stack/shared';
import { deployment, entraVouchesForEmailDomain, safeErrorSummary } from '@stack/shared';
import type {
  IdentityVerificationProvider,
  VerificationContext,
  InitiateResult,
  VerificationResult,
  VerifiedClaim,
} from '../types.js';
import type { KmsService } from '../../crypto/kms.js';
import type { OidcIdpConfigRepository } from '../../repositories/oidc-idp-config-repo.js';

/**
 * OIDC Identity Provider — Part of the Signed Primitive
 * epic. Federates an operator's existing OIDC IdP (Auth0, Okta,
 * Microsoft Entra, etc.) as an L1/L2 trust source for STACK
 * passports.
 *
 * v1 SCOPE — one OIDC IdP config per operator. initiate() builds the
 * authorize URL with PKCE+nonce+state; the user authenticates at the
 * IdP and is redirected back to STACK's callback. Callback stores
 * the authorization_code keyed by state in Redis. complete() pulls
 * the code, exchanges it at the token endpoint, verifies the ID
 * token signature against the IdP's JWKS, asserts nonce matches,
 * and maps OIDC claims to STACK claims per the operator's
 * claim_mapping_policy_json.
 *
 * Cryptographic stance:
 *   - PKCE S256 mandatory (no plain).
 *   - State + nonce are 256-bit random; state is the index into
 *     Redis, nonce is bound to the ID token to prevent replay.
 *   - ID token signature verified against issuer's JWKS. The JWKS URI
 *     comes from the discovery doc. The key set is cached in Redis for
 *     the config's jwks_cache_ttl_seconds. A token whose kid is not in
 *     the cached set triggers one forced refetch (at most one per
 *     JWKS_REFETCH_COOLDOWN_SECONDS per JWKS URI), which is how a key
 *     rotation is picked up before the TTL expires. If the issuer is
 *     unreachable the last-known-good copy persisted on the config is used.
 *   - Assurance is never inferred from a successful login. Claims are
 *     minted at the lowest level unless the token's acr or amr matches
 *     an entry in the operator's assurance_map (see OidcAssuranceMap).
 *   - exp/nbf are checked with a small clock tolerance for IdP skew.
 *   - Audience pinned when configured (otherwise accept any aud
 *     present on the ID token).
 *   - Issuer claim re-verified against config.issuer_uri.
 *
 * What's deferred:
 *   - Per-operator multi-IdP support (v2; today the unique index on
 *     operator_id enforces one IdP per operator).
 *   - Refresh-token rotation against the IdP (today's complete is
 *     one-shot; we don't store offline_access tokens).
 *   - UserInfo endpoint dereferencing (today's claims come from the
 *     ID token only; for IdPs that put richer claims in UserInfo,
 *     v2 adds an explicit UserInfo fetch).
 *   - Front-channel logout / back-channel logout integration.
 */

// The numbers below are the specification's (spec/sso-login/SPEC.md); they are defined once, in @stack/shared.
const STATE_TTL_SECONDS = SSO_STATE_TTL_SECONDS;       // 10-minute auth-code window
const CODE_TTL_SECONDS = SSO_CODE_TTL_SECONDS;         // 5-minute code-redemption window
const DISCOVERY_TTL_SECONDS = SSO_DISCOVERY_TTL_SECONDS;  // discovery rarely changes
const FETCH_TIMEOUT_MS = SSO_FETCH_TIMEOUT_SECONDS * 1000;
/**
 * Tolerance for IdP clock skew on exp/nbf, in seconds. Matches the
 * passport signer's tolerance (CLOCK_TOLERANCE_SECONDS in
 * crypto/passport-signer.ts).
 */
const ID_TOKEN_CLOCK_TOLERANCE_SECONDS = SSO_ID_TOKEN_CLOCK_TOLERANCE_SECONDS;
/**
 * Minimum gap between forced JWKS refetches for one JWKS URI. An unknown
 * kid forces a refetch to pick up a key rotation, and this stops a stream
 * of tokens with unknown kids from turning into a stream of upstream fetches.
 */
const JWKS_REFETCH_COOLDOWN_SECONDS = SSO_JWKS_REFETCH_COOLDOWN_SECONDS;
const OIDC_JWKS_KEY_PREFIX = 'oidc:jwks:';
const OIDC_JWKS_REFETCH_KEY_PREFIX = 'oidc:jwks-refetch:';

/**
 * Optional `assurance_map` key inside an operator's claim_mapping_policy_json.
 * It maps values of the ID token's `acr` claim (a string) and `amr` claim
 * (an array of strings) to the assurance level STACK records on the claims
 * minted from that token. Levels are 'low' | 'substantial' | 'high'; an
 * entry with any other level is ignored.
 *
 *   { "assurance_map": { "acr": { "urn:example:ial2": "high" },
 *                        "amr": { "hwk": "high", "otp": "substantial" } } }
 *
 * Conservative default: with no map, no matching acr/amr value, or no acr
 * and amr in the token, claims are 'low'. A successful login at the IdP,
 * including an email-and-password one, is not evidence of a stronger
 * assurance. When several values match, the highest level wins.
 */
export interface OidcAssuranceMap {
  acr?: Record<string, AssuranceLevel>;
  amr?: Record<string, AssuranceLevel>;
}

const ASSURANCE_RANK: Record<AssuranceLevel, number> = { low: 0, substantial: 1, high: 2 };
const LOWEST_ASSURANCE: AssuranceLevel = 'low';

function isAssuranceLevel(value: unknown): value is AssuranceLevel {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(ASSURANCE_RANK, value);
}

/** Level the operator's assurance_map assigns to this token; 'low' when nothing matches. */
function assuranceForToken(payload: JWTPayload, policy: Record<string, unknown> | null): AssuranceLevel {
  const map = policy?.['assurance_map'];
  if (!map || typeof map !== 'object' || Array.isArray(map)) return LOWEST_ASSURANCE;
  const { acr: acrMap, amr: amrMap } = map as Record<string, unknown>;

  const lookup = (table: unknown, value: unknown): AssuranceLevel | null => {
    if (typeof value !== 'string' || !table || typeof table !== 'object' || Array.isArray(table)) return null;
    if (!Object.prototype.hasOwnProperty.call(table, value)) return null;
    const level = (table as Record<string, unknown>)[value];
    return isAssuranceLevel(level) ? level : null;
  };

  let best: AssuranceLevel = LOWEST_ASSURANCE;
  const consider = (level: AssuranceLevel | null) => {
    if (level && ASSURANCE_RANK[level] > ASSURANCE_RANK[best]) best = level;
  };
  consider(lookup(acrMap, payload['acr']));
  const amr = payload['amr'];
  if (Array.isArray(amr)) for (const value of amr) consider(lookup(amrMap, value));
  return best;
}

const OIDC_PROVIDER_KEY = 'oidc';

const OIDC_STATE_KEY_PREFIX = 'oidc:state:';
const OIDC_CODE_KEY_PREFIX = 'oidc:code:';
const OIDC_DISCOVERY_KEY_PREFIX = 'oidc:disc:';
const OIDC_AUTHORITY_EVIDENCE_KEY_PREFIX = 'oidc:authority-evidence:';

interface OidcStateRecord {
  operator_id: string;
  config_id: string;
  pkce_verifier: string;
  nonce: string;
  return_url: string | null;
  requested_claims: string[];
  created_at: number;
}

interface OidcDiscoveryDoc {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
}

export interface OidcTokenResponse {
  id_token: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface VerifiedOidcAuthorityEvidence {
  operator_id: string;
  config_id: string;
  id_token: string;
  nonce: string;
  payload: JWTPayload;
  signature_algorithm: string;
  issuer_key_thumbprint: string;
  expires_at: Date;
}

export type OidcFetchFn = typeof fetch;

/**
 * SSRF guard for the provider's outbound calls. Injectable for the same
 * reason InboundWebhookService and NotificationService make theirs
 * injectable: production must fail closed, while tests and the local
 * test-IdP harness (which serves http://localhost) need a way through
 * that does not weaken the default.
 */
export type OidcUrlGuardFn = (
  url: string,
  opts?: { allowedProtocols?: string[] },
) => Promise<unknown> | unknown;

/** What an SSO login needs out of a verified ID token. */
export interface OidcLoginIdentity {
  operator_id: string;
  config_id: string;
  default_member_role: string;
  /** Normalised: trimmed + lowercased, because it is a lookup key. */
  email: string;
  email_verified: boolean;
  /**
   * The ID token has no `email_verified` claim at all (some providers, Microsoft Entra ID among them, never send it).
   * Only then may another assurance of the address stand in for it; a token that says false, or anything but the boolean
   * true, has said something and is taken at its word.
   */
  email_verified_absent: boolean;
  /**
   * The issuer says, in its own documented claim, that the address's domain is verified: Microsoft Entra's `xms_edov`,
   * read only for one tenant of Entra's own v2 issuer whose `tid` is that tenant (`entraVouchesForEmailDomain`).
   */
  issuer_vouches_email_domain: boolean;
  name: string | null;
  sub: string;
  iss: string;
}

export class OidcIdpProvider implements IdentityVerificationProvider {
  readonly providerKey = OIDC_PROVIDER_KEY;
  readonly displayName = 'OIDC (federated)';
  readonly claimTypes = ['verified_human', 'verified_identity'] as const;
  readonly supportedLayers: readonly TrustLayer[] = ['humanity', 'identity'];
  /**
   * The floor, which is what an ID token earns with no acr/amr mapping.
   * Per-claim levels come from the operator's assurance_map and can be higher.
   */
  readonly assuranceLevel: AssuranceLevel = 'low';

  constructor(
    private redis: Redis,
    private configRepo: OidcIdpConfigRepository,
    private kms: KmsService,
    private fetcher: OidcFetchFn = publicFetch,
    /** Always-allowed return origin (our own dashboard): this deployment's site unless the caller names it. */
    private dashboardOrigin: string = deployment().siteUrl,
    /** Defaults to the real SSRF guard — production is fail-closed. */
    private urlGuard: OidcUrlGuardFn = assertPublicUrl,
  ) {}

  /**
   * Every outbound call this provider makes goes through here.
   *
   * Two protections, and they are separate bugs:
   *
   * 1. The destination is operator-influenced. issuer_uri comes from the
   *    operator; token_endpoint and jwks_uri come from a discovery
   *    document that the operator chose the host of. Unguarded, that is
   *    an SSRF primitive pointed at our own network.
   * 2. Redirects are not followed. Guarding a URL and then letting fetch
   *    follow a 302 guards the wrong address — the checked host answers
   *    with a redirect to a private one and the guard never sees it.
   *    These are all static documents and one token endpoint, so nothing
   *    legitimate here redirects.
   */
  private async guardedFetch(url: string, init?: RequestInit): Promise<Response> {
    await this.urlGuard(url, { allowedProtocols: ['https:'] });
    const res = await this.fetcher(url, { ...(init ?? {}), redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      throw new Error(`OIDC endpoint redirected (HTTP ${res.status}); refusing to follow`);
    }
    return res;
  }

  // ── initiate ────────────────────────────────────────────────────

  async initiate(operatorId: string, context: VerificationContext): Promise<InitiateResult> {
    const config = await this.configRepo.findActiveByOperator(operatorId);
    if (!config) {
      throw new Error(`No active OIDC IdP configuration for operator "${operatorId}"`);
    }

    // Refuse an off-allowlist return_url HERE, before anything is parked.
    // The callback that consumes it is public and unauthenticated, so a
    // return_url that survives to that point is an open redirect wearing
    // our domain. Validating at initiate means a bad value can never be
    // stored, rather than being caught on the way back out.
    if (context.return_url) {
      assertReturnUrlAllowed(context.return_url, config.allowed_return_origins ?? null, this.dashboardOrigin);
    }

    const discovery = await this.resolveDiscovery(config.issuer_uri);

    // Generate PKCE pair (S256), nonce, state.
    const pkceVerifier = base64UrlBytes(32);
    const pkceChallenge = createHash('sha256').update(pkceVerifier).digest('base64url');
    const nonce = base64UrlBytes(32);
    const state = base64UrlBytes(32);

    // Persist the state record so the callback + complete() can resolve.
    const record: OidcStateRecord = {
      operator_id: operatorId,
      config_id: config.id,
      pkce_verifier: pkceVerifier,
      nonce,
      return_url: context.return_url ?? null,
      requested_claims: context.requested_claims,
      created_at: Date.now(),
    };
    await this.redis.set(
      OIDC_STATE_KEY_PREFIX + state,
      JSON.stringify(record),
      'EX',
      STATE_TTL_SECONDS,
    );

    // Build the authorize URL.
    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', config.client_id);
    url.searchParams.set('redirect_uri', config.redirect_uri);
    url.searchParams.set('scope', (config.scopes_json ?? ['openid', 'email', 'profile']).join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', pkceChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return {
      session_ref: state,
      verification_url: url.toString(),
      expires_at: new Date(Date.now() + STATE_TTL_SECONDS * 1000),
    };
  }

  // ── callback handoff (called by the route) ─────────────────────

  /**
   * Called by the public callback route after the IdP redirects back
   * to STACK with a code+state pair. Stores the code keyed by state
   * so complete() can redeem it. Returns the return_url the caller
   * should redirect the user to (if one was provided at initiate
   * time), so the caller can complete the dance.
   *
   * Throws if state is unknown or expired.
   */
  async acceptCallback(
    state: string,
    code: string,
  ): Promise<{ return_url: string | null; config_id: string; operator_id: string }> {
    const raw = await this.redis.get(OIDC_STATE_KEY_PREFIX + state);
    if (!raw) {
      throw new Error('OIDC state is unknown or expired');
    }
    const record = JSON.parse(raw) as OidcStateRecord;
    // Single-use. NX makes the parking atomic: the FIRST callback for a
    // given state wins and every later one is refused, so an attacker who
    // replays the callback URL cannot overwrite the parked code with one
    // of their own and have the operator's complete() redeem it. Without
    // NX this was a plain SET, replayable for the state's full 10-minute
    // TTL (the state key is only deleted in complete()).
    const parked = await this.redis.set(
      OIDC_CODE_KEY_PREFIX + state,
      code,
      'EX',
      CODE_TTL_SECONDS,
      'NX',
    );
    if (parked === null) {
      throw new Error('OIDC callback has already been used for this state');
    }

    // Re-check on the way out as well as at initiate. Initiate is the gate
    // that matters for anything parked from now on; this catches a state
    // that was parked BEFORE the allowlist existed and is still inside its
    // 10-minute TTL. Cheap, and it means the redirect below cannot fire on
    // a value nothing ever validated.
    if (record.return_url) {
      const config = await this.configRepo.findById(record.config_id);
      assertReturnUrlAllowed(
        record.return_url,
        config?.allowed_return_origins ?? null,
        this.dashboardOrigin,
      );
    }

    return { return_url: record.return_url, config_id: record.config_id, operator_id: record.operator_id };
  }

  // ── complete ────────────────────────────────────────────────────

  async complete(operatorId: string, sessionRef: string): Promise<VerificationResult> {
    const stateRaw = await this.redis.get(OIDC_STATE_KEY_PREFIX + sessionRef);
    if (!stateRaw) {
      return { success: false, claims: [], raw_response: { error: 'state_expired_or_unknown' } };
    }
    const record = JSON.parse(stateRaw) as OidcStateRecord;
    if (record.operator_id !== operatorId) {
      return { success: false, claims: [], raw_response: { error: 'operator_mismatch' } };
    }

    const code = await this.redis.get(OIDC_CODE_KEY_PREFIX + sessionRef);
    if (!code) {
      // Callback hasn't fired yet, or the code expired.
      return { success: false, claims: [], raw_response: { error: 'code_not_received' } };
    }

    const config = await this.configRepo.findById(record.config_id);
    if (!config) {
      return { success: false, claims: [], raw_response: { error: 'config_not_found' } };
    }

    const discovery = await this.resolveDiscovery(config.issuer_uri);
    const clientSecret = await this.kms.decrypt(config.client_secret_encrypted, {
      operator_id: operatorId,
      provider: OIDC_PROVIDER_KEY,
    });

    // Exchange code for tokens.
    const tokens = await this.exchangeCode({
      tokenEndpoint: discovery.token_endpoint,
      clientId: config.client_id,
      clientSecret,
      code,
      redirectUri: config.redirect_uri,
      pkceVerifier: record.pkce_verifier,
    });

    // Verify ID token signature + nonce + audience + issuer.
    const jwks = await this.resolveJwksForToken(config, discovery.jwks_uri, tokens.id_token);
    const payload = await this.verifyIdToken({
      idToken: tokens.id_token,
      jwks,
      expectedIssuer: config.issuer_uri,
      expectedAudience: config.audience ?? config.client_id,
      expectedNonce: record.nonce,
    });

    // Map OIDC claims to STACK claims per the operator's policy.
    const claims = this.mapClaims(payload, record.requested_claims, config.claim_mapping_policy_json);

    // Cleanup: state + code are single-use.
    await this.redis.del(OIDC_STATE_KEY_PREFIX + sessionRef);
    await this.redis.del(OIDC_CODE_KEY_PREFIX + sessionRef);

    return {
      success: true,
      claims,
      raw_response: { sub: payload['sub'], iss: payload['iss'] },
    };
  }

  // ── complete, for LOGIN ────────────────────────────────────────
  //
  // Same exchange + verification as complete(), different output and
  // different caller. complete() answers "what claims did this prove?"
  // and runs behind an AUTHENTICATED route. Login cannot: you are not
  // signed in yet, which is the whole point. So this takes the operator
  // from the state record — which the 256-bit state, the PKCE verifier
  // and the nonce already bind — and returns the identity a session
  // needs rather than folding email away into claim metadata.
  //
  // Deliberately not widening complete()'s claim path: an identity claim
  // keeps PII KMS-encrypted behind an opaque claim_id, and login needs
  // the email in hand. Two callers, two shapes.

  async completeForLogin(sessionRef: string): Promise<OidcLoginIdentity> {
    const stateRaw = await this.redis.get(OIDC_STATE_KEY_PREFIX + sessionRef);
    if (!stateRaw) throw new Error('OIDC state is unknown or expired');
    const record = JSON.parse(stateRaw) as OidcStateRecord;

    const code = await this.redis.get(OIDC_CODE_KEY_PREFIX + sessionRef);
    if (!code) throw new Error('OIDC authorization code was not received');

    const config = await this.configRepo.findById(record.config_id);
    if (!config) throw new Error('OIDC configuration no longer exists');
    if (!config.sso_login_enabled) {
      // Re-checked at redemption, not just at entry: an admin who turns
      // SSO off mid-flight must not have an in-flight login land anyway.
      throw new Error('SSO login is not enabled for this organisation');
    }

    const discovery = await this.resolveDiscovery(config.issuer_uri);
    const clientSecret = await this.kms.decrypt(config.client_secret_encrypted, {
      operator_id: record.operator_id,
      provider: OIDC_PROVIDER_KEY,
    });

    const tokens = await this.exchangeCode({
      tokenEndpoint: discovery.token_endpoint,
      clientId: config.client_id,
      clientSecret,
      code,
      redirectUri: config.redirect_uri,
      pkceVerifier: record.pkce_verifier,
    });

    const jwks = await this.resolveJwksForToken(config, discovery.jwks_uri, tokens.id_token);
    const payload = await this.verifyIdToken({
      idToken: tokens.id_token,
      jwks,
      expectedIssuer: config.issuer_uri,
      expectedAudience: config.audience ?? config.client_id,
      expectedNonce: record.nonce,
    });

    // Single-use, same as complete().
    await this.redis.del(OIDC_STATE_KEY_PREFIX + sessionRef);
    await this.redis.del(OIDC_CODE_KEY_PREFIX + sessionRef);

    const email = typeof payload['email'] === 'string' ? payload['email'].trim().toLowerCase() : '';
    if (!email) {
      // No email, no way to resolve or create a member row. Refuse rather
      // than invent an identifier.
      throw new Error('the ID token carried no email claim, so no account can be resolved');
    }

    return {
      operator_id: record.operator_id,
      config_id: config.id,
      default_member_role: config.default_member_role,
      email,
      email_verified: payload['email_verified'] === true,
      email_verified_absent: payload['email_verified'] === undefined,
      issuer_vouches_email_domain: entraVouchesForEmailDomain(payload as Record<string, unknown>, config.issuer_uri),
      name: typeof payload['name'] === 'string' ? payload['name'] : null,
      sub: String(payload['sub'] ?? ''),
      iss: String(payload['iss'] ?? ''),
    };
  }

  /**
   * Redeem an OIDC callback for an Authority ceremony. The verified native
   * token is cached KMS-encrypted before the one-time code state is removed,
   * so a retry after a downstream database failure never needs to redeem the
   * provider code twice.
   */
  async completeForAuthority(operatorId: string, sessionRef: string): Promise<VerifiedOidcAuthorityEvidence> {
    const cacheKey = OIDC_AUTHORITY_EVIDENCE_KEY_PREFIX + sessionRef;
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      const plaintext = await this.kms.decrypt(cached, {
        operator_id: operatorId,
        provider: OIDC_PROVIDER_KEY,
        session_ref: sessionRef,
        store: 'authority_oidc_evidence',
      });
      const parsed = JSON.parse(plaintext) as Omit<VerifiedOidcAuthorityEvidence, 'payload' | 'expires_at'> & {
        payload: JWTPayload;
        expires_at: string;
      };
      if (parsed.operator_id !== operatorId) throw new Error('OIDC Authority evidence operator mismatch');
      return { ...parsed, expires_at: new Date(parsed.expires_at) };
    }

    const stateRaw = await this.redis.get(OIDC_STATE_KEY_PREFIX + sessionRef);
    if (!stateRaw) throw new Error('OIDC state is unknown or expired');
    const record = JSON.parse(stateRaw) as OidcStateRecord;
    if (record.operator_id !== operatorId) throw new Error('OIDC Authority evidence operator mismatch');
    const code = await this.redis.get(OIDC_CODE_KEY_PREFIX + sessionRef);
    if (!code) throw new Error('OIDC authorization code was not received');
    const config = await this.configRepo.findById(record.config_id);
    if (!config || config.operator_id !== operatorId || !config.active) {
      throw new Error('OIDC configuration is unavailable');
    }
    const discovery = await this.resolveDiscovery(config.issuer_uri);
    const clientSecret = await this.kms.decrypt(config.client_secret_encrypted, {
      operator_id: operatorId,
      provider: OIDC_PROVIDER_KEY,
    });
    const tokens = await this.exchangeCode({
      tokenEndpoint: discovery.token_endpoint,
      clientId: config.client_id,
      clientSecret,
      code,
      redirectUri: config.redirect_uri,
      pkceVerifier: record.pkce_verifier,
    });
    const verified = await this.verifyAuthorityEvidence({
      operatorId,
      configId: config.id,
      idToken: tokens.id_token,
      expectedNonce: record.nonce,
    });
    const result: VerifiedOidcAuthorityEvidence = {
      operator_id: operatorId,
      config_id: config.id,
      id_token: tokens.id_token,
      nonce: record.nonce,
      payload: verified.payload,
      signature_algorithm: verified.signature_algorithm,
      issuer_key_thumbprint: verified.issuer_key_thumbprint,
      expires_at: verified.expires_at,
    };
    const encrypted = await this.kms.encrypt(JSON.stringify({
      ...result,
      expires_at: result.expires_at.toISOString(),
    }), {
      operator_id: operatorId,
      provider: OIDC_PROVIDER_KEY,
      session_ref: sessionRef,
      store: 'authority_oidc_evidence',
    });
    await this.redis.set(cacheKey, encrypted.ciphertext, 'EX', STATE_TTL_SECONDS);
    await this.redis.del(OIDC_STATE_KEY_PREFIX + sessionRef);
    await this.redis.del(OIDC_CODE_KEY_PREFIX + sessionRef);
    return result;
  }

  async discardAuthorityEvidence(sessionRef: string): Promise<void> {
    await this.redis.del(OIDC_AUTHORITY_EVIDENCE_KEY_PREFIX + sessionRef);
  }

  /** Re-verify stored native evidence against the operator's pinned IdP. */
  async verifyAuthorityEvidence(input: {
    operatorId: string;
    configId: string;
    idToken: string;
    expectedNonce: string;
  }): Promise<Pick<VerifiedOidcAuthorityEvidence,
    'payload' | 'signature_algorithm' | 'issuer_key_thumbprint' | 'expires_at'>> {
    const config = await this.configRepo.findById(input.configId);
    if (!config || config.operator_id !== input.operatorId || !config.active) {
      throw new Error('OIDC configuration is unavailable');
    }
    const discovery = await this.resolveDiscovery(config.issuer_uri);
    const jwks = await this.resolveJwksForToken(config, discovery.jwks_uri, input.idToken);
    const header = decodeProtectedHeader(input.idToken);
    if (!header.kid || !header.alg) throw new Error('ID token missing kid or alg in header');
    const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
    if (!jwk) throw new Error('ID token signing key is unavailable');
    const payload = await this.verifyIdToken({
      idToken: input.idToken,
      jwks,
      expectedIssuer: config.issuer_uri,
      expectedAudience: config.audience ?? config.client_id,
      expectedNonce: input.expectedNonce,
    });
    if (typeof payload.exp !== 'number') throw new Error('ID token has no expiry');
    return {
      payload,
      signature_algorithm: header.alg,
      issuer_key_thumbprint: await calculateJwkThumbprint(jwk),
      expires_at: new Date(payload.exp * 1000),
    };
  }

  // ── token exchange ─────────────────────────────────────────────

  private async exchangeCode(opts: {
    tokenEndpoint: string;
    clientId: string;
    clientSecret: string;
    code: string;
    redirectUri: string;
    pkceVerifier: string;
  }): Promise<OidcTokenResponse> {
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', opts.code);
    body.set('redirect_uri', opts.redirectUri);
    body.set('client_id', opts.clientId);
    body.set('client_secret', opts.clientSecret);
    body.set('code_verifier', opts.pkceVerifier);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let response: Response;
    try {
      response = await this.guardedFetch(opts.tokenEndpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: body.toString(),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new Error(`OIDC token endpoint HTTP ${response.status}`);
    }
    const json = (await response.json()) as OidcTokenResponse & { error?: string; error_description?: string };
    if (json.error || !json.id_token) {
      throw new Error('OIDC token endpoint did not return a valid identity token');
    }
    return json;
  }

  // ── ID token verification ──────────────────────────────────────

  private async verifyIdToken(opts: {
    idToken: string;
    jwks: { keys: JWK[] };
    expectedIssuer: string;
    expectedAudience: string;
    expectedNonce: string;
  }): Promise<JWTPayload> {
    let header;
    try {
      header = decodeProtectedHeader(opts.idToken);
    } catch {
      throw new Error('ID token header is malformed');
    }
    if (!header.kid) throw new Error('ID token missing kid in header');
    const jwk = opts.jwks.keys.find((k) => k.kid === header.kid);
    if (!jwk) throw new Error(`ID token kid "${header.kid}" not found in issuer JWKS`);

    const algForJwk = jwk.alg ?? algFromJwk(jwk) ?? header.alg;
    const key = await importJWK(jwk, algForJwk);

    const verified = await jwtVerify(opts.idToken, key, {
      issuer: opts.expectedIssuer,
      audience: opts.expectedAudience,
      clockTolerance: ID_TOKEN_CLOCK_TOLERANCE_SECONDS,
      // OpenID Connect Core 2: an ID token has an expiry and a subject. A token with no `exp` would never expire.
      requiredClaims: ['exp', 'sub'],
    });

    // OIDC §3.1.3.7: nonce in the ID token MUST equal the nonce we sent.
    if (verified.payload['nonce'] !== opts.expectedNonce) {
      throw new Error('ID token nonce mismatch');
    }
    return verified.payload;
  }

  // ── claim mapping ──────────────────────────────────────────────

  private mapClaims(
    payload: JWTPayload,
    requestedClaims: string[],
    policy: Record<string, unknown> | null,
  ): VerifiedClaim[] {
    const out: VerifiedClaim[] = [];
    const expiresAt = typeof payload['exp'] === 'number' ? new Date(payload['exp'] * 1000) : new Date(Date.now() + 24 * 3600 * 1000);
    const verifiedAt = typeof payload['iat'] === 'number' ? new Date(payload['iat'] * 1000) : new Date();

    const assuranceLevel = assuranceForToken(payload, policy);
    const wantHuman = requestedClaims.includes('verified_human');
    const wantIdentity = requestedClaims.includes('verified_identity');

    // Default policy: verified_human requires email_verified=true OR
    // an MFA assurance ('mfa' in amr); verified_identity requires sub
    // to exist (every valid ID token has one). Operators override via
    // claim_mapping_policy_json.
    const evalPolicy = (
      claim_type: string,
      defaultPredicate: (p: JWTPayload) => boolean,
    ): boolean => {
      const rules = policy?.[claim_type] as { require?: Array<Record<string, unknown>> } | undefined;
      if (!rules || !Array.isArray(rules.require)) return defaultPredicate(payload);
      return rules.require.every((rule) => {
        const claimName = String(rule['claim'] ?? '');
        const value = payload[claimName];
        if ('equals' in rule) return value === rule['equals'];
        if ('exists' in rule) return value !== undefined;
        if ('includes' in rule && Array.isArray(value)) {
          return (value as unknown[]).includes(rule['includes']);
        }
        return false;
      });
    };

    if (wantHuman) {
      const ok = evalPolicy('verified_human', (p) => {
        const emailVerified = p['email_verified'];
        const amr = p['amr'];
        return emailVerified === true || (Array.isArray(amr) && (amr as unknown[]).includes('mfa'));
      });
      if (ok) {
        out.push({
          claim_type: 'verified_human',
          layer: 'humanity',
          assertion: sha256(String(payload['sub'] ?? '') + String(payload['iss'] ?? '')),
          assurance_level: assuranceLevel,
          verified_at: verifiedAt,
          expires_at: expiresAt,
          metadata: { iss: payload['iss'], sub: payload['sub'] },
        });
      }
    }

    if (wantIdentity) {
      const ok = evalPolicy('verified_identity', (p) => typeof p['sub'] === 'string' && p['sub'].length > 0);
      if (ok) {
        out.push({
          claim_type: 'verified_identity',
          layer: 'identity',
          assertion: sha256(String(payload['sub'] ?? '') + String(payload['iss'] ?? '') + ':id'),
          assurance_level: assuranceLevel,
          verified_at: verifiedAt,
          expires_at: expiresAt,
          metadata: {
            iss: payload['iss'],
            sub: payload['sub'],
            // OIDC identity claims commonly carry these; surface in metadata
            // for the L2-PII storage path (PII is KMS-encrypted at rest).
            ...(typeof payload['email'] === 'string' ? { pii: { email: payload['email'] } } : {}),
          },
        });
      }
    }

    return out;
  }

  // ── discovery + JWKS ───────────────────────────────────────────

  private async resolveDiscovery(issuerUri: string): Promise<OidcDiscoveryDoc> {
    const cacheKey = OIDC_DISCOVERY_KEY_PREFIX + sha256(issuerUri);
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      try {
        return JSON.parse(cached) as OidcDiscoveryDoc;
      } catch {
        // fall through to refresh
      }
    }
    const url = issuerUri.replace(/\/$/, '') + '/.well-known/openid-configuration';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let response: Response;
    try {
      response = await this.guardedFetch(url, { signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      throw new Error(`OIDC discovery HTTP ${response.status} from ${url}`);
    }
    const doc = (await response.json()) as OidcDiscoveryDoc;
    if (!doc.token_endpoint || !doc.authorization_endpoint || !doc.jwks_uri) {
      throw new Error('OIDC discovery doc missing required endpoints');
    }
    await this.redis.set(cacheKey, JSON.stringify(doc), 'EX', DISCOVERY_TTL_SECONDS);
    return doc;
  }

  /**
   * JWKS for verifying one specific token. If the cached key set has no key
   * for the token's kid, the issuer has probably rotated: refetch once,
   * rather than rejecting every login until the cache TTL runs out. The
   * refetch is rate-limited per JWKS URI so a token with a made-up kid
   * cannot be used to make us hammer the issuer.
   */
  private async resolveJwksForToken(
    config: { id: string; jwks_cached_jwks_json: unknown; jwks_cache_ttl_seconds: number },
    jwksUri: string,
    idToken: string,
  ): Promise<{ keys: JWK[] }> {
    const jwks = await this.resolveJwks(config, jwksUri);
    let kid: string | undefined;
    try {
      kid = decodeProtectedHeader(idToken).kid;
    } catch {
      return jwks; // verifyIdToken reports the malformed header
    }
    if (!kid || jwks.keys.some((k) => k.kid === kid)) return jwks;

    const claimed = await this.redis.set(
      OIDC_JWKS_REFETCH_KEY_PREFIX + sha256(jwksUri),
      '1',
      'EX',
      JWKS_REFETCH_COOLDOWN_SECONDS,
      'NX',
    );
    if (claimed !== 'OK') return jwks;
    return this.resolveJwks(config, jwksUri, { bypassCache: true });
  }

  private async resolveJwks(
    config: { id: string; jwks_cached_jwks_json: unknown; jwks_cache_ttl_seconds: number },
    jwksUri: string,
    opts: { bypassCache?: boolean } = {},
  ): Promise<{ keys: JWK[] }> {
    const cacheKey = OIDC_JWKS_KEY_PREFIX + sha256(jwksUri);
    const cached = opts.bypassCache ? null : await this.redis.get(cacheKey);
    if (cached) {
      try {
        return JSON.parse(cached) as { keys: JWK[] };
      } catch {
        // fall through
      }
    }
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      let response: Response;
      try {
        response = await this.guardedFetch(jwksUri, { signal: controller.signal });
      } finally {
        clearTimeout(timeout);
      }
      if (!response.ok) {
        throw new Error(`OIDC JWKS HTTP ${response.status} from ${jwksUri}`);
      }
      const parsed = (await response.json()) as { keys?: JWK[] };
      if (!parsed.keys || !Array.isArray(parsed.keys) || parsed.keys.length === 0) {
        throw new Error('OIDC JWKS response missing non-empty keys array');
      }
      const jwks: { keys: JWK[] } = { keys: parsed.keys };
      await this.redis.set(cacheKey, JSON.stringify(jwks), 'EX', config.jwks_cache_ttl_seconds);
      try {
        await this.configRepo.persistLastKnownGoodJwks(config.id, jwks, new Date());
      } catch (err) {
        console.warn('[oidc] last-known-good persist failed:', safeErrorSummary(err));
      }
      return jwks;
    } catch (err) {
      // Fail-open to DB last-known-good
      const lkg = config.jwks_cached_jwks_json;
      if (lkg && typeof lkg === 'object' && 'keys' in lkg && Array.isArray((lkg as { keys: unknown }).keys)) {
        return lkg as { keys: JWK[] };
      }
      throw err;
    }
  }
}

// ─── Helpers ────────────────────────────────────────────────────────

/**
 * Open-redirect guard for the verification handoff.
 *
 * NOT url-guard's assertPublicUrl — that is an SSRF guard. It blocks
 * private and internal targets, which is the opposite problem: an open
 * redirect is abusive precisely because the target is a perfectly
 * reachable PUBLIC host the attacker controls. Only an allowlist helps.
 *
 * NULL/empty allowlist = the dashboard origin only. Comparison is on
 * origin (scheme + host + port), so a path or query cannot smuggle a
 * different destination, and https is required for anything configured.
 */
export function assertReturnUrlAllowed(
  returnUrl: string,
  allowedOrigins: string[] | null,
  dashboardOrigin: string,
): void {
  let parsed: URL;
  try {
    parsed = new URL(returnUrl);
  } catch {
    throw new Error('return_url is not a valid absolute URL');
  }

  const allowed = new Set<string>();
  try {
    allowed.add(new URL(dashboardOrigin).origin);
  } catch {
    /* misconfigured dashboard origin — fall through to the operator list */
  }
  for (const o of allowedOrigins ?? []) {
    try {
      allowed.add(new URL(o).origin);
    } catch {
      // A malformed configured origin is ignored rather than treated as a
      // wildcard. Fail closed: an unparseable entry allows nothing.
    }
  }

  if (!allowed.has(parsed.origin)) {
    throw new Error(
      `return_url origin "${parsed.origin}" is not in this operator's allowed return origins`,
    );
  }
}

function base64UrlBytes(byteLength: number): string {
  return randomBytes(byteLength).toString('base64url');
}

function algFromJwk(jwk: JWK): string | undefined {
  if (jwk.kty === 'EC') {
    if (jwk.crv === 'P-256') return 'ES256';
    if (jwk.crv === 'P-384') return 'ES384';
    if (jwk.crv === 'P-521') return 'ES512';
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  if (jwk.kty === 'RSA') return 'RS256';
  return undefined;
}
