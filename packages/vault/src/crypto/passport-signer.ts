import { SignJWT, jwtVerify, importJWK, importPKCS8, exportJWK, generateKeyPair, decodeJwt, errors as joseErrors, type JWK, type JWTPayload } from 'jose';
import {
  deployment,
  PASSPORT_JWT_AUDIENCE,
  SESSION_JWT_AUDIENCE,
  SESSION_JWT_TTL_SECONDS,
  OAUTH_ACCESS_TOKEN_AUDIENCE_API,
  OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
  OAUTH_CONSENT_JWT_AUDIENCE,
  OAUTH_CONSENT_JWT_TTL_SECONDS,
  AGENT_JWT_ISSUER,
  AGENT_JWT_AUDIENCE,
  AGENT_JWT_MAX_TTL_SECONDS,
  AGENT_JWT_CLOCK_TOLERANCE_SECONDS,
  ENROLLMENT_TICKET_AUDIENCE,
  ENROLLMENT_TICKET_TTL_SECONDS,
  PassportExpiredError,
  PassportInvalidError,
  PASSPORT_TOKEN_MAX_CHARS,
  InvalidRequestError,
  AuthorityReceiverPresentationPayload,
  PassportClaims as PassportClaimsSchema,
  type PassportClaimRef,
  type IntentRef,
} from '@stack/shared';
import {
  LEGACY_DEPLOYMENT_SIGNING_KID,
  validateDeploymentSigningKid,
} from './deployment-signing-config.js';

export interface OAuthConsentClaims {
  client_id: string;
  redirect_uri: string;
  scope: string;
  resource: string;
  code_challenge: string;
  code_challenge_method: string;
  state: string;
  nonce?: string;
  /**
   * When the cookie session approving consent is a team-member session
   * (signMemberSessionToken), the member_id is propagated through the
   * consent token + auth code + access/refresh tokens so the parent
   * operator's row stays the source of truth for tier/billing while the
   * member's row gates role + allowed_connections at request time.
   * Undefined when the approver is the operator themselves.
   */
  member_id?: string;
}

// jose v6 key type
type JoseKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

const AUTHORITY_CEREMONY_ISSUER = 'stack:authority-ceremony';
const AUTHORITY_CEREMONY_AUDIENCE = 'stack:authority-core';
const AUTHORITY_CEREMONY_DEFAULT_TTL_SECONDS = 5 * 60;
const AUTHORITY_CEREMONY_MAX_TTL_SECONDS = 60 * 60;
const PROVIDER_OAUTH_STATE_AUDIENCE = 'stack:provider-oauth-state';
const PROVIDER_OAUTH_STATE_TTL_SECONDS = 10 * 60;

const DRIVE_LINK_AUDIENCE = 'stack:drive-link';

/** What an agent-drive share link is signed over. `link_id` is the token's jti. */
export interface DriveLinkClaims {
  link_id: string;
  file_id: string;
  operator_id: string;
}

export interface FleetSessionClaims {
  operator_id: string;
  agent_id: string;
  membership_id?: string;
  principal_kind: 'worker' | 'provisioner';
  policy_id: string;
  policy_revision: number;
  key_digest: string;
}

export interface ProviderOAuthStateClaims {
  operator_id: string;
  member_id?: string;
  service_id: string;
  provider: string;
  scopes: string[];
  nonce: string;
  return_to: 'connect' | 'services';
  allowed_hosts?: string[];
  code_verifier_hash?: string;
  oauth_app_id: string;
  oauth_app_owner_id: string;
  oauth_app_provider: string;
  oauth_client_id_hash: string;
  /** A connect link this consent completes; only its id, never its token. */
  connect_link_id?: string;
  /** What the connection this consent makes is called; signed here so the browser cannot change it between consent and return. */
  connection_name?: string;
}

function verifiedPassportPayload(payload: import('jose').JWTPayload): {
  jti: string;
  sub: string;
  stk: PassportPayload;
  exp: number;
  iat: number;
} {
  const stk = PassportClaimsSchema.parse(payload['stk']) as PassportPayload;
  const requiredClaims: Array<[string, unknown]> = [
    ['jti', payload.jti],
    ['sub', payload.sub],
    ['exp', payload.exp],
    ['iat', payload.iat],
  ];
  for (const [claim, value] of requiredClaims) {
    const invalid = claim === 'exp' || claim === 'iat'
      ? typeof value !== 'number'
      : typeof value !== 'string';
    if (invalid) {
      throw new joseErrors.JWTClaimValidationFailed(
        `missing or invalid required "${claim}" claim`,
        payload,
        claim,
        'invalid',
      );
    }
  }
  if (payload.sub !== stk.agent_id) {
    throw new joseErrors.JWTClaimValidationFailed(
      'passport subject does not match stk.agent_id',
      payload,
      'sub',
      'mismatch',
    );
  }
  return {
    jti: payload.jti as string,
    sub: payload.sub as string,
    stk,
    exp: payload.exp as number,
    iat: payload.iat as number,
  };
}

/**
 * (auth refactor): platform-intent values used for passport-as
 * inbound-auth on STACK's own API.
 *
 *  - `staff`   — caller acts as STACK platform-staff. Gates routes under
 *                /v1/admin/* via `requirePlatformStaff` middleware.
 *                Issuance gated by issuer.is_platform_staff = true.
 *  - `monitor` — caller is the future 24/7 monitoring agent.
 *                Gates the read-only monitoring + write-resolution surface
 *                via `requirePlatformMonitor`. Issuance restricted to
 *                op_stack_system as the parent operator.
 *
 * Invariants:
 *  - platform_intent NEVER carries through delegation. The child of a
 *    platform passport is a regular passport. Defense against the
 *    obvious "delegate platform-staff to a less-trusted child agent"
 *    privilege-escalation path.
 *  - platform_intent only survives refresh if the issuing operator is
 *    STILL platform-staff at refresh time. Removing the flag invalidates
 *    every existing platform passport at next refresh, even before TTL.
 */
export type PlatformIntent = 'staff' | 'monitor';

export interface PassportPayload {
  operator_id: string;
  agent_id: string;
  agent_name: string;
  services: Array<{
    service_id: string;
    service_name: string;
    scopes: string[];
    credential_ref: string;
    // Canonical connection id (`scon_*`). Optional only for backward-compat
    // with passports issued before this field landed; new passports always
    // carry it. Used by verify() freshness check + delegate() parent-find.
    connection_id?: string;
    // Parameter-level constraints. Optional for backward-compat with
    // passports issued before the constraint substrate landed.
    constraints?: import('@stack/shared').Constraint[];
    // Closed-operation policy. Absent → open, i.e. legacy behaviour.
    //
    // Declared here as well as on the shared ServiceScope schema because
    // this interface is what sign() and verify() are typed against. It
    // passed through at runtime without it — the JWT is JSON — but the type
    // said the field did not exist, so every consumer had to cast, and a
    // cast is exactly how a security control gets silently dropped in a
    // later refactor.
    policy?: import('@stack/shared').ScopePolicy;
    // Services whose content may flow into this one. See ServiceScope.
    allow_data_from?: string[];
  }>;
  /** Claim references — Layer 1 & 3 inline data, Layer 2 PII resolved server-side */
  identity_claims: PassportClaimRef[];
  /** Opaque authority binding references. No proof payload or PII is carried. */
  authority_refs?: import('@stack/shared').AuthorityReference[];
  fleet?: import('@stack/shared').FleetPassportBinding;
  /** Set only on a Passport made for one workspace command; delegation carries it and refresh refuses it. */
  workspace_command?: import('@stack/shared').WorkspaceCommandBinding;
  delegation_depth: number;
  parent_passport_id?: string;
  session_id: string;
  // Accountability
  accountability?: 'enforced' | 'logged' | 'standard';
  intent_summary?: string;
  intent_services?: string[];
  // Full intent references (name + params) preserved on the JWT so
  // proxy telemetry can identify the specific intent responsible for
  // upstream failures. Optional for backward compatibility.
  intent_refs?: IntentRef[];
  checkpoint_interval?: number;
  /**
   * (auth refactor): platform-intent claim. Only present when the
   * passport authenticates inbound calls to STACK's own API at the
   * platform-staff or platform-monitor scope. Regular operator-scoped
   * passports never carry this.
   */
  platform_intent?: PlatformIntent;
  /**
   * mission binding. When set, every intent
   * submitted under this passport implicitly references one of these
   * missions (producer auto-resolve when exactly one is active; explicit
   * mission_ref on the intent payload overrides). The proxy gate
   * enforces each active mission's scope + caps on every action.
   * Empty / omitted = passport not bound to any mission (standard
   * behavior; passport.services + intent_services are the
   * only scope ceiling).
   */
  mission_ids?: string[];
}

export interface SignedPassport {
  token: string;
  jti: string;
  expires_at: Date;
}

/**
 * clock tolerance for every JWT verification.
 *
 * Agent JWTs carry iat/nbf stamped by the CLIENT's clock. jose verifies
 * nbf/exp against THIS machine's clock with zero tolerance by default —
 * a client running fractionally ahead of the server mints tokens that
 * are 'not yet valid' on arrival, and the resulting
 * JWTClaimValidationFailed is (correctly) classed as a credential fault
 * → 401. Measured live 2026-07-19: prod machine 0.34s behind the
 * reporting client → ~34% of calls failed exactly at the observed rate.
 * 30s is the standard allowance; replay of agent JWTs stays impossible
 * (jti burn) and the effective post-expiry window grows by the same
 * 30s, which the threat model absorbs.
 */
const CLOCK_TOLERANCE_SECONDS = 30;

export class PassportSigner {
  private privateKey: JoseKey | undefined;
  private publicKey: JoseKey | undefined;
  private readonly kid: string;

  constructor(options: { kid?: string } = {}) {
    this.kid = validateDeploymentSigningKid(
      options.kid ?? LEGACY_DEPLOYMENT_SIGNING_KID,
      'PassportSigner kid',
    );
  }

  async init(sessionSigningKeyPem?: string): Promise<void> {
    if (sessionSigningKeyPem) {
      // Import PKCS8 PEM — shared with dashboard for session JWT verification
      // extractable: true needed so we can export to JWK and derive public key
      const privKey = await importPKCS8(sessionSigningKeyPem, 'EdDSA', { extractable: true });
      this.privateKey = privKey;
      // Derive public key: export as JWK, remove private field, re-import
      const jwk = await exportJWK(privKey);
      delete jwk.d; // Remove private component
      this.publicKey = (await importJWK(jwk, 'EdDSA')) as JoseKey;
      return;
    }
    // extractable: true required by jose v6 — default-non-extractable
    // CryptoKey cannot be exported via exportJWK. The PEM-import path
    // above already sets it; the in-memory generate path missed it,
    // which crashed createServices when it tried to feed the private
    // JWK into ClaimSigner (the claims-registry-service wiring
    // added that getPrivateJwk() call in the API wiring). Symptom:
    // workload.test.ts setup failing with "non-extractable CryptoKey
    // cannot be exported as a JWK". Affects test + dev environments
    // (no KEY_PAIR_PEM); prod always took the PEM-import branch.
    const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    this.privateKey = kp.privateKey;
    this.publicKey = kp.publicKey;
  }

  async initWithKeys(privateJwk: JWK, publicJwk: JWK): Promise<void> {
    this.privateKey = (await importJWK(privateJwk, 'EdDSA')) as JoseKey;
    this.publicKey = (await importJWK(publicJwk, 'EdDSA')) as JoseKey;
  }

  async getPublicJwk(): Promise<JWK> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    const jwk = await exportJWK(this.publicKey);
    jwk.kid = this.kid;
    jwk.alg = 'EdDSA';
    jwk.use = 'sig';
    return jwk;
  }

  async getPrivateJwk(): Promise<JWK> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    return exportJWK(this.privateKey);
  }

  async sign(
    jti: string,
    payload: PassportPayload,
    ttlSeconds: number,
  ): Promise<SignedPassport> {
    if (!this.privateKey) throw new Error('Signer not initialized');

    // Authoring types disappear at the JSON boundary. Parse before signing so
    // STACK cannot mint a structurally invalid Passport that its own verifier
    // would later reject (especially malformed authority references).
    const validatedPayload = PassportClaimsSchema.parse(payload) as PassportPayload;

    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

    const token = await new SignJWT({ stk: validatedPayload })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setIssuer(deployment().passportIssuer)
      .setAudience(PASSPORT_JWT_AUDIENCE)
      .setSubject(validatedPayload.agent_id)
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .setJti(jti)
      .sign(this.privateKey);

    // A Passport is sent in a header, and a header that is too long is refused before STACK reads it.
    if (token.length > PASSPORT_TOKEN_MAX_CHARS) {
      throw new InvalidRequestError(
        `This Passport would be ${token.length} characters, more than the ${PASSPORT_TOKEN_MAX_CHARS} one can be. Give it fewer constraints or shorter ones.`,
      );
    }

    return { token, jti, expires_at: expiresAt };
  }

  /** MCP bearer session stays a worker identity, never an operator session. */
  async signFleetSession(claims: FleetSessionClaims, expiresAt: number): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt > now + 300) throw new Error('Invalid input');
    return new SignJWT({ fleet_session: claims })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setIssuer(deployment().passportIssuer).setAudience('stack:fleet-session')
      .setSubject(claims.agent_id).setIssuedAt(now).setExpirationTime(expiresAt)
      .setJti(crypto.randomUUID()).sign(this.privateKey);
  }

  async verifyFleetSession(token: string): Promise<FleetSessionClaims> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: deployment().passportIssuer, audience: 'stack:fleet-session', algorithms: ['EdDSA'],
      requiredClaims: ['sub', 'iat', 'exp', 'jti'], maxTokenAge: '300s',
    });
    const value = payload['fleet_session'] as FleetSessionClaims | undefined;
    if (!value || ['operator_id', 'agent_id', 'policy_id', 'key_digest'].some(key =>
      typeof value[key as keyof FleetSessionClaims] !== 'string' || !value[key as keyof FleetSessionClaims]) ||
      !['worker', 'provisioner'].includes(value.principal_kind) ||
      (value.principal_kind === 'worker' ? typeof value.membership_id !== 'string' || !value.membership_id : value.membership_id !== undefined) ||
      !Number.isSafeInteger(value.policy_revision) || value.policy_revision < 1 || payload.sub !== value.agent_id ||
      !payload.exp || !payload.iat || payload.exp - payload.iat > 300) throw new Error('Invalid input');
    return value;
  }

  /**
   * Sign an agent-drive share link. The token names one link row (its jti),
   * one file and the customer, and ends at `expiresAt`. It opens nothing but
   * the public download route: the audience is its own, so it is never read as
   * a session, a Passport or any other token.
   */
  async signDriveLink(claims: DriveLinkClaims, expiresAt: number): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) throw new Error('Invalid input');
    return new SignJWT({ drive_link: { operator_id: claims.operator_id, file_id: claims.file_id } })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setIssuer(deployment().passportIssuer)
      .setAudience(DRIVE_LINK_AUDIENCE)
      .setSubject(claims.file_id)
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .setJti(claims.link_id)
      .sign(this.privateKey);
  }

  /** The claims of a valid, unexpired share-link token; throws on anything else. */
  async verifyDriveLink(token: string): Promise<DriveLinkClaims> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: deployment().passportIssuer,
      audience: DRIVE_LINK_AUDIENCE,
      algorithms: ['EdDSA'],
      requiredClaims: ['sub', 'iat', 'exp', 'jti'],
    });
    const value = payload['drive_link'] as { operator_id?: unknown; file_id?: unknown } | undefined;
    if (
      !value || typeof value.operator_id !== 'string' || typeof value.file_id !== 'string' ||
      payload.sub !== value.file_id || typeof payload.jti !== 'string'
    ) {
      throw new Error('Invalid input');
    }
    return { link_id: payload.jti, file_id: value.file_id, operator_id: value.operator_id };
  }

  /** Mint a dashboard owner session without exporting the deployment key. */
  async signDashboardOwnerSession(args: {
    operatorId: string;
    email: string;
    tier: string;
    isAdmin: boolean;
    ownerSessionRevision: string;
    sessionId: string;
    tokenId: string;
    authenticatedAt: number;
  }): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    return new SignJWT({
      email: args.email,
      tier: args.tier,
      is_admin: args.isAdmin,
      owner_session_revision: args.ownerSessionRevision,
      sid: args.sessionId,
      auth_time: args.authenticatedAt,
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setSubject(args.operatorId)
      .setIssuer(deployment().passportIssuer)
      .setAudience(SESSION_JWT_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${SESSION_JWT_TTL_SECONDS}s`)
      .setJti(args.tokenId)
      .sign(this.privateKey);
  }

  /** Mint a dashboard member session without exporting the deployment key. */
  async signDashboardMemberSession(args: {
    operatorId: string;
    memberId: string;
    email: string;
    role: string;
    tier: string;
    sessionId: string;
    tokenId: string;
    authenticatedAt: number;
  }): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    return new SignJWT({
      email: args.email,
      member_id: args.memberId,
      role: args.role,
      tier: args.tier,
      is_member: true,
      sid: args.sessionId,
      auth_time: args.authenticatedAt,
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setSubject(args.operatorId)
      .setIssuer(deployment().passportIssuer)
      .setAudience(SESSION_JWT_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${SESSION_JWT_TTL_SECONDS}s`)
      .setJti(args.tokenId)
      .sign(this.privateKey);
  }

  /**
   * Sign the complete provider-OAuth transaction inside the API process.
   * Only identifiers and digests are carried; client credentials never enter
   * state or cross the dashboard boundary.
   */
  async signProviderOAuthState(claims: ProviderOAuthStateClaims): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    return new SignJWT({ provider_oauth: claims })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid, typ: 'JWT' })
      .setIssuer(deployment().passportIssuer)
      .setAudience(PROVIDER_OAUTH_STATE_AUDIENCE)
      .setSubject(claims.operator_id)
      .setIssuedAt()
      .setExpirationTime(`${PROVIDER_OAUTH_STATE_TTL_SECONDS}s`)
      .sign(this.privateKey);
  }

  /** Verify provider-OAuth state with the deployment public key. */
  async verifyProviderOAuthState(token: string): Promise<ProviderOAuthStateClaims> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: deployment().passportIssuer,
      audience: PROVIDER_OAUTH_STATE_AUDIENCE,
      algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    const claims = payload['provider_oauth'];
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      throw new joseErrors.JWTClaimValidationFailed(
        'provider OAuth state payload is missing',
        payload,
        'provider_oauth',
        'missing',
      );
    }
    return claims as unknown as ProviderOAuthStateClaims;
  }

  /**
   * Sign the inner receiver presentation with the deployment Ed25519 key.
   * The authority service constructs and validates the complete, short-lived
   * audience-bound payload before calling this method; this signer adds only
   * the protected algorithm/key metadata and never logs the private payload.
   */
  async signAuthorityPresentation(payload: Record<string, unknown>): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    const validated = AuthorityReceiverPresentationPayload.parse(payload);
    if (validated.iss !== deployment().presentationIssuer) {
      throw new Error('Authority presentation issuer does not match this deployment');
    }
    return new SignJWT(validated)
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid, typ: 'JWT' })
      .sign(this.privateKey);
  }

  /**
   * Server-only evidence envelope for OIDC-backed Authority ceremonies.
   * The browser never receives a bearer credential from this method. The
   * envelope is imported directly into the encrypted Authority proof store.
   */
  async signAuthorityCeremony(
    subject: string,
    payload: Record<string, unknown>,
    ttlSeconds = AUTHORITY_CEREMONY_DEFAULT_TTL_SECONDS,
  ): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > AUTHORITY_CEREMONY_MAX_TTL_SECONDS) {
      throw new Error('Authority ceremony lifetime is invalid');
    }
    const now = new Date();
    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid, typ: 'JWT' })
      .setIssuer(AUTHORITY_CEREMONY_ISSUER)
      .setAudience(AUTHORITY_CEREMONY_AUDIENCE)
      .setSubject(subject)
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(new Date(now.getTime() + ttlSeconds * 1000))
      .sign(this.privateKey);
  }

  async verifyAuthorityCeremony(token: string): Promise<JWTPayload> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: AUTHORITY_CEREMONY_ISSUER,
      audience: AUTHORITY_CEREMONY_AUDIENCE,
      algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    return payload;
  }

  async verify(token: string, options?: { ignoreExpiration?: boolean }): Promise<{
    jti: string;
    sub: string;
    stk: PassportPayload;
    exp: number;
    iat: number;
  }> {
    if (!this.publicKey) throw new Error('Signer not initialized');

    const verifyOpts: Parameters<typeof jwtVerify>[2] = {
      issuer: deployment().passportIssuer,
      audience: PASSPORT_JWT_AUDIENCE,
      algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    };

    let verified: JWTPayload;
    try {
      ({ payload: verified } = await jwtVerify(token, this.publicKey, verifyOpts));
    } catch (err) {
      // Refresh path: tolerate expired tokens but enforce a 24h grace window.
      // jose's JWTExpired error attaches the verified payload — so signature,
      // issuer, audience, and algorithm have already been checked. We just
      // need to enforce our additional grace-window policy.
      // (Previously this used `currentDate: new Date(0)` to skip exp check,
      // but that made jose treat any modern iat as "in the future" and threw
      // ERR_JWT_CLAIM_VALIDATION_FAILED on iat. Don't do that.)
      if (err instanceof joseErrors.JWTExpired && options?.ignoreExpiration) {
        const payload = err.payload;
        const exp = payload.exp;
        if (typeof exp === 'number') {
          const ageMsPastExp = Date.now() - exp * 1000;
          if (ageMsPastExp <= 24 * 60 * 60 * 1000) {
            // Within grace window — accept the expired token for refresh
            return verifiedPassportPayload(payload);
          }
        }
        throw new PassportExpiredError();
      }
      if (err instanceof joseErrors.JWTExpired) {
        throw new PassportExpiredError();
      }
      // Not a Passport of this deployment (unreadable, tampered, another audience or issuer): its own code, which says
      // the token is not valid and never that it was revoked, and never an unclassified error, which would answer a
      // caller's bad token with a 500.
      if (err instanceof joseErrors.JOSEError) throw new PassportInvalidError();
      throw err;
    }
    // A token with this deployment's own signature whose claims disagree with each other was not made by this signer's
    // issue path: that is a fault of ours, and it is not turned into a refusal of the caller.
    return verifiedPassportPayload(verified);
  }

  async signSession(
    operatorId: string,
    email: string,
    tier: string,
    ttlSeconds: number,
  ): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');

    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

    return new SignJWT({ email, tier })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setIssuer(deployment().passportIssuer)
      .setSubject(operatorId)
      .setAudience(SESSION_JWT_AUDIENCE)
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .sign(this.privateKey);
  }

  async verifySession(token: string): Promise<{ sub: string; email: string; tier: string }> {
    if (!this.publicKey) throw new Error('Signer not initialized');

    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: deployment().passportIssuer,
      audience: SESSION_JWT_AUDIENCE,
      algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });

    return {
      sub: payload.sub!,
      email: payload['email'] as string,
      tier: payload['tier'] as string,
    };
  }

  async getJwks(): Promise<{ keys: JWK[] }> {
    const pub = await this.getPublicJwk();
    return { keys: [pub] };
  }

  // ─── Passport claim attachments ────────────
  // Sign a typed-claim attachment binding (claim_id + passport_id +
  // claim_hash + type) as a compact JWS reusing the passport signer's
  // EdDSA key. External verifiers fetch the JWKS from the same /.well-
  // known/jwks.json endpoint and verify exactly like a passport JWT.
  // iss is fixed to `stack:passport-claim` so verifiers can route by
  // issuer. The signed JWT IS the persisted `passport_claims.signature`.
  async signClaimAttachment(args: {
    claim_id: string;
    passport_id: string;
    claim_hash: string;
    type: string;
  }): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    return new SignJWT({
      claim_id: args.claim_id,
      passport_id: args.passport_id,
      claim_hash: args.claim_hash,
      claim_type: args.type,
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid, typ: 'JWT' })
      .setIssuer('stack:passport-claim')
      .setIssuedAt()
      .sign(this.privateKey);
  }

  // ─── OAuth 2.1 access tokens ─────────────────────────────
  // EdDSA-signed JWTs reusing the same keypair as passport + session
  // signing. The `aud` claim disambiguates: `stack:api` for API calls,
  // `stack:mcp` for MCP calls. iss = the deployment OAuth issuer. Tokens are bearer;
  // refresh-rotation + revocation live in the API/route layer.
  async signAccessToken(args: {
    operatorId: string;
    audience: typeof OAUTH_ACCESS_TOKEN_AUDIENCE_API | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_MCP;
    clientId: string;
    scope: string;
    jti: string;
    ttlSeconds: number;
    memberId?: string;
    // The refresh-token family this access token belongs to. Stamped as a
    // claim so the auth path can enforce a family revocation live on the
    // next call (mirrors the passport `revoked:<jti>` model). Without it an
    // issued access token is un-revocable until its TTL expires.
    tokenFamilyId?: string;
    // The exact RFC 8707 resource URL the token was granted for. Two MCP
    // resources share the `stack:mcp` audience (/mcp and /directory); the
    // signed claim lets the MCP transport refuse a token on the other path.
    resource?: string;
  }): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + args.ttlSeconds * 1000);
    const payload: Record<string, unknown> = {
      client_id: args.clientId,
      scope: args.scope,
      token_use: 'access',
    };
    if (args.memberId) payload['member_id'] = args.memberId;
    if (args.tokenFamilyId) payload['token_family_id'] = args.tokenFamilyId;
    if (args.resource) payload['resource'] = args.resource;
    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setIssuer(deployment().oauthIssuer)
      .setSubject(args.operatorId)
      .setAudience(args.audience)
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(expiresAt)
      .setJti(args.jti)
      .sign(this.privateKey);
  }

  /**
   * Verify a bearer token that may be a dashboard session JWT or an OAuth 2.1
   * access token (api or mcp audience). Returns the decoded payload + matched
   * audience so the auth middleware can route resolution. Throws if signature,
   * issuer, or audience don't match any of the recognized envelopes.
   */
  async verifyAccessOrSession(token: string): Promise<{
    aud: typeof SESSION_JWT_AUDIENCE | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_API | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_MCP;
    sub: string;
    payload: Record<string, unknown>;
  }> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    // verification accepts the legacy and RFC 8414 metadata issuers.
    // Signing stays on the legacy issuer until the release 2 cutover.
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: [deployment().passportIssuer, deployment().oauthIssuer, deployment().oauthMetadataIssuer],
      audience: [
        SESSION_JWT_AUDIENCE,
        OAUTH_ACCESS_TOKEN_AUDIENCE_API,
        OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
      ],
      algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    const aud = payload.aud as typeof SESSION_JWT_AUDIENCE | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_API | typeof OAUTH_ACCESS_TOKEN_AUDIENCE_MCP;
    return { aud, sub: payload.sub!, payload: payload as Record<string, unknown> };
  }

  // ─── OAuth consent handoff JWT ─────────────────────────────────────
  // Short-lived JWT (15 min, OAUTH_CONSENT_JWT_TTL_SECONDS) carrying the /oauth/authorize request from
  // the API to the dashboard consent page and back. Bound to a single
  // operator (sub) — the dashboard MUST verify the cookie session matches
  // sub before accepting the user's approval. This is a defense-in-depth
  // wrap around the cookie session, NOT a substitute for it.
  async signOAuthConsentToken(operatorId: string, claims: OAuthConsentClaims): Promise<string> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + OAUTH_CONSENT_JWT_TTL_SECONDS * 1000);
    return new SignJWT({ ...claims })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setIssuer(deployment().oauthIssuer)
      .setSubject(operatorId)
      .setAudience(OAUTH_CONSENT_JWT_AUDIENCE)
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .sign(this.privateKey);
  }

  // ─── Agent-signed request JWTs ───────────────────────────
  // The agent's SDK signs short-lived JWTs with the agent's own privkey
  // (generated locally, never crosses the network). The server verifies
  // against the stored pubkey for that agent_id. Replay protection +
  // operator lookup live in the auth middleware; this method does
  // signature + standard-claim verification only.
  //
  // Throws on: bad signature, wrong issuer, wrong audience, expired,
  // not-yet-valid, or TTL > AGENT_JWT_MAX_TTL_SECONDS.

  /**
   * Decode the JWT header + claims WITHOUT verifying the signature, so
   * the auth middleware can extract `sub` (agent_id) and look up the
   * pubkey from the agents table before verifying.
   *
   * Caller MUST verify with the resolved pubkey before trusting any
   * claim. Used to peek-then-verify; never as the verification step.
   */
  peekAgentJwt(token: string): { iss?: string; sub?: string; jti?: string; iat?: number; exp?: number } {
    return decodeJwt(token);
  }

  async verifyAgentJwt(
    token: string,
    pubkey: JWK,
  ): Promise<{ sub: string; jti: string; exp: number; iat: number; nonce?: string }> {
    const key = await importJWK(pubkey, 'EdDSA');
    const { payload } = await jwtVerify(token, key as JoseKey, {
      issuer: AGENT_JWT_ISSUER,
      audience: AGENT_JWT_AUDIENCE,
      algorithms: ['EdDSA'],
      clockTolerance: AGENT_JWT_CLOCK_TOLERANCE_SECONDS,
    });
    // A token the agent signed badly is a refused credential (a JOSE claim failure, so the auth path
    // answers 401), never an infrastructure failure (503).
    if (!payload.exp || !payload.iat) {
      throw new joseErrors.JWTClaimValidationFailed('agent JWT missing iat/exp', payload, 'iat', 'missing');
    }
    if (payload.exp - payload.iat > AGENT_JWT_MAX_TTL_SECONDS) {
      throw new joseErrors.JWTClaimValidationFailed(`agent JWT TTL exceeds max ${AGENT_JWT_MAX_TTL_SECONDS}s`, payload, 'exp', 'ttl_exceeded');
    }
    // A token is only as long-lived as its lifetime allows: one dated ahead of this clock would be
    // acceptable for longer than the limit above says, and the replay memory would not cover it.
    if (payload.iat > Math.floor(Date.now() / 1000) + AGENT_JWT_CLOCK_TOLERANCE_SECONDS) {
      throw new joseErrors.JWTClaimValidationFailed('agent JWT issued in the future', payload, 'iat', 'future');
    }
    return {
      sub: payload.sub!,
      jti: payload.jti!,
      exp: payload.exp,
      iat: payload.iat,
      nonce: payload['nonce'] as string | undefined,
    };
  }

  // ─── SDK enrollment ticket ───────────────────────────────
  // Minted by the dashboard when an operator approves an SDK agent
  // enrollment in the browser. Single-use bearer for /enrollment-
  // challenge + /enroll, bound to one (operator, member, agent). Burned
  // by the auth middleware on /enroll success via Redis jti.
  //
  // The ticket replaces the OAuth-bearer-silent enrollment path for
  // interactive (TTY) SDK runs. Headless/CI runs still use the OAuth
  // bearer directly — both paths land at the same enrollment routes,
  // and the route handlers don't care which one authenticated.
  async signEnrollmentTicket(args: {
    operatorId: string;
    memberId: string | null;
    agentId: string;
    machineLabel: string | null;
  }): Promise<{ token: string; jti: string; expiresAt: Date }> {
    if (!this.privateKey) throw new Error('Signer not initialized');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ENROLLMENT_TICKET_TTL_SECONDS * 1000);
    // jti is the burn-key in Redis on enroll success — single-use.
    const jti = `ent_${now.getTime()}_${Math.random().toString(36).slice(2, 14)}`;
    const token = await new SignJWT({
      agent_id: args.agentId,
      member_id: args.memberId,
      machine_label: args.machineLabel,
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid })
      .setIssuer(deployment().oauthIssuer)
      .setSubject(args.operatorId)
      .setAudience(ENROLLMENT_TICKET_AUDIENCE)
      .setIssuedAt(now)
      .setExpirationTime(expiresAt)
      .setJti(jti)
      .sign(this.privateKey);
    return { token, jti, expiresAt };
  }

  async verifyEnrollmentTicket(token: string): Promise<{
    operator_id: string;
    member_id: string | null;
    agent_id: string;
    machine_label: string | null;
    jti: string;
    exp: number;
  }> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: [deployment().oauthIssuer, deployment().oauthMetadataIssuer],
      audience: ENROLLMENT_TICKET_AUDIENCE,
      algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    return {
      operator_id: payload.sub!,
      member_id: (payload['member_id'] as string | null | undefined) ?? null,
      agent_id: payload['agent_id'] as string,
      machine_label: (payload['machine_label'] as string | null | undefined) ?? null,
      jti: payload.jti!,
      exp: payload.exp!,
    };
  }

  async verifyOAuthConsentToken(token: string): Promise<{ sub: string; claims: OAuthConsentClaims }> {
    if (!this.publicKey) throw new Error('Signer not initialized');
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: [deployment().oauthIssuer, deployment().oauthMetadataIssuer],
      audience: OAUTH_CONSENT_JWT_AUDIENCE,
      algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    return {
      sub: payload.sub!,
      claims: {
        client_id: payload['client_id'] as string,
        redirect_uri: payload['redirect_uri'] as string,
        scope: payload['scope'] as string,
        resource: payload['resource'] as string,
        code_challenge: payload['code_challenge'] as string,
        code_challenge_method: payload['code_challenge_method'] as string,
        state: payload['state'] as string,
        nonce: payload['nonce'] as string | undefined,
        member_id: payload['member_id'] as string | undefined,
      },
    };
  }
}
