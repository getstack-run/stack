import { jwtVerify, createRemoteJWKSet, importJWK, type JWK } from 'jose';
import type { AuthorityReference } from './types.js';

/**
 * Decoded claims returned on successful offline verification. Shape
 * matches the JWT issued by `@stack/api`, namespaced under `stk`.
 */
export interface VerifiedPassportClaims {
  jti: string;
  sub: string;
  iss: string;
  aud: string | string[];
  iat: number;
  exp: number;
  stk: {
    operator_id: string;
    agent_id: string;
    agent_name: string;
    services: Array<{
      service_id: string;
      service_name: string;
      scopes: string[];
      credential_ref: string;
      /** Canonical connection id (`scon_*`). Optional only on tokens issued before this field landed. */
      connection_id?: string;
      constraints?: unknown;
    }>;
    identity_claims: unknown[];
    delegation_depth: number;
    parent_passport_id?: string;
    session_id: string;
    accountability?: 'enforced' | 'logged' | 'standard';
    intent_summary?: string;
    intent_services?: string[];
    checkpoint_interval?: number;
    /** Opaque, PII-free references to active authority bindings. */
    authority_refs?: AuthorityReference[];
  };
}

export interface VerifyOfflineOptions {
  /**
   * JWKS source. Exactly one of:
   *   - `jwksUrl`   — a URL to `/v1/.well-known/jwks.json`; keys are
   *                   fetched once and cached per process.
   *   - `publicJwk` — a pre-fetched public key for fully air-gapped
   *                   verification (no network at verify time, ever).
   */
  jwksUrl?: string;
  publicJwk?: JWK;
  /**
   * Expected token issuer. Defaults to the STACK issuer used by the
   * reference API (`getstack.run`). Override if you run a self-hosted
   * deployment.
   */
  issuer?: string;
  /** Expected audience. Defaults to the passport audience. */
  audience?: string;
}

const DEFAULT_ISSUER = 'getstack.run';
const DEFAULT_AUDIENCE = 'stack:passport';

// Cache remote JWKS resolvers per URL so repeat verifies share the key cache.
const remoteJwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getRemoteJwks(url: string) {
  let cached = remoteJwksCache.get(url);
  if (!cached) {
    cached = createRemoteJWKSet(new URL(url));
    remoteJwksCache.set(url, cached);
  }
  return cached;
}

/**
 * Verify a STACK passport using only the public signing key.
 *
 * This function never calls the STACK API for revocation, freshness, or
 * any other status. It is strictly cryptographic: signature, issuer,
 * audience, and expiry.
 *
 * For downstream services that need to reject revoked passports, combine
 * this with a short-window cache against `/v1/passports/verify` (which
 * does consult the revocation store). This split lets high-frequency
 * paths stay offline while still honoring explicit revocations.
 *
 * @throws on any failure — invalid signature, wrong issuer/audience,
 * expired, or malformed JWT. The caller should treat any throw as a
 * rejected passport.
 */
export async function verifyPassportOffline(
  token: string,
  options: VerifyOfflineOptions,
): Promise<VerifiedPassportClaims> {
  if (!options.jwksUrl && !options.publicJwk) {
    throw new Error('verifyPassportOffline: supply either jwksUrl or publicJwk');
  }
  if (options.jwksUrl && options.publicJwk) {
    throw new Error('verifyPassportOffline: pass only one of jwksUrl or publicJwk');
  }

  const verifyOpts = {
    issuer: options.issuer ?? DEFAULT_ISSUER,
    audience: options.audience ?? DEFAULT_AUDIENCE,
    algorithms: ['EdDSA'],
  };

  // Split the call so each overload resolves cleanly. jwtVerify has
  // separate signatures for a static key vs a GetKey function, and the
  // union of the two doesn't narrow in a single call site.
  const { payload } = options.publicJwk
    ? await jwtVerify(token, await importJWK(options.publicJwk, 'EdDSA'), verifyOpts)
    : await jwtVerify(token, getRemoteJwks(options.jwksUrl!), verifyOpts);

  if (!payload.jti || !payload.sub || !payload.iss || !payload.aud
    || typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
    throw new Error('verifyPassportOffline: token missing required claims');
  }

  const stk = parseStackClaims(payload['stk']);
  if (payload.sub !== stk.agent_id) {
    throw new Error('verifyPassportOffline: sub must match stk.agent_id');
  }

  return {
    jti: payload.jti,
    sub: payload.sub,
    iss: payload.iss,
    aud: payload.aud,
    iat: payload.iat!,
    exp: payload.exp!,
    stk,
  };
}

function parseStackClaims(value: unknown): VerifiedPassportClaims['stk'] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('verifyPassportOffline: token missing stk claims');
  }
  const stk = value as Record<string, unknown>;
  if (typeof stk['operator_id'] !== 'string' || typeof stk['agent_id'] !== 'string') {
    throw new Error('verifyPassportOffline: token missing authority principal claims');
  }
  if (!Array.isArray(stk['services']) || !Array.isArray(stk['identity_claims'])) {
    throw new Error('verifyPassportOffline: malformed stk claims');
  }
  if (stk['authority_refs'] !== undefined) {
    if (!Array.isArray(stk['authority_refs']) || stk['authority_refs'].length > 8) {
      throw new Error('verifyPassportOffline: malformed authority_refs');
    }
    for (const ref of stk['authority_refs']) assertAuthorityReference(ref);
  }
  return value as VerifiedPassportClaims['stk'];
}

function assertAuthorityReference(value: unknown): asserts value is AuthorityReference {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('verifyPassportOffline: malformed authority_ref');
  }
  const ref = value as Record<string, unknown>;
  const strings = [
    'binding_id',
    'binding_claim_id',
    'binding_digest',
    'receiver_id',
    'receiver_profile_version_id',
  ];
  if (strings.some((key) => typeof ref[key] !== 'string')
    || !/^abn_[\w-]+$/.test(String(ref['binding_id']))
    || !/^pc_[\w-]+$/.test(String(ref['binding_claim_id']))
    || !/^sha256:[0-9a-f]{64}$/.test(String(ref['binding_digest']))
    || !/^rcv_[\w-]+$/.test(String(ref['receiver_id']))
    || !/^apv_[\w-]+$/.test(String(ref['receiver_profile_version_id']))
    || typeof ref['binding_version'] !== 'number'
    || !Number.isInteger(ref['binding_version'])
    || ref['binding_version'] < 1
    || typeof ref['expires_at'] !== 'number'
    || !Number.isInteger(ref['expires_at'])
    || ref['expires_at'] < 0) {
    throw new Error('verifyPassportOffline: malformed authority_ref');
  }
}
