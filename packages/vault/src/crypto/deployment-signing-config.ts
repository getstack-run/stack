import { createHash, createPublicKey } from 'node:crypto';
import type { JWK } from 'jose';

export type DeploymentPublicJwk = JWK;

export const LEGACY_DEPLOYMENT_SIGNING_KID = 'stack-passport-v1';
export const MAX_TRUSTED_HISTORICAL_DEPLOYMENT_KEYS = 16;

const DEPLOYMENT_KID_PATTERN = /^stack-passport-v[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface DeploymentSigningConfig {
  kid: string;
  trustedHistoricalPublicJwks: JWK[];
}

export function publicJwkThumbprint(jwk: JWK): string {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('deployment verification keys must be Ed25519 public JWKs');
  }
  if (!BASE64URL_PATTERN.test(jwk.x)) {
    throw new Error('deployment verification key x must be base64url');
  }
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash('sha256').update(canonical).digest('base64url');
}

export function dedupePublicJwksByThumbprint(jwks: readonly JWK[]): JWK[] {
  const unique = new Map<string, JWK>();
  for (const jwk of jwks) {
    const thumbprint = publicJwkThumbprint(jwk);
    if (!unique.has(thumbprint)) unique.set(thumbprint, jwk);
  }
  return [...unique.values()];
}

export function validateDeploymentSigningKid(kid: string, source: string): string {
  if (!DEPLOYMENT_KID_PATTERN.test(kid)) {
    throw new Error(
      `${source} must start with 'stack-passport-v' and contain only deployment-safe characters`,
    );
  }
  return kid;
}

function validateTrustedDeploymentJwk(value: unknown, index: number): JWK {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`trusted deployment JWKS key ${index} must be an object`);
  }
  const jwk = value as JWK;
  if ('d' in jwk) {
    throw new Error(`trusted deployment JWKS key ${index} must not contain private key material`);
  }
  if (typeof jwk.kid !== 'string') {
    throw new Error(`trusted deployment JWKS key ${index} must contain kid`);
  }
  validateDeploymentSigningKid(jwk.kid, `trusted deployment JWKS key ${index} kid`);
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error(`trusted deployment JWKS key ${index} must be an Ed25519 public JWK`);
  }
  if (jwk.alg !== 'EdDSA' || jwk.use !== 'sig') {
    throw new Error(`trusted deployment JWKS key ${index} must declare alg=EdDSA and use=sig`);
  }
  publicJwkThumbprint(jwk);
  try {
    createPublicKey({ key: jwk as import('node:crypto').JsonWebKey, format: 'jwk' });
  } catch {
    throw new Error(`trusted deployment JWKS key ${index} is not a usable Ed25519 public key`);
  }
  return jwk;
}

export function parseTrustedDeploymentJwks(raw: string | undefined): JWK[] {
  if (!raw?.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON must contain valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON must contain a JWKS object');
  }
  const keys = (parsed as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) {
    throw new Error('TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON must contain a keys array');
  }
  if (keys.length > MAX_TRUSTED_HISTORICAL_DEPLOYMENT_KEYS) {
    throw new Error(
      `TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON must contain at most ${MAX_TRUSTED_HISTORICAL_DEPLOYMENT_KEYS} keys`,
    );
  }

  const byThumbprint = new Map<string, JWK>();
  for (const [index, value] of keys.entries()) {
    const jwk = validateTrustedDeploymentJwk(value, index);
    const thumbprint = publicJwkThumbprint(jwk);
    const existing = byThumbprint.get(thumbprint);
    if (existing?.kid && existing.kid !== jwk.kid) {
      throw new Error(
        `trusted deployment JWKS reuses one public key under kids '${existing.kid}' and '${jwk.kid}'`,
      );
    }
    if (!existing) byThumbprint.set(thumbprint, jwk);
  }
  return [...byThumbprint.values()];
}

export function readDeploymentSigningConfig(
  environment: {
    DEPLOYMENT_SIGNING_KID?: string;
    TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON?: string;
  },
): DeploymentSigningConfig {
  const configuredKid = environment['DEPLOYMENT_SIGNING_KID']?.trim();
  return {
    kid: validateDeploymentSigningKid(
      configuredKid || LEGACY_DEPLOYMENT_SIGNING_KID,
      'DEPLOYMENT_SIGNING_KID',
    ),
    trustedHistoricalPublicJwks: parseTrustedDeploymentJwks(
      environment['TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON'],
    ),
  };
}

export function deploymentJwkCandidates(
  kid: string,
  current: JWK,
  historical: readonly JWK[],
): JWK[] {
  if (!DEPLOYMENT_KID_PATTERN.test(kid)) return [];
  return dedupePublicJwksByThumbprint(
    [current, ...historical].filter((jwk) => jwk.kid === kid),
  );
}
