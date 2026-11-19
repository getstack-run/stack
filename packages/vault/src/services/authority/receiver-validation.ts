/** Validation of receiver endpoints, keys and token lifetimes. */
import type { JWK } from 'jose';
import {
  ForbiddenError,
  assertPublicUrl,
  isBlockedIp,
  type AddAuthorityReceiverKeyInput,
} from '@stack/shared';
import { lookup } from 'node:dns/promises';
import type { AuthorityReceiverKeyRecord } from './records.js';
import { sha256 } from './digest.js';

export async function validatePublicHttpsEndpoint(
  raw: string,
): Promise<{ normalized: string; addresses: string[] }> {
  let url: URL;
  try {
    url = await assertPublicUrl(raw, { allowedProtocols: ['https:'] });
  } catch {
    throw new ForbiddenError('receiver delivery endpoint is not a public HTTPS URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new ForbiddenError(
      'receiver delivery endpoint must be credential-free HTTPS without a fragment',
    );
  }
  url.hostname = url.hostname.toLowerCase();
  const addresses = [
    ...new Set(
      (await lookup(url.hostname, { all: true, verbatim: true })).map((item) => item.address),
    ),
  ];
  if (addresses.length === 0 || addresses.some(isBlockedIp)) {
    throw new ForbiddenError('receiver delivery endpoint resolves to a non-public address');
  }
  return { normalized: url.toString(), addresses };
}

export function assertPublicReceiverJwk(input: AddAuthorityReceiverKeyInput): void {
  const jwk = input.public_jwk as JWK;
  for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    if ((jwk as Record<string, unknown>)[secret] !== undefined)
      throw new ForbiddenError('receiver keys must be public asymmetric JWKs');
  }
  const compatible =
    (input.algorithm === 'EdDSA' && jwk.kty === 'OKP' && jwk.crv === 'Ed25519') ||
    (input.algorithm === 'ES256' && jwk.kty === 'EC' && jwk.crv === 'P-256') ||
    (input.algorithm === 'ECDH-ES+A256KW' && jwk.kty === 'EC' && jwk.crv === 'P-256');
  if (!compatible)
    throw new ForbiddenError('receiver key type does not match its declared algorithm');
}

export function receiverJwkThumbprint(jwk: JWK): string {
  let canonical: Record<string, unknown>;
  if (jwk.kty === 'OKP') canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  else if (jwk.kty === 'EC') canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  else if (jwk.kty === 'RSA') canonical = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  else throw new ForbiddenError('unsupported receiver JWK type');
  return sha256(JSON.stringify(canonical));
}

export function assertBoundedJwtLifetime(
  issuedAt: number,
  expiresAt: number,
  now: Date,
  maximumAgeSeconds: number,
  label: string,
): void {
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (
    !Number.isInteger(issuedAt) ||
    !Number.isInteger(expiresAt) ||
    !Number.isInteger(maximumAgeSeconds) ||
    maximumAgeSeconds <= 0 ||
    issuedAt > nowSeconds + AUTHORITY_CLOCK_TOLERANCE_SECONDS ||
    issuedAt < nowSeconds - maximumAgeSeconds ||
    expiresAt <= nowSeconds ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > maximumAgeSeconds
  ) {
    throw new ForbiddenError(`${label} lifetime is invalid`);
  }
}

export function assertReceiverKeyUsable(
  key: AuthorityReceiverKeyRecord | null,
  now: Date,
  algorithm: string,
): asserts key is AuthorityReceiverKeyRecord {
  if (
    !key ||
    key.status !== 'active' ||
    key.algorithm !== algorithm ||
    key.valid_from > now ||
    (key.valid_until && key.valid_until <= now)
  ) {
    throw new ForbiddenError('receiver key is unavailable, expired, or incompatible');
  }
}

/**
 * The lifetimes and tolerances of the authority receiver protocol. They are the
 * numbers spec/authority-receiver/SPEC.md publishes (scripts/generate-spec.mjs
 * reads them from here), so a receiver implementing the specification and the
 * checks above agree.
 */
export const AUTHORITY_CLOCK_TOLERANCE_SECONDS = 5;
/** The most a receiver's per-call assertion may live (a receiver profile may ask for less). */
export const AUTHORITY_ASSERTION_MAX_SECONDS = 60;
/** The most a signed presentation request, and the agent proof and presentation that answer it, may live. */
export const AUTHORITY_PRESENTATION_MAX_SECONDS = 120;
/** The most a receipt may live. */
export const AUTHORITY_RECEIPT_MAX_SECONDS = 60;
/** How long an origin verification challenge stays valid. */
export const AUTHORITY_VERIFICATION_CHALLENGE_SECONDS = 300;
