// A reference acceptor of a workload identity token (spec/workload-identity/SPEC.md, section 4, steps 1, 2, 4 and 5),
// written from the specification with nothing but node:crypto. It is the worked example the `workload-token` suite
// runs against in CI.

import { constants, createPublicKey, verify } from 'node:crypto';

const SPIFFE_ID = /^spiffe:\/\/([^/]+)(\/.*)?$/;

class Refusal extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/** The algorithm a key gives: its own `alg`, else the one its type implies. */
function algorithmOf(jwk) {
  if (jwk.alg) return jwk.alg;
  if (jwk.kty === 'EC') return { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' }[jwk.crv];
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  if (jwk.kty === 'RSA') return 'RS256';
  return undefined;
}

const SHA = { 256: 'sha256', 384: 'sha384', 512: 'sha512' };

/** Verify one JWS signature with a public key, for the asymmetric algorithms of the specification only. */
function signatureVerifies(alg, input, signature, jwk) {
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const bits = alg.slice(-3);
  if (alg === 'EdDSA') return verify(null, input, key, signature);
  if (alg.startsWith('ES')) return verify(SHA[bits], input, { key, dsaEncoding: 'ieee-p1363' }, signature);
  if (alg.startsWith('RS')) return verify(SHA[bits], input, key, signature);
  if (alg.startsWith('PS')) return verify(SHA[bits], input, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }, signature);
  return false;
}

const ASYMMETRIC = new Set(['ES256', 'ES384', 'ES512', 'EdDSA', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

export async function accept({ kind, token, config, jwks, now = () => Math.floor(Date.now() / 1000) }) {
  // 1. Decode.
  const parts = typeof token === 'string' ? token.split('.') : [];
  let header;
  let claims;
  try {
    if (parts.length !== 3) throw new Error('parts');
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new Error('payload');
  } catch {
    throw new Refusal('malformed_jwt', 'not a compact JWS with a JSON payload');
  }
  // 2. Identity claims.
  if (kind === 'spiffe') {
    const match = typeof claims.sub === 'string' ? SPIFFE_ID.exec(claims.sub) : null;
    if (!match) throw new Refusal('invalid_spiffe_id', 'sub is not a SPIFFE id');
    if (match[1] !== config.trust_domain) throw new Refusal('trust_domain_mismatch', 'another trust domain');
  } else {
    if (typeof claims.iss !== 'string' || !claims.iss) throw new Refusal('missing_iss', 'no iss');
    if (claims.iss !== config.issuer_uri) throw new Refusal('issuer_mismatch', 'another issuer');
    if (typeof claims.sub !== 'string' || !claims.sub) throw new Refusal('missing_sub', 'no sub');
  }
  // 4. The key, and only the algorithm it gives.
  if (typeof header?.kid !== 'string' || !header.kid) throw new Refusal('missing_kid', 'no kid');
  const jwk = (jwks?.keys ?? []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Refusal('unknown_kid', 'no key under the kid');
  const alg = algorithmOf(jwk);
  if (!alg || !ASYMMETRIC.has(alg)) throw new Refusal('verify_failed', 'the key gives no asymmetric algorithm');
  if (header.alg !== alg) throw new Refusal('verify_failed', 'the token\'s algorithm is not the key\'s');
  // 5. Signature, then claims.
  let ok;
  try {
    ok = signatureVerifies(alg, Buffer.from(`${parts[0]}.${parts[1]}`), Buffer.from(parts[2], 'base64url'), jwk);
  } catch {
    ok = false;
  }
  if (!ok) throw new Refusal('signature_invalid', 'the signature does not verify');
  const t = now();
  if (typeof claims.exp !== 'number' || claims.exp <= t) throw new Refusal('expired', 'expired or no exp');
  if (typeof claims.nbf === 'number' && claims.nbf > t) throw new Refusal('verify_failed', 'not valid yet');
  if (config.audience) {
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(config.audience)) throw new Refusal('audience_mismatch', 'another audience');
  }
  return {
    subject: claims.sub,
    issuer: typeof claims.iss === 'string' ? claims.iss : '',
    ...(typeof claims.aud === 'string' ? { audience: claims.aud } : {}),
    not_after: claims.exp,
  };
}
