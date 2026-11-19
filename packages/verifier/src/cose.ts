/**
 * Minimal COSE_Sign1 decoder + verifier per RFC 9052 §4.2.
 *
 * Mirrors the production-side signer in
 * `@stack/vault/src/crypto/claim-signer.ts` — same wire format, same
 * Ed25519 verification path via Node `crypto.verify`. Duplicated
 * here intentionally so this package has zero STACK runtime deps.
 *
 * COSE_Sign1 message shape: `[protected, unprotected, payload, signature]`
 * where:
 *   - `protected` is a CBOR-encoded map containing alg (-8 for EdDSA),
 *     kid (UTF-8 bytes), and a content-type label.
 *   - `unprotected` is a CBOR map (always empty in v1).
 *   - `payload` is the CBOR-encoded ClaimEnvelope bytes.
 *   - `signature` is the Ed25519 signature over Sig_structure1.
 *
 * Sig_structure1 per RFC 9052 §4.4 is built as
 * `["Signature1", protected_bytes, external_aad (empty), payload_bytes]`
 * then CBOR-encoded and signed. The verifier reconstructs this and
 * runs `crypto.verify(null, ...)` against the resolved public key.
 */

import * as nodeCrypto from 'node:crypto';
import { decode as cborDecode, encode as cborEncode } from 'cbor-x';

// ─── COSE constants per RFC 9052 / 9053 ─────────────────────────────

const COSE_ALG_EDDSA = -8;
const COSE_HEADER_ALG = 1;
const COSE_HEADER_KID = 4;
const SIG_STRUCTURE_CONTEXT = 'Signature1';

// ─── Public types ───────────────────────────────────────────────────

/** Minimal JWK shape — matches RFC 7517 + Ed25519 (RFC 8037 OKP). */
export interface JwkLike {
  kty: string;
  kid?: string;
  crv?: string;
  x?: string; // Ed25519 public key, base64url
  [key: string]: unknown;
}

export interface CoseDecodeResult {
  kid: string;
  alg: number;
  protectedBytes: Buffer;
  payloadBytes: Buffer;
  signatureBytes: Buffer;
  /** Decoded payload assumed to be CBOR-encoded ClaimEnvelope. */
  envelope: Record<string, unknown>;
}

export interface CoseVerifyOptions {
  /**
   * Resolver that maps a kid to its JWK. Verifier orchestrator wires
   * inline JWKS first; only falls back to URL fetch when explicitly
   * opted in via the `--fresh-jwks` flag.
   */
  resolveJwk: (kid: string) => Promise<JwkLike | readonly JwkLike[] | null>;
}

// ─── Implementation ─────────────────────────────────────────────────

/**
 * Decode a base64url-encoded COSE_Sign1 message into its four
 * structural parts. Throws on malformed input.
 */
export function decodeCoseSign1(base64UrlCose: string): CoseDecodeResult {
  const coseBytes = Buffer.from(base64UrlCose, 'base64url');
  const cose = cborDecode(coseBytes) as unknown;
  if (!Array.isArray(cose) || cose.length !== 4) {
    throw new Error('invalid COSE_Sign1 structure (expected 4-element CBOR array)');
  }
  const [protectedBytes, _unprotected, payloadBytes, signatureBytes] = cose as [
    Uint8Array,
    unknown,
    Uint8Array,
    Uint8Array,
  ];
  if (!(protectedBytes instanceof Uint8Array)) {
    throw new Error('COSE_Sign1 protected header is not bytes');
  }
  if (!(payloadBytes instanceof Uint8Array)) {
    throw new Error('COSE_Sign1 payload is not bytes');
  }
  if (!(signatureBytes instanceof Uint8Array)) {
    throw new Error('COSE_Sign1 signature is not bytes');
  }
  const protectedMap = cborDecode(Buffer.from(protectedBytes)) as Map<number, unknown>;
  if (!(protectedMap instanceof Map)) {
    throw new Error('COSE_Sign1 protected header is not a CBOR map');
  }
  const alg = protectedMap.get(COSE_HEADER_ALG);
  if (alg !== COSE_ALG_EDDSA) {
    throw new Error(`unsupported alg ${String(alg)} (only EdDSA / -8 supported in v1)`);
  }
  const kidRaw = protectedMap.get(COSE_HEADER_KID);
  const kid =
    kidRaw instanceof Uint8Array
      ? Buffer.from(kidRaw).toString('utf8')
      : typeof kidRaw === 'string'
        ? kidRaw
        : null;
  if (!kid) {
    throw new Error('COSE_Sign1 protected header missing kid');
  }
  const envelope = cborDecode(Buffer.from(payloadBytes)) as Record<string, unknown>;

  return {
    kid,
    alg: alg as number,
    protectedBytes: Buffer.from(protectedBytes),
    payloadBytes: Buffer.from(payloadBytes),
    signatureBytes: Buffer.from(signatureBytes),
    envelope,
  };
}

/**
 * Verify the COSE_Sign1 signature against a resolved JWK. Returns
 * `{valid, error?}`. Does NOT throw on signature mismatch; the
 * caller decides how to surface the result.
 */
export async function verifyCoseSign1(
  decoded: CoseDecodeResult,
  options: CoseVerifyOptions,
): Promise<{ valid: boolean; error?: string }> {
  const resolved = await options.resolveJwk(decoded.kid);
  const candidates = resolved
    ? Array.isArray(resolved)
      ? resolved
      : [resolved as JwkLike]
    : [];
  if (candidates.length === 0) {
    return { valid: false, error: `no JWK resolved for kid '${decoded.kid}'` };
  }

  // Build Sig_structure1 per RFC 9052 §4.4 and CBOR-encode.
  const sigStructure = [
    SIG_STRUCTURE_CONTEXT,
    decoded.protectedBytes,
    Buffer.alloc(0),
    decoded.payloadBytes,
  ];
  const sigStructureBytes = cborEncode(sigStructure);

  const unique = new Map<string, JwkLike>();
  for (const jwk of candidates) {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
      return {
        valid: false,
        error: `JWK candidate for kid '${decoded.kid}' is not a public Ed25519 OKP key`,
      };
    }
    if (typeof jwk['d'] === 'string') {
      return { valid: false, error: 'private key material is forbidden in verification JWKS' };
    }
    if (jwk.kid !== undefined && jwk.kid !== decoded.kid) {
      return {
        valid: false,
        error: `JWK candidate kid '${jwk.kid}' does not match '${decoded.kid}'`,
      };
    }
    if (jwk['alg'] !== undefined && jwk['alg'] !== 'EdDSA') {
      return { valid: false, error: 'JWK candidate alg must be EdDSA' };
    }
    if (jwk['use'] !== undefined && jwk['use'] !== 'sig') {
      return { valid: false, error: 'JWK candidate use must be sig' };
    }
    const thumbprint = nodeCrypto
      .createHash('sha256')
      .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }), 'utf8')
      .digest('base64url');
    if (!unique.has(thumbprint)) unique.set(thumbprint, jwk);
  }

  const matches: string[] = [];
  for (const [thumbprint, jwk] of unique) {
    let publicKey: nodeCrypto.KeyObject;
    try {
      publicKey = nodeCrypto.createPublicKey({
        key: jwk as nodeCrypto.JsonWebKey,
        format: 'jwk',
      });
    } catch (err) {
      return {
        valid: false,
        error: `failed to import JWK for kid '${decoded.kid}': ${(err as Error).message}`,
      };
    }

    try {
      if (nodeCrypto.verify(null, sigStructureBytes, publicKey, decoded.signatureBytes)) {
        matches.push(thumbprint);
      }
    } catch (err) {
      return {
        valid: false,
        error: `crypto.verify threw: ${(err as Error).message}`,
      };
    }
  }

  if (matches.length === 1) return { valid: true };
  if (matches.length > 1) {
    return {
      valid: false,
      error: `ambiguous signature verification: ${matches.length} distinct trusted keys verified`,
    };
  }
  return {
    valid: false,
    error:
      unique.size === 1
        ? 'signature verification failed'
        : 'no trusted key candidate verified signature',
  };
}

/**
 * Verify a detached Ed25519 signature over arbitrary bytes. Used for
 * `audit_chain_anchor.head_signature` which is a plain raw signature
 * (not COSE-wrapped) over the canonical-JSON of the (head_hash +
 * timestamps) tuple. Same resolver shape as `verifyCoseSign1`.
 */
export async function verifyDetachedEd25519(
  data: Buffer,
  signatureBase64Url: string,
  jwk: JwkLike,
): Promise<{ valid: boolean; error?: string }> {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    return {
      valid: false,
      error: `JWK is not Ed25519 OKP (kty=${jwk.kty}, crv=${String(jwk.crv ?? '?')})`,
    };
  }
  let publicKey: nodeCrypto.KeyObject;
  try {
    publicKey = nodeCrypto.createPublicKey({
      key: jwk as nodeCrypto.JsonWebKey,
      format: 'jwk',
    });
  } catch (err) {
    return { valid: false, error: `failed to import JWK: ${(err as Error).message}` };
  }
  const signature = Buffer.from(signatureBase64Url, 'base64url');
  try {
    const ok = nodeCrypto.verify(null, data, publicKey, signature);
    return ok ? { valid: true } : { valid: false, error: 'signature verification failed' };
  } catch (err) {
    return { valid: false, error: `crypto.verify threw: ${(err as Error).message}` };
  }
}
