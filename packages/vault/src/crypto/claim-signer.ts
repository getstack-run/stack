/**
 * COSE_Sign1 producer + verifier for claim envelopes.
 *
 * Part of the Signed Primitive epic. See
 * the claims registry design design decision Q1 for
 * the wire-format rationale (COSE-canonical to match SCITT
 * conformance, not a JWS-with-COSE-serializer afterthought).
 *
 * The signer wraps a `ClaimEnvelope` Zod object into a COSE_Sign1
 * message per RFC 9052 §4.2. Output is the base64url-encoded
 * CBOR-encoded COSE_Sign1 bytes, stored in `passport_claims.envelope_cose`.
 *
 * Signing-algorithm-pluggable from day one. v1 ships EdDSA (Ed25519,
 * COSE alg label -8 per RFC 9053 §2.2). The `alg` parameter is the
 * extension point for ML-DSA-65 (NIST FIPS 204) when the COSE/JOSE
 * draft for post-quantum signatures lands at RFC.
 *
 * Why we own this instead of using @auth0/cose or cose-js:
 * - @auth0/cose was published April 2024 across three quick versions
 *   then went silent. auth0-lab projects routinely get abandoned.
 *   Adding a stale transitive-dep tree (pkijs + cbor-x + peculiar/
 *   webcrypto + typedmap) for a ~150-line implementation is the
 *   wrong tradeoff.
 * - cose-js last published 2023-09. Also stale.
 * - COSE_Sign1 is a small, fully-spec-defined structure. Owning the
 *   implementation removes ecosystem-lifecycle risk and lets us
 *   evolve to ML-DSA without waiting on upstream maintainers.
 *
 * Direct deps: `cbor-x` (RFC 8949 CBOR, actively maintained) + Node's
 * built-in `crypto.sign('Ed25519', ...)`. No new transitive trees.
 */
import * as nodeCrypto from 'node:crypto';
import { encode as cborEncode, decode as cborDecode } from 'cbor-x';
import type { JWK } from 'jose';
import type { ClaimEnvelope, CoSignature } from '@stack/shared';
import {
  dedupePublicJwksByThumbprint,
  publicJwkThumbprint,
} from './deployment-signing-config.js';

export {
  parseTrustedDeploymentJwks,
  publicJwkThumbprint,
} from './deployment-signing-config.js';

// ─── COSE constants per RFC 9052 / 9053 ─────────────────────────────

/** Algorithm identifier for EdDSA (Ed25519) — RFC 9053 §2.2. */
const COSE_ALG_EDDSA = -8;

/** Protected header label for `alg` — RFC 9052 §3.1. */
const COSE_HEADER_ALG = 1;
/** Protected header label for `kid`. */
const COSE_HEADER_KID = 4;
/** Protected header label for `typ` (content type). */
const COSE_HEADER_TYP = 16;

/** Stable media-type label for a STACK claim envelope. */
const STACK_CLAIM_TYP = 'stack/claim+cose';

/** Sig_structure1 context string — RFC 9052 §4.4. */
const SIG_STRUCTURE_CONTEXT = 'Signature1';

// ─── Public types ───────────────────────────────────────────────────

/**
 * Signing algorithms STACK's claim signer accepts. v1 = EdDSA only.
 * ML-DSA-65 is reserved for the post-quantum future per the ADR's
 * alg-pluggable-from-day-one decision.
 */
export type ClaimSignAlg = 'EdDSA' | 'ML-DSA-65';

export interface ClaimSignerOptions {
  /**
   * Signing key in JWK form. Caller (typically the bootstrap service
   * layer) loads this from the existing PassportSigner or directly
   * from the KMS-unwrapped key material. The claim signer does NOT
   * hold KMS credentials — same security posture as PassportSigner.
   */
  privateKeyJwk: JWK;
  /**
   * Key id matching an entry in the operator's JWKS. Embedded in the
   * COSE protected header so verifiers can look up the public key
   * without external lookup.
   */
  kid: string;
  /** Defaults to 'EdDSA'. ML-DSA-65 throws "not yet implemented" until the JOSE/COSE draft lands at RFC. */
  alg?: ClaimSignAlg;
}

export interface ClaimVerifyResult {
  valid: boolean;
  /** The decoded envelope. Present iff `valid === true`. */
  envelope?: ClaimEnvelope;
  /** The kid extracted from the COSE protected header. Present iff the bytes parsed as COSE_Sign1. */
  kid?: string;
  /** The COSE alg label from the protected header. */
  alg?: number;
  /** RFC 7638 thumbprint of the one distinct trusted key that verified the signature. */
  verified_key_thumbprint?: string;
  /** Failure detail when `valid === false`. */
  error?: string;
  /**
   * Per-co-signature verification results when co_signatures were
   * passed to verify(). One entry per input co-signature, in the
   * same order. `valid: true` overall requires the primary signature
   * + EVERY co_signature to verify; any co-signature failure marks
   * the overall result invalid.
   *
   * Empty array when no co_signatures were provided.
   */
  co_signature_results?: Array<{
    signer_kid: string;
    signer_role: CoSignature['signer_role'];
    valid: boolean;
    error?: string;
  }>;
}

export type ClaimJwksResolver = (
  kid: string,
) => Promise<JWK | readonly JWK[] | null>;

/**
 * Output of `ClaimSigner.coSign()` — a single co-signature ready to
 * attach to an envelope. Caller stores this alongside the primary
 * envelope_cose; it is NOT folded into envelope_cose bytes (those
 * stay immutable to preserve claim_hash for audit chain integrity).
 */
export type CoSignatureOutput = CoSignature;

// ─── ClaimSigner ────────────────────────────────────────────────────

/**
 * Produces + verifies COSE_Sign1 messages wrapping ClaimEnvelope
 * objects. One instance per operator (each operator's signing key is
 * separate; the signer holds operator-scoped state).
 */
export class ClaimSigner {
  private cachedPrivateKey: nodeCrypto.KeyObject | null = null;

  constructor(private readonly opts: ClaimSignerOptions) {
    const alg = opts.alg ?? 'EdDSA';
    if (alg !== 'EdDSA') {
      throw new Error(
        `ClaimSigner: algorithm '${alg}' is reserved but not yet implemented. ` +
          `Only 'EdDSA' is supported in v1. ML-DSA-65 ships when the JOSE/COSE ` +
          `post-quantum draft (draft-ietf-cose-dilithium) lands at RFC.`,
      );
    }
  }

  /**
   * The kid embedded in every COSE_Sign1 protected header this signer
   * produces. Verifiers pass this to their jwksResolver to locate the
   * matching pubkey. Exposed (instead of forcing callers to read
   * opts directly) so AgentSigner can wire dynamic resolvers for the
   * co_signed verify path.
   */
  getKid(): string {
    return this.opts.kid;
  }

  /**
   * The public half of this signer's keypair as a JWK. For Ed25519
   * OKP, this is the private JWK with the `d` (private scalar) field
   * stripped. Used by AgentSigner.verifyClaim to build a single
   * resolver covering both the agent's kid AND the operator's kid
   * without forcing callers to plumb the operator's JWKS through every
   * call site. Production callers SHOULD pass an explicit
   * operatorJwksResolver scoped to the operator's full key history,
   * but for dogfood + tests + first-key state, this getter is the
   * minimum-friction path.
   */
  getPublicJwk(): JWK {
    const { d: _d, ...rest } = this.opts.privateKeyJwk as JWK & { d?: string };
    return rest;
  }

  /**
   * Lazy-load the Node KeyObject from the JWK on first use. Caching
   * avoids re-parsing the JWK on every sign() call.
   */
  private async ensurePrivateKey(): Promise<nodeCrypto.KeyObject> {
    if (this.cachedPrivateKey) return this.cachedPrivateKey;
    this.cachedPrivateKey = nodeCrypto.createPrivateKey({
      key: this.opts.privateKeyJwk as nodeCrypto.JsonWebKey,
      format: 'jwk',
    });
    return this.cachedPrivateKey;
  }

  /**
   * Wrap a ClaimEnvelope in a COSE_Sign1 message and sign with EdDSA.
   * Returns the base64url-encoded message ready for storage in
   * `passport_claims.envelope_cose`.
   *
   * The returned bytes are the canonical signed artifact. Verifiers
   * MUST verify against these bytes, not against the envelope object,
   * because the signature is computed over the CBOR-encoded form.
   * Any field-order or whitespace difference in a JSON representation
   * of the envelope would produce a different signature.
   *
   * Co-signatures are SIGNED INDEPENDENTLY and stored alongside the
   * primary envelope_cose — they do NOT go into the bytes returned
   * here. Use `coSign()` to produce a co-signature given a primary
   * COSE_Sign1, then attach it to the envelope via
   * `ClaimRegistryService`.
   */
  async sign(envelope: ClaimEnvelope): Promise<string> {
    // CBOR-encode the envelope payload. Done once here so the
    // payload_bytes can be reused by co-signers (they sign the same
    // bytes; otherwise different CBOR encodings would yield different
    // signatures over the same logical payload).
    const payloadBytes = cborEncode(envelope);

    const privateKey = await this.ensurePrivateKey();
    return this.signPayloadBytes(payloadBytes, this.opts.kid, privateKey);
  }

  /**
   * Produce a co-signature on an existing primary COSE_Sign1. The
   * co-signer signs the SAME payload_bytes the primary signed,
   * producing a standalone COSE_Sign1 with their own kid in the
   * protected header.
   *
   * (ADR Design Decision 1). The
   * returned `CoSignature` is stored alongside the primary
 * envelope_cose by the caller (storage column lands
   * when co_signed mode actually fires). The primary
   * envelope_cose is NEVER modified — its claim_hash stays stable
   * for audit chain integrity.
   *
   * Throws if the primary COSE_Sign1 cannot be parsed (malformed
   * input). Does NOT verify the primary signature here — the caller
   * is expected to have already verified the primary before
   * co-signing (otherwise you'd be co-signing arbitrary bytes).
   *
   * @param primaryCoseBase64 The primary COSE_Sign1 to co-sign,
   *   as base64url-encoded bytes (the format produced by `sign()`).
   * @param role Why this co-signer is attaching their signature.
   *   See `CoSignature` semantic notes in envelope.ts.
   */
  async coSign(
    primaryCoseBase64: string,
    role: CoSignature['signer_role'],
  ): Promise<CoSignatureOutput> {
    const primaryBytes = Buffer.from(primaryCoseBase64, 'base64url');
    const primaryCose = cborDecode(primaryBytes) as unknown;

    if (!Array.isArray(primaryCose) || primaryCose.length !== 4) {
      throw new Error(
        'ClaimSigner.coSign: primary input is not a valid COSE_Sign1 (expected 4-element CBOR array)',
      );
    }

    // Extract payload_bytes from primary's [protected, unprotected, payload, signature].
    const payloadBytes = primaryCose[2] as Uint8Array;
    if (!(payloadBytes instanceof Uint8Array)) {
      throw new Error(
        'ClaimSigner.coSign: primary payload is not bytes — input may be malformed',
      );
    }

    const privateKey = await this.ensurePrivateKey();
    const coSignCose = await this.signPayloadBytes(
      Buffer.from(payloadBytes),
      this.opts.kid,
      privateKey,
    );

    return {
      signer_kid: this.opts.kid,
      signer_role: role,
      cose_sign1: coSignCose,
    };
  }

  /**
   * Sign arbitrary bytes with this signer's Ed25519 key. Returns the
   * raw signature, base64url-encoded.
   *
   * This is NOT a COSE_Sign1 — it produces a plain Ed25519 signature
   * for use cases that need a small detached signature outside the
   * envelope path. An earlier change uses it for
   * `EvidencePackClaim.audit_chain_anchor.head_signature` (attesting
   * the chain head hash + timestamp the pack was exported against)
   * and reuses it for the daily external chain-head
   * anchor commits to a public registry.
   *
   * Verifier reconstructs the signing surface by the producer-side
   * convention (e.g. canonical-JSON-of-tuple, then sign). The signer
   * does not impose a surface — caller decides what bytes to sign.
   */
  async signBytes(data: Buffer): Promise<string> {
    const privateKey = await this.ensurePrivateKey();
    const signature = nodeCrypto.sign(null, data, privateKey);
    return Buffer.from(signature).toString('base64url');
  }

  /**
   * Internal: produce a COSE_Sign1 over the given payload bytes with
   * the given kid + private key. Shared between sign() (primary) and
   * coSign() (additional signers) so both produce structurally
   * identical COSE_Sign1 messages that verify the same way.
   *
   * The two callers differ only in WHERE payload_bytes comes from:
   *   sign(envelope):           payload_bytes = cborEncode(envelope)
   *   coSign(primaryCose, ...): payload_bytes = extracted from primary
   *
   * Either way the same signing structure (Sig_structure1) is built
   * and signed.
   */
  private signPayloadBytes(
    payloadBytes: Uint8Array,
    kid: string,
    privateKey: nodeCrypto.KeyObject,
  ): string {
    // Build the protected header. COSE protected header is a CBOR-
    // encoded map (typically uint-keyed). Order matters for the bytes
    // BUT the verifier uses these bytes verbatim — they're the same
    // bytes that go into Sig_structure1 — so as long as we produce
    // them deterministically here, verification works.
    const protectedHeader = new Map<number, unknown>([
      [COSE_HEADER_ALG, COSE_ALG_EDDSA],
      [COSE_HEADER_KID, Buffer.from(kid, 'utf8')],
      [COSE_HEADER_TYP, STACK_CLAIM_TYP],
    ]);
    const protectedBytes = cborEncode(protectedHeader);

    // Sig_structure1 per RFC 9052 §4.4. Array form is canonical for
    // EdDSA Sign1.
    const sigStructure = [
      SIG_STRUCTURE_CONTEXT,
      protectedBytes,
      Buffer.alloc(0), // external_aad: empty (we don't use AAD)
      payloadBytes,
    ];
    const sigStructureBytes = cborEncode(sigStructure);

    // Ed25519 signing via Node's built-in crypto. The first arg is
    // the digest algorithm name; Node passes null/undefined for
    // Ed25519 because the algorithm has its own internal hashing.
    const signature = nodeCrypto.sign(null, sigStructureBytes, privateKey);

    // COSE_Sign1 = [protected, unprotected, payload, signature]
    // Unprotected header is empty in v1 (no fields that don't need
    // to be in the signature). Future: may put receipt
    // proofs here so receipts can be added post-signing without
    // invalidating the envelope's signature.
    const coseSign1 = [protectedBytes, new Map(), payloadBytes, signature];

    const coseBytes = cborEncode(coseSign1);
    return Buffer.from(coseBytes).toString('base64url');
  }

  /**
   * Static verify path. Decodes the COSE_Sign1, extracts the kid from
   * the protected header, fetches the public key via the resolver,
   * reconstructs Sig_structure1, and verifies the signature.
   *
   * The `jwksResolver` is a function the caller provides. Typically
   * it queries the operator's JWKS endpoint and returns the JWK
   * matching the requested kid. STACK's JWKS is exposed at
   * `https://api.getstack.run/.well-known/jwks.json` and indexed by
   * operator + kid; the resolver is what loads it.
   *
   * When `coSignatures` is provided, each
   * entry is verified INDEPENDENTLY against the same payload_bytes
   * as the primary. Verification flow per co-signature:
   *
   *   1. Decode the co-signature's standalone COSE_Sign1.
   *   2. Extract its kid from its own protected header.
   *   3. Assert the protected-header kid matches the
   *      `signer_kid` field on the CoSignature entry (defense
   *      against kid mismatch / spoofing).
   *   4. Resolve the co-signer's pubkey via the same jwksResolver.
   *   5. Reconstruct Sig_structure1 with the SAME payload_bytes the
   *      primary signed (extracted from the co-sig's own COSE_Sign1).
   *   6. Run nodeCrypto.verify against the co-signer's pubkey.
   *
   * Per-co-signature results are returned in `co_signature_results`.
   * Overall `valid: true` requires the primary AND every co-signature
   * to verify. Any co-signature failure marks the overall result
   * invalid — but the primary's status is still reported on its own
   * fields so the caller can distinguish "primary OK, co-sig bad" from
   * "primary itself broken."
   */
  static async verify(
    base64CoseBytes: string,
    jwksResolver: ClaimJwksResolver,
    coSignatures: CoSignature[] = [],
  ): Promise<ClaimVerifyResult> {
    let primaryPayloadBytes: Uint8Array | null;
    let primaryResult: ClaimVerifyResult;

    try {
      // Decode outer COSE_Sign1.
      const coseBytes = Buffer.from(base64CoseBytes, 'base64url');
      const cose = cborDecode(coseBytes) as unknown;

      if (!Array.isArray(cose) || cose.length !== 4) {
        return { valid: false, error: 'invalid COSE_Sign1 structure (expected 4-element array)' };
      }
      const [protectedBytes, _unprotected, payloadBytes, signatureBytes] = cose as [
        Uint8Array,
        unknown,
        Uint8Array,
        Uint8Array,
      ];
      primaryPayloadBytes = payloadBytes;

      // Decode the protected header map.
      const protectedMap = headerMapOf(cborDecode(protectedBytes));
      if (!protectedMap) {
        return { valid: false, error: 'protected header is not a CBOR map' };
      }

      const alg = protectedMap.get(COSE_HEADER_ALG);
      if (alg !== COSE_ALG_EDDSA) {
        return {
          valid: false,
          error: `unsupported alg ${alg as number} (only EdDSA / -8 supported in v1)`,
        };
      }

      const kidRaw = protectedMap.get(COSE_HEADER_KID);
      const kid =
        kidRaw instanceof Uint8Array
          ? Buffer.from(kidRaw).toString('utf8')
          : typeof kidRaw === 'string'
            ? kidRaw
            : null;
      if (!kid) {
        return { valid: false, error: 'kid missing or unparseable in protected header' };
      }

      // Resolve every pinned candidate for this kid. Legacy deployment
      // keys reused stack-passport-v1, so kid alone is not unique.
      const resolved = await jwksResolver(kid);
      const candidates = normalizeResolvedJwks(resolved);
      if (candidates.length === 0) {
        return { valid: false, kid, alg: alg as number, error: `kid '${kid}' not found in JWKS` };
      }

      // Reconstruct Sig_structure1 from the same protected_bytes +
      // payload_bytes we got off the wire. Do NOT re-encode the
      // envelope — the signature is over the bytes that were on the
      // wire at sign time.
      const sigStructure = [
        SIG_STRUCTURE_CONTEXT,
        protectedBytes,
        Buffer.alloc(0),
        payloadBytes,
      ];
      const sigStructureBytes = cborEncode(sigStructure);

      const candidateResult = verifyAgainstCandidates(
        kid,
        candidates,
        sigStructureBytes,
        signatureBytes,
      );
      if (!candidateResult.valid) {
        return {
          valid: false,
          kid,
          alg: alg as number,
          error: candidateResult.error,
        };
      }

      const envelope = cborDecode(payloadBytes) as ClaimEnvelope;
      primaryResult = {
        valid: true,
        envelope,
        kid,
        alg: alg as number,
        verified_key_thumbprint: candidateResult.thumbprint,
      };
    } catch (err) {
      return { valid: false, error: `COSE decode error: ${(err as Error).message}` };
    }

    // ─── Co-signature verification ────────────────────────────────
    // Verify each co-signature independently against the SAME
    // payload_bytes the primary signed. Each co-signature is a
    // standalone COSE_Sign1; its protected header carries the
    // co-signer's kid. We assert kid-header-matches-CoSignature-field
    // as a defense against caller-side mismatch.
    if (coSignatures.length === 0) {
      return { ...primaryResult, co_signature_results: [] };
    }

    const co_signature_results: NonNullable<ClaimVerifyResult['co_signature_results']> = [];
    let anyCoSigInvalid = false;

    for (const coSig of coSignatures) {
      const result = await ClaimSigner.verifyCoSignature(
        coSig,
        primaryPayloadBytes,
        jwksResolver,
      );
      co_signature_results.push(result);
      if (!result.valid) anyCoSigInvalid = true;
    }

    return {
      ...primaryResult,
      valid: primaryResult.valid && !anyCoSigInvalid,
      co_signature_results,
    };
  }

  /**
   * Internal: verify a single co-signature against the primary's
   * payload bytes. Extracted from `verify()` so the per-co-signature
   * verification logic is clearly isolated + testable.
   *
   * Each co-signature is a standalone COSE_Sign1 over the SAME
   * payload bytes the primary signed. We check:
   *   1. It decodes as a 4-element COSE_Sign1 array.
   *   2. Its protected header carries a usable kid.
   *   3. The protected-header kid matches the CoSignature.signer_kid
   *      field (defense against caller-side mismatch / kid spoofing).
   *   4. The co-signature's payload_bytes equal the primary's
   *      payload_bytes (defense against caller signing the wrong
   *      payload).
   *   5. The signature verifies against the co-signer's pubkey
   *      (resolved via the same jwksResolver).
   */
  private static async verifyCoSignature(
    coSig: CoSignature,
    primaryPayloadBytes: Uint8Array,
    jwksResolver: ClaimJwksResolver,
  ): Promise<NonNullable<ClaimVerifyResult['co_signature_results']>[number]> {
    try {
      const coseBytes = Buffer.from(coSig.cose_sign1, 'base64url');
      const cose = cborDecode(coseBytes) as unknown;

      if (!Array.isArray(cose) || cose.length !== 4) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: 'co-signature is not a valid COSE_Sign1 (expected 4-element array)',
        };
      }

      const [protectedBytes, _unprotected, payloadBytes, signatureBytes] = cose as [
        Uint8Array,
        unknown,
        Uint8Array,
        Uint8Array,
      ];

      // (4) Co-sig's payload_bytes must equal the primary's. If not,
      // the co-signer signed a different payload — reject.
      if (!buffersEqual(payloadBytes, primaryPayloadBytes)) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: "co-signature's payload_bytes differ from primary's payload_bytes",
        };
      }

      const protectedMap = headerMapOf(cborDecode(protectedBytes));
      if (!protectedMap) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: 'co-signature protected header is not a CBOR map',
        };
      }

      const alg = protectedMap.get(COSE_HEADER_ALG);
      if (alg !== COSE_ALG_EDDSA) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: `co-signature uses unsupported alg ${alg as number} (only EdDSA / -8 supported in v1)`,
        };
      }

      const kidRaw = protectedMap.get(COSE_HEADER_KID);
      const headerKid =
        kidRaw instanceof Uint8Array
          ? Buffer.from(kidRaw).toString('utf8')
          : typeof kidRaw === 'string'
            ? kidRaw
            : null;
      if (!headerKid) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: 'co-signature kid missing or unparseable in protected header',
        };
      }

      // (3) Kid in protected header must match the signer_kid field.
      // Catches caller-side mismatch / kid spoofing where the storage
      // field claims one kid but the cryptographic envelope signs
      // under another.
      if (headerKid !== coSig.signer_kid) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: `co-signature kid mismatch: header=${headerKid} field=${coSig.signer_kid}`,
        };
      }

      const resolved = await jwksResolver(headerKid);
      const candidates = normalizeResolvedJwks(resolved);
      if (candidates.length === 0) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: `co-signature kid '${headerKid}' not found in JWKS`,
        };
      }

      const sigStructure = [
        SIG_STRUCTURE_CONTEXT,
        protectedBytes,
        Buffer.alloc(0),
        payloadBytes,
      ];
      const sigStructureBytes = cborEncode(sigStructure);

      const candidateResult = verifyAgainstCandidates(
        headerKid,
        candidates,
        sigStructureBytes,
        signatureBytes,
      );
      if (!candidateResult.valid) {
        return {
          signer_kid: coSig.signer_kid,
          signer_role: coSig.signer_role,
          valid: false,
          error: `co-signature ${candidateResult.error}`,
        };
      }

      return {
        signer_kid: coSig.signer_kid,
        signer_role: coSig.signer_role,
        valid: true,
      };
    } catch (err) {
      return {
        signer_kid: coSig.signer_kid,
        signer_role: coSig.signer_role,
        valid: false,
        error: `co-signature decode error: ${(err as Error).message}`,
      };
    }
  }
}

/**
 * The protected header as a map of integer labels, or null when it is not a map. The reference producer writes the
 * map under CBOR tag 259 and the decoder reads that as a Map; the same map without the tag is read as a plain
 * object with text keys, which spec/record section 4.4 says a verifier SHOULD also accept.
 */
function headerMapOf(decoded: unknown): Map<number, unknown> | null {
  if (decoded instanceof Map) return decoded as Map<number, unknown>;
  if (decoded && typeof decoded === 'object' && !Array.isArray(decoded) && !(decoded instanceof Uint8Array)) {
    const entries = Object.entries(decoded as Record<string, unknown>);
    if (entries.every(([key]) => /^-?\d+$/.test(key))) return new Map(entries.map(([key, value]) => [Number(key), value]));
  }
  return null;
}

function normalizeResolvedJwks(resolved: JWK | readonly JWK[] | null): readonly JWK[] {
  if (!resolved) return [];
  return Array.isArray(resolved) ? resolved : [resolved as JWK];
}

function verifyAgainstCandidates(
  kid: string,
  candidates: readonly JWK[],
  signingInput: Uint8Array,
  signature: Uint8Array,
): { valid: true; thumbprint: string } | { valid: false; error: string } {
  let unique: JWK[];
  try {
    unique = dedupePublicJwksByThumbprint(candidates);
  } catch (error) {
    return { valid: false, error: `invalid trusted key candidate: ${(error as Error).message}` };
  }

  const matches: string[] = [];
  for (const candidate of unique) {
    if ('d' in candidate) {
      return { valid: false, error: 'invalid trusted key candidate: private key material is forbidden' };
    }
    if (candidate.kid !== undefined && candidate.kid !== kid) {
      return {
        valid: false,
        error: `invalid trusted key candidate: kid '${candidate.kid}' does not match '${kid}'`,
      };
    }
    if (candidate.alg !== undefined && candidate.alg !== 'EdDSA') {
      return { valid: false, error: 'invalid trusted key candidate: alg must be EdDSA' };
    }
    if (candidate.use !== undefined && candidate.use !== 'sig') {
      return { valid: false, error: 'invalid trusted key candidate: use must be sig' };
    }

    let publicKey: nodeCrypto.KeyObject;
    try {
      publicKey = nodeCrypto.createPublicKey({
        key: candidate as nodeCrypto.JsonWebKey,
        format: 'jwk',
      });
    } catch {
      return { valid: false, error: 'invalid trusted key candidate: unusable Ed25519 JWK' };
    }
    if (nodeCrypto.verify(null, signingInput, publicKey, signature)) {
      matches.push(publicJwkThumbprint(candidate));
    }
  }

  if (matches.length === 1) return { valid: true, thumbprint: matches[0]! };
  if (matches.length > 1) {
    return {
      valid: false,
      error: `ambiguous signature verification: ${matches.length} distinct trusted keys verified`,
    };
  }
  return {
    valid: false,
    error:
      unique.length === 1
        ? 'signature verification failed'
        : 'no trusted key candidate verified signature',
  };
}

/**
 * Constant-time-ish byte comparison for the primary↔co-signature
 * payload check. Exact equality (lengths + bytes); not timing-attack-
 * resistant because the values being compared are payload bytes, not
 * secrets. Either side leaking would only reveal the public payload.
 */
function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
