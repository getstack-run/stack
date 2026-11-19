/**
 * Customer-side COSE_Sign1 signer for `customer_managed` agents.
 *
 * of the Signed Primitive epic.
 *
 * `customer_managed` mode (ADR Design Decision 10) keeps the agent's
 * private key on customer infrastructure. STACK only stores the pubkey
 * (registered via the proof-of-possession dance at `POST /v1/agents/:id
 * /enroll`). When the customer's agent produces a STACK claim envelope
 * (intent_claim, intent_outcome, detector_signal, intent_denial,
 * intent_simulation), the envelope is signed locally with this helper
 * and submitted pre-signed.
 *
 * The wire format is byte-identical to what `@stack/vault`'s
 * `ClaimSigner.sign` produces server-side, so the same `ClaimSigner
 * .verify` path on STACK accepts both. We do NOT depend on
 * `@stack/vault` here — that's a server package, not published, and
 * we don't want a transitive `@aws-sdk/client-kms` blob landing in
 * customer apps. The encoding logic is small (~50 lines) and trivially
 * duplicated.
 *
 * Defaults to EdDSA / Ed25519. Algorithm is pluggable from day one so
 * the same call site picks up ML-DSA-65 when the JOSE/COSE post-quantum
 * draft hits RFC.
 */
import { encode as cborEncode } from 'cbor-x';
import { createPrivateKey, sign as cryptoSign, type JsonWebKey } from 'node:crypto';
import type { JWK } from 'jose';

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
 * Shape of the STACK claim envelope. Mirrors the server-side
 * `ClaimEnvelope` Zod schema (see `@stack/shared` schemas/passport-
 * claims/envelope.ts) at the field level. Re-declared here so the SDK
 * does not have to import the shared package's full schema graph for
 * one type.
 *
 * `claim_type` discriminates the payload shape. The signer treats the
 * envelope as opaque CBOR-encodable JSON — it does NOT validate the
 * payload against the per-claim-type Zod schema. The customer is
 * responsible for producing a well-formed envelope; STACK validates
 * shape on the receive side.
 */
export interface ClaimEnvelope {
  envelope_version: 1;
  issuer: string;
  subject: string;
  issued_at: number;
  claim_type: string;
  claim_version: number;
  payload: unknown;
  receipt: unknown | null;
  co_signatures: unknown[];
  [extra: string]: unknown;
}

export interface SignClaimEnvelopeOptions {
  /**
   * The agent's local private key, in JWK form. For customers using the
   * SDK's built-in enrollment, the keypair is persisted at
   * `~/.stack/agents/<agent_id>.json` by `agent-auth.ts`; pass
   * `storedKey.privateKey` into this option. For customers managing
   * their own key material, pass the JWK directly.
   */
  privateKey: JWK;
  /**
   * The agent id this signature speaks for. The COSE protected header's
   * `kid` is set to `agent:<id>:v1`. STACK's verifyPreSigned path uses
   * the kid to look up the enrolled pubkey; a mismatch fails
   * verification.
   */
  agentId: string;
  /**
   * Defaults to 'EdDSA'. ML-DSA-65 is reserved but not yet implemented
   * (waiting on the JOSE/COSE post-quantum draft).
   */
  alg?: 'EdDSA' | 'ML-DSA-65';
}

/**
 * Sign a STACK claim envelope locally and produce a base64url-encoded
 * COSE_Sign1 message. The output is the wire-format string the customer
 * submits to STACK in the body of the eventual `POST /v1/claims`
 * endpoint (lands with the producer migrations).
 *
 * The function is synchronous-friendly (no awaits beyond what cbor-x
 * needs). Throws on unsupported algorithm or malformed JWK.
 *
 * Wire-format compatibility: byte-identical output to
 * `@stack/vault`'s `ClaimSigner.sign` over the same envelope + kid +
 * key material. Verified by the vault-side test
 * `AgentSigner.verifyPreSigned` consuming the SDK's output unmodified.
 */
export function signClaimEnvelope(
  envelope: ClaimEnvelope,
  opts: SignClaimEnvelopeOptions,
): string {
  const alg = opts.alg ?? 'EdDSA';
  if (alg !== 'EdDSA') {
    throw new Error(
      `signClaimEnvelope: algorithm '${alg}' is reserved but not yet ` +
        `implemented. Only 'EdDSA' is supported in v1. ML-DSA-65 ships ` +
        `when the JOSE/COSE post-quantum draft (draft-ietf-cose-dilithium) ` +
        `lands at RFC.`,
    );
  }

  const kid = `agent:${opts.agentId}:v1`;
  const privateKey = createPrivateKey({
    key: opts.privateKey as JsonWebKey,
    format: 'jwk',
  });

  // Payload bytes — CBOR-encoded envelope. Deterministic given the
  // input (cbor-x stable iteration order for plain objects).
  const payloadBytes = cborEncode(envelope);

  // Protected header — kid + alg + typ. Order is fixed for byte-
  // identical output across SDK + vault.
  const protectedHeader = new Map<number, unknown>([
    [COSE_HEADER_ALG, COSE_ALG_EDDSA],
    [COSE_HEADER_KID, Buffer.from(kid, 'utf8')],
    [COSE_HEADER_TYP, STACK_CLAIM_TYP],
  ]);
  const protectedBytes = cborEncode(protectedHeader);

  // Sig_structure1 per RFC 9052 §4.4. The signer signs this whole
  // structure, not the envelope or payload alone. external_aad is
  // empty (we don't use AAD on STACK claims).
  const sigStructure = [
    SIG_STRUCTURE_CONTEXT,
    protectedBytes,
    Buffer.alloc(0),
    payloadBytes,
  ];
  const sigStructureBytes = cborEncode(sigStructure);

  // Ed25519: pass null as digest — algorithm has its own internal
  // hashing per RFC 8032.
  const signature = cryptoSign(null, sigStructureBytes, privateKey);

  // COSE_Sign1 = [protected, unprotected, payload, signature]
  const coseSign1 = [protectedBytes, new Map(), payloadBytes, signature];
  const coseBytes = cborEncode(coseSign1);
  return Buffer.from(coseBytes).toString('base64url');
}
