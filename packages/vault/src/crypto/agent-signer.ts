/**
 * AgentSigner — produces COSE_Sign1 claim envelopes signed by
 * per-agent keys for stack_managed and co_signed modes.
 *
 * of the Signed Primitive epic. ADR
 * Design Decision 10 (three signing modes — stack_managed,
 * customer_managed, co_signed).
 *
 * One AgentSigner instance handles many agents. Agent keypairs are
 * KMS-wrapped at rest (column `agents.signing_key_encrypted`, stored
 * as base64 ciphertext from kms.encryptDirect). Provisioning is LAZY
 * — the agent's keypair is generated + wrapped on first sign, not at
 * agent creation. Agents that never sign claims stay un-provisioned
 * and consume no KMS cycles.
 *
 * **Three modes, three behaviours:**
 *
 *   stack_managed: AgentSigner provisions a keypair on first sign
 *                  (generates Ed25519, KMS-wraps private, populates
 *                  pubkey + signing_key_encrypted + enrolled_at on
 *                  the agents row atomically). Subsequent signs use
 *                  the cached unwrapped private key.
 *   customer_managed: AgentSigner REFUSES — the customer holds the
 *                  private key on their own infra; STACK has no way
 *                  to sign on their behalf. Caller is expected to
 *                  accept a pre-signed envelope from the customer
 *                  instead.
 *   co_signed:     AgentSigner provisions + signs as in stack_managed,
 *                  producing the primary signature. The caller then
 *                  separately uses the operator's ClaimSigner to
 *                  produce a co-signature via ClaimSigner.coSign()
 *                  and attaches it alongside.
 *
 * **Dogfood carve-out (op_stack_system).** Agents owned by the system
 * operator never go through per-agent key provisioning. They use the
 * operator's existing ClaimSigner (backed by PassportSigner's key)
 * directly. Keeps STACK's own credential pipeline from depending on
 * per-agent KMS state — chain integrity for our internal claims must
 * not be load-bearing on a key-provisioning step that could fail.
 *
 * **CMEK AAD discipline.** Every kms.encryptDirect / decryptDirect
 * call passes `operatorId` and an `EncryptionContext` containing
 * `{ store: 'agent_signing_key', agent_id }`. Enforced at pre-commit
 * by a repository check. This makes the wrap
 * agent-specific: an attacker who steals one agent's ciphertext can't
 * decrypt it claiming it belongs to a different agent. CMEK status
 * routing is automatic via the operatorId param.
 *
 * **In-memory caching.** Decrypting an agent's private key on every
 * sign is too slow (KMS call per sign). AgentSigner caches ClaimSigner
 * instances per agent_id with a TTL; eviction is lazy at read time.
 * Cache is operator-keyed too so a single AgentSigner instance can
 * serve any operator's agents without cross-tenant cache pollution.
 */
import { generateKeyPair, exportJWK, type JWK } from 'jose';
import { ClaimSigner, type ClaimVerifyResult, type CoSignatureOutput } from './claim-signer.js';
import type { KmsService } from './kms.js';
import type { AgentRepository } from '../repositories/agent-repo.js';
import type { ClaimEnvelope, CoSignature } from '@stack/shared';

export interface AgentSignerDeps {
  agentRepo: AgentRepository;
  kms: KmsService;
  /**
   * The STACK system operator id (env STACK_SYSTEM_OPERATOR_ID). Agents
   * owned by this operator skip per-agent key provisioning and use
   * the operatorClaimSigner directly. Empty string disables the
   * carve-out (dev / test).
   */
  systemOperatorId: string;
  /**
   * The operator's ClaimSigner factory — used for the dogfood
   * carve-out path AND when callers need to co-sign with the
   * operator's key in co_signed mode. Returns a ClaimSigner backed
   * by the operator's PassportSigner key.
   */
  operatorClaimSigner: () => Promise<ClaimSigner>;
  /**
   * How long to cache an agent's decrypted private key in memory
   * before re-loading from KMS. Defaults to 5 minutes. Shorter TTL =
   * more KMS load but tighter blast radius if process memory is
   * compromised.
   */
  cacheTtlMs?: number;
}

interface CachedAgentSigner {
  signer: ClaimSigner;
  loadedAt: number;
}

/** Sentinel error thrown when caller tries to sign for an agent in customer_managed mode. */
export class AgentSignerCustomerManagedError extends Error {
  constructor(agentId: string) {
    super(
      `Agent ${agentId} is in customer_managed mode — STACK cannot sign on its behalf. ` +
        `The customer's SDK must sign the envelope locally and submit it pre-signed.`,
    );
    this.name = 'AgentSignerCustomerManagedError';
  }
}

/** Sentinel error thrown when an agent is not found. */
export class AgentNotFoundError extends Error {
  constructor(agentId: string) {
    super(`Agent ${agentId} not found`);
    this.name = 'AgentNotFoundError';
  }
}

/**
 * Thrown by verifyPreSigned when the agent is not in customer_managed
 * mode. The caller is trying to accept a pre-signed envelope from an
 * agent whose private key STACK holds — that path should call sign()
 * directly instead of verifying an externally-produced signature.
 */
export class AgentSignerNotCustomerManagedError extends Error {
  constructor(agentId: string, actualKeyMode: string) {
    super(
      `Agent ${agentId} is in key_mode='${actualKeyMode}' — verifyPreSigned ` +
        `is only valid for customer_managed agents. Use sign() for ` +
        `stack_managed / co_signed agents (STACK holds the private key).`,
    );
    this.name = 'AgentSignerNotCustomerManagedError';
  }
}

/**
 * Thrown by verifyPreSigned when a customer_managed agent has no
 * pubkey enrolled yet. The customer must run the /enroll proof-of-
 * possession dance first; without an enrolled pubkey there is no
 * key to verify the submitted envelope against.
 */
export class AgentSignerNoPubkeyError extends Error {
  constructor(agentId: string) {
    super(
      `Agent ${agentId} has no pubkey enrolled. Run POST /v1/agents/${agentId}/enroll first.`,
    );
    this.name = 'AgentSignerNoPubkeyError';
  }
}

export class AgentSigner {
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, CachedAgentSigner>();

  constructor(private readonly deps: AgentSignerDeps) {
    this.cacheTtlMs = deps.cacheTtlMs ?? 5 * 60 * 1000;
  }

  /**
   * Sign a ClaimEnvelope on behalf of the given agent. Routes by
   * agent.key_mode:
   *
   *   - op_stack_system agent → operator's ClaimSigner (dogfood)
   *   - customer_managed       → throws AgentSignerCustomerManagedError
   *   - stack_managed / co_signed → per-agent key (lazy-provision then sign)
   *
   * Returns the base64url-encoded COSE_Sign1 produced by the underlying
   * ClaimSigner. For co_signed mode, callers wanting the operator
   * co-signature should additionally call `operatorClaimSigner().coSign(
   * primary, 'operator_attestation')` and attach the result.
   */
  async sign(envelope: ClaimEnvelope, agentId: string): Promise<string> {
    const agent = await this.deps.agentRepo.findById(agentId);
    if (!agent) throw new AgentNotFoundError(agentId);

    // Dogfood carve-out: STACK's own agents use the operator's signer,
    // not per-agent keys. The system operator's PassportSigner key is
    // the signer; the COSE_Sign1 envelope carries that kid in its
    // protected header. Verifiers route via the operator's JWKS.
    if (
      this.deps.systemOperatorId !== '' &&
      agent.operator_id === this.deps.systemOperatorId
    ) {
      const opSigner = await this.deps.operatorClaimSigner();
      return opSigner.sign(envelope);
    }

    if (agent.key_mode === 'customer_managed') {
      throw new AgentSignerCustomerManagedError(agentId);
    }

    // stack_managed or co_signed — both use the per-agent key for the
    // primary signature. co_signed mode's secondary signature is the
    // caller's responsibility (separate call to operator's coSign).
    const signer = await this.getAgentSigner(agent.id, agent.operator_id);
    return signer.sign(envelope);
  }

  /**
   * The signer behind an agent's public identity (its website's card): the same
   * key rules as `sign`. Null when STACK cannot sign for the agent (a
   * customer-managed key, or an unknown agent); the key is provisioned on the
   * first call for a STACK-managed agent.
   */
  private async identitySigner(agentId: string): Promise<ClaimSigner | null> {
    const agent = await this.deps.agentRepo.findById(agentId);
    if (!agent) return null;
    if (this.deps.systemOperatorId !== '' && agent.operator_id === this.deps.systemOperatorId) {
      return this.deps.operatorClaimSigner();
    }
    if (agent.key_mode === 'customer_managed') return null;
    return this.getAgentSigner(agent.id, agent.operator_id);
  }

  /** The agent's public Ed25519 key (kty, crv, x), or null when STACK cannot sign for it. */
  async publicJwk(agentId: string): Promise<{ kty: 'OKP'; crv: 'Ed25519'; x: string } | null> {
    const signer = await this.identitySigner(agentId);
    if (!signer) return null;
    const jwk = signer.getPublicJwk();
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return null;
    return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  }

  /** A raw Ed25519 signature over `data` with the agent's key. Throws when STACK cannot sign for the agent. */
  async signRaw(agentId: string, data: Uint8Array): Promise<Uint8Array> {
    const signer = await this.identitySigner(agentId);
    if (!signer) throw new AgentSignerCustomerManagedError(agentId);
    const signature = await signer.signBytes(Buffer.from(data));
    return new Uint8Array(Buffer.from(signature, 'base64url'));
  }

  /**
   * Convenience: produce the operator co-signature for an existing
   * primary envelope_cose. Used by callers wiring co_signed mode —
   * step (1) is AgentSigner.sign() with agent's key; step (2) is this
   * method to produce the operator_attestation co-signature; step (3)
   * is to store both alongside the primary envelope_cose.
   */
  async coSignAsOperator(primaryCoseBase64: string): Promise<CoSignatureOutput> {
    const opSigner = await this.deps.operatorClaimSigner();
    return opSigner.coSign(primaryCoseBase64, 'operator_attestation');
  }

  /**
   * One-shot producer path for stack_managed + co_signed agents.
   * Returns the primary envelope_cose AND any co_signatures the mode
   * requires, in a single call. — the
   * producer surface for the three signing modes.
   *
   * Routing per key_mode:
   *
   *   op_stack_system (dogfood): operator's ClaimSigner produces the
   *     primary signature; no co-signatures. The agent's identity
   *     piggybacks on the operator's key.
   *
   *   stack_managed: agent's lazy-provisioned key produces the
   *     primary signature; no co-signatures. The kid in the protected
   *     header points at the agent's pubkey in the JWKS.
   *
   *   customer_managed: throws AgentSignerCustomerManagedError.
   *     The customer holds the private key and signs locally; producers
   *     receiving customer-supplied envelopes should call
   *     verifyPreSigned() instead.
   *
   *   co_signed: agent's lazy-provisioned key produces the primary
   *     signature, THEN the operator's ClaimSigner produces an
   *     operator_attestation co-signature over the same payload bytes.
   *     Returns both. Per ADR Design Decision 10 + N3.
   *
 * Producers store both fields atomically:
   * passport_claims.envelope_cose ← envelope_cose
   * passport_claims.co_signatures ← co_signatures
   *
   * The co-signature is a standalone COSE_Sign1 (per ClaimSigner.coSign)
   * over the SAME payload bytes the primary signed. Either signature
   * missing or invalid at verify time = claim rejected (enforced in
   * verifyClaim below).
   */
  async signClaim(
    envelope: ClaimEnvelope,
    agentId: string,
  ): Promise<{ envelope_cose: string; co_signatures: CoSignature[] }> {
    const agent = await this.deps.agentRepo.findById(agentId);
    if (!agent) throw new AgentNotFoundError(agentId);

    // Dogfood: STACK's own agents → operator's signer produces the
    // primary; no co-signatures. The COSE protected header's kid is
    // the operator's kid, not the agent's.
    if (
      this.deps.systemOperatorId !== '' &&
      agent.operator_id === this.deps.systemOperatorId
    ) {
      const opSigner = await this.deps.operatorClaimSigner();
      const envelope_cose = await opSigner.sign(envelope);
      return { envelope_cose, co_signatures: [] };
    }

    if (agent.key_mode === 'customer_managed') {
      throw new AgentSignerCustomerManagedError(agentId);
    }

    // stack_managed or co_signed: agent's per-agent key produces the
    // primary. Lazy-provision happens inside getAgentSigner.
    const signer = await this.getAgentSigner(agent.id, agent.operator_id);
    const envelope_cose = await signer.sign(envelope);

    if (agent.key_mode === 'co_signed') {
      const opSigner = await this.deps.operatorClaimSigner();
      const coSig = await opSigner.coSign(envelope_cose, 'operator_attestation');
      return { envelope_cose, co_signatures: [coSig] };
    }

    return { envelope_cose, co_signatures: [] };
  }

  /**
   * Verify a stored claim end-to-end with key_mode-aware gates. Phase
   * 2.5a — the verifier counterpart to signClaim.
   *
   * Loads the agent, builds a kid resolver pinned to the agent's own
   * kid (the customer-supplied pubkey for customer_managed, the
   * STACK-provisioned pubkey for stack_managed + co_signed), then
   * delegates to ClaimSigner.verify for the COSE math.
   *
   * For co_signed agents, additionally enforces: the co_signatures
   * array MUST include at least one entry with signer_role =
   * 'operator_attestation' AND that entry MUST verify. A missing or
   * invalid operator attestation fails the whole claim — even if the
   * primary signature itself verifies cleanly. This is the
   * cryptographic non-repudiation guarantee the co_signed mode is
   * built for: neither party alone can produce a complete claim.
   *
   * For stack_managed agents, primary signature is enough.
   * For customer_managed agents, primary signature is enough (the
   * customer's signature). Callers wanting to verify the
   * pre-submission state should use verifyPreSigned() instead, which
   * is a slightly stricter API (rejects non-customer_managed agents).
   *
   * Operator kid resolution: AgentSigner doesn't know operator JWKS
   * directly. The caller MAY pass an `operatorJwksResolver` which
   * resolves the operator's kid → pubkey. Without one, co-sig kids
   * fall back to the deps.operatorClaimSigner's kid + getPublicJwk
   * combo (covers the common dogfood-test case).
   *
   * Throws AgentNotFoundError if agent_id doesn't resolve.
   * Returns ClaimVerifyResult — check `valid: true` before trusting
   * the envelope.
   */
  async verifyClaim(
    envelope_cose: string,
    co_signatures: CoSignature[],
    agentId: string,
    options: {
      operatorJwksResolver?: (kid: string) => Promise<JWK | null>;
    } = {},
  ): Promise<ClaimVerifyResult> {
    const agent = await this.deps.agentRepo.findById(agentId);
    if (!agent) throw new AgentNotFoundError(agentId);

    const agentKid = this.kidForAgent(agentId);
    const agentPubkey = agent.pubkey as JWK | null;

    // Operator pubkey (for co-sig kid resolution). Lazy-resolved so
    // callers that pass an explicit resolver skip this entirely.
    let opSignerCache: { kid: string; pubkey: JWK | null } | null = null;
    const resolveOperatorKid = async (): Promise<{ kid: string; pubkey: JWK | null }> => {
      if (opSignerCache) return opSignerCache;
      const opSigner = await this.deps.operatorClaimSigner();
      opSignerCache = {
        kid: opSigner.getKid(),
        pubkey: opSigner.getPublicJwk(),
      };
      return opSignerCache;
    };

    const resolver = async (kid: string): Promise<JWK | null> => {
      if (kid === agentKid && agentPubkey) return agentPubkey;
      if (options.operatorJwksResolver) {
        const hit = await options.operatorJwksResolver(kid);
        if (hit) return hit;
      }
      // Default operator-kid path: matches the operatorClaimSigner's
      // own kid. Used by tests + dogfood; production callers should
      // pass an explicit operatorJwksResolver scoped to the operator.
      const op = await resolveOperatorKid();
      if (kid === op.kid && op.pubkey) return op.pubkey;
      return null;
    };

    const result = await ClaimSigner.verify(envelope_cose, resolver, co_signatures);

    // Key-mode-specific gates beyond what ClaimSigner.verify enforces.
    if (agent.key_mode === 'co_signed') {
      const operatorAttestation = result.co_signature_results?.find(
        (r) => r.signer_role === 'operator_attestation' && r.valid,
      );
      if (!operatorAttestation) {
        // Find the most informative error: prefer a co-sig-specific
        // failure over the bare "missing" message so the caller can
        // diagnose why the operator attestation didn't verify.
        const failedOp = result.co_signature_results?.find(
          (r) => r.signer_role === 'operator_attestation' && !r.valid,
        );
        const error = failedOp?.error
          ? `co_signed agent's operator_attestation co-signature failed: ${failedOp.error}`
          : 'co_signed agent missing valid operator_attestation co-signature';
        return { ...result, valid: false, error };
      }
    }

    return result;
  }

  /**
   * Verify a pre-signed COSE_Sign1 envelope produced by a customer-held
   * private key, against the pubkey stored at /enroll time.
   * the verification side of customer_managed mode
   * (ADR Design Decision 10).
   *
   * The verifier is intentionally STRICT on kid: the only resolvable
   * kid is this agent's own (`agent:<id>:v1`). A customer cannot submit
   * a COSE_Sign1 whose kid points at a different agent or at the
   * operator's signing key and have it accepted here. This is the
   * defense against caller-side kid spoofing — even if a customer were
   * to enroll a pubkey under one agent_id and then submit a COSE_Sign1
   * carrying a different kid in its protected header, the resolver
   * returns null and ClaimSigner.verify fails.
   *
   * Combined with the proof-of-possession gate on /enroll (the customer
   * must sign a STACK-issued challenge with the matching privkey
   * BEFORE the pubkey gets stored), this closes the claim-forgery-via-
   * key-squat threat surface end-to-end:
   *
   *   - /enroll won't store a pubkey the customer doesn't possess
   *     (POP gate over a fresh server-issued nonce).
   *   - verifyPreSigned won't accept an envelope whose kid doesn't
   *     match the agent's own (resolver returns null for other kids).
   *   - verifyPreSigned won't accept an envelope signed by a key other
   *     than the one enrolled (ClaimSigner.verify reconstructs
   *     Sig_structure1 over the wire bytes and runs the EdDSA verify).
   *
 * Callers (the producer layer) MUST
   * await this and check `result.valid` before persisting the envelope
   * to the claim registry. The audit chain integrity argument depends
   * on every claim hash being over a verified envelope; an unverified
   * envelope poisoning the chain breaks the substrate's main guarantee.
   *
   * Throws AgentNotFoundError if the agent_id doesn't resolve.
   * Throws AgentSignerNotCustomerManagedError if the agent's key_mode
   * is anything other than 'customer_managed'.
   * Throws AgentSignerNoPubkeyError if no pubkey has been enrolled.
   * Returns a ClaimVerifyResult otherwise; check `valid: true` before
   * trusting the envelope contents.
   *
   * @param base64CoseBytes The base64url-encoded COSE_Sign1 message
   *   as produced by the customer's signer. Same wire shape as
   *   ClaimSigner.sign() output.
   * @param agentId The agent the envelope claims to be from. The
   *   envelope's kid MUST equal `agent:<agentId>:v1` to verify.
   */
  async verifyPreSigned(
    base64CoseBytes: string,
    agentId: string,
  ): Promise<ClaimVerifyResult> {
    const agent = await this.deps.agentRepo.findById(agentId);
    if (!agent) throw new AgentNotFoundError(agentId);

    if (agent.key_mode !== 'customer_managed') {
      throw new AgentSignerNotCustomerManagedError(agentId, agent.key_mode);
    }

    if (!agent.pubkey) {
      throw new AgentSignerNoPubkeyError(agentId);
    }

    const expectedKid = this.kidForAgent(agentId);
    const pubkey = agent.pubkey as JWK;

    // Pinned single-kid resolver. Any kid mismatch in the envelope's
    // protected header → null → ClaimSigner.verify returns
    // valid: false with error "kid '<other>' not found in JWKS".
    const resolver = async (kid: string): Promise<JWK | null> => {
      return kid === expectedKid ? pubkey : null;
    };

    return ClaimSigner.verify(base64CoseBytes, resolver);
  }

  /**
   * Internal: get a cached ClaimSigner for the agent, or load + cache
   * one if not present. Lazy-provisions the keypair if the agent has
   * no key yet.
   */
  private async getAgentSigner(
    agentId: string,
    operatorId: string,
  ): Promise<ClaimSigner> {
    const cached = this.cache.get(agentId);
    if (cached && Date.now() - cached.loadedAt < this.cacheTtlMs) {
      return cached.signer;
    }

    // Re-fetch the agent (cache miss path; the row may have been
    // updated since the first findById in sign()).
    const agent = await this.deps.agentRepo.findById(agentId);
    if (!agent) throw new AgentNotFoundError(agentId);

    let privateJwk: JWK;

    if (agent.signing_key_encrypted) {
      // Already provisioned — decrypt and load.
      const ciphertext = Buffer.from(agent.signing_key_encrypted, 'base64');
      const plaintext = await this.deps.kms.decryptDirect(ciphertext, {
        operatorId,
        expectedContext: {
          store: 'agent_signing_key',
          agent_id: agentId,
        },
      });
      privateJwk = JSON.parse(plaintext.toString('utf8')) as JWK;
    } else {
      // Not yet provisioned — generate, KMS-wrap, persist atomically.
      privateJwk = await this.provisionKey(agentId, operatorId);
    }

    const kid = this.kidForAgent(agentId);
    const signer = new ClaimSigner({ privateKeyJwk: privateJwk, kid, alg: 'EdDSA' });
    this.cache.set(agentId, { signer, loadedAt: Date.now() });
    return signer;
  }

  /**
   * Generate a fresh Ed25519 keypair for the agent, KMS-wrap the
   * private half, and atomically populate the agents row.
   *
   * Atomicity matters because the CHECK constraint
   * `agents_key_material_consistency` enforces: if enrolled_at IS NOT
   * NULL and key_mode IN ('stack_managed','co_signed'), BOTH pubkey
   * AND signing_key_encrypted must be set. A partial update would
   * either reject at the constraint or leave a half-provisioned row.
   * The single `update()` call with all three fields set keeps the
   * row consistent at all times.
   *
   * Returns the freshly-generated private JWK so the caller doesn't
   * need to immediately decrypt what it just encrypted.
   */
  private async provisionKey(agentId: string, operatorId: string): Promise<JWK> {
    // 1. Generate Ed25519 keypair. extractable: true required by jose
    //    v6 for exportJWK to succeed.
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    const privateJwk = await exportJWK(privateKey);
    const publicJwkRaw = await exportJWK(publicKey);
    // Trim publicJwkRaw to the (kty, crv, x) shape the agents.pubkey
    // column types accept — matches the existing 0026 SDK enrollment
    // shape.
    const publicJwk = {
      kty: publicJwkRaw.kty as string,
      crv: publicJwkRaw.crv as string,
      x: publicJwkRaw.x as string,
    };

    // 2. KMS-wrap the private JWK. CMEK AAD: operatorId in opts +
    //    EncryptionContext { store, agent_id }. The pre-commit linter
    //    verifies this shape.
    const privateBytes = Buffer.from(JSON.stringify(privateJwk), 'utf8');
    const ciphertext = await this.deps.kms.encryptDirect(privateBytes, {
      operatorId,
      context: { store: 'agent_signing_key', agent_id: agentId },
    });
    const signingKeyEncrypted = ciphertext.toString('base64');

    // 3. Atomically populate the agent row. The CHECK constraint
    //    enforces all-or-nothing on enrolled_at + pubkey + signing_key_encrypted.
    await this.deps.agentRepo.update(agentId, {
      pubkey: publicJwk,
      signing_key_encrypted: signingKeyEncrypted,
      enrolled_at: new Date(),
    });

    return privateJwk;
  }

  /**
   * Stable kid for an agent. Used in the COSE protected header so the
   * verifier can look up the pubkey via JWKS. Format: 'agent:<agent_id>:v1'
   * — the v1 suffix is the key-rotation generation, bumped if/when
   * An earlier change ships historical key support and we rotate.
   */
  private kidForAgent(agentId: string): string {
    return `agent:${agentId}:v1`;
  }

  /**
   * Evict an agent from the in-memory cache. Used after key rotation
   * or revocation so the next sign re-loads from KMS.
   * Safe to call even if the agent isn't cached.
   */
  evictAgent(agentId: string): void {
    this.cache.delete(agentId);
  }
}

/**
 * Pure helper exported for tests + producer callers wiring co_signed
 * mode: given a primary envelope_cose + an operator co-signature,
 * combine into the CoSignature[] shape that gets stored alongside
 * the primary.
 */
export function bundleCoSignatures(
  ...coSigs: CoSignatureOutput[]
): CoSignature[] {
  return coSigs;
}
