/**
 * Claim Registry Service — Part of the Signed Primitive
 * epic. Architecture doc: the claims registry design.
 *
 * Wires together:
 *   - the `ClaimEnvelope` Zod shape (chunk 1)
 *   - the `passport_claims` extended schema (chunk 2)
 *   - the `ClaimSigner` COSE_Sign1 producer (chunk 3)
 * into a business-logic service with four operations:
 *
 *   registerClaim()  — validate payload, build envelope, sign,
 *                      persist. Tier-gate at the service layer per
 *                      ADR decision Q4.
 *   verifyClaim()    — fetch row, COSE-verify envelope_cose against
 *                      operator's JWKS.
 *   listBySubject()  — list active envelope-shape claims by subject
 *                      URI. Hot path for the active-claims view.
 *   cascadeRevoke()  — passport revocation propagates: every active
 *                      claim attached to the passport gets revoked
 *                      in one statement.
 *
 * The service does NOT touch the legacy JWS-shape paths
 * (passport-service.attachClaim). Both paths coexist on the same
 * passport_claims table during; the SPIFFE consumer
 * migration switches the live caller from the
 * legacy path to this one.
 */
import { createHash } from 'node:crypto';
import { canonicalize, safeErrorSummary } from '@stack/shared';
import {
  PASSPORT_CLAIM_SCHEMAS,
  buildClaimEnvelope,
  subjectForPassport,
  subjectForOperator,
  ClaimEnvelope as ClaimEnvelopeSchema,
  type ClaimEnvelope,
  type ClaimType,
  type PassportClaimType,
  ids,
  SchemaValidationError,
  NotFoundError,
} from '@stack/shared';
import type { JWK } from 'jose';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import { ClaimSigner, type ClaimVerifyResult } from '../crypto/claim-signer.js';

// ─── Public input/output types ──────────────────────────────────────

export interface RegisterClaimInput {
  operatorId: string;
  /**
   * Passport JTI to scope the claim to. Required for passport-scoped
   * claim types. An earlier change introduces operator-scoped
   * claims (identity_claim): callers pass `passportJti: undefined` AND
   * `subjectOverride: 'operator'` to bind the claim to the operator
   * subject `stack://operator/{op_id}` instead of a passport.
   */
  passportJti?: string;
  /**
   * explicit signal that this claim is
   * operator-scoped (no passport). When set to 'operator', the
   * envelope's subject is `stack://operator/{operatorId}` and the
   * persisted row has `passport_id = null`. Defaults to undefined
   * which requires `passportJti` to be set.
   */
  subjectOverride?: 'operator';
  claimType: ClaimType;
  payload: unknown;
  /**
   * Override the schema's default version. Almost never needed —
   * default 1 is correct for every claim type in PASSPORT_CLAIM_SCHEMAS
   * today. Used by migrations that re-sign historical claims
   * with their original schema version.
   */
  claimVersion?: number;
  /** Durable producer identity. Both fields are required together. */
  sourceOperationId?: string;
  sourceRole?: string;
}

export interface RegisterClaimResult {
  claimId: string;
  envelopeCose: string;
  subject: string;
}

export interface RegisterClaimOptions {
  /**
   * Optional transaction-bound claim writer.
   *
   * Evidence-pack export uses this to persist the signed pack claim and its
   * object metadata in one database transaction. All normal callers use the
   * repository configured on the service.
   */
  persistence?: Pick<PassportClaimsRepository, 'insert'>;
}

export interface ListBySubjectEntry {
  claim_id: string;
  envelope: ClaimEnvelope;
}

export interface ClaimRegistryDeps {
  /** Repository handle for the underlying `passport_claims` table. */
  repo: PassportClaimsRepository;
  /**
   * Factory: returns the ClaimSigner for a given operator, loaded with
   * that operator's private signing key. The api bootstrap wires this
   * by looking up the operator's key in the existing PassportSigner
   * machinery. Construction-time injection keeps this service free of
   * direct KMS/key-loading concerns.
   */
  signerForOperator: (operatorId: string) => Promise<ClaimSigner>;
  /**
   * Resolves a public JWK for a given operator + kid. Used by
   * verifyClaim() to fetch the verification key from the operator's
   * JWKS without coupling this service to the JWKS endpoint
   * machinery.
   */
  resolvePublicJwk: (
    operatorId: string,
    kid: string,
  ) => Promise<JWK | readonly JWK[] | null>;
}

/**
 * post-persist hook for
 * intent_outcome claims. Implementations compare the just-persisted
 * outcome against any paired intent_simulation on the same passport
 * and emit a `simulation_divergence` detector_signal claim on
 * mismatch. Mirror of `SecurityEventService.setClaimRegistryService`
 * late-wiring — kept structural so tests can stub.
 */
export interface SimulationDivergenceHook {
  check(args: {
    operatorId: string;
    passportJti: string;
    outcomeClaimId: string;
  }): Promise<void>;
}

/**
 * behavioral drift detector hook (wire-key: `genome_drift`).
 * When a behavioral_genome claim lands, the hook reads the prior genome
 * via the chain pointer (`prior_genome_ref` on the just-persisted
 * payload), runs BehavioralGenomeService.computeDiff, and on threshold
 * breach fires a `genome_drift` security event + paired detector_signal
 * claim. Mirror of SimulationDivergenceHook shape. Late-wiring pattern
 * lets the detector be constructed AFTER the registry (avoids circular
 * dep) and stubbed in tests.
 */
export interface BehavioralDriftHook {
  check(args: {
    operatorId: string;
    passportJti: string;
    claimId: string;
  }): Promise<void>;
}

/**
 * twin intent-claim mirror hook. Fires AFTER every
 * intent_claim registration. Wired in apps/api/src/config/services.ts
 * to call TwinOrchestrationService.mirrorIntent when the passport has
 * an active twin run (lookup by real_passport_jti in twin_runs).
 *
 * Best-effort: failure logs, never blocks the real claim's persist.
 * Gated to claim_type='intent_claim' INSIDE registerClaim so the hot
 * path stays tight — other claim types are no-ops at the registry
 * level, no hook invocation overhead.
 */
export interface TwinMirrorHook {
  fire(args: {
    realClaimId: string;
    realIntentClaim: import('@stack/shared').IntentClaim;
    passportJti: string;
    operatorId: string;
  }): Promise<void>;
}

// ─── Service ────────────────────────────────────────────────────────

export class ClaimRegistryService {
  private simulationDivergence: SimulationDivergenceHook | null = null;
  private behavioralDrift: BehavioralDriftHook | null = null;
  private twinMirror: TwinMirrorHook | null = null;

  constructor(private readonly deps: ClaimRegistryDeps) {}

  /**
   * Late-wire the simulation_divergence detector. Called from
   * services.ts after the detector itself is constructed (the
   * detector reads from this same repo, so the circular dep is
   * resolved via post-construction injection — same pattern as
   * SecurityEventService.setClaimRegistryService).
   */
  setSimulationDivergenceHook(hook: SimulationDivergenceHook): void {
    this.simulationDivergence = hook;
  }

  /**
   * late-wire the behavioral drift detector (wire-key:
   * `genome_drift`). Called from services.ts AND worker.ts (the worker
   * emits the bulk of behavioral_genome claims via the daily cron —
   * wiring only api-side would silently miss cron-emitted drift). Same
   * late-wiring rationale as setSimulationDivergenceHook above.
   */
  setBehavioralDriftHook(hook: BehavioralDriftHook): void {
    this.behavioralDrift = hook;
  }

  /**
   * late-wire the twin intent-claim mirror hook. Called
   * from apps/api/src/config/services.ts. Same late-wiring pattern as
   * the other hooks. The hook fires post-persist on every intent_claim
   * registration; the wired implementation looks up the passport's
   * twin run and calls TwinOrchestrationService.mirrorIntent when
   * present. Best-effort throughout.
   */
  setTwinMirrorHook(hook: TwinMirrorHook): void {
    this.twinMirror = hook;
  }

  /**
   * Sign + persist a claim envelope attached to a passport. Every claim type
   * registers for every account: the registry has no plan gate, and a feature
   * that needs controls is refused where the feature is used, never here.
   * Throws:
   *
   *  - SchemaValidationError  — claim_type reserved but not yet implemented
   *                             OR payload fails the claim type's Zod schema
   *
   * Returns the claim_id (for later lookup) + the signed COSE_Sign1
   * envelope_cose (for the caller's audit / response shape).
   */
  /**
   * Everything `registerClaim` checks before it signs, and nothing it writes: a caller that must refuse before it
   * spends (meters an action, mints a passport) asks this first. Throws SchemaValidationError when the claim type has
   * no payload schema yet or the payload fails it; returns the parsed payload.
   */
  assertRegistrable(claimType: ClaimType, payload: unknown): unknown {
    // 1. Schema lookup. Reserved-but-unimplemented claim types fail
    //    here with a clear message so callers can't smuggle
    //    unvalidated bytes into the registry.
    const schema = PASSPORT_CLAIM_SCHEMAS[claimType as PassportClaimType];
    if (!schema) {
      throw new SchemaValidationError({
        message:
          `claim type '${claimType}' is reserved in the registry but its v1 ` +
          `payload schema is not yet implemented. Implemented today: svid_attestation, ` +
          `workload_attestation, rats_evidence, slsa_provenance, ai_bom_ref, ` +
          `c2pa_assertion. The remaining reserved types are not accepted yet.`,
        claim_type: claimType,
      });
    }

    // 2. Payload validation against the claim type's Zod schema.
    const parsed = schema.safeParse(payload);
    if (!parsed.success) {
      throw new SchemaValidationError({
        message: `payload validation failed for claim type '${claimType}'`,
        claim_type: claimType,
        zod_error: parsed.error.message,
      });
    }
    return parsed.data;
  }

  async registerClaim(
    input: RegisterClaimInput,
    options: RegisterClaimOptions = {},
  ): Promise<RegisterClaimResult> {
    // 1-2. Schema lookup and payload validation.
    const parsedPayload = this.assertRegistrable(input.claimType, input.payload);

    // 3. Build the envelope. Subject defaults to passport-scoped URI
    //    per ADR design decision Q2. An earlier change adds
    //    operator-scoped envelopes for identity_claim — caller passes
    //    `subjectOverride: 'operator'` AND omits passportJti.
    let subject: string;
    if (input.subjectOverride === 'operator') {
      subject = subjectForOperator(input.operatorId);
    } else {
      if (!input.passportJti) {
        throw new SchemaValidationError({
          message:
            'passportJti is required for passport-scoped claims. To register an ' +
            'operator-scoped claim, pass `subjectOverride: "operator"` explicitly.',
          claim_type: input.claimType,
        });
      }
      subject = subjectForPassport(input.operatorId, input.passportJti);
    }
    const envelope = buildClaimEnvelope({
      issuer: input.operatorId,
      subject,
      claim_type: input.claimType,
      claim_version: input.claimVersion ?? 1,
      payload: parsedPayload,
    });

    // 4. Sign as COSE_Sign1 via the operator-scoped signer.
    const signer = await this.deps.signerForOperator(input.operatorId);
    const envelopeCose = await signer.sign(envelope);

    // 5. Persist. Legacy JWS-shape columns (body_json, signature) get
    //    sentinel values for envelope-canonical rows; readers that
    //    need the body should decode envelope_cose instead. The
    //    `claim_hash` column is REAL — it's sha256(envelope_cose) so
    //    the audit-chain binding (which hashes the active claim
    //    hashes into audit_log.passport_claims_at_event) captures the
    //    canonical signed content. Tampering envelope_cose changes
    //    sha256(envelope_cose) which diverges from the stored
    //    claim_hash at verify time.
    const envelopeBytes = Buffer.from(envelopeCose, 'base64url');
    const claimHash = createHash('sha256').update(envelopeBytes).digest('hex');
    if ((input.sourceOperationId === undefined) !== (input.sourceRole === undefined)) {
      throw new SchemaValidationError({
        message: 'sourceOperationId and sourceRole must be supplied together',
        claim_type: input.claimType,
      });
    }
    const claimId = ids.passportClaim();
    const stored = input.sourceOperationId && input.sourceRole && !options.persistence
      ? await this.deps.repo.insertFromSource({
          claim_id: claimId,
          passport_id: input.passportJti as unknown as string,
          type: input.claimType,
          body_json: parsedPayload as Record<string, unknown>,
          claim_hash: claimHash,
          signature: '',
          operator_id: input.operatorId,
          subject,
          envelope_version: 1,
          claim_version: input.claimVersion ?? 1,
          envelope_cose: envelopeCose,
          issuer: input.operatorId,
          issued_at_ms: envelope.issued_at,
          receipt: null,
          source_operation_id: input.sourceOperationId,
          source_role: input.sourceRole,
        })
      : await (options.persistence ?? this.deps.repo).insert({
      claim_id: claimId,
      // Operator-scoped claims (subjectOverride='operator') persist
      // with passport_id = null; the legacy NOT NULL constraint was
      // dropped in migration 0005. The Drizzle
      // $inferInsert type re-derives from schema.ts on next build; this
      // cast bridges the window while shared/dist catches up.
      passport_id: input.passportJti as unknown as string,
      type: input.claimType,
      // Legacy body_json + signature columns kept for backward-compat
      // schema invariants; envelope-shape rows authoritative source is
      // envelope_cose, not these.
      body_json: parsedPayload as Record<string, unknown>,
      claim_hash: claimHash,
      signature: '',
      // Envelope columns (chunk 2 migration)
      operator_id: input.operatorId,
      subject,
      envelope_version: 1,
      claim_version: input.claimVersion ?? 1,
      envelope_cose: envelopeCose,
      issuer: input.operatorId,
      issued_at_ms: envelope.issued_at,
      receipt: null,
    });

    if (stored.claim_id !== claimId) {
      const same = stored.operator_id === input.operatorId
        && stored.passport_id === (input.passportJti ?? null)
        && stored.type === input.claimType
        && canonicalize(stored.body_json) === canonicalize(parsedPayload);
      if (!same || !stored.envelope_cose || !stored.subject) {
        throw new Error('Durable claim producer identity conflicts with existing signed content');
      }
      return {
        claimId: stored.claim_id,
        envelopeCose: stored.envelope_cose,
        subject: stored.subject,
      };
    }

    // post-persist hook for intent_outcome claims.
    // Fire-and-forget against the simulation_divergence detector;
    // errors logged, never bubbled (the outcome registration itself
    // succeeded and must not be undone by a divergence-check failure).
    if (input.claimType === 'intent_outcome' && this.simulationDivergence && input.passportJti) {
      this.simulationDivergence.check({
        operatorId: input.operatorId,
        passportJti: input.passportJti,
        outcomeClaimId: claimId,
      }).catch((err: unknown) => {
        console.error('[ClaimRegistryService] simulation_divergence check failed:', safeErrorSummary(err));
      });
    }

    // post-persist hook for behavioral_genome claims.
    // Fire-and-forget against the genome_drift detector. Mirror of the
    // simulation_divergence block above. Cold-start (no prior_genome_ref)
    // and small-sample (prior.call_count < N) cases handled inside the
    // detector itself — the registry just passes the claim_id through.
    if (input.claimType === 'behavioral_genome' && this.behavioralDrift && input.passportJti) {
      this.behavioralDrift.check({
        operatorId: input.operatorId,
        passportJti: input.passportJti,
        claimId,
      }).catch((err: unknown) => {
        console.error('[ClaimRegistryService] genome_drift check failed:', safeErrorSummary(err));
      });
    }

    // post-persist twin mirror hook. Fires only for
    // intent_claim so the lookup (findByRealPassportJti) doesn't run
    // on every claim type. The hook implementation handles the no-
    // twin-run case (returns early). Best-effort: hook failure is
    // logged inside the hook + caught here as a backstop.
    if (input.claimType === 'intent_claim' && this.twinMirror && input.passportJti) {
      this.twinMirror.fire({
        realClaimId: claimId,
        realIntentClaim: input.payload as import('@stack/shared').IntentClaim,
        passportJti: input.passportJti,
        operatorId: input.operatorId,
      }).catch((err: unknown) => {
        console.error('[ClaimRegistryService] twin mirror hook failed:', safeErrorSummary(err));
      });
    }

    return { claimId, envelopeCose, subject };
  }

  /**
   * record an intent_denial with dedup.
   *
   * Computes parameters_hash = sha256(canonical(attempted_intent.parameters))
   * and looks up an existing active denial on the same passport whose
   * attempted_intent.named_intent + parameters_hash match. If found:
   * increments the storage-only metadata.retry_count and returns the
   * existing claim_id (signed envelope unchanged). If not found:
   * writes a fresh signed claim with retry_count=1.
   *
   * Append-only carve-out: incrementDenialMetadataRetryCount UPDATEs
   * body_json's metadata.retry_count. The signed envelope_cose +
   * claim_hash + claim_id are immutable; only the storage-side counter
   * ticks. Verifier interpretation per ADR Design Decision 7.
   *
   * Race note: this implementation does NOT take an advisory lock
   * (planned but deferred to 1.19b). Two concurrent denials of the
   * same Intent within the same passport TTL can produce 2 fresh
   * claims (retry_count=1 each) instead of 1 with retry_count=2.
   * Acceptable for v1 — rare and idempotently observable. The
   * dedup-via-(passport_jti, named_intent, parameters_hash) key works
   * deterministically on subsequent retries.
   */
  async recordIntentDenial(input: {
    operatorId: string;
    passportJti: string;
    attemptedIntent: import('@stack/shared').IntentClaim;
    denialReason: import('@stack/shared').IntentDenialClaim['denial_reason'];
    message: string;
    metadata?: Record<string, unknown>;
    denyingDetectorKey?: string;
  }): Promise<{ claimId: string; retryCount: number; deduped: boolean }> {
    // Canonicalize attempted_intent.parameters → sha256 hex.
    const canonical = JSON.stringify(
      input.attemptedIntent.parameters,
      Object.keys(input.attemptedIntent.parameters).sort(),
    );
    const parametersHash = createHash('sha256').update(canonical).digest('hex');

    const existing = await this.deps.repo.findActiveDenialByDedupKey(
      input.passportJti,
      input.attemptedIntent.named_intent,
      parametersHash,
    );
    if (existing) {
      const retryCount = await this.deps.repo.incrementDenialMetadataRetryCount(existing.claim_id);
      return { claimId: existing.claim_id, retryCount, deduped: true };
    }

    // Fresh denial — register a new claim with retry_count=1.
    // 5.0.4 — inherit mission_ref from the attempted intent (already
    // populated by the producer at intent-submit time). Denials filter
    // by mission cleanly because they mirror the intent's binding.
    const result = await this.registerClaim({
      operatorId: input.operatorId,
      passportJti: input.passportJti,
      claimType: 'intent_denial',
      payload: {
        type: 'intent_denial',
        attempted_intent: input.attemptedIntent,
        denial_reason: input.denialReason,
        ...(input.denyingDetectorKey ? { denying_detector_key: input.denyingDetectorKey } : {}),
        message: input.message,
        parameters_hash: parametersHash,
        retry_count: 1,
        metadata: { retry_count: 1, ...(input.metadata ?? {}) },
        denied_at: Date.now(),
        ...(input.attemptedIntent.mission_ref
          ? { mission_ref: input.attemptedIntent.mission_ref }
          : {}),
      },
    });
    return { claimId: result.claimId, retryCount: 1, deduped: false };
  }

  /**
   * Fetch a claim by id, verify its COSE_Sign1 envelope against the
   * operator's JWKS, return the decoded envelope. Returns valid=false
   * with a typed error for any failure mode (row not found, legacy
   * JWS row, kid not in JWKS, signature mismatch).
   */
  async verifyClaim(claimId: string): Promise<ClaimVerifyResult> {
    const row = await this.deps.repo.findByClaimId(claimId);
    if (!row) {
      return { valid: false, error: `claim ${claimId} not found` };
    }
    if (!row.envelope_cose) {
      return {
        valid: false,
        error: `claim ${claimId} is a legacy JWS-shape row (pre-envelope); use ` +
          `PassportService.verifyAttachedClaim() instead`,
      };
    }
    if (!row.operator_id) {
      return { valid: false, error: `claim ${claimId} missing operator_id (data integrity error)` };
    }
    return this.verifyEnvelopeRow(row);
  }

  /**
   * List active envelope-shape claims attached to a subject (typically
   * a passport URI). Skips legacy JWS rows. Verifies each row's COSE
   * envelope; rows that fail verification are dropped silently from
   * the result (caller cannot rely on a stale verifier for active
   * claim state).
   *
   * Hot path — hits `pc_subject_active_idx` (partial index ON subject
   * WHERE revoked_at IS NULL).
   */
  async listBySubject(subject: string): Promise<ListBySubjectEntry[]> {
    const rows = await this.deps.repo.findActiveBySubject(subject);
    const verified: ListBySubjectEntry[] = [];
    for (const row of rows) {
      if (!row.envelope_cose || !row.operator_id) continue;
      const result = await this.verifyEnvelopeRow(row);
      if (result.valid && result.envelope) {
        verified.push({ claim_id: row.claim_id, envelope: result.envelope });
      }
    }
    return verified;
  }

  private async verifyEnvelopeRow(
    row: NonNullable<Awaited<ReturnType<PassportClaimsRepository['findByClaimId']>>>,
  ): Promise<ClaimVerifyResult> {
    if (!row.envelope_cose || !row.operator_id) {
      return { valid: false, error: `claim ${row.claim_id} lacks an envelope or operator_id` };
    }

    const envelopeBytes = Buffer.from(row.envelope_cose, 'base64url');
    const computedHash = createHash('sha256').update(envelopeBytes).digest('hex');
    if (computedHash !== row.claim_hash) {
      return { valid: false, error: 'claim_hash does not match the exact stored COSE bytes' };
    }

    const operatorId = row.operator_id;
    const signatureResult = await ClaimSigner.verify(row.envelope_cose, async (kid) =>
      this.deps.resolvePublicJwk(operatorId, kid),
    );
    if (!signatureResult.valid || !signatureResult.envelope) return signatureResult;

    const parsedEnvelope = ClaimEnvelopeSchema.safeParse(signatureResult.envelope);
    if (!parsedEnvelope.success) {
      return { ...signatureResult, valid: false, envelope: undefined, error: 'claim envelope schema validation failed' };
    }
    const envelope = parsedEnvelope.data;

    if (row.issuer !== row.operator_id || envelope.issuer !== row.operator_id) {
      return {
        ...signatureResult,
        valid: false,
        envelope: undefined,
        error: 'operator_id/issuer mismatch between row and signed envelope',
      };
    }
    if (row.subject !== envelope.subject) {
      return { ...signatureResult, valid: false, envelope: undefined, error: 'subject mismatch between row and signed envelope' };
    }
    const expectedSubject = row.passport_id
      ? subjectForPassport(row.operator_id, row.passport_id)
      : subjectForOperator(row.operator_id);
    if (envelope.subject !== expectedSubject) {
      return {
        ...signatureResult,
        valid: false,
        envelope: undefined,
        error: 'passport_id/subject scope mismatch between row and signed envelope',
      };
    }
    if (row.type !== envelope.claim_type) {
      return { ...signatureResult, valid: false, envelope: undefined, error: 'type mismatch between row and signed envelope' };
    }
    if (row.envelope_version !== envelope.envelope_version) {
      return { ...signatureResult, valid: false, envelope: undefined, error: 'envelope_version mismatch between row and signed envelope' };
    }
    if (row.claim_version !== envelope.claim_version) {
      return { ...signatureResult, valid: false, envelope: undefined, error: 'claim_version mismatch between row and signed envelope' };
    }
    if (row.issued_at_ms !== envelope.issued_at) {
      return { ...signatureResult, valid: false, envelope: undefined, error: 'issued_at_ms mismatch between row and signed envelope' };
    }
    if (envelope.claim_version !== 1) {
      return { ...signatureResult, valid: false, envelope: undefined, error: `unsupported claim_version ${envelope.claim_version}` };
    }

    const payloadSchema = PASSPORT_CLAIM_SCHEMAS[envelope.claim_type as PassportClaimType];
    if (!payloadSchema) {
      return { ...signatureResult, valid: false, envelope: undefined, error: `unsupported claim type '${envelope.claim_type}'` };
    }
    const parsedPayload = payloadSchema.safeParse(envelope.payload);
    if (!parsedPayload.success) {
      return { ...signatureResult, valid: false, envelope: undefined, error: 'payload schema validation failed' };
    }

    return {
      ...signatureResult,
      valid: true,
      envelope: { ...envelope, payload: parsedPayload.data },
    };
  }

  /**
   * Cascade-revoke every active claim attached to a passport. Used by
   * passport-service.revoke() to propagate the revoke through the
   * registry. Returns the count of rows affected for caller logging.
   *
   * Idempotent: re-revoking already-revoked claims is a no-op (the
   * underlying `markAllRevokedByPassportId` filters `revoked_at IS
   * NULL`).
   */
  async cascadeRevoke(
    passportJti: string,
    reason: string,
  ): Promise<{ revokedCount: number; claimIds: string[] }> {
    const revoked = await this.deps.repo.markAllRevokedByPassportId(passportJti, reason);
    return {
      revokedCount: revoked.length,
      claimIds: revoked.map((r) => r.claim_id),
    };
  }

  /**
   * Fetch one claim by id without verifying. For admin / debug surfaces
   * where the caller wants the raw row, not the verified envelope.
   * Throws NotFoundError if absent.
   */
  async getClaim(claimId: string) {
    const row = await this.deps.repo.findByClaimId(claimId);
    if (!row) throw new NotFoundError('claim', claimId);
    return row;
  }
}
