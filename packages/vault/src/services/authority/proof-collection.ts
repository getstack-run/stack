/** Provider-driven proof collection sessions and their encrypted workflow state. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  canonicalize,
  generateId,
  isBlockedIp,
  type AuthorityProofCallbackInput,
  type CreateAuthorityProofCollectionSessionInput,
} from '@stack/shared';
import { isIP } from 'node:net';
import { randomBytes } from 'node:crypto';
import type {
  AuthorityProofAdapter,
  AuthorityProofCallbackAuthContext,
  AuthorityProofCollectionWorkflowPayload,
  AuthorityProofCollectionWorkflowRecord,
  AuthorityServiceDeps,
  VerifiedAuthorityProof,
} from './contracts.js';
import type { AuthorityProofProfileVersionRecord } from './records.js';
import type { AuthorityRepositoryPort } from './port.js';
import { AuthorityCore } from './core.js';
import { readFact } from './fact-path.js';
import { safeProof } from './redaction.js';
import { persistExternalNativeProof } from './proof-persistence.js';
import { sha256 } from './digest.js';

export class ProofCollectionService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(private readonly core: AuthorityCore) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async createProofCollectionSession(
    operatorId: string,
    input: CreateAuthorityProofCollectionSessionInput,
    idempotencyKey: string,
  ) {
    if (!idempotencyKey) throw new ForbiddenError('Idempotency-Key is required');
    const [principal, profile] = await Promise.all([
      this.deps.repo.findPrincipal(operatorId, input.subject_principal_id),
      this.deps.repo.findProofProfileVersion(operatorId, input.profile_version_id),
    ]);
    if (!principal || principal.status !== 'active')
      throw new NotFoundError('AuthorityPrincipal', input.subject_principal_id);
    if (input.represented_principal_id) {
      const represented = await this.deps.repo.findPrincipal(
        operatorId,
        input.represented_principal_id,
      );
      if (!represented || represented.status !== 'active')
        throw new NotFoundError('AuthorityPrincipal', input.represented_principal_id);
    }
    if (
      !profile ||
      profile.status !== 'active' ||
      !profile.accepted_native_formats.includes(input.native_format)
    ) {
      throw new ForbiddenError('authority proof collection profile is unavailable or incompatible');
    }
    const validation = profile.config_json.validation as Record<string, unknown>;
    const acceptedIssuers = (validation.accepted_issuer_ids as string[]) ?? [];
    if (!acceptedIssuers.includes(input.issuer_identifier)) {
      throw new ForbiddenError('authority proof issuer is not accepted by the immutable profile');
    }
    const adapter = this.core.adapters.get(`${profile.adapter_key}@${profile.adapter_version}`);
    if (!adapter?.initiateCollection)
      throw new ServiceUnavailableError('required proof collection adapter is unavailable');

    const sessionId = generateId('pcs');
    const ledgerId = generateId('aik');
    const now = this.now();
    const ceremonyExpiresAt = new Date(now.getTime() + 15 * 60_000);
    const ledgerExpiresAt = new Date(now.getTime() + 24 * 60 * 60_000);
    const stateClaims = canonicalize({
      ledger_id: ledgerId,
      operator_id: operatorId,
      session_id: sessionId,
      profile_version_id: profile.id,
      exp: Math.floor(ceremonyExpiresAt.getTime() / 1000),
      nonce: randomBytes(16).toString('base64url'),
    });
    const stateCipher = await this.deps.kms.encrypt(stateClaims, {
      operator_id: operatorId,
      ledger_id: ledgerId,
      session_id: sessionId,
      store: 'authority_proof_collection_state',
    });
    const stateToken = Buffer.from(stateCipher.ciphertext, 'utf8').toString('base64url');
    const payload: AuthorityProofCollectionWorkflowPayload = {
      request: input,
      adapter_key: profile.adapter_key,
      adapter_version: profile.adapter_version,
      state_hash: sha256(stateToken),
      state_token: stateToken,
      ceremony_expires_at: ceremonyExpiresAt.toISOString(),
      initiation_operation_id: `proof-session:${sessionId}:initiate:v1`,
    };
    const payloadEncrypted = await this.encryptProofWorkflowPayload(
      operatorId,
      ledgerId,
      sessionId,
      payload,
    );
    const reserved = await this.deps.repo.reserveProofCollectionWorkflow({
      ledgerId,
      operatorId,
      sessionId,
      idempotencyKey,
      requestHash: sha256(payloadEncrypted),
      workflowPayloadEncrypted: payloadEncrypted,
      expiresAt: ledgerExpiresAt,
      now,
    });
    const storedPayload = await this.decryptProofWorkflowPayload(reserved.workflow);
    if (canonicalize(storedPayload.request) !== canonicalize(input)) {
      throw new ConflictError(
        'Idempotency-Key was already used with a different proof collection request',
      );
    }
    if (
      reserved.workflow.workflow_phase === 'ready' ||
      reserved.workflow.workflow_phase === 'completed'
    ) {
      return this.safeProofCollectionWorkflow(
        reserved.workflow,
        storedPayload,
        storedPayload.state_token,
      );
    }
    const leaseToken = randomBytes(32).toString('base64url');
    const leased = await this.deps.repo.acquireProofCollectionWorkflowLease({
      operatorId,
      sessionId: reserved.workflow.session_id,
      from: ['reserved'],
      to: 'initiating',
      leaseTokenHash: sha256(leaseToken),
      leaseExpiresAt: new Date(now.getTime() + 30_000),
      now,
    });
    if (!leased?.acquired) {
      const current =
        leased?.workflow ??
        (await this.deps.repo.findProofCollectionWorkflow(
          reserved.workflow.session_id,
          operatorId,
        ));
      if (current?.workflow_phase === 'ready' || current?.workflow_phase === 'completed') {
        const currentPayload = await this.decryptProofWorkflowPayload(current);
        return this.safeProofCollectionWorkflow(
          current,
          currentPayload,
          currentPayload.state_token,
        );
      }
      throw new ConflictError('proof collection initiation is already in progress');
    }
    const initiated = await adapter
      .initiateCollection({
        operationId: storedPayload.initiation_operation_id,
        sessionId: reserved.workflow.session_id,
        stateToken: storedPayload.state_token,
        subjectPrincipalId: input.subject_principal_id,
        ...(input.represented_principal_id
          ? { representedPrincipalId: input.represented_principal_id }
          : {}),
        issuerIdentifier: input.issuer_identifier,
        profile,
        nativeFormat: input.native_format,
      })
      .catch(() => {
        throw new ServiceUnavailableError('proof provider collection initiation is unavailable');
      });
    if (initiated.expiresAt <= now || initiated.expiresAt > ceremonyExpiresAt) {
      throw new ForbiddenError('proof provider returned an invalid collection lifetime');
    }
    if (initiated.authorizationUrl)
      this.assertAuthorizationUrl(adapter, initiated.authorizationUrl);
    const readyPayload: AuthorityProofCollectionWorkflowPayload = {
      ...storedPayload,
      ...(initiated.authorizationUrl ? { authorization_url: initiated.authorizationUrl } : {}),
      ...(initiated.providerSessionReference
        ? { provider_session_reference: initiated.providerSessionReference }
        : {}),
      provider_expires_at: initiated.expiresAt.toISOString(),
    };
    const readyEncrypted = await this.encryptProofWorkflowPayload(
      operatorId,
      reserved.workflow.ledger_id,
      reserved.workflow.session_id,
      readyPayload,
    );
    const ready = await this.deps.repo.transitionProofCollectionWorkflow({
      operatorId,
      sessionId: reserved.workflow.session_id,
      from: 'initiating',
      leaseTokenHash: sha256(leaseToken),
      to: 'ready',
      workflowPayloadEncrypted: readyEncrypted,
      now: this.now(),
    });
    if (!ready) throw new ConflictError('proof collection initiation lost a concurrent transition');
    return this.safeProofCollectionWorkflow(ready, readyPayload, readyPayload.state_token);
  }

  async getProofCollectionSession(operatorId: string, sessionId: string) {
    const workflow = await this.deps.repo.findProofCollectionWorkflow(sessionId, operatorId);
    if (!workflow) throw new NotFoundError('AuthorityProofCollectionSession', sessionId);
    return this.safeProofCollectionWorkflow(
      workflow,
      await this.decryptProofWorkflowPayload(workflow),
    );
  }

  async authenticateProofCallbackRequest(
    adapterKey: string,
    sessionId: string,
    input: {
      method: 'POST';
      path: string;
      headers: Readonly<Record<string, string | undefined>>;
      bodyHash: string;
    },
  ): Promise<AuthorityProofCallbackAuthContext> {
    const workflow = await this.deps.repo.findProofCollectionWorkflow(sessionId);
    if (!workflow || workflow.expires_at <= this.now())
      throw new ForbiddenError('proof callback is unavailable');
    const payload = await this.decryptProofWorkflowPayload(workflow).catch(() => {
      throw new ForbiddenError('proof callback is unavailable');
    });
    if (new Date(payload.provider_expires_at ?? payload.ceremony_expires_at) <= this.now()) {
      throw new ForbiddenError('proof callback is unavailable');
    }
    if (payload.adapter_key !== adapterKey)
      throw new ForbiddenError('proof callback is unavailable');
    const adapter = this.core.adapters.get(`${payload.adapter_key}@${payload.adapter_version}`);
    if (!adapter?.authenticateCallback) throw new ForbiddenError('proof callback is unavailable');
    const authenticated = await adapter.authenticateCallback(input).catch((error: unknown) => {
      if (error instanceof ServiceUnavailableError) throw error;
      throw new ForbiddenError('proof callback authentication failed');
    });
    return {
      adapterKey,
      callbackJti: authenticated.jti,
      issuerIdentifier: authenticated.issuerIdentifier,
      expiresAt: authenticated.expiresAt,
    };
  }

  async completeProofCollectionSession(
    auth: AuthorityProofCallbackAuthContext,
    input: AuthorityProofCallbackInput,
  ) {
    let workflow = await this.deps.repo.findProofCollectionWorkflow(input.session_id);
    if (!workflow || workflow.expires_at <= this.now())
      throw new ForbiddenError('proof callback is unavailable');
    let payload = await this.decryptProofWorkflowPayload(workflow);
    if (
      payload.adapter_key !== auth.adapterKey ||
      payload.request.issuer_identifier !== auth.issuerIdentifier ||
      payload.state_hash !== sha256(input.state_token)
    ) {
      throw new ForbiddenError('proof callback is not bound to this collection session');
    }
    const callbackHash = sha256(input.signed_callback);
    const callbackJtiHash = sha256(auth.callbackJti);
    if (
      payload.callback_hash &&
      (payload.callback_hash !== callbackHash || payload.callback_jti_hash !== callbackJtiHash)
    ) {
      throw new ConflictError('proof collection callback replay used different evidence');
    }
    if (workflow.workflow_phase === 'completed' && payload.proof_view) return payload.proof_view;
    if (
      auth.expiresAt <= this.now() ||
      new Date(payload.provider_expires_at ?? payload.ceremony_expires_at) <= this.now()
    ) {
      throw new ForbiddenError('proof callback is unavailable');
    }
    const adapter = this.core.adapters.get(`${payload.adapter_key}@${payload.adapter_version}`);
    if (!adapter?.completeCollection)
      throw new ServiceUnavailableError('required proof collection adapter is unavailable');
    if (!payload.callback_result) {
      const leaseToken = randomBytes(32).toString('base64url');
      const leased = await this.deps.repo.acquireProofCollectionWorkflowLease({
        operatorId: workflow.operator_id,
        sessionId: workflow.session_id,
        from: ['ready'],
        to: 'callback_verifying',
        leaseTokenHash: sha256(leaseToken),
        leaseExpiresAt: new Date(this.now().getTime() + 30_000),
        now: this.now(),
      });
      if (!leased?.acquired)
        throw new ConflictError('proof callback verification is already in progress');
      const operationId = `proof-session:${workflow.session_id}:callback:${callbackJtiHash}:v1`;
      const completed = await adapter
        .completeCollection({
          operationId,
          sessionId: workflow.session_id,
          signedCallback: input.signed_callback,
          expectedIssuerIdentifier: payload.request.issuer_identifier,
          ...(payload.provider_session_reference
            ? { providerSessionReference: payload.provider_session_reference }
            : {}),
        })
        .catch(() => {
          throw new ServiceUnavailableError('proof provider callback completion is unavailable');
        });
      const profile = await this.deps.repo.findProofProfileVersion(
        workflow.operator_id,
        payload.request.profile_version_id,
      );
      if (!profile || profile.status !== 'active')
        throw new ForbiddenError('proof collection profile is unavailable');
      const verified = await adapter.verify({
        nativeEvidence: completed.nativeEvidence,
        nativeFormat: completed.nativeFormat,
        expectedIssuer: payload.request.issuer_identifier,
        expectedSubjectPrincipalId: payload.request.subject_principal_id,
        ...(payload.request.represented_principal_id
          ? { expectedRepresentedPrincipalId: payload.request.represented_principal_id }
          : {}),
        profile,
      });
      payload = {
        ...payload,
        callback_jti_hash: callbackJtiHash,
        callback_hash: callbackHash,
        callback_operation_id: operationId,
        callback_result: {
          native_evidence: completed.nativeEvidence,
          native_format: completed.nativeFormat,
          verified: {
            normalized_facts: verified.normalizedFacts,
            issuer_identifier: verified.issuerIdentifier,
            ...(verified.issuerKeyThumbprint
              ? { issuer_key_thumbprint: verified.issuerKeyThumbprint }
              : {}),
            subject_principal_id: verified.subjectPrincipalId,
            ...(verified.representedPrincipalId
              ? { represented_principal_id: verified.representedPrincipalId }
              : {}),
            verification_method: verified.verificationMethod,
            verifier_identifier: verified.verifierIdentifier,
            verifier_version: verified.verifierVersion,
            ...(verified.assuranceUri ? { assurance_uri: verified.assuranceUri } : {}),
            verified_at: verified.verifiedAt.toISOString(),
            valid_from: verified.validFrom.toISOString(),
            ...(verified.expiresAt ? { expires_at: verified.expiresAt.toISOString() } : {}),
            ...(verified.statusFreshUntil
              ? { status_fresh_until: verified.statusFreshUntil.toISOString() }
              : {}),
            signature_verified: verified.signatureVerified,
            ...(verified.signatureAlgorithm
              ? { signature_algorithm: verified.signatureAlgorithm }
              : {}),
            ...(verified.mandateTermsDigest
              ? { mandate_terms_digest: verified.mandateTermsDigest }
              : {}),
          },
        },
      };
      const encrypted = await this.encryptProofWorkflowPayload(
        workflow.operator_id,
        workflow.ledger_id,
        workflow.session_id,
        payload,
      );
      const verifiedWorkflow = await this.deps.repo.transitionProofCollectionWorkflow({
        operatorId: workflow.operator_id,
        sessionId: workflow.session_id,
        from: 'callback_verifying',
        leaseTokenHash: sha256(leaseToken),
        to: 'callback_verified',
        workflowPayloadEncrypted: encrypted,
        now: this.now(),
      });
      if (!verifiedWorkflow)
        throw new ConflictError('proof callback verification lost a concurrent transition');
      workflow = verifiedWorkflow;
    }
    const finalLease = randomBytes(32).toString('base64url');
    const finalLeased = await this.deps.repo.acquireProofCollectionWorkflowLease({
      operatorId: workflow.operator_id,
      sessionId: workflow.session_id,
      from: ['callback_verified'],
      to: 'callback_verifying',
      leaseTokenHash: sha256(finalLease),
      leaseExpiresAt: new Date(this.now().getTime() + 30_000),
      now: this.now(),
    });
    if (!finalLeased?.acquired)
      throw new ConflictError('proof collection finalization is already in progress');
    const result = payload.callback_result!;
    return this.deps.repo.atomic(async (repo) => {
      const profile = await repo.findProofProfileVersion(
        workflow.operator_id,
        payload.request.profile_version_id,
      );
      if (!profile || profile.status !== 'active')
        throw new ForbiddenError('proof collection profile is unavailable');
      const verified = this.deserializeProofCollectionVerification(result.verified);
      this.assertVerifiedProofMatchesProfile(profile, payload.request, verified, this.now());
      const proofView = await this.persistVerifiedProof(
        repo,
        workflow.operator_id,
        payload.request,
        profile,
        result.native_evidence,
        result.native_format,
        verified,
      );
      payload = { ...payload, proof_view: proofView };
      const finalEncrypted = await this.encryptProofWorkflowPayload(
        workflow.operator_id,
        workflow.ledger_id,
        workflow.session_id,
        payload,
      );
      const finalized = await repo.transitionProofCollectionWorkflow({
        operatorId: workflow.operator_id,
        sessionId: workflow.session_id,
        from: 'callback_verifying',
        leaseTokenHash: sha256(finalLease),
        to: 'completed',
        workflowPayloadEncrypted: finalEncrypted,
        now: this.now(),
        safeResponse: { proof: proofView },
        responseStatus: 201,
      });
      if (!finalized)
        throw new ConflictError('proof collection finalization lost a concurrent transition');
      return proofView;
    });
  }

  private proofWorkflowContext(operatorId: string, ledgerId: string, sessionId: string) {
    return {
      operator_id: operatorId,
      ledger_id: ledgerId,
      session_id: sessionId,
      store: 'authority_proof_collection_workflow',
    };
  }

  private async encryptProofWorkflowPayload(
    operatorId: string,
    ledgerId: string,
    sessionId: string,
    payload: AuthorityProofCollectionWorkflowPayload,
  ): Promise<string> {
    return (
      await this.deps.kms.encrypt(
        canonicalize(payload),
        this.proofWorkflowContext(operatorId, ledgerId, sessionId),
      )
    ).ciphertext;
  }

  private async decryptProofWorkflowPayload(
    workflow: AuthorityProofCollectionWorkflowRecord,
  ): Promise<AuthorityProofCollectionWorkflowPayload> {
    const plaintext = await this.deps.kms.decrypt(
      workflow.workflow_payload_encrypted,
      this.proofWorkflowContext(workflow.operator_id, workflow.ledger_id, workflow.session_id),
    );
    let payload: unknown;
    try {
      payload = JSON.parse(plaintext);
    } catch {
      throw new ForbiddenError('proof collection workflow state is invalid');
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new ForbiddenError('proof collection workflow state is invalid');
    }
    return payload as AuthorityProofCollectionWorkflowPayload;
  }

  private safeProofCollectionWorkflow(
    workflow: AuthorityProofCollectionWorkflowRecord,
    payload: AuthorityProofCollectionWorkflowPayload,
    stateToken?: string,
  ) {
    return {
      id: workflow.session_id,
      status: workflow.workflow_phase,
      authorization_url: payload.authorization_url ?? null,
      expires_at: payload.provider_expires_at ?? workflow.expires_at.toISOString(),
      ...(stateToken ? { state_token: stateToken } : {}),
      ...(payload.proof_view ? { proof: payload.proof_view } : {}),
    };
  }

  private assertAuthorizationUrl(adapter: AuthorityProofAdapter, raw: string): void {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new ForbiddenError('proof provider returned an invalid authorization URL');
    }
    const allowed = adapter.authorizationOrigins ?? [];
    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.hash ||
      isIP(url.hostname) !== 0 ||
      isBlockedIp(url.hostname) ||
      !allowed.includes(url.origin)
    ) {
      throw new ForbiddenError(
        'proof provider authorization URL is outside the pinned adapter policy',
      );
    }
  }

  private deserializeProofCollectionVerification(
    value: NonNullable<AuthorityProofCollectionWorkflowPayload['callback_result']>['verified'],
  ): VerifiedAuthorityProof {
    return {
      normalizedFacts: value.normalized_facts,
      issuerIdentifier: value.issuer_identifier,
      ...(value.issuer_key_thumbprint ? { issuerKeyThumbprint: value.issuer_key_thumbprint } : {}),
      verificationMethod: value.verification_method,
      verifierIdentifier: value.verifier_identifier,
      verifierVersion: value.verifier_version,
      ...(value.assurance_uri ? { assuranceUri: value.assurance_uri } : {}),
      verifiedAt: new Date(value.verified_at),
      validFrom: new Date(value.valid_from),
      ...(value.expires_at ? { expiresAt: new Date(value.expires_at) } : {}),
      ...(value.status_fresh_until ? { statusFreshUntil: new Date(value.status_fresh_until) } : {}),
      signatureVerified: value.signature_verified,
      ...(value.signature_algorithm ? { signatureAlgorithm: value.signature_algorithm } : {}),
      subjectPrincipalId: value.subject_principal_id,
      ...(value.represented_principal_id
        ? { representedPrincipalId: value.represented_principal_id }
        : {}),
      ...(value.mandate_terms_digest ? { mandateTermsDigest: value.mandate_terms_digest } : {}),
    };
  }

  private assertVerifiedProofMatchesProfile(
    profile: AuthorityProofProfileVersionRecord,
    input: CreateAuthorityProofCollectionSessionInput,
    verified: VerifiedAuthorityProof,
    verificationTime: Date,
  ): void {
    const validation = profile.config_json.validation as Record<string, unknown>;
    const freshness = profile.config_json.freshness as Record<string, unknown>;
    const acceptedIssuers = (validation.accepted_issuer_ids as string[]) ?? [];
    if (
      verified.issuerIdentifier !== input.issuer_identifier ||
      !acceptedIssuers.includes(verified.issuerIdentifier)
    ) {
      throw new ForbiddenError('authority proof issuer is not accepted by the immutable profile');
    }
    if (validation.signature_required === true && !verified.signatureVerified) {
      throw new ForbiddenError('authority proof signature was not verified');
    }
    const acceptedAlgs = (validation.accepted_signature_algs as string[]) ?? [];
    if (
      verified.signatureVerified &&
      (!verified.signatureAlgorithm || !acceptedAlgs.includes(verified.signatureAlgorithm))
    ) {
      throw new ForbiddenError('authority proof signature algorithm is not accepted');
    }
    if (
      verified.subjectPrincipalId !== input.subject_principal_id ||
      (verified.representedPrincipalId ?? undefined) !== input.represented_principal_id
    ) {
      throw new ForbiddenError('authority proof subject binding mismatch');
    }
    for (const factPath of (validation.required_claim_paths as string[]) ?? [])
      readFact(verified.normalizedFacts, factPath);
    if (
      !Number.isFinite(verified.verifiedAt.getTime()) ||
      !Number.isFinite(verified.validFrom.getTime()) ||
      verified.validFrom > verificationTime ||
      (verified.expiresAt && verified.expiresAt <= verificationTime)
    ) {
      throw new ForbiddenError('authority proof validity is invalid');
    }
    const maximumAge = Number(freshness.maximum_age_seconds ?? 0);
    if (
      !Number.isFinite(maximumAge) ||
      maximumAge < 0 ||
      verified.verifiedAt.getTime() + maximumAge * 1000 < verificationTime.getTime()
    ) {
      throw new ForbiddenError('authority proof is older than its immutable profile permits');
    }
    if (
      freshness.live_status_required === true &&
      (!verified.statusFreshUntil || verified.statusFreshUntil <= verificationTime)
    ) {
      throw new ServiceUnavailableError('authority proof profile requires live issuer status');
    }
  }

  private async persistVerifiedProof(
    repo: AuthorityRepositoryPort,
    operatorId: string,
    input: CreateAuthorityProofCollectionSessionInput,
    profile: AuthorityProofProfileVersionRecord,
    nativeEvidence: string,
    nativeFormat: string,
    verified: VerifiedAuthorityProof,
  ): Promise<Record<string, unknown>> {
    if (!profile.accepted_native_formats.includes(nativeFormat)) {
      throw new ForbiddenError('proof provider returned an unsupported native format');
    }
    return safeProof(
      await persistExternalNativeProof(this.core, repo, {
        operatorId,
        subjectPrincipalId: input.subject_principal_id,
        representedPrincipalId: input.represented_principal_id,
        profileVersionId: profile.id,
        proofKind: profile.proof_kind,
        schemaUri: profile.schema_uri,
        schemaVersion: profile.schema_version,
        nativeFormat,
        nativeEvidence,
        facts: verified.normalizedFacts,
        verified,
      }),
    );
  }
}
