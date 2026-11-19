/** Receiver presentation requests and their delivery. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  canonicalize,
  deployment,
  generateId,
  type ReceiverChallengeInput,
} from '@stack/shared';
import type {
  AuthorityBindingRecord,
  AuthorityPresentationRecord,
  AuthorityProofRecord,
  AuthorityReceiverAuthContext,
  AuthorityReceiverRecord,
  AuthorityUseRecord,
} from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import type { AuthorityRepositoryPort } from './port.js';
import { ApprovalService } from './approvals.js';
import { AuthorityCore } from './core.js';
import { AuthorityGuards } from './guards.js';
import { DomainSemantics } from './semantics.js';
import { EvaluationService } from './evaluation.js';
import { RuntimeUseService } from './runtime-use.js';
import {
  assertBoundedJwtLifetime,
  assertReceiverKeyUsable,
  validatePublicHttpsEndpoint,
  AUTHORITY_ASSERTION_MAX_SECONDS,
  AUTHORITY_PRESENTATION_MAX_SECONDS,
} from './receiver-validation.js';
import {
  authorityAgentKeyThumbprint,
  bindingDigest,
  sha256,
  transactionRequestHash,
  transactionResourceHash,
} from './digest.js';
import {
  assertRequiredProofsLive,
  buildDisclosureManifest,
  buildEvidenceRefs,
  deduplicateProofRows,
} from './disclosure.js';
import { FactDisclosure } from './fact-disclosure.js';
import { verifyPresentationAgentProof } from './agent-proof.js';
import { safePresentation } from './redaction.js';

export class PresentationService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(
    private readonly core: AuthorityCore,
    private readonly guards: AuthorityGuards,
    private readonly semantics: DomainSemantics,
    private readonly evaluation: EvaluationService,
    private readonly approvals: ApprovalService,
    private readonly runtimeUse: RuntimeUseService,
    private readonly facts: FactDisclosure,
  ) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async createPresentationRequest(
    auth: AuthorityReceiverAuthContext,
    input: ReceiverChallengeInput,
  ) {
    const { receiver, profile, protocol, requestKey, requestExpiry, requestMaximumAge, now } =
      await this.verifyReceiverChallenge(auth, input);
    const requestedFacts = input.requested_facts;
    const receiverConfig = profile.config_json;
    const receiverFacts = new Map(
      ((receiverConfig.required_facts as Array<Record<string, unknown>>) ?? []).map((fact) => [
        String(fact.fact_id),
        fact,
      ]),
    );
    const { binding, use: authorizedUse } = await this.authorizeNativeUse(
      auth,
      input,
      receiver,
      requestMaximumAge,
      now,
    );
    const authorizedUseId = authorizedUse.id;
    const authorizedUseOperatorId = authorizedUse.operator_id;
    const deliveryUse = authorizedUse;
    try {
      return await this.deps.repo.atomic(async (repo) => {
        let use = deliveryUse;
        await repo.lockBindingGraphForDisclosure(use!.operator_id, binding.id, binding.version);
        await this.guards.assertBindingUsable(repo, binding, now);
        const disclosure = await this.guards.decryptBindingDisclosure(binding);
        await this.approvals.ensureApprovalRequests(
          repo,
          binding,
          'presentation',
          use.request_hash,
          use.id,
        );
        if (
          await repo.hasUnsatisfiedApprovals(
            use.operator_id,
            binding.id,
            binding.version,
            use.request_hash,
          )
        ) {
          throw new ForbiddenError('principal confirmation is required before disclosure');
        }
        await repo.consumeSatisfiedApprovals({
          operatorId: use.operator_id,
          bindingId: binding.id,
          bindingVersion: binding.version,
          phase: 'presentation',
          requestHash: use.request_hash,
          now,
        });
        const { bindingRules, manifest } = buildDisclosureManifest(
          requestedFacts,
          receiverFacts,
          disclosure.rules,
        );
        const links = await repo.listBindingProofs(use.operator_id, binding.id, binding.version);
        const resolvedProofRows = (
          await Promise.all(
            links.map((link) =>
              repo.findProof(use!.operator_id, link.proof_id, link.proof_version),
            ),
          )
        ).filter((proof): proof is AuthorityProofRecord => Boolean(proof));
        const proofRows = deduplicateProofRows(resolvedProofRows);
        if (disclosure.live_status_required || receiverConfig.live_status_required === true) {
          assertRequiredProofsLive(links, proofRows, now);
        }
        const disclosedFacts = await this.facts.discloseFacts(repo, {
          use,
          receiverId: receiver.id,
          receiverConfig,
          manifest,
          bindingRules,
          proofRows,
          now,
        });
        use = await this.upgradeIssuerEvidenceStrength(repo, use, binding, disclosedFacts);
        const delivery = receiverConfig.delivery as Record<string, unknown>;
        const endpoint = await validatePublicHttpsEndpoint(String(delivery.endpoint));
        const encryptionKeyIds = delivery.encryption_key_ids as string[];
        const encryptionKeys = await repo.listReceiverKeys(receiver.id, 'response_encryption');
        const encryptionKey = encryptionKeys.find(
          (key) =>
            encryptionKeyIds.includes(key.key_id) &&
            key.status === 'active' &&
            key.valid_from <= now &&
            (!key.valid_until || key.valid_until > now),
        );
        if (!encryptionKey)
          throw new ServiceUnavailableError('receiver response-encryption key is unavailable');
        const id = generateId('prs');
        const presentationJti = generateId('pjt');
        const expiresAt = new Date(Math.min(requestExpiry * 1000, binding.expires_at.getTime()));
        const encryptedRequest = await this.deps.kms.encrypt(input.signed_request, {
          operator_id: use.operator_id,
          presentation_id: id,
          store: 'authority_presentation_request',
        });
        const row: AuthorityPresentationRecord = {
          id,
          operator_id: use.operator_id,
          authority_use_id: use.id,
          binding_id: binding.id,
          binding_version: binding.version,
          receiver_id: receiver.id,
          receiver_profile_version_id: profile.id,
          request_signing_key_id: requestKey!.id,
          response_encryption_key_id: encryptionKey.id,
          nonce_hash: sha256(input.nonce),
          state_hash: null,
          signed_request_hash: sha256(input.signed_request),
          request_payload_encrypted: encryptedRequest.ciphertext,
          requested_fact_ids: manifest.map((item) => item.fact_id),
          presentation_jti_hash: sha256(presentationJti),
          payload_hash: null,
          disclosure_manifest: manifest,
          proof_refs: proofRows.map((proof) => ({ id: proof.id, version: proof.version })),
          signing_key_id: null,
          signing_algorithm: null,
          key_management_algorithm: null,
          content_encryption_algorithm: null,
          status: 'pending',
          created_at: now,
          expires_at: expiresAt,
          prepared_at: null,
          delivered_at: null,
          last_error_code: null,
          erased_at: null,
          tombstone_hash: null,
          tombstone_claim_id: null,
        };
        await repo.insertPresentation(row);
        const evidenceRefs = buildEvidenceRefs(links, proofRows, disclosedFacts);
        const approvalEvidence = await repo.listSatisfiedApprovalClaimRefs({
          operatorId: use.operator_id,
          bindingId: binding.id,
          bindingVersion: binding.version,
          authorityUseId: use.id,
        });
        const payload = {
          iss: deployment().presentationIssuer,
          aud: profile.audience,
          jti: presentationJti,
          iat: Math.floor(now.getTime() / 1000),
          exp: Math.floor(expiresAt.getTime() / 1000),
          authority_use_id: use.id,
          agent_id: use.agent_id,
          agent_key_thumbprint: use.agent_key_thumbprint,
          binding_ref: await this.guards.authorityReference(binding),
          principal_ref: binding.principal_id,
          mission_id: use.mission_id,
          action_uri: use.action_uri,
          resource_hash: use.resource_hash,
          request_hash: use.request_hash,
          receiver_id: use.receiver_id,
          receiver_profile_version_id: use.receiver_profile_version_id,
          domain_profile_version_id: use.domain_profile_version_id,
          proof_profile_version_ids: [
            ...new Set(evidenceRefs.map((proof) => proof.profile_version_id)),
          ],
          live_check_time: Math.floor(now.getTime() / 1000),
          evidence_refs: evidenceRefs,
          approval_claim_refs: approvalEvidence.claimRefs,
          approval_requirements: approvalEvidence.requirements,
          proof_strength: use.proof_strength,
          nonce: input.nonce,
          disclosed_facts: disclosedFacts,
        };
        await repo.updatePresentation({
          receiverId: receiver.id,
          presentationId: id,
          from: ['pending'],
          patch: {
            status: 'prepared',
            payload_hash: sha256(canonicalize(payload)),
            prepared_at: this.now(),
          },
        });
        const dispatched = await repo.markAuthorityUseDispatched(
          use.operator_id,
          use.id,
          this.now(),
        );
        if (!dispatched) throw new ConflictError('authority use dispatch transition failed');
        try {
          const delivered = await protocol.signEncryptAndDeliver({
            payload,
            receiverKey: encryptionKey,
            endpoint: endpoint.normalized,
            resolvedAddresses: endpoint.addresses,
            audience: profile.audience,
            presentationId: id,
          });
          const updated = await repo.updatePresentation({
            receiverId: receiver.id,
            presentationId: id,
            from: ['prepared'],
            patch: {
              status: 'delivered',
              payload_hash: delivered.payloadHash,
              signing_key_id: delivered.signingKeyId,
              signing_algorithm: 'EdDSA',
              key_management_algorithm: 'ECDH-ES+A256KW',
              content_encryption_algorithm: 'A256GCM',
              delivered_at: delivered.deliveredAt,
            },
          });
          if (!updated)
            throw new ConflictError('authority presentation delivery transition failed');
          return safePresentation(updated);
        } catch (error) {
          await repo.updatePresentation({
            receiverId: receiver.id,
            presentationId: id,
            from: ['prepared'],
            patch: {
              status: 'delivery_failed',
              last_error_code: 'DELIVERY_FAILED',
              request_payload_encrypted: null,
            },
          });
          await this.runtimeUse.completeRuntimeAuthorityUse({
            operatorId: use.operator_id,
            useId: use.id,
            outcome: 'failed',
            exactResult: { code: 'DELIVERY_FAILED' },
          });
          if (
            error instanceof ForbiddenError ||
            error instanceof ConflictError ||
            error instanceof ServiceUnavailableError
          )
            throw error;
          throw new ServiceUnavailableError('authority presentation delivery failed');
        }
      });
    } catch (error) {
      const current = await this.deps.repo.findAuthorityUseForOperator(
        authorizedUseOperatorId,
        authorizedUseId,
      );
      if (current?.status === 'authorized') {
        await this.runtimeUse.completeRuntimeAuthorityUse({
          operatorId: authorizedUseOperatorId,
          useId: authorizedUseId,
          outcome: 'failed',
          exactResult: { code: 'PRESENTATION_PREPARATION_FAILED' },
        });
      }
      if (
        error instanceof ForbiddenError ||
        error instanceof ConflictError ||
        error instanceof ServiceUnavailableError
      )
        throw error;
      throw new ServiceUnavailableError('authority presentation preparation failed');
    }
  }

  /** Verifies the receiver's signed challenge and consumes its single-use identifier. */
  private async verifyReceiverChallenge(
    auth: AuthorityReceiverAuthContext,
    input: ReceiverChallengeInput,
  ) {
    const receiver = await this.deps.repo.findReceiverById(auth.receiverId);
    if (!receiver) throw new ForbiddenError('receiver is unavailable');
    const profile = await this.deps.repo.findReceiverProfile(
      receiver.managed_by_operator_id,
      input.receiver_profile_version_id,
    );
    if (
      !receiver ||
      receiver.status !== 'active' ||
      !profile ||
      profile.status !== 'active' ||
      receiver.current_profile_version_id !== profile.id
    ) {
      throw new ForbiddenError('receiver or profile is no longer active');
    }
    const protocol = this.core.presentationProtocolForConfig(profile.config_json);
    protocol.validateProfile(profile.config_json);
    const route = protocol.peekReceiverRequest(input.signed_request);
    if (route.receiverId !== receiver.id)
      throw new ForbiddenError('receiver challenge issuer mismatch');
    const requestKey = await this.deps.repo.findReceiverKey(
      receiver.id,
      route.keyId,
      'request_signing',
    );
    const now = this.now();
    assertReceiverKeyUsable(requestKey, now, route.algorithm);
    const request = (
      await protocol.verifyPresentationRequest({
        compactRequest: input.signed_request,
        receiver,
        profile,
        key: requestKey,
        audience: `${this.deps.receiverRequestAudience.replace(/\/$/, '')}/v1/authority/presentation-requests`,
        now,
      })
    ).payload;
    const duplicated = {
      authority_ref: input.authority_ref,
      receiver_profile_version_id: input.receiver_profile_version_id,
      receiver_request_id: input.receiver_request_id,
      mission_id: input.mission_id,
      action_uri: input.action_uri,
      resource_hash: input.resource_hash,
      request_hash: input.request_hash,
      requested_facts: input.requested_facts,
      nonce: input.nonce,
      issued_at: input.issued_at,
      expires_at: input.expires_at,
      passport_hash: sha256(input.passport),
      agent_proof_hash: sha256(input.agent_proof),
      normalized_request: input.normalized_request,
    };
    for (const [keyName, expected] of Object.entries(duplicated)) {
      if (canonicalize(request[keyName]) !== canonicalize(expected)) {
        throw new ForbiddenError(`receiver challenge signed payload mismatch for ${keyName}`);
      }
    }
    if (
      !request.jti ||
      Number(request.iat) !== input.issued_at ||
      Number(request.exp) !== input.expires_at
    ) {
      throw new ForbiddenError(
        'receiver challenge protected lifetime does not match its signed body',
      );
    }
    const requestExpiry = Number(request.exp);
    const requestIssuedAt = Number(request.iat);
    const requestAuth = profile.config_json.request_authentication as Record<string, unknown>;
    const requestMaximumAge = Math.min(
      Number(requestAuth.maximum_age_seconds ?? AUTHORITY_ASSERTION_MAX_SECONDS),
      AUTHORITY_PRESENTATION_MAX_SECONDS,
    );
    assertBoundedJwtLifetime(
      requestIssuedAt,
      requestExpiry,
      now,
      requestMaximumAge,
      'receiver challenge',
    );
    if (
      !(await this.deps.repo.consumeReceiverJti({
        receiverId: receiver.id,
        jtiHash: sha256(String(request.jti)),
        expiresAt: new Date(requestExpiry * 1000),
      }))
    ) {
      throw new ConflictError('receiver challenge expired or replayed');
    }
    return { receiver, profile, protocol, requestKey, requestExpiry, requestMaximumAge, now };
  }

  /**
   * Binds the challenge to a usable binding, the Passport's agent and its
   * proof of possession, then returns the authorized native authority use,
   * evaluating authority first when none exists yet.
   */
  private async authorizeNativeUse(
    auth: AuthorityReceiverAuthContext,
    input: ReceiverChallengeInput,
    receiver: AuthorityReceiverRecord,
    requestMaximumAge: number,
    now: Date,
  ) {
    const binding = await this.deps.repo.findBinding(
      receiver.managed_by_operator_id,
      input.authority_ref.binding_id,
      input.authority_ref.binding_version,
    );
    if (!binding) throw new ForbiddenError('authority binding is unavailable');
    await this.guards.assertBindingUsable(this.deps.repo, binding, now);
    await this.guards.assertReferenceMatches(binding, input.authority_ref);
    const passport = await this.deps.passportVerifier.verifyPresentationPassport({
      token: input.passport,
      operatorId: binding.operator_id,
      receiverId: receiver.id,
      authorityRef: input.authority_ref,
      missionId: input.mission_id,
    });
    const currentAgentKey = await this.deps.repo.resolveCurrentAgentKey(
      binding.operator_id,
      passport.agentId,
    );
    if (
      !currentAgentKey?.active ||
      binding.agent_id !== passport.agentId ||
      currentAgentKey.thumbprint !== binding.agent_key_thumbprint ||
      authorityAgentKeyThumbprint(
        currentAgentKey.publicJwk as { kty: string; crv: string; x: string },
      ) !== currentAgentKey.thumbprint
    ) {
      throw new ForbiddenError('agent proof-of-possession key is unavailable or stale');
    }
    await verifyPresentationAgentProof(this.deps.repo, {
      binding,
      currentAgentKey,
      receiverId: receiver.id,
      input,
      requestMaximumAge,
      now,
    });
    const normalizedRequestHash = transactionRequestHash(
      input.receiver_request_id,
      input.normalized_request,
    );
    if (normalizedRequestHash !== input.request_hash)
      throw new ForbiddenError('native request hash mismatch');
    const semantics = await this.semantics.resolveNativeSemantics(
      binding,
      input.normalized_request,
    );
    if (
      semantics.actionUri !== input.action_uri ||
      (semantics.resourceRef
        ? transactionResourceHash(input.receiver_request_id, semantics.resourceRef)
        : null) !== input.resource_hash
    ) {
      throw new ForbiddenError(
        'receiver-declared action/resource does not match the pinned domain profile',
      );
    }
    let use = await this.deps.repo.findAuthorityUseForPresentation(
      auth.receiverId,
      input.receiver_request_id,
      input.request_hash,
    );
    if (!use) {
      const evaluated = await this.evaluation.evaluateAuthority(binding.operator_id, {
        bindingId: binding.id,
        bindingVersion: binding.version,
        passportJti: passport.jti,
        agentId: passport.agentId,
        agentKeyThumbprint: currentAgentKey.thumbprint,
        receiverId: receiver.id,
        receiverRequestId: input.receiver_request_id,
        ...(input.mission_id ? { missionId: input.mission_id } : {}),
        actionUri: semantics.actionUri,
        ...(semantics.resourceRef ? { resourceRef: semantics.resourceRef } : {}),
        requestHash: input.request_hash,
        normalizedRequest: input.normalized_request,
        disclosureManifest: input.requested_facts,
        verificationMode: 'native_receiver',
      });
      if (!evaluated.allowed || !evaluated.authorityUseId)
        throw new ForbiddenError('authority approval is required');
      use = await this.deps.repo.findAuthorityUseById(receiver.id, evaluated.authorityUseId);
    }
    if (
      !use ||
      use.status !== 'authorized' ||
      use.receiver_profile_version_id !== input.receiver_profile_version_id ||
      use.passport_jti !== passport.jti ||
      use.agent_id !== passport.agentId
    ) {
      throw new ForbiddenError('native authority use is unavailable or mismatched');
    }
    return { binding, use };
  }

  /**
   * When every disclosed fact is issuer-native evidence, the authority use is
   * re-signed at that stronger proof strength before delivery.
   */
  private async upgradeIssuerEvidenceStrength(
    repo: AuthorityRepositoryPort,
    use: AuthorityUseRecord,
    binding: AuthorityBindingRecord,
    disclosedFacts: Array<Record<string, unknown>>,
  ): Promise<AuthorityUseRecord> {
    if (
      use.proof_strength === 'native_stack_attestation' &&
      disclosedFacts.length > 0 &&
      disclosedFacts.every((fact) => fact.proof_strength === 'native_issuer_evidence')
    ) {
      use = await repo.atomic(async (repo) => {
        const deliveredUse: AuthorityUseRecord = {
          ...use,
          proof_strength: 'native_issuer_evidence',
        };
        const claim = await this.deps.claimIssuer
          .registerAuthorityUseClaim(
            {
              operatorId: deliveredUse.operator_id,
              use: deliveredUse,
              bindingDigest: bindingDigest(
                binding,
                await repo.listBindingProofs(deliveredUse.operator_id, binding.id, binding.version),
              ),
              domainProfileVersionId: binding.domain_profile_version_id,
            },
            repo.currentTransaction(),
          )
          .catch(() => {
            throw new ServiceUnavailableError(
              'delivered authority proof-strength signing is unavailable',
            );
          });
        if (!claim.claimId || !claim.claimHash) {
          throw new ServiceUnavailableError(
            'delivered authority proof-strength claim is unavailable',
          );
        }
        const updated = await repo.setAuthorityUseProofStrength({
          operatorId: deliveredUse.operator_id,
          useId: deliveredUse.id,
          from: 'native_stack_attestation',
          to: 'native_issuer_evidence',
        });
        if (!updated)
          throw new ConflictError(
            'authority proof-strength transition lost a concurrent transition',
          );
        return updated;
      });
    }
    return use;
  }

  async getPresentationRequest(auth: AuthorityReceiverAuthContext, presentationId: string) {
    const row = await this.deps.repo.findPresentation(auth.receiverId, presentationId);
    if (!row) throw new NotFoundError('AuthorityPresentation', presentationId);
    return safePresentation(row);
  }
}
