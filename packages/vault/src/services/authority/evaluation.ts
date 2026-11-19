/** Authority evaluation: constraints, approvals and the runtime chokepoint. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  canonicalize,
  generateId,
  type AuthorityConstraint,
} from '@stack/shared';
import type {
  AuthorityBindingRecord,
  AuthorityEvaluationInput,
  AuthorityEvaluationResult,
  AuthorityProofRecord,
  AuthorityRuntimeBoundary,
  AuthorityUseInsert,
  AuthorityUseRecord,
} from './records.js';
import type { AuthorityRepositoryPort } from './port.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { ApprovalService } from './approvals.js';
import { AuthorityCore } from './core.js';
import { AuthorityGuards } from './guards.js';
import { DomainSemantics } from './semantics.js';
import { bindingDigest, transactionRequestHash, transactionResourceHash } from './digest.js';
import { readFact, valueAtPath } from './fact-path.js';

export class EvaluationService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(
    core: AuthorityCore,
    private readonly guards: AuthorityGuards,
    private readonly approvals: ApprovalService,
    private readonly semantics: DomainSemantics,
  ) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async evaluateAuthority(
    operatorId: string,
    input: AuthorityEvaluationInput,
  ): Promise<AuthorityEvaluationResult> {
    const binding = await this.deps.repo.findBinding(
      operatorId,
      input.bindingId,
      input.bindingVersion,
    );
    if (!binding) throw new NotFoundError('AuthorityBinding', input.bindingId);
    const now = this.now();
    await this.guards.assertBindingUsable(this.deps.repo, binding, now);
    if (
      binding.agent_id !== input.agentId ||
      binding.agent_key_thumbprint !== input.agentKeyThumbprint
    ) {
      throw new ForbiddenError('authority agent or proof-of-possession key mismatch');
    }
    if (binding.receiver_id !== input.receiverId)
      throw new ForbiddenError('authority receiver mismatch');
    if (
      binding.mission_ids.length > 0 &&
      (!input.missionId || !binding.mission_ids.includes(input.missionId))
    ) {
      throw new ForbiddenError('authority Mission mismatch');
    }
    if (
      transactionRequestHash(input.receiverRequestId, input.normalizedRequest) !== input.requestHash
    ) {
      throw new ForbiddenError(
        'authority request hash does not match the server-normalized request',
      );
    }
    const scope = await this.guards.decryptBindingScope(binding);
    const action = scope.actions.find((candidate) => candidate.action_uri === input.actionUri);
    if (!action) throw new ForbiddenError('authority action is outside scope');
    if (
      action.resource_refs.length > 0 &&
      (!input.resourceRef || !action.resource_refs.includes(input.resourceRef))
    ) {
      throw new ForbiddenError('authority resource is outside scope');
    }
    if (
      !(await this.constraintsPermit(
        this.deps.repo,
        binding,
        action.constraints,
        input.normalizedRequest,
      ))
    ) {
      throw new ForbiddenError('authority request violates a scope constraint');
    }
    const proofStrength =
      input.verificationMode === 'proxy_mediated'
        ? ('proxy_stack_enforced' as const)
        : ('native_stack_attestation' as const);
    const baseUse: AuthorityUseInsert = {
      id: generateId('aus'),
      operator_id: operatorId,
      binding_id: binding.id,
      binding_version: binding.version,
      passport_jti: input.passportJti,
      mission_id: input.missionId ?? null,
      agent_id: binding.agent_id,
      agent_key_thumbprint: binding.agent_key_thumbprint,
      receiver_id: binding.receiver_id,
      receiver_profile_version_id: binding.receiver_profile_version_id,
      domain_profile_version_id: binding.domain_profile_version_id,
      receiver_request_id: input.receiverRequestId,
      action_uri: input.actionUri,
      resource_hash: input.resourceRef
        ? transactionResourceHash(input.receiverRequestId, input.resourceRef)
        : null,
      request_hash: input.requestHash,
      effective_scope_hash: binding.scope_hash,
      proof_set_hash: binding.proof_set_hash,
      disclosure_manifest: input.disclosureManifest ?? [],
      verification_mode: input.verificationMode,
      proof_strength: proofStrength,
      status: 'waiting_approval',
      denial_code: 'APPROVAL_REQUIRED',
      created_at: now,
      authorized_at: null,
    };
    let use = await this.deps.repo.findAuthorityUseByRuntimeRequest(
      operatorId,
      binding.receiver_id,
      input.receiverRequestId,
    );
    if (
      use &&
      (use.passport_jti !== input.passportJti ||
        use.agent_id !== input.agentId ||
        use.binding_id !== binding.id ||
        use.binding_version !== binding.version ||
        use.request_hash !== input.requestHash ||
        use.action_uri !== input.actionUri ||
        use.mission_id !== (input.missionId ?? null) ||
        use.verification_mode !== input.verificationMode)
    ) {
      throw new ConflictError('authority request ID was already bound to a different transaction');
    }
    if (!use) {
      use = await this.deps.repo.atomic(async (repo) => {
        const signedWaiting = await this.deps.claimIssuer
          .registerAuthorityUseClaim(
            {
              operatorId,
              use: baseUse,
              bindingDigest: bindingDigest(
                binding,
                await repo.listBindingProofs(operatorId, binding.id, binding.version),
              ),
              domainProfileVersionId: binding.domain_profile_version_id,
            },
            repo.currentTransaction(),
          )
          .catch(() => {
            throw new ServiceUnavailableError('waiting authority use signing is unavailable');
          });
        if (!signedWaiting.claimId || !signedWaiting.claimHash)
          throw new ServiceUnavailableError('waiting authority use claim is unavailable');
        return repo.insertAuthorityUse(baseUse);
      });
    }
    if (
      use.status === 'authorized' ||
      use.status === 'dispatched' ||
      use.status === 'succeeded' ||
      use.status === 'failed'
    )
      return {
        allowed: true,
        authorityUseId: use.id,
        bindingId: binding.id,
        bindingVersion: binding.version,
        proofStrength: use.proof_strength,
        receiverId: binding.receiver_id,
        receiverProfileVersionId: binding.receiver_profile_version_id,
        executionState: use.status,
      };
    if (use.status !== 'waiting_approval')
      throw new ConflictError('authority request is already terminal or dispatched');
    await this.approvals.ensureApprovalRequests(
      this.deps.repo,
      binding,
      'action',
      input.requestHash,
      use.id,
    );
    if (
      await this.deps.repo.hasUnsatisfiedApprovals(
        operatorId,
        binding.id,
        binding.version,
        input.requestHash,
      )
    ) {
      return {
        allowed: false,
        authorityUseId: use.id,
        bindingId: binding.id,
        bindingVersion: binding.version,
        receiverId: binding.receiver_id,
        receiverProfileVersionId: binding.receiver_profile_version_id,
        denialCode: 'APPROVAL_REQUIRED',
      };
    }
    await this.deps.repo.consumeSatisfiedApprovals({
      operatorId,
      bindingId: binding.id,
      bindingVersion: binding.version,
      phase: 'action',
      requestHash: input.requestHash,
      now,
    });
    use = await this.deps.repo.atomic(async (repo) => {
      const authorizedTarget: AuthorityUseRecord = {
        ...use!,
        status: 'authorized',
        denial_code: null,
        authorized_at: now,
      };
      const signedUse = await this.deps.claimIssuer
        .registerAuthorityUseClaim(
          {
            operatorId,
            use: authorizedTarget,
            bindingDigest: bindingDigest(
              binding,
              await repo.listBindingProofs(operatorId, binding.id, binding.version),
            ),
            domainProfileVersionId: binding.domain_profile_version_id,
          },
          repo.currentTransaction(),
        )
        .catch(() => {
          throw new ServiceUnavailableError('authority use signing is unavailable');
        });
      if (!signedUse.claimId || !signedUse.claimHash)
        throw new ServiceUnavailableError('authority use claim is unavailable');
      const authorized = await repo.authorizeWaitingAuthorityUse(operatorId, use!.id, now);
      if (!authorized)
        throw new ConflictError('authority use authorization lost a concurrent transition');
      return authorized;
    });
    return {
      allowed: true,
      authorityUseId: use.id,
      bindingId: binding.id,
      bindingVersion: binding.version,
      proofStrength,
      receiverId: binding.receiver_id,
      receiverProfileVersionId: binding.receiver_profile_version_id,
      executionState: use.status,
    };
  }

  /**
   * Single runtime chokepoint for proxy, Skills, LLM and A2A. It loads the
   * Passport's persisted refs, selects exactly one active matching binding,
   * and refuses both zero matches and ambiguity before creating authority_use.
   */
  async evaluateRuntimeAuthority(input: {
    operatorId: string;
    passportJti: string;
    agentId: string;
    authenticatedAgentId: string | null;
    boundary: AuthorityRuntimeBoundary;
    receiverRequestId?: string | null;
    missionId?: string;
    normalizedRequest: unknown;
    requestHash?: string | null;
    verificationMode: 'native_receiver' | 'proxy_mediated';
  }): Promise<AuthorityEvaluationResult | { enforced: false }> {
    const refs = await this.deps.repo.listPassportRefs(input.operatorId, input.passportJti);
    if (refs.length === 0) return { enforced: false };
    const receiverRequestId = input.receiverRequestId;
    if (!receiverRequestId || !/^[A-Za-z0-9_-]{22,256}$/.test(receiverRequestId)) {
      throw new ForbiddenError(
        'authority-bearing request requires a stable high-entropy authority request ID',
      );
    }
    const requestHash = input.requestHash;
    if (!requestHash || !/^sha256:[0-9a-f]{64}$/.test(requestHash)) {
      throw new ForbiddenError(
        'authority-bearing request requires a transaction-bound request hash',
      );
    }
    if (!input.authenticatedAgentId || input.authenticatedAgentId !== input.agentId) {
      throw new ForbiddenError(
        'authority-bearing Passport requires matching authenticated agent proof of possession',
      );
    }
    const currentKey = await this.deps.repo.resolveCurrentAgentKey(input.operatorId, input.agentId);
    if (!currentKey?.active) throw new ForbiddenError('authority agent key is unavailable');
    const computedRequestHash = transactionRequestHash(receiverRequestId, input.normalizedRequest);
    if (computedRequestHash !== requestHash)
      throw new ForbiddenError('runtime request hash mismatch');
    const receivers = await this.deps.repo.resolveRuntimeReceivers(
      input.operatorId,
      input.boundary,
    );
    if (receivers.length === 0)
      throw new ForbiddenError('no authority receiver matches the runtime destination');
    if (receivers.length > 1) throw new ForbiddenError('authority receiver mapping is ambiguous');
    const receiver = receivers[0]!;
    const matches: Array<{
      binding: AuthorityBindingRecord;
      actionUri: string;
      resourceRef?: string;
    }> = [];
    for (const ref of refs) {
      const binding = await this.deps.repo.findBinding(input.operatorId, ref.binding_id);
      if (!binding) continue;
      try {
        await this.guards.assertReferenceMatches(binding, ref);
      } catch (error) {
        if (error instanceof ForbiddenError || error instanceof NotFoundError) continue;
        if (error instanceof ServiceUnavailableError || error instanceof ConflictError) throw error;
        throw new ServiceUnavailableError(
          'authority reference verification dependency is unavailable',
        );
      }
      if (
        binding.agent_id !== input.agentId ||
        binding.receiver_id !== receiver.id ||
        (binding.mission_ids.length > 0 &&
          (!input.missionId || !binding.mission_ids.includes(input.missionId)))
      )
        continue;
      try {
        await this.guards.assertBindingUsable(this.deps.repo, binding, this.now());
        const semantics = await this.semantics.resolveRuntimeSemantics(
          binding,
          input.boundary,
          input.normalizedRequest,
        );
        const scope = await this.guards.decryptBindingScope(binding);
        const actions = scope.actions.filter(
          (candidate) => candidate.action_uri === semantics.actionUri,
        );
        if (actions.length !== 1) continue;
        const action = actions[0]!;
        if (
          action.resource_refs.length > 0 &&
          (!semantics.resourceRef || !action.resource_refs.includes(semantics.resourceRef))
        )
          continue;
        if (
          !(await this.constraintsPermit(
            this.deps.repo,
            binding,
            action.constraints,
            input.normalizedRequest,
          ))
        )
          continue;
        matches.push({ binding, ...semantics });
      } catch (error) {
        if (error instanceof ServiceUnavailableError) throw error;
        if (!(error instanceof ForbiddenError || error instanceof NotFoundError)) {
          if (error instanceof ConflictError) throw error;
          throw new ServiceUnavailableError('authority evaluation dependency is unavailable');
        }
        // An unusable candidate is not a match; ambiguity is computed only
        // over currently valid bindings. Zero valid matches still denies.
      }
    }
    if (matches.length === 0)
      throw new ForbiddenError('no active authority binding matches this exact action');
    if (matches.length > 1) throw new ForbiddenError('authority binding selection is ambiguous');
    return this.evaluateAuthority(input.operatorId, {
      ...input,
      receiverRequestId,
      requestHash,
      agentKeyThumbprint: currentKey.thumbprint,
      receiverId: receiver.id,
      actionUri: matches[0]!.actionUri,
      resourceRef: matches[0]!.resourceRef,
      disclosureManifest: [],
      bindingId: matches[0]!.binding.id,
      bindingVersion: matches[0]!.binding.version,
    });
  }

  async constraintsPermit(
    repo: AuthorityRepositoryPort,
    binding: AuthorityBindingRecord,
    constraints: AuthorityConstraint[],
    normalizedRequest: unknown,
  ): Promise<boolean> {
    for (const constraint of constraints) {
      const actual = valueAtPath(normalizedRequest, constraint.path);
      if (constraint.op === 'exists') {
        if (!actual.found) return false;
        else continue;
      }
      if (constraint.op === 'not_exists') {
        if (actual.found) return false;
        else continue;
      }
      if (!actual.found) return false;
      let expected: unknown = constraint.value;
      if (constraint.value_ref !== undefined) {
        const links = await repo.listBindingProofs(
          binding.operator_id,
          binding.id,
          binding.version,
        );
        const candidates: Array<{ proof: AuthorityProofRecord; path: string }> = [];
        for (const link of links) {
          const proof = await repo.findProof(
            binding.operator_id,
            link.proof_id,
            link.proof_version,
          );
          if (!proof) continue;
          const profile = await repo.findProofProfileVersion(
            binding.operator_id,
            proof.profile_version_id,
          );
          const fact = (
            (profile?.config_json.disclosable_facts as Array<Record<string, unknown>>) ?? []
          ).find((item) => item.fact_id === constraint.value_ref);
          if (profile?.status === 'active' && fact && typeof fact.native_path === 'string') {
            candidates.push({ proof, path: fact.native_path });
          }
        }
        if (candidates.length !== 1) return false;
        await this.guards.assertProofUsable(repo, candidates[0]!.proof, this.now());
        expected = readFact(
          await this.guards.decryptProofFacts(candidates[0]!.proof),
          candidates[0]!.path,
        );
      }
      if (constraint.op === 'eq') {
        if (canonicalize(actual.value) !== canonicalize(expected)) return false;
        else continue;
      }
      if (constraint.op === 'not_eq') {
        if (canonicalize(actual.value) === canonicalize(expected)) return false;
        else continue;
      }
      if (constraint.op === 'in') {
        if (
          !Array.isArray(expected) ||
          !expected.some((item) => canonicalize(item) === canonicalize(actual.value))
        )
          return false;
        continue;
      }
      if (constraint.op === 'not_in') {
        if (
          !Array.isArray(expected) ||
          expected.some((item) => canonicalize(item) === canonicalize(actual.value))
        )
          return false;
        continue;
      }
      if (
        typeof actual.value !== 'number' ||
        typeof expected !== 'number' ||
        !Number.isFinite(actual.value) ||
        !Number.isFinite(expected)
      )
        return false;
      if (constraint.op === 'lt' && !(actual.value < expected)) return false;
      else if (constraint.op === 'lte' && !(actual.value <= expected)) return false;
      else if (constraint.op === 'gt' && !(actual.value > expected)) return false;
      else if (constraint.op === 'gte' && !(actual.value >= expected)) return false;
      else if (!['lt', 'lte', 'gt', 'gte'].includes(constraint.op)) return false;
    }
    return true;
  }
}
