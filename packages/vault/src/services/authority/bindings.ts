/** Authority bindings: creation, activation, delegation, revocation and listing. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  canonicalize,
  generateId,
  type CreateAuthorityBindingInput,
  type DelegateAuthorityBindingInput,
} from '@stack/shared';
import type {
  AuthorityBindingRecord,
  AuthorityMutationActor,
  AuthorityProofRecord,
} from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { ApprovalService } from './approvals.js';
import { AuthorityCore } from './core.js';
import { AuthorityGuards } from './guards.js';
import {
  PROOF_KINDS_BY_ASSIGNMENT_ROLE,
  assertApprovalPolicyAssignments,
  assertDisclosurePolicySatisfiesReceiver,
  assertReceiverApprovalRequirements,
} from './binding-policy.js';
import {
  assertBrowserDecisionSession,
  type BrowserDecisionSession,
} from '../browser-decision-session.js';
import { authorityDelegationViolations } from '../authority-policy.js';
import { authorityMandateTermsDigest } from './mandate-terms.js';
import { bindingContext } from './kms-context.js';
import { bindingDigest, committedEnvelope, sha256 } from './digest.js';
import { safeBinding, safePrincipal, safeProof, safeReceiver } from './redaction.js';

export class BindingService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(
    private readonly core: AuthorityCore,
    private readonly guards: AuthorityGuards,
    private readonly approvals: ApprovalService,
  ) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async createBinding(
    operatorId: string,
    input: CreateAuthorityBindingInput,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      'binding.create',
      idempotencyKey,
      input,
      async (repo) => {
        const now = this.now();
        const principal = await repo.findPrincipal(operatorId, input.principal_id);
        if (!principal || principal.status !== 'active')
          throw new NotFoundError('AuthorityPrincipal', input.principal_id);
        const agentKey = await repo.resolveCurrentAgentKey(operatorId, input.agent_id);
        if (!agentKey?.active)
          throw new ForbiddenError('authority binding agent key is unavailable');
        const receiver = await repo.findReceiver(operatorId, input.receiver_id);
        if (!receiver || receiver.status !== 'active')
          throw new ForbiddenError('authority receiver is unavailable');
        const receiverProfile = await repo.findReceiverProfile(
          operatorId,
          input.receiver_profile_version_id,
        );
        if (
          !receiverProfile ||
          receiverProfile.status !== 'active' ||
          receiverProfile.receiver_id !== receiver.id ||
          receiver.current_profile_version_id !== receiverProfile.id
        )
          throw new ForbiddenError('authority receiver profile is unavailable or stale');
        for (const missionId of input.mission_ids) {
          if (!(await repo.isMissionActive(operatorId, missionId))) {
            throw new ForbiddenError('authority binding Mission is unavailable');
          }
        }

        const requiredRoles = new Set(
          input.proofs.filter((proof) => proof.required).map((proof) => proof.role),
        );
        for (const role of ['principal_identity', 'authoriser_identity', 'mandate'] as const) {
          if (!requiredRoles.has(role)) {
            throw new ForbiddenError(
              `authority binding requires a required ${role} proof assignment`,
            );
          }
        }

        const proofRows: AuthorityProofRecord[] = [];
        const authoriserIds = [
          ...new Set(
            input.proofs
              .map((proof) => proof.authoriser_principal_id)
              .filter((id): id is string => Boolean(id)),
          ),
        ].sort();
        const mandateTermsDigest = authorityMandateTermsDigest({
          principalId: input.principal_id,
          authoriserPrincipalIds: authoriserIds,
          agentId: input.agent_id,
          agentKeyThumbprint: agentKey.thumbprint,
          receiverId: input.receiver_id,
          receiverProfileVersionId: input.receiver_profile_version_id,
          ...(input.domain_profile_version_id
            ? { domainProfileVersionId: input.domain_profile_version_id }
            : {}),
          missionIds: input.mission_ids,
          purposeCode: input.purpose_code,
          ...(input.purpose_statement ? { purposeStatement: input.purpose_statement } : {}),
          scope: input.scope,
          approvalPolicy: input.approval_policy,
          disclosurePolicy: input.disclosure_policy,
          delegationPolicy: input.delegation_policy,
          validFrom: input.valid_from,
          expiresAt: input.expires_at,
        });
        for (const proofInput of input.proofs) {
          const proof = await repo.findProof(
            operatorId,
            proofInput.proof_id,
            proofInput.proof_version,
          );
          if (!proof) throw new NotFoundError('AuthorityProof', proofInput.proof_id);
          await this.guards.assertProofUsable(repo, proof, now);
          if (!PROOF_KINDS_BY_ASSIGNMENT_ROLE[proofInput.role].includes(proof.proof_kind)) {
            throw new ForbiddenError(
              `${proofInput.role} proof assignment is incompatible with ${proof.proof_kind} evidence`,
            );
          }
          if (
            proofInput.role === 'principal_identity' &&
            proof.subject_principal_id !== input.principal_id
          ) {
            throw new ForbiddenError('principal identity proof subject mismatch');
          }
          if (
            proofInput.role === 'authoriser_capacity' &&
            proof.represented_principal_id !== input.principal_id
          ) {
            throw new ForbiddenError(
              'authoriser capacity does not represent the binding principal',
            );
          }
          if (
            (proofInput.role === 'mandate' ||
              proof.proof_kind === 'mandate' ||
              proof.proof_kind === 'consent' ||
              proof.proof_kind === 'signature') &&
            proof.normalized_facts_encrypted
          ) {
            const facts = await this.guards.decryptProofFacts(proof);
            if (facts.mandate_terms_digest !== mandateTermsDigest) {
              throw new ForbiddenError('mandate proof is not bound to these exact authority terms');
            }
          } else if (proofInput.role === 'mandate') {
            throw new ForbiddenError('mandate proof has no exact mandate terms binding');
          }
          proofRows.push(proof);
        }
        for (const authoriserId of authoriserIds) {
          const identityIndex = input.proofs.findIndex(
            (proof) =>
              proof.role === 'authoriser_identity' &&
              proof.authoriser_principal_id === authoriserId &&
              proof.required,
          );
          if (
            identityIndex < 0 ||
            proofRows[identityIndex]!.subject_principal_id !== authoriserId
          ) {
            throw new ForbiddenError('named authoriser has no matching identity proof assignment');
          }
          if (principal.kind === 'organisation') {
            const capacityIndex = input.proofs.findIndex(
              (proof) =>
                proof.role === 'authoriser_capacity' &&
                proof.authoriser_principal_id === authoriserId &&
                proof.required,
            );
            if (
              capacityIndex < 0 ||
              proofRows[capacityIndex]!.subject_principal_id !== authoriserId ||
              proofRows[capacityIndex]!.represented_principal_id !== input.principal_id
            ) {
              throw new ForbiddenError(
                'organisation authoriser has no matching capacity proof assignment',
              );
            }
          }
        }
        assertApprovalPolicyAssignments(input.approval_policy, input.proofs);
        assertReceiverApprovalRequirements(
          input.approval_policy,
          receiverProfile.config_json.approval_policy,
        );
        assertDisclosurePolicySatisfiesReceiver(
          input.disclosure_policy,
          input.approval_policy,
          receiverProfile.config_json,
        );
        const id = generateId('abn');
        const version = 1;
        const scopeCommitment = committedEnvelope(input.scope);
        const approvalCommitment = committedEnvelope(input.approval_policy);
        const disclosureCommitment = committedEnvelope(input.disclosure_policy);
        const purposeCommitment = input.purpose_statement
          ? committedEnvelope(input.purpose_statement)
          : null;
        const delegationPolicy = input.delegation_policy;
        const [scopeEncrypted, approvalEncrypted, disclosureEncrypted, purposeEncrypted] =
          await Promise.all([
            this.deps.kms.encrypt(
              scopeCommitment.plaintext,
              bindingContext(operatorId, id, version, 'authority_binding_scope'),
            ),
            this.deps.kms.encrypt(
              approvalCommitment.plaintext,
              bindingContext(operatorId, id, version, 'authority_binding_approval'),
            ),
            this.deps.kms.encrypt(
              disclosureCommitment.plaintext,
              bindingContext(operatorId, id, version, 'authority_binding_disclosure'),
            ),
            input.purpose_statement
              ? this.deps.kms.encrypt(
                  purposeCommitment!.plaintext,
                  bindingContext(operatorId, id, version, 'authority_binding_purpose'),
                )
              : Promise.resolve(null),
          ]);
        const proofSetHash = sha256(
          canonicalize(
            proofRows
              .map((proof) => ({
                id: proof.id,
                version: proof.version,
                hash: proof.native_evidence_hash,
              }))
              .sort((a, b) => `${a.id}:${a.version}`.localeCompare(`${b.id}:${b.version}`)),
          ),
        );
        const row: AuthorityBindingRecord = {
          id,
          version,
          operator_id: operatorId,
          principal_id: input.principal_id,
          agent_id: input.agent_id,
          agent_key_thumbprint: agentKey.thumbprint,
          receiver_id: input.receiver_id,
          receiver_profile_version_id: input.receiver_profile_version_id,
          domain_profile_version_id: input.domain_profile_version_id ?? null,
          mission_ids: [...new Set(input.mission_ids)],
          parent_binding_id: null,
          parent_binding_version: null,
          lineage_root_id: id,
          lineage_root_version: version,
          delegation_depth: 0,
          purpose_code: input.purpose_code,
          purpose_statement_encrypted: purposeEncrypted?.ciphertext ?? null,
          purpose_hash: purposeCommitment?.hash ?? sha256(input.purpose_code),
          scope_encrypted: scopeEncrypted.ciphertext,
          scope_hash: scopeCommitment.hash,
          approval_policy_encrypted: approvalEncrypted.ciphertext,
          approval_policy_hash: approvalCommitment.hash,
          disclosure_policy_encrypted: disclosureEncrypted.ciphertext,
          disclosure_policy_hash: disclosureCommitment.hash,
          delegation_policy: delegationPolicy,
          delegation_policy_hash: sha256(canonicalize(delegationPolicy)),
          allow_further_delegation: delegationPolicy.allow_further_delegation,
          max_delegation_depth: delegationPolicy.max_delegation_depth,
          proof_set_hash: proofSetHash,
          valid_from: input.valid_from,
          expires_at: input.expires_at,
          status: 'draft',
          claim_id: null,
          claim_hash: null,
          created_at: now,
          activated_at: null,
          revoked_at: null,
          revoked_reason: null,
          erased_at: null,
          tombstone_hash: null,
          tombstone_claim_id: null,
        };
        const links = input.proofs.map((proofInput, index) => ({
          binding_id: id,
          binding_version: version,
          proof_id: proofInput.proof_id,
          proof_version: proofRows[index]!.version,
          role: proofInput.role,
          authoriser_principal_id: proofInput.authoriser_principal_id ?? null,
          group_key: proofInput.group_key,
          weight: proofInput.weight,
          required: proofInput.required,
          ordinal: proofInput.ordinal,
        }));
        return safeBinding(await repo.insertBinding(row, links));
      },
      201,
    );
  }

  async listBindings(operatorId: string) {
    return (await this.deps.repo.listBindings(operatorId)).map(safeBinding);
  }

  async listAgentBindings(
    operatorId: string,
    agentId: string,
    page: number,
    limit: number,
    binding?: { id: string; version: number },
  ) {
    if (
      !Number.isSafeInteger(page) ||
      page < 1 ||
      page > 100_000 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 50
    ) {
      throw new ForbiddenError('invalid authority page');
    }
    const result = await this.deps.repo.listAgentBindings(
      operatorId,
      agentId,
      page,
      limit,
      binding,
    );
    return {
      items: result.bindings.map((binding) => ({
        ...safeBinding(binding),
        proof_refs: result.links
          .filter(
            (link) => link.binding_id === binding.id && link.binding_version === binding.version,
          )
          .map((link) => ({
            proof_id: link.proof_id,
            proof_version: link.proof_version,
            role: link.role,
            authoriser_principal_id: link.authoriser_principal_id,
            group_key: link.group_key,
            weight: link.weight,
            required: link.required,
            ordinal: link.ordinal,
          })),
      })),
      principals: result.principals.map(safePrincipal),
      receivers: result.receivers.map(safeReceiver),
      proofs: result.proofs.map(safeProof),
      page,
      limit,
      has_more: result.has_more,
    };
  }

  async getBinding(operatorId: string, bindingId: string, version?: number) {
    const row = await this.deps.repo.findBinding(operatorId, bindingId, version);
    if (!row) throw new NotFoundError('AuthorityBinding', bindingId);
    return safeBinding(row);
  }

  async activateBinding(
    operatorId: string,
    bindingId: string,
    version: number | undefined,
    idempotencyKey: string,
    browserSession?: BrowserDecisionSession,
  ) {
    return this.core.idempotent(
      operatorId,
      `binding.activate:${bindingId}:${version ?? 'current'}`,
      idempotencyKey,
      {},
      async (repo) => {
        if (browserSession) {
          const transaction = repo.currentTransaction();
          if (!transaction)
            throw new ServiceUnavailableError('authority activation requires a transaction');
          await assertBrowserDecisionSession(transaction, operatorId, browserSession);
        }
        const row = await repo.findBinding(operatorId, bindingId, version);
        if (!row) throw new NotFoundError('AuthorityBinding', bindingId);
        if (row.status === 'active' && row.claim_id) return safeBinding(row);
        if (row.status !== 'draft' && row.status !== 'pending_approval') {
          throw new ConflictError(`authority binding cannot activate from ${row.status}`);
        }
        await this.guards.assertBindingUsable(repo, row, this.now(), { requireActive: false });
        await this.approvals.ensureApprovalRequests(
          repo,
          row,
          'activation',
          bindingDigest(row, await repo.listBindingProofs(operatorId, row.id, row.version)),
        );
        if (await repo.hasUnsatisfiedApprovals(operatorId, row.id, row.version)) {
          throw new ForbiddenError('authority binding approval threshold is not satisfied');
        }
        const activationHash = bindingDigest(
          row,
          await repo.listBindingProofs(operatorId, row.id, row.version),
        );
        await repo.consumeSatisfiedApprovals({
          operatorId,
          bindingId: row.id,
          bindingVersion: row.version,
          phase: 'activation',
          requestHash: activationHash,
          now: this.now(),
        });
        const links = await repo.listBindingProofs(operatorId, row.id, row.version);
        const digest = bindingDigest(row, links);
        const activatedAt = this.now();
        const activeClaimBinding: AuthorityBindingRecord = {
          ...row,
          status: 'active',
          activated_at: activatedAt,
        };
        const signed = await this.deps.claimIssuer
          .registerBindingClaim(
            {
              operatorId,
              binding: activeClaimBinding,
              proofRefs: links,
              bindingDigest: digest,
            },
            repo.currentTransaction(),
          )
          .catch((error: unknown) => {
            if (error instanceof ForbiddenError || error instanceof ConflictError) throw error;
            throw new ServiceUnavailableError('authority binding signing is unavailable');
          });
        if (!signed.claimId || !signed.claimHash) {
          throw new ServiceUnavailableError(
            'authority binding signing returned no verifiable claim',
          );
        }
        const activated = await repo.activateBinding({
          operatorId,
          bindingId: row.id,
          version: row.version,
          claimId: signed.claimId,
          claimHash: signed.claimHash,
          now: activatedAt,
        });
        if (!activated)
          throw new ConflictError('authority binding activation lost a concurrent transition');
        return safeBinding(activated);
      },
    );
  }

  async delegateBinding(
    operatorId: string,
    parentBindingId: string,
    input: DelegateAuthorityBindingInput,
    actor: AuthorityMutationActor,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `binding.delegate:${parentBindingId}`,
      idempotencyKey,
      input,
      async (repo) => {
        const parent = await repo.findBinding(operatorId, parentBindingId);
        if (!parent) throw new NotFoundError('AuthorityBinding', parentBindingId);
        if (actor.kind === 'agent' && actor.agent_id !== parent.agent_id) {
          throw new ForbiddenError(
            'an agent may delegate only its currently assigned authority binding',
          );
        }
        if (
          actor.kind === 'agent' &&
          !(await repo.isPassportAuthorizedForBinding({
            operatorId,
            passportJti: actor.passport_jti,
            agentId: actor.agent_id,
            bindingId: parent.id,
            bindingVersion: parent.version,
            now: this.now(),
          }))
        ) {
          throw new ForbiddenError(
            'agent Passport does not carry the exact parent authority binding',
          );
        }
        if (!parent.allow_further_delegation)
          throw new ForbiddenError('authority binding forbids further delegation');
        const now = this.now();
        await this.guards.assertBindingUsable(repo, parent, now);
        if (
          parent.delegation_depth >= 4 ||
          parent.delegation_depth >= parent.max_delegation_depth
        ) {
          throw new ForbiddenError('authority delegation depth exhausted');
        }
        const [parentScope, parentDisclosure] = await Promise.all([
          this.guards.decryptBindingScope(parent),
          this.guards.decryptBindingDisclosure(parent),
        ]);
        const violations = authorityDelegationViolations(
          {
            scope: input.scope,
            disclosurePolicy: input.disclosure_policy,
            validFrom: input.valid_from,
            expiresAt: input.expires_at,
            allowFurtherDelegation: input.allow_further_delegation,
            maxDelegationDepth: input.max_delegation_depth,
          },
          {
            scope: parentScope,
            disclosurePolicy: parentDisclosure,
            validFrom: parent.valid_from,
            expiresAt: parent.expires_at,
            allowFurtherDelegation: parent.allow_further_delegation,
            maxDelegationDepth: parent.max_delegation_depth,
          },
        );
        if (violations.length)
          throw new ForbiddenError(`authority delegation widens: ${violations.join(', ')}`);
        const childKey = await repo.resolveCurrentAgentKey(operatorId, input.child_agent_id);
        if (!childKey?.active) throw new ForbiddenError('child authority agent key is unavailable');
        if (
          input.child_agent_key_thumbprint &&
          input.child_agent_key_thumbprint !== childKey.thumbprint
        ) {
          throw new ForbiddenError('child authority agent key mismatch');
        }
        if (input.mission_ids.some((missionId) => !parent.mission_ids.includes(missionId))) {
          throw new ForbiddenError('delegation cannot add or substitute a Mission');
        }
        const id = generateId('abn');
        const version = 1;
        const scopeCommitment = committedEnvelope(input.scope);
        const disclosureCommitment = committedEnvelope(input.disclosure_policy);
        const [scopeEncrypted, disclosureEncrypted, approvalEncrypted, purposeEncrypted] =
          await Promise.all([
            this.deps.kms.encrypt(
              scopeCommitment.plaintext,
              bindingContext(operatorId, id, version, 'authority_binding_scope'),
            ),
            this.deps.kms.encrypt(
              disclosureCommitment.plaintext,
              bindingContext(operatorId, id, version, 'authority_binding_disclosure'),
            ),
            parent.approval_policy_encrypted
              ? this.guards.reencryptBindingCommitment(
                  parent.approval_policy_encrypted,
                  bindingContext(
                    operatorId,
                    parent.id,
                    parent.version,
                    'authority_binding_approval',
                  ),
                  parent.approval_policy_hash,
                  bindingContext(operatorId, id, version, 'authority_binding_approval'),
                )
              : Promise.reject(
                  new ForbiddenError('parent authority approval policy is unavailable'),
                ),
            parent.purpose_statement_encrypted
              ? this.guards.reencryptBindingCommitment(
                  parent.purpose_statement_encrypted,
                  bindingContext(
                    operatorId,
                    parent.id,
                    parent.version,
                    'authority_binding_purpose',
                  ),
                  parent.purpose_hash,
                  bindingContext(operatorId, id, version, 'authority_binding_purpose'),
                )
              : Promise.resolve(null),
          ]);
        const links = await repo.listBindingProofs(operatorId, parent.id, parent.version);
        const child: AuthorityBindingRecord = {
          ...parent,
          id,
          version,
          agent_id: input.child_agent_id,
          agent_key_thumbprint: childKey.thumbprint,
          mission_ids: input.mission_ids,
          parent_binding_id: parent.id,
          parent_binding_version: parent.version,
          delegation_depth: parent.delegation_depth + 1,
          scope_encrypted: scopeEncrypted.ciphertext,
          scope_hash: scopeCommitment.hash,
          disclosure_policy_encrypted: disclosureEncrypted.ciphertext,
          disclosure_policy_hash: disclosureCommitment.hash,
          approval_policy_encrypted: approvalEncrypted.ciphertext,
          purpose_statement_encrypted: purposeEncrypted?.ciphertext ?? null,
          delegation_policy: {
            allow_further_delegation: input.allow_further_delegation,
            max_delegation_depth: input.max_delegation_depth,
          },
          delegation_policy_hash: sha256(
            canonicalize({
              allow_further_delegation: input.allow_further_delegation,
              max_delegation_depth: input.max_delegation_depth,
            }),
          ),
          allow_further_delegation: input.allow_further_delegation,
          max_delegation_depth: input.max_delegation_depth,
          valid_from: input.valid_from,
          expires_at: input.expires_at,
          status: 'draft',
          claim_id: null,
          claim_hash: null,
          created_at: now,
          activated_at: null,
          revoked_at: null,
          revoked_reason: null,
          erased_at: null,
          tombstone_hash: null,
          tombstone_claim_id: null,
        };
        return safeBinding(
          await repo.insertBinding(
            child,
            links.map((link) => ({ ...link, binding_id: id, binding_version: version })),
          ),
        );
      },
      201,
    );
  }

  async revokeBinding(
    operatorId: string,
    bindingId: string,
    reason: string,
    actor: AuthorityMutationActor,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `binding.revoke:${bindingId}`,
      idempotencyKey,
      { reason },
      async (repo) => {
        const target = await repo.findBinding(operatorId, bindingId);
        if (!target) throw new NotFoundError('AuthorityBinding', bindingId);
        if (
          actor.kind === 'agent' &&
          !(await repo.isBindingInAgentChain(operatorId, target.id, target.version, actor.agent_id))
        ) {
          throw new ForbiddenError('an agent may revoke only its own authority delegation chain');
        }
        const revoked = await repo.revokeBindingCascade(operatorId, bindingId, this.now(), reason);
        if (!revoked) throw new NotFoundError('AuthorityBinding', bindingId);
        await this.deps.passportRevocationPublisher
          .publishAuthorityRevocations(revoked.passportJtis, reason)
          .catch(() => {
            throw new ServiceUnavailableError('authority Passport revocation propagation failed');
          });
        return {
          ...safeBinding(revoked.binding),
          revoked_passport_count: revoked.passportJtis.length,
        };
      },
    );
  }
}
