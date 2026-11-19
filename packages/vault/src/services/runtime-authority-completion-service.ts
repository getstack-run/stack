import { canonicalize, sha256, ConflictError, ServiceUnavailableError } from '@stack/shared';
import type {
  AuthorityBindingProofRecord,
  AuthorityBindingRecord,
  AuthorityClaimIssuer,
  AuthorityRepositoryPort,
} from './authority-service.js';

export class RuntimeAuthorityCompletionService {
  constructor(private readonly deps: {
    repo: AuthorityRepositoryPort;
    claimIssuer: Pick<AuthorityClaimIssuer, 'registerAuthorityUseClaim'>;
    now?: () => Date;
  }) {}

  async completeRuntimeAuthorityUseByHash(input: {
    operatorId: string;
    useId: string;
    outcome: 'succeeded' | 'failed';
    resultHash: string;
    intentClaimId?: string;
    outcomeClaimId?: string;
  }): Promise<void> {
    if (!/^sha256:[0-9a-f]{64}$/.test(input.resultHash)) {
      throw new ConflictError('authority result commitment is invalid');
    }
    await this.deps.repo.atomic(async (repo) => {
      const existing = await repo.findAuthorityUseForOperator(input.operatorId, input.useId);
      if (!existing) throw new ConflictError('authority use is missing');
      if (existing.status === input.outcome && existing.result_hash === input.resultHash) return;
      if (existing.status !== 'dispatched' && !(input.outcome === 'failed' && existing.status === 'authorized')) {
        throw new ConflictError('authority use completion conflicts with its durable state');
      }
      const binding = await repo.findBinding(input.operatorId, existing.binding_id, existing.binding_version);
      if (!binding) throw new ConflictError('authority use binding is unavailable');
      const completedAt = (this.deps.now ?? (() => new Date()))();
      const terminalUse = {
        ...existing,
        status: input.outcome,
        result_hash: input.resultHash,
        completed_at: completedAt,
        intent_claim_id: input.intentClaimId ?? existing.intent_claim_id,
        outcome_claim_id: input.outcomeClaimId ?? existing.outcome_claim_id,
      } as const;
      const terminalClaim = await this.deps.claimIssuer.registerAuthorityUseClaim({
        operatorId: input.operatorId,
        use: terminalUse,
        bindingDigest: authorityBindingDigest(
          binding,
          await repo.listBindingProofs(input.operatorId, binding.id, binding.version),
        ),
        domainProfileVersionId: binding.domain_profile_version_id,
      }, repo.currentTransaction()).catch(() => {
        throw new ServiceUnavailableError('terminal authority use signing is unavailable');
      });
      if (!terminalClaim.claimId || !terminalClaim.claimHash) {
        throw new ServiceUnavailableError('terminal authority use claim is unavailable');
      }
      const row = await repo.completeAuthorityUse({
        operatorId: input.operatorId,
        useId: input.useId,
        outcome: input.outcome,
        resultHash: input.resultHash,
        ...(input.intentClaimId ? { intentClaimId: input.intentClaimId } : {}),
        ...(input.outcomeClaimId ? { outcomeClaimId: input.outcomeClaimId } : {}),
        now: completedAt,
      });
      if (!row) throw new ConflictError('authority use completion conflicts with its durable state');
    });
  }
}

export function authorityBindingDigest(
  binding: AuthorityBindingRecord,
  links: AuthorityBindingProofRecord[],
): string {
  return `sha256:${sha256(canonicalize({
    id: binding.id,
    version: binding.version,
    principal_id: binding.principal_id,
    agent_id: binding.agent_id,
    agent_key_thumbprint: binding.agent_key_thumbprint,
    receiver_id: binding.receiver_id,
    receiver_profile_version_id: binding.receiver_profile_version_id,
    domain_profile_version_id: binding.domain_profile_version_id,
    mission_ids: binding.mission_ids,
    lineage_root_id: binding.lineage_root_id,
    lineage_root_version: binding.lineage_root_version,
    parent_binding_id: binding.parent_binding_id,
    parent_binding_version: binding.parent_binding_version,
    delegation_depth: binding.delegation_depth,
    purpose_code: binding.purpose_code,
    purpose_hash: binding.purpose_hash,
    scope_hash: binding.scope_hash,
    approval_policy_hash: binding.approval_policy_hash,
    disclosure_policy_hash: binding.disclosure_policy_hash,
    delegation_policy_hash: binding.delegation_policy_hash,
    proof_set_hash: binding.proof_set_hash,
    valid_from: binding.valid_from.toISOString(),
    expires_at: binding.expires_at.toISOString(),
    proofs: links.map((link) => ({
      proof_id: link.proof_id,
      proof_version: link.proof_version,
      role: link.role,
      authoriser_principal_id: link.authoriser_principal_id,
      group_key: link.group_key,
      weight: link.weight,
      required: link.required,
      ordinal: link.ordinal,
    })).sort((a, b) => `${a.role}:${a.proof_id}`.localeCompare(`${b.role}:${b.proof_id}`)),
  }))}`;
}
