/** Authority references carried by Passports. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  type AuthorityReference,
} from '@stack/shared';
import type { AuthorityBindingRecord, AuthorityDbTransaction } from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import { AuthorityGuards } from './guards.js';

export class PassportRefService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(
    core: AuthorityCore,
    private readonly guards: AuthorityGuards,
  ) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async resolvePassportRefs(input: {
    operatorId: string;
    agentId: string;
    bindingIds: string[];
    missionIds?: string[];
    now?: Date;
  }): Promise<AuthorityReference[]> {
    if (input.bindingIds.length > 8)
      throw new ForbiddenError('a Passport may carry at most eight authority references');
    const refs: AuthorityReference[] = [];
    for (const id of [...new Set(input.bindingIds)]) {
      const binding = await this.deps.repo.findBinding(input.operatorId, id);
      if (!binding) throw new NotFoundError('AuthorityBinding', id);
      await this.guards.assertBindingUsable(this.deps.repo, binding, input.now ?? this.now());
      if (binding.agent_id !== input.agentId)
        throw new ForbiddenError('authority binding agent mismatch');
      this.assertMissionSet(binding, input.missionIds);
      if (!binding.claim_id) throw new ForbiddenError('authority binding has no signed claim');
      refs.push(await this.guards.authorityReference(binding));
    }
    return refs;
  }

  async delegatePassportRefs(input: {
    operatorId: string;
    parentRefs: AuthorityReference[];
    childAgentId: string;
    childAgentKeyThumbprint: string;
    expiresAt: Date;
    now?: Date;
  }): Promise<AuthorityReference[]> {
    const refs: AuthorityReference[] = [];
    for (const ref of input.parentRefs) {
      const parent = await this.deps.repo.findBinding(input.operatorId, ref.binding_id);
      if (!parent) throw new ForbiddenError('authority reference mismatch');
      await this.guards.assertReferenceMatches(parent, ref);
      await this.guards.assertBindingUsable(this.deps.repo, parent, input.now ?? this.now());
      if (
        !parent.allow_further_delegation ||
        parent.delegation_depth >= parent.max_delegation_depth
      ) {
        throw new ForbiddenError('authority reference cannot be delegated');
      }
      if (input.expiresAt > parent.expires_at)
        throw new ForbiddenError('delegated Passport outlives authority');
      const child = (await this.deps.repo.listBindings(input.operatorId)).find(
        (candidate) =>
          candidate.parent_binding_id === parent.id &&
          candidate.parent_binding_version === parent.version &&
          candidate.agent_id === input.childAgentId &&
          candidate.agent_key_thumbprint === input.childAgentKeyThumbprint &&
          candidate.status === 'active',
      );
      if (!child?.claim_id)
        throw new ForbiddenError(
          'a narrowed child authority binding is required before Passport delegation',
        );
      refs.push(await this.guards.authorityReference(child));
    }
    return refs;
  }

  async verifyPassportRefs(input: {
    operatorId: string;
    agentId: string;
    refs: AuthorityReference[];
    missionIds?: string[];
    now?: Date;
  }): Promise<void> {
    if (input.refs.length > 8) throw new ForbiddenError('too many Passport authority references');
    for (const ref of input.refs) {
      const binding = await this.deps.repo.findBinding(input.operatorId, ref.binding_id);
      if (!binding) throw new ForbiddenError('authority reference is invalid');
      await this.guards.assertReferenceMatches(binding, ref);
      await this.guards.assertBindingUsable(this.deps.repo, binding, input.now ?? this.now());
      if (binding.agent_id !== input.agentId)
        throw new ForbiddenError('authority reference agent mismatch');
      this.assertMissionSet(binding, input.missionIds);
    }
  }

  async linkPassportRefs(
    input: {
      operatorId: string;
      passportJti: string;
      refs: AuthorityReference[];
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<void> {
    if (input.refs.length > 8) throw new ForbiddenError('too many Passport authority references');
    if (
      new Set(input.refs.map((ref) => `${ref.binding_id}:${ref.binding_claim_id}`)).size !==
      input.refs.length
    ) {
      throw new ConflictError('duplicate Passport authority reference');
    }
    // Re-verify immediately before the transaction insert. The repository
    // enforces same-operator composite FKs and idempotent PK insertion.
    const bindings: AuthorityBindingRecord[] = [];
    for (const ref of input.refs) {
      const binding = await this.deps.repo.findBinding(input.operatorId, ref.binding_id);
      if (!binding) throw new ForbiddenError('authority reference is invalid');
      await this.guards.assertReferenceMatches(binding, ref);
      await this.guards.assertBindingUsable(this.deps.repo, binding, this.now());
      bindings.push(binding);
    }
    await this.deps.repo.linkPassportRefs(input, transaction);
  }

  /** Safe opaque projection for operator-facing Passport inventory. */
  async listPassportAuthorityRefs(operatorId: string, passportJti: string) {
    return this.deps.repo.listPassportRefs(operatorId, passportJti);
  }

  async listPassportAuthorityRefsForPassports(operatorId: string, passportJtis: string[]) {
    return this.deps.repo.listPassportRefsForPassports(operatorId, passportJtis);
  }

  private assertMissionSet(binding: AuthorityBindingRecord, missionIds?: string[]): void {
    if (binding.mission_ids.some((missionId) => !(missionIds ?? []).includes(missionId))) {
      throw new ForbiddenError('Passport does not carry the authority binding Mission');
    }
  }
}
