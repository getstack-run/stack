/** Approval requests and decisions attached to bindings and uses. */
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  canonicalize,
  generateId,
  type AuthorityApprovalDecisionInput,
  type CreateAuthorityApprovalRequestsInput,
  type HumanOperatorAuthor,
} from '@stack/shared';
import type { AuthorityApprovalClaimContext, AuthorityBindingRecord } from './records.js';
import type { AuthorityRepositoryPort } from './port.js';
import type { AuthorityServiceDeps } from './contracts.js';
import type { ResolvedAuthorityApprovalDecision } from './approval-verifier.js';
import { AuthorityCore } from './core.js';
import { AuthorityGuards } from './guards.js';
import {
  assertBrowserDecisionSession,
  type BrowserDecisionSession,
} from '../browser-decision-session.js';
import { bindingDigest, sha256 } from './digest.js';
import { parseAuthorityApprovalPolicy } from './approval-policy.js';
import { safeApprovalRequest } from './redaction.js';

export class ApprovalService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(
    private readonly core: AuthorityCore,
    private readonly guards: AuthorityGuards,
  ) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async createApprovalRequests(
    operatorId: string,
    bindingId: string,
    input: CreateAuthorityApprovalRequestsInput,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `binding.approval-requests:${bindingId}`,
      idempotencyKey,
      input,
      async (repo) => {
        const binding = await repo.findBinding(operatorId, bindingId);
        if (!binding) throw new NotFoundError('AuthorityBinding', bindingId);
        let requestHash: string;
        let authorityUseId: string | undefined;
        if (input.phase === 'activation') {
          requestHash = bindingDigest(
            binding,
            await repo.listBindingProofs(operatorId, binding.id, binding.version),
          );
        } else {
          if (!input.authority_use_id)
            throw new ForbiddenError(`${input.phase} approval requires an authority use`);
          const use = await repo.findAuthorityUseForOperator(operatorId, input.authority_use_id);
          if (!use || use.binding_id !== binding.id || use.binding_version !== binding.version) {
            throw new ForbiddenError('authority use is not bound to this binding version');
          }
          requestHash = use.request_hash;
          authorityUseId = use.id;
        }
        await this.ensureApprovalRequests(repo, binding, input.phase, requestHash, authorityUseId);
        return (await repo.listApprovalRequests(operatorId, binding.id)).map(safeApprovalRequest);
      },
      201,
    );
  }

  async listApprovalRequests(operatorId: string, bindingId: string) {
    const binding = await this.deps.repo.findBinding(operatorId, bindingId);
    if (!binding) throw new NotFoundError('AuthorityBinding', bindingId);
    return (await this.deps.repo.listApprovalRequests(operatorId, bindingId)).map(
      safeApprovalRequest,
    );
  }

  async decideApproval(
    operatorId: string,
    requestId: string,
    authenticatedAuthor: HumanOperatorAuthor,
    input: AuthorityApprovalDecisionInput,
    idempotencyKey: string,
    browserSession?: BrowserDecisionSession,
  ) {
    if (input.request_id !== requestId)
      throw new NotFoundError('AuthorityApprovalRequest', requestId);
    return this.core.idempotent(
      operatorId,
      `approval.decide:${requestId}`,
      idempotencyKey,
      {
        request_id: input.request_id,
        decision: input.decision,
        request_hash: input.request_hash,
        signed_decision_hash: sha256(input.signed_decision),
      },
      async (repo) => {
        if (browserSession) {
          const transaction = repo.currentTransaction();
          if (!transaction)
            throw new ServiceUnavailableError('authority approval requires a transaction');
          await assertBrowserDecisionSession(transaction, operatorId, browserSession, {
            allowedMemberRoles:
              authenticatedAuthor.kind === 'team_member'
                ? [authenticatedAuthor.role_at_signing]
                : [],
          });
        }
        let resolved: ResolvedAuthorityApprovalDecision;
        try {
          resolved = await this.deps.approvalDecisionVerifier.verify({
            operatorId,
            requestId,
            requestHash: input.request_hash,
            decision: input.decision,
            signedDecision: input.signed_decision,
            authenticatedAuthor,
          });
        } catch (error) {
          if (error instanceof ServiceUnavailableError) throw error;
          if (error instanceof ForbiddenError) {
            throw new ForbiddenError('authority approval ceremony proof is invalid');
          }
          throw new ServiceUnavailableError('authority approval verification is unavailable');
        }
        const decisionId = generateId('apd');
        const approvedContext = await repo.validateApprovalDecision({
          operatorId,
          requestId,
          authenticatedAuthor,
          decision: input,
          resolved,
          now: this.now(),
        });
        if (!approvedContext) {
          throw new ForbiddenError('authority approval is invalid, expired, or ineligible');
        }
        const claim: AuthorityApprovalClaimContext = {
          ...approvedContext,
          decision_id: decisionId,
          decided_at: this.now(),
          revoked_at: null,
        };
        const signed = await this.deps.claimIssuer
          .registerApprovalClaim(
            {
              operatorId,
              claim,
            },
            repo.currentTransaction(),
          )
          .catch(() => {
            throw new ServiceUnavailableError('authority approval signing is unavailable');
          });
        if (!signed.claimId || !signed.claimHash)
          throw new ServiceUnavailableError('authority approval claim is unavailable');
        const result = await repo.decideApproval({
          operatorId,
          requestId,
          authenticatedAuthor,
          decision: input,
          resolved,
          decisionId,
          now: this.now(),
        });
        if (!result)
          throw new ForbiddenError(
            'authority approval is invalid, expired, ineligible, or already decided',
          );
        return result;
      },
    );
  }

  async ensureApprovalRequests(
    repo: AuthorityRepositoryPort,
    binding: AuthorityBindingRecord,
    phase: 'activation' | 'action' | 'presentation',
    requestHash: string,
    authorityUseId?: string,
  ): Promise<void> {
    const policy = await this.guards.decryptBindingApproval(binding);
    const groups = parseAuthorityApprovalPolicy(policy);
    for (const group of groups) {
      if (group.phase !== phase) continue;
      await repo.ensureApprovalRequest({
        operatorId: binding.operator_id,
        bindingId: binding.id,
        bindingVersion: binding.version,
        ...(authorityUseId ? { authorityUseId } : {}),
        phase,
        groupKey: group.group_key,
        requestHash,
        challengeHash: sha256(
          canonicalize({
            binding_id: binding.id,
            binding_version: binding.version,
            phase,
            group_key: group.group_key,
            request_hash: requestHash,
          }),
        ),
        requiredWeight: group.required_weight,
        rejectMode: group.reject_mode,
        expiresAt: new Date(
          Math.min(
            binding.expires_at.getTime(),
            this.now().getTime() + group.maximum_age_seconds * 1000,
          ),
        ),
      });
    }
  }
}
