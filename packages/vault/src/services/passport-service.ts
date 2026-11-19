import type { Redis } from 'ioredis';
import { ForbiddenError, WorkspaceCommandBinding } from '@stack/shared';
import type {
  Database,
  DelegatePassportInput,
  FleetPassportBinding,
  IssuePassportInput,
  PassportClaim,
} from '@stack/shared';
import type { AgentRepository } from '../repositories/agent-repo.js';
import type { ServiceRepository } from '../repositories/service-repo.js';
import type { PassportRepository, RevokedPassportRow } from '../repositories/passport-repo.js';
import type { OperatorRepository } from '../repositories/operator-repo.js';
import type { PassportSigner } from '../crypto/passport-signer.js';
import { attachPassportClaim } from './passport/claims.js';
import { assertPassportDependencies } from './passport/context.js';
import { delegatePassport } from './passport/delegate.js';
import { issueFleetMissionPassports } from './passport/fleet-mission.js';
import { assertServiceIdentityRequirements } from './passport/identity-requirements.js';
import { issuePassport, issuePassportInternal } from './passport/issue.js';
import { refreshPassport } from './passport/refresh.js';
import {
  blockAgent,
  revokeAllForAgent,
  revokeAllForAgentIn,
  revokeAllForOperatorIn,
  revokeAllForSuspendedOperatorIn,
  revokeAllForOperator,
  revokeByCarriedClaim,
  revokeBySession,
  revokePassport,
  syncAuthorityRevocations,
  syncBlockedAgentRevocations,
} from './passport/revoke.js';
import type {
  PassportContext,
  PassportJWTPayload,
  PassportServiceDependencies,
} from './passport/types.js';
import { verifyPassportCore, type VerifyOptions } from './passport/verify.js';

// The pieces of the Passport lifecycle live in ./passport/, one module per
// concern. This file is the one class the rest of the codebase constructs, plus
// the names other packages import from it.
export {
  REVOCATION_CHANNEL,
  type RevocationEvent,
  type MissionLookup,
  type PassportAuthorityLookup,
  type PassportFleetLookup,
  type PassportJWTPayload,
  type PassportServiceDependencies,
} from './passport/types.js';
export { passportAuthorityAgentKeyThumbprint } from './passport/authority-refs.js';
export {
  identityClaimIdsForRefresh,
  identityClaimIsExpired,
  preserveIdentityClaimsForDelegation,
} from './passport/identity-requirements.js';
export { passportServiceGrantIsFresh } from './passport/verify.js';
export {
  createMissionPassportRevoker,
  PassportRevokeFlagsError,
  revokePassportsByCarriedClaim,
  type PassportRevokeOutcome,
} from './passport/revoke.js';

export class PassportService {
  private readonly ctx: PassportContext;

  constructor(
    passportRepo: PassportRepository,
    agentRepo: AgentRepository,
    serviceRepo: ServiceRepository,
    signer: PassportSigner,
    redis: Redis,
    operatorRepo: OperatorRepository,
    /**
     * The platform-monitor passport intent is restricted to issuers with
     * id === systemOperatorId. Wired from env.STACK_SYSTEM_OPERATOR_ID at boot.
     * Empty string disables the 'monitor' issuance path entirely (issue() will
     * refuse it).
     */
    systemOperatorId: string,
    db: Database,
    dependencies: PassportServiceDependencies,
  ) {
    assertPassportDependencies(dependencies);
    this.ctx = {
      passportRepo,
      agentRepo,
      serviceRepo,
      signer,
      redis,
      operatorRepo,
      systemOperatorId,
      db,
      ...dependencies,
    };
  }

  /** Expose passport record lookup for credential-time checks */
  async findByJti(jti: string) {
    return this.ctx.passportRepo.findByJti(jti);
  }

  /**
   * Attach a typed claim to a passport. Validates the body against the
   * registered claim schema, signs the attachment and stores it append-only.
   */
  async attachClaim(passportId: string, claim: PassportClaim) {
    return attachPassportClaim(this.ctx, passportId, claim);
  }

  async issue(operatorId: string, input: IssuePassportInput) {
    return issuePassport(this.ctx, operatorId, input);
  }

  /**
   * A Passport made for one workspace command. Only the workspace service calls this: the marker is server-derived,
   * the public issue input has no such field, a platform intent cannot be combined with it, and the API refuses a
   * Passport that carries it as a bearer anywhere but the proxy.
   */
  async issueWorkspaceCommand(operatorId: string, input: IssuePassportInput, binding: WorkspaceCommandBinding) {
    if (input.intent?.platform_intent) throw new ForbiddenError('A command Passport carries no platform intent');
    const parsed = WorkspaceCommandBinding.parse(binding);
    await this.ctx.fleetLookup().assertUnboundIssue(operatorId, input.agent_id);
    return issuePassportInternal(this.ctx, operatorId, input, undefined, undefined, parsed);
  }

  /** Only the server's Mission coordinator calls this. The root token never leaves it. */
  async issueFleetMission(
    operatorId: string,
    rootInput: IssuePassportInput,
    childInput: Omit<DelegatePassportInput, 'parent_passport_token'>,
    binding: FleetPassportBinding,
    sessionId?: string,
  ) {
    return issueFleetMissionPassports(
      this.ctx,
      operatorId,
      rootInput,
      childInput,
      binding,
      sessionId,
    );
  }

  async verify(token: string, options?: VerifyOptions) {
    return (await verifyPassportCore(this.ctx, token, options)).claims;
  }

  /**
   * `verify`, plus the Passport's own row as read during verification.
   *
   * For a caller that needs row state the JWT does not carry (the proxy's
   * checkout check) without a second read of the same row. The row
   * comes from the verification's own lineage read when it made one, which
   * includes the read under the operator lock; otherwise it is read once
   * here. Every check `verify` makes is made; nothing is skipped.
   */
  async verifyDetailed(
    token: string,
    options?: { service_id?: string; check_freshness?: boolean },
  ): Promise<{
    claims: PassportJWTPayload;
    record: NonNullable<Awaited<ReturnType<PassportRepository['findByJti']>>> | null;
  }> {
    const { claims, record } = await verifyPassportCore(this.ctx, token, options);
    return {
      claims,
      record: record ?? (await this.ctx.passportRepo.findByJti(claims.jti)) ?? null,
    };
  }

  /**
   * The per-service identity requirements gate for a Passport that has ALREADY
   * been verified on this request. The proxy learns the service only after
   * verifying, so it calls this instead of verifying the same token twice.
   */
  async assertServiceIdentityRequirements(
    claims: PassportJWTPayload,
    serviceId: string,
  ): Promise<void> {
    return assertServiceIdentityRequirements(this.ctx, claims, serviceId);
  }

  async delegate(operatorId: string, input: DelegatePassportInput) {
    return delegatePassport(this.ctx, operatorId, input);
  }

  async refresh(operatorId: string, token: string, ttlSeconds?: number) {
    return refreshPassport(this.ctx, operatorId, token, ttlSeconds);
  }

  /**
   * Revoke a Passport and everything delegated from it. Every caller names the
   * operator it acts for; a Passport owned by any other operator is reported as
   * not found, so a jti never reveals whether another tenant holds it.
   */
  async revoke(input: { jti: string; operatorId: string; reason: string }) {
    return revokePassport(this.ctx, input);
  }

  /**
   * Cache and broadcast revocations already committed by the authority
   * repository, without mutating the database or traversing descendants again.
   */
  async syncAuthorityRevocations(jtis: string[], reason: string): Promise<void> {
    return syncAuthorityRevocations(this.ctx, jtis, reason);
  }

  async listActive(operatorId: string, filters?: { agent_id?: string; session_id?: string }) {
    return this.ctx.passportRepo.findActiveByOperator(operatorId, filters);
  }

  async revokeAllForAgent(agentId: string, reason: string) {
    return revokeAllForAgent(this.ctx, agentId, reason);
  }

  /**
   * Revoke every Passport of an operator inside a transaction the caller holds, with the operator lock taken
   * (`acquireOAuthOperatorLock`). Run `publish` after the transaction commits.
   */
  async revokeAllForOperatorIn(
    operatorId: string,
    reason: string,
    tx: Parameters<typeof revokeAllForOperatorIn>[3],
  ) {
    return revokeAllForOperatorIn(this.ctx, operatorId, reason, tx);
  }

  /**
   * What suspending an account does to its Passports: takes the operator lock inside the caller's transaction and
   * revokes every unrevoked Passport of the account, in the same transaction that sets the suspension, so there is no
   * moment an account is suspended and a Passport of it still stands. Run `publish` after the transaction commits.
   */
  async revokeAllForSuspendedOperatorIn(
    operatorId: string,
    reason: string,
    tx: Parameters<typeof revokeAllForOperatorIn>[3],
  ) {
    return revokeAllForSuspendedOperatorIn(this.ctx, operatorId, reason, tx);
  }

  /**
   * Revoke every Passport of an agent inside a transaction the caller holds, with the operator lock taken
   * (`acquireOAuthOperatorLock`). Run `publish` after the transaction commits.
   */
  async revokeAllForAgentIn(
    agentId: string,
    operatorId: string,
    reason: string,
    tx: Parameters<typeof revokeAllForAgentIn>[4],
  ) {
    return revokeAllForAgentIn(this.ctx, agentId, operatorId, reason, tx);
  }

  /**
   * Block future issuance and revoke the agent's entire unrevoked Passport chain
   * in one database transaction. Redis is a post-commit accelerator only;
   * online verification still checks the authoritative database on a miss.
   */
  async blockAgent(
    operatorId: string,
    agentId: string,
    reason: string,
    blockedAt: Date = new Date(),
  ): Promise<{ revoked_count: number }> {
    return blockAgent(this.ctx, operatorId, agentId, reason, blockedAt);
  }

  /** Post-commit Redis/event synchronization for transaction owners elsewhere. */
  async syncBlockedAgentRevocations(
    operatorId: string,
    agentId: string,
    reason: string,
    revoked: RevokedPassportRow[],
  ): Promise<void> {
    return syncBlockedAgentRevocations(this.ctx, operatorId, agentId, reason, revoked);
  }

  async revokeBySession(operatorId: string, sessionId: string, reason: string) {
    return revokeBySession(this.ctx, operatorId, sessionId, reason);
  }

  /** Revoke only passports carrying a specific identity claim (smart revoke) */
  async revokeByCarriedClaim(operatorId: string, claimId: string, reason: string) {
    return revokeByCarriedClaim(this.ctx, operatorId, claimId, reason);
  }

  async revokeAllForOperator(operatorId: string, reason: string) {
    return revokeAllForOperator(this.ctx, operatorId, reason);
  }
}
