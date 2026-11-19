import type { Redis } from 'ioredis';
import type { Database, AuthorityReference, FleetPassportBinding } from '@stack/shared';
import type { AgentRepository } from '../../repositories/agent-repo.js';
import type { ServiceRepository } from '../../repositories/service-repo.js';
import type { PassportRepository } from '../../repositories/passport-repo.js';
import type { OperatorRepository } from '../../repositories/operator-repo.js';
import type { PassportClaimsRepository } from '../../repositories/passport-claims-repo.js';
import type { PassportSigner } from '../../crypto/passport-signer.js';
import type { IdentityVerificationService } from '../../identity/identity-verification-service.js';
import type { ClaimMatchingService } from '../../identity/claim-matching.js';
import type { IdentityRepository } from '../../identity/identity-repo.js';
import type { SecurityEventService } from '../security-event-service.js';

/**
 * Redis pub/sub channel for revocation events. Any component that keeps a
 * passport-verification cache (proxy workers, downstream services) can
 * subscribe here to invalidate eagerly, in addition to the `revoked:*`
 * key lookups on the verify path.
 */
export const REVOCATION_CHANNEL = 'stack:revoked';

export type RevocationEvent =
  | {
      type: 'single';
      operator_id: string;
      jti: string;
      cascaded: string[];
      reason: string;
      at: number;
    }
  | {
      type: 'bulk_agent';
      operator_id: string;
      agent_id: string;
      revoked_count: number;
      cascaded_count: number;
      reason: string;
      at: number;
    }
  | {
      type: 'bulk_session';
      operator_id: string;
      session_id: string;
      revoked_count: number;
      reason: string;
      at: number;
    }
  | {
      type: 'bulk_operator';
      operator_id: string;
      revoked_count: number;
      reason: string;
      at: number;
    }
  | {
      type: 'bulk_claim';
      operator_id: string;
      claim_id: string;
      revoked_count: number;
      reason: string;
      at: number;
    }
  // Mission revoked. Carries the mission_id and the revoke_reason from
  // MissionService.revoke. Subscribers (proxy, dashboard, worker) use this to
  // invalidate any per-mission cache they hold (today: no cache; published for
  // forward-compat when an in-process cache lands). cascaded_passport_jtis
  // enumerates the passports the forward cascade revoked alongside the
  // mission, so the dashboard can surface "this mission revoke also killed
  // these passports" in the activity feed.
  | {
      type: 'bulk_mission';
      operator_id: string;
      mission_id: string;
      revoke_reason: string;
      cascaded_passport_jtis: string[];
      at: number;
    };

/**
 * Mission lookup for PassportService: a thin interface, not MissionService.
 *
 * Every agent Passport is bound to exactly one live Mission. issue(),
 * delegate() and refresh() all resolve that Mission through `findById` and
 * refuse when it is missing, foreign, completed, revoked or expired. The only
 * exemption is a STACK platform staff/monitor Passport (platform_intent), which
 * is never bound to a Mission.
 *
 * Lifecycle direction is one-way: a Mission's end revokes its Passports
 * (createMissionPassportRevoker, run inside MissionService's terminal
 * transaction). A Passport revoke never ends its Mission: a Mission is the
 * task, a Passport a short-lived credential for it. See
 * the system architecture.
 */
export interface MissionLookup {
  findById(missionId: string): Promise<{
    mission_id: string;
    operator_id: string;
    intent_services: string[];
    expires_at: Date;
    completed_at: Date | null;
    revoked_at: Date | null;
    /** The agent the Mission was opened for, when one was named. */
    assigned_agent_id?: string | null;
  } | null>;
}

export type LiveMission = NonNullable<Awaited<ReturnType<MissionLookup['findById']>>>;

export type PassportAuthorityTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export type PassportJWTPayload = Awaited<ReturnType<PassportSigner['verify']>>;

export interface PassportFleetLookup {
  /**
   * Whether this agent may hold a Passport no fleet binds. A fleet's members may not be issued one directly, so the
   * fleet's rules cannot be walked around; `delegated` is a Passport an agent was handed by another agent of the same
   * account, whose authority is the parent's (and so no fleet's), and that a member may hold.
   */
  assertUnboundIssue(operatorId: string, agentId: string, options?: { delegated?: boolean }): Promise<void>;
  validate(claims: PassportJWTPayload): Promise<void>;
  validateDelegation(
    parent: PassportJWTPayload,
    childAgentId: string,
  ): Promise<FleetPassportBinding>;
  authorizeIssue(
    operatorId: string,
    binding: FleetPassportBinding,
    agentId: string,
  ): Promise<{ expiresAt: Date }>;
}

/** The authority engine is the only component allowed to resolve or narrow bindings. */
export interface PassportAuthorityLookup {
  resolvePassportRefs(input: {
    operatorId: string;
    agentId: string;
    bindingIds: string[];
    missionIds?: string[];
    now?: Date;
  }): Promise<AuthorityReference[]>;
  delegatePassportRefs(input: {
    operatorId: string;
    parentRefs: AuthorityReference[];
    childAgentId: string;
    childAgentKeyThumbprint: string;
    expiresAt: Date;
    now?: Date;
  }): Promise<AuthorityReference[]>;
  verifyPassportRefs(input: {
    operatorId: string;
    agentId: string;
    refs: AuthorityReference[];
    missionIds?: string[];
    now?: Date;
  }): Promise<void>;
  linkPassportRefs(
    input: { operatorId: string; passportJti: string; refs: AuthorityReference[] },
    tx?: PassportAuthorityTransaction,
  ): Promise<void>;
}

/**
 * What PassportService needs beyond its repositories. Every entry is required;
 * the service cannot be constructed without them, so no code path can run
 * against a half-wired service.
 *
 * The four accessors exist because each of those collaborators is itself built
 * from the PassportService (or from something that is): security events block
 * agents through it, the Mission service builds its twin runtime on it, the
 * authority service verifies presentations through it, and the fleet service
 * issues Passports through it. The composition root passes `() => thing` and
 * the service reads it at call time. The accessor is required, and a call made
 * before the collaborator exists fails instead of skipping its check.
 */
export interface PassportServiceDependencies {
  identityVerification: IdentityVerificationService;
  claimMatcher: ClaimMatchingService;
  identityRepo: IdentityRepository;
  /** Attached typed claims, and the cascade that revokes them with the Passport. */
  passportClaimsRepo: PassportClaimsRepository;
  missionLookup: () => MissionLookup;
  securityEvent: () => SecurityEventService;
  authorityLookup: () => PassportAuthorityLookup;
  fleetLookup: () => PassportFleetLookup;
}

/** The state every Passport operation reads. Built once by PassportService. */
export interface PassportContext extends PassportServiceDependencies {
  readonly passportRepo: PassportRepository;
  readonly agentRepo: AgentRepository;
  readonly serviceRepo: ServiceRepository;
  readonly signer: PassportSigner;
  readonly redis: Redis;
  readonly operatorRepo: OperatorRepository;
  /**
   * The platform-monitor passport intent is restricted to issuers with
   * id === systemOperatorId. Empty string disables the 'monitor' issuance path
   * entirely (issue() will refuse it).
   */
  readonly systemOperatorId: string;
  readonly db: Database;
}
