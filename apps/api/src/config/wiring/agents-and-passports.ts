import type { Database } from '@stack/shared';
import {
  AgentService,
  PassportService,
  AccountabilityService,
  CheckpointRepository,
  CheckoutRepository,
  ReviewRepository,
  type BehavioralGenomeService,
  type ClaimMatchingService,
  type ClaimRegistryService,
  type IdentityVerificationService,
  type IntentDeviationGrader,
  type PassportServiceDependencies,
  type PassportSigner,
  type PlanLimitsReader,
} from '@stack/vault';
import { env } from '../env.js';
import type { RedisClient } from './infra.js';
import type { CoreRepositories } from './repositories.js';

export interface AgentsAndPassports {
  agent: AgentService;
  passport: PassportService;
}

/**
 * The four collaborators PassportService reads at call time because each is
 * built from the passport (or from something built from it): security events
 * block agents through it, the Mission service builds its twin runtime on it,
 * the authority service verifies presentations through it and the fleet service
 * issues passports through it. The composition root passes accessors into the
 * services it builds later; a call made before one exists fails.
 */
export type PassportLookups = Pick<
  PassportServiceDependencies,
  'missionLookup' | 'securityEvent' | 'authorityLookup' | 'fleetLookup'
>;

/**
 * Agents and the passports issued to them. The identity services and the claims
 * repository are built first and passed to the passport at construction; the
 * lookups that cannot be built first arrive as accessors.
 */
export function createAgentsAndPassports(deps: {
  db: Database;
  redis: RedisClient;
  signer: PassportSigner;
  repos: CoreRepositories;
  identity: IdentityVerificationService;
  claimMatcher: ClaimMatchingService;
  lookups: PassportLookups;
  /** How many agents a tier may register. */
  planLimits: PlanLimitsReader;
}): AgentsAndPassports {
  const { db, redis, signer, repos, identity, claimMatcher, lookups, planLimits } = deps;
  const agent = new AgentService(repos.agentRepo, repos.operatorRepo, planLimits);
  const passport = new PassportService(
    repos.passportRepo,
    repos.agentRepo,
    repos.serviceRepo,
    signer,
    redis,
    repos.operatorRepo,
    env.STACK_SYSTEM_OPERATOR_ID,
    db,
    {
      identityVerification: identity,
      claimMatcher,
      identityRepo: repos.identityRepo,
      // attachClaim and the cascade that revokes attached claims with a passport.
      passportClaimsRepo: repos.passportClaimsRepo,
      ...lookups,
    },
  );
  return { agent, passport };
}

/**
 * Checkpoints, checkouts and reviews. Dual-writes a signed checkpoint_approval
 * claim per checkpoint, fires a fire-and-forget behavioral genome emit after
 * each one (the response latency is unchanged), and runs the intent-deviation
 * grader the deployment passes, when it passes one. Without it the detector
 * raises nothing, like the rest of the service.
 */
export function createAccountability(deps: {
  db: Database;
  redis: RedisClient;
  repos: CoreRepositories;
  passport: PassportService;
  claimRegistry: ClaimRegistryService;
  behavioralGenome: BehavioralGenomeService;
  /** The deployment's own grader of declared-versus-observed behaviour. Null: the review rules alone decide. */
  intentDeviation: IntentDeviationGrader | null;
}): AccountabilityService {
  const { db, redis, repos, passport, claimRegistry, behavioralGenome, intentDeviation } = deps;
  const accountability = new AccountabilityService(
    new CheckpointRepository(db),
    new CheckoutRepository(db),
    new ReviewRepository(db),
    repos.passportRepo,
    repos.agentRepo,
    redis,
    repos.securityEventRepo,
    repos.passportClaimsRepo,
  );
  accountability.setAgentBlocker(passport);
  if (intentDeviation) accountability.setIntentDeviationGrader(intentDeviation);
  accountability.setClaimRegistryService(claimRegistry);
  accountability.setBehavioralGenomeService(behavioralGenome);
  return accountability;
}
