import type { Database } from '@stack/shared';
import {
  PartnerTenantService,
  FleetService,
  FleetRepository,
  FleetAdmissionService,
  type AgentService,
  type ApprovalGateService,
  type ClaimRegistryService,
  type IntentApprovalService,
  type MissionService,
  type PassportService,
  type EntitlementResolver,
  type PlanLimitsReader,
  type PartnerTenantServiceDeps,
} from '@stack/vault';
import type { CoreRepositories } from './repositories.js';
import type { RedisClient } from './infra.js';

export interface PartnerServices {
  /**
   * Partner tenancy. A platform partner provisions isolated child operators on
   * behalf of its customers. The partner has is_partner=true on its operator
   * row; children have parent_operator_id=partner.id and their own audit chain,
   * KMS context, signing key and webhook surface. The partner sees aggregate
   * counters but never child audit content.
   */
  partnerTenants: PartnerTenantService;
}

export function createPartnerServices(deps: {
  db: Database;
  repos: Pick<CoreRepositories, 'operatorRepo' | 'usageRepo' | 'memberRepo'>;
  /** How many active partner-managed accounts a partner's plan allows. */
  planLimits: PlanLimitsReader;
  /** The deployment's billing of accounts (what the partner pays for each). Absent: accounts have no plan. */
  accountPlans?: PartnerTenantServiceDeps['accountPlans'];
}): PartnerServices {
  const { db, repos, planLimits, accountPlans } = deps;
  const partnerTenants = new PartnerTenantService({
    db,
    operatorRepo: repos.operatorRepo,
    poolUsage: repos.usageRepo,
    planLimits,
    members: repos.memberRepo,
    ...(accountPlans ? { accountPlans } : {}),
  });
  return { partnerTenants };
}

export interface FleetServices {
  fleet: FleetService;
  fleetRepo: FleetRepository;
  fleetAdmission: FleetAdmissionService;
}

/**
 * Fleets of externally-run agents. The fleet becomes the guard that lets the
 * agent service tell an external agent from a hosted one. The composition root
 * also hands the fleet to the passport and credential services, which read it
 * through accessors because they are built first.
 */
export function createFleetServices(deps: {
  db: Database;
  redis: RedisClient;
  passport: PassportService;
  agent: AgentService;
  mission: MissionService;
  entitlements: Pick<EntitlementResolver, 'resolve'>;
  claimRegistry: ClaimRegistryService;
  intentApproval: IntentApprovalService;
  approvalGate: ApprovalGateService;
}): FleetServices {
  const { db, redis, passport, agent, mission, entitlements } = deps;
  const fleetRepo = new FleetRepository(db);
  const fleet = new FleetService({ repo: fleetRepo, mission, passport, redis, entitlements });
  const fleetAdmission = new FleetAdmissionService({
    repo: fleetRepo,
    claimRegistry: deps.claimRegistry,
    intentApproval: deps.intentApproval,
    approvalGate: deps.approvalGate,
  });
  agent.setExternalAgentGuard((operatorId, agentId) => fleet.assertExternalAgent(operatorId, agentId));
  return { fleet, fleetRepo, fleetAdmission };
}
