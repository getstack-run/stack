import type { Database } from '@stack/shared';
import {
  OperatorRepository,
  AgentRepository,
  ServiceRepository,
  PassportRepository,
  IdentityRepository,
  MemberRepository,
  PassportClaimsRepository,
  UsageRepository,
  LlmUsageRepository,
  SecurityEventRepository,
  type OperatorRepositoryOptions,
  type UsageRepositoryOptions,
} from '@stack/vault';

/**
 * Repositories that more than one domain module reads. A repository used by a
 * single domain is built inside that domain's module.
 */
export interface CoreRepositories {
  operatorRepo: OperatorRepository;
  agentRepo: AgentRepository;
  serviceRepo: ServiceRepository;
  passportRepo: PassportRepository;
  identityRepo: IdentityRepository;
  memberRepo: MemberRepository;
  passportClaimsRepo: PassportClaimsRepository;
  usageRepo: UsageRepository;
  llmUsageRepo: LlmUsageRepository;
  securityEventRepo: SecurityEventRepository;
}

export function createCoreRepositories(
  db: Database,
  operator: OperatorRepositoryOptions = {},
  usage: UsageRepositoryOptions = {},
): CoreRepositories {
  return {
    operatorRepo: new OperatorRepository(db, operator),
    agentRepo: new AgentRepository(db),
    serviceRepo: new ServiceRepository(db),
    passportRepo: new PassportRepository(db),
    identityRepo: new IdentityRepository(db),
    memberRepo: new MemberRepository(db),
    passportClaimsRepo: new PassportClaimsRepository(db),
    usageRepo: new UsageRepository(db, usage),
    llmUsageRepo: new LlmUsageRepository(db),
    securityEventRepo: new SecurityEventRepository(db),
  };
}
