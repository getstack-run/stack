import type {
  AuditArchiveService,
  AuditService,
  BehavioralGenomeService,
  CmekMigrationWorker,
  FleetRepository,
  InboundWebhookReceiptsRepository,
  MissionRepository,
  MissionService,
  ObjectStore,
  PassportClaimsRepository,
  PassportRepository,
  ProxyAccountingReconciler,
  ProxyOperationService,
  ProxyPostResponseService,
  SecurityEventRepository,
  SecurityEventService,
} from '@stack/vault';
import type { DropoffService } from '@stack/dropoff';
import type { createOAuthRefreshPruneGate, createOAuthRetryCleanupGate } from './oauth-retry-cleanup.js';
import type { createOperatorErasureRetryGate } from './operator-erasure-retry.js';
import type { createEmailChangeDeliveryRetryGate } from './email-change-delivery-retry.js';
import type { WorkerDb, WorkerRedis } from './redis.js';

/** Mutable process state that outlives a single tick. */
export interface WorkerState {
  /** Read by `/health`. Null until the first CMEK tick, and always null when CMEK is off. */
  cmekTickLastRanAt: Date | null;
}

/**
 * The wired worker: every service a job may need, built once at boot. Each
 * job takes a `Pick<WorkerRuntime, ...>` of exactly what it uses, so a job's
 * dependencies are readable from its signature and testable with plain fakes.
 */
export interface WorkerRuntime {
  db: WorkerDb;
  redis: WorkerRedis;
  stackSystemOperatorId: string;
  state: WorkerState;

  // Time-gated jobs. Each gate holds its own cadence and lives for the process.
  gates: {
    oauthRetryCleanup: ReturnType<typeof createOAuthRetryCleanupGate>;
    oauthRefreshPrune: ReturnType<typeof createOAuthRefreshPruneGate>;
    operatorErasureRetry: ReturnType<typeof createOperatorErasureRetryGate>;
    emailChangeRetry: ReturnType<typeof createEmailChangeDeliveryRetryGate>;
    reviewDemoRefresh: () => Promise<void>;
  };

  // Audit, archive and security signals.
  audit: AuditService;
  archive: AuditArchiveService;
  /** The cold archive's object store, probed for health. */
  archiveStore: ObjectStore;
  securityEvent: SecurityEventService;
  securityEventRepo: SecurityEventRepository;
  passportRepo: PassportRepository;
  passportClaimsRepo: PassportClaimsRepository;

  // Drop-offs.
  dropoffService: DropoffService;

  // Missions and claims.
  missionRepo: MissionRepository;
  missionService: MissionService;
  behavioralGenome: BehavioralGenomeService;

  // Proxy and fleets.
  fleetRepo: FleetRepository;
  proxyOperations: ProxyOperationService;
  proxyPostResponse: ProxyPostResponseService;
  proxyAccounting: ProxyAccountingReconciler;

  // Inbound retention: inbound-webhook receipts.
  inboundReceiptsRepo: Pick<InboundWebhookReceiptsRepository, 'sweepOlderThan'>;

  /** Operators the audit-chain verifier leaves out of its counts. */
  auditCheckSkipOperatorIds: readonly string[];

  /** Whether an operator's passports get a daily behavioral_genome claim: the account has controls on. */
  genomeEligible: (operatorId: string) => Promise<boolean>;

  /** Null outside production-shaped deployments (no real KMS configured). */
  cmekMigrationWorker: CmekMigrationWorker | null;
}
