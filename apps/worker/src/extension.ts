import type {
  AgentRepository,
  ArchiveStoreProbeResult,
  AuditService,
  EntitlementResolver,
  CmekMigrationStep,
  KmsService,
  MissionService,
  ArchiveErasePrefix,
  ErasureStep,
  StreamingObjectStore,
  OperatorDeleteStep,
  OperatorRepositoryOptions,
  OperatorRepository,
  ProxyPostResponseService,
  ResendEmailService,
  SecurityEventService,
} from '@stack/vault';
import type { JobReport, PassHandle } from '@stack/shared';
import type { WorkerRuntime } from './runtime.js';
import type { TickOutcome } from './loop.js';
import type { AuditRetentionRuntime } from './jobs/audit-retention.js';
import type { WorkerDb, WorkerRedis } from './redis.js';
import type { buildClaimSigning } from './boot/signing.js';

/**
 * The points of one tick where a deployment's own jobs run. The engine's jobs
 * run in a fixed order; each slot is a place in that order, named after the
 * engine job it follows, and the jobs a deployment puts there run in the order
 * it lists them. A job that throws is recorded and sent to Sentry, and the tick goes on with the jobs after it and still counts as clean;
 * only an unreachable database or Redis ends the tick, and fails it, so the poll classifies it as an outage.
 */
export type TickSlot =
  | 'start'
  | 'afterDropoffs'
  | 'afterRetries'
  | 'afterIdentityRevoke'
  | 'afterGenomeRollup'
  | 'afterMissionExpiry'
  | 'end';

/**
 * What a job can say about its own run. A job that throws is reported `down` by the tick; a job that catches its own errors and only
 * logs them says so here (`failed`), or says it finished with part of its work undone (`degraded`), so the failure is not silent.
 */
export type JobOutcome = PassHandle;

/** One job of a deployment, named so that what it records reads `job:worker:<name>`. */
export interface WorkerJob<Parts extends object = object> {
  name: string;
  run(runtime: WorkerRuntime & Parts, outcome: JobOutcome): Promise<void>;
}

/** What the engine builds without any deployment: everything a job of the engine reads. */
export type EngineWorkerRuntime = Omit<WorkerRuntime, 'proxyAccounting'>;

/** What a deployment may replace of the engine's own beside the parts it adds. */
export interface WorkerOverrides {
  /** Settles the holds of proxy operations. Absent: the engine's own, which holds nothing. */
  proxyAccounting?: WorkerRuntime['proxyAccounting'];
  /** The app-store review account's refresh, fired beside the tick and never awaited by it. */
  reviewDemoRefresh?: () => Promise<void>;
}

/** The analytics client of the proxy's post-response work. */
export type ProxyAnalytics = NonNullable<ConstructorParameters<typeof ProxyPostResponseService>[0]['analytics']>;

/** What the engine built on the way, which a deployment's own parts are built from. */
export interface WorkerCore {
  db: WorkerDb;
  redis: WorkerRedis;
  stackSystemOperatorId: string;
  /** Real when configured, otherwise the dev mock: signing and vault credential reads go through it. */
  deploymentKms: KmsService;
  /** The base64 dev KMS: for paths that only ever delete the ciphertext they hold. */
  devKms: KmsService;
  agentRepo: AgentRepository;
  operatorRepo: OperatorRepository;
  audit: AuditService;
  archiveStore: StreamingObjectStore;
  securityEvent: SecurityEventService;
  missionService: MissionService;
  signerForOperator: Awaited<ReturnType<typeof buildClaimSigning>>['signerForOperator'];
  /** The email sender of the digest and the notices the worker sends, when one is configured. */
  email: ResendEmailService | null;
}

/**
 * What a deployment adds to the engine's worker. `Parts` is the runtime it adds to the engine's: its jobs read the
 * engine's runtime and these parts together.
 */
export interface WorkerExtension<Parts extends object = object> {
  /** Hosted tables, merged into the one database handle (relational queries on them need them). */
  dbSchema: Record<string, unknown>;
  /** The deployment's billing accounts, read for whether an account has controls on. An engine alone is on the contract plan, where controls are always on. */
  entitlements(core: { operatorRepo: OperatorRepository; db: WorkerDb }): EntitlementResolver;
  /** Stores of ciphertext the deployment adds to the engine's, which the customer-managed-key migration re-encrypts too. */
  cmekSteps?: readonly CmekMigrationStep[];
  /** What the deployment keeps outside the database, which goes with an account before anything of the account is erased. */
  erasureSteps?: (core: { db: WorkerDb }) => readonly ErasureStep[];
  /** What the deployment keeps in the audit archive's object store besides the segments (the agent drive's prefixes): an erasure the worker finishes deletes and verifies them too. */
  archiveErasePrefixes?: readonly ArchiveErasePrefix[];
  /** The analytics client the proxy's post-response work reports to. Absent: none. */
  analytics?(redis: WorkerRedis): Promise<ProxyAnalytics>;
  /** Operators the audit-chain verifier leaves out of its counts. Absent: none. */
  auditCheckSkipOperatorIds?: readonly string[];
  /** Builds what the deployment adds to the runtime, after the engine's own is built. */
  runtime(engine: EngineWorkerRuntime, core: WorkerCore): Promise<Parts & WorkerOverrides>;
  /** The deployment's jobs, by the slot of the tick they run in. */
  jobs: Partial<Record<TickSlot, ReadonlyArray<WorkerJob<Parts>>>>;
  retention: {
    /**
     * Runs before the cold archive can remove the rows it reads (a deployment's own rollup of them). True once what
     * it keeps is durable; anything else, a throw included, stops the archive and the prune for this tick.
     */
    beforeArchive?(runtime: AuditRetentionRuntime): Promise<boolean>;
  };
  /** What the deployment deletes of an operator's account beside the engine's own statements, each at its named point. */
  operatorDeleteSteps?: readonly OperatorDeleteStep[];
  /** The actions a plan includes in a month (`Infinity`: none named), snapshotted beside a plan write. Absent: the contract plan's. */
  monthlyActionLimit?: OperatorRepositoryOptions['monthlyActionLimit'];
  /** Told how each tick ended (the deployment's record of its systems). Must not throw. Absent: nothing is recorded. */
  observeTick?: (outcome: TickOutcome) => void;
  /** Told how each job of the tick ended, the engine's and the deployment's (`worker:<name>`). Must not throw. Absent: nothing is recorded. */
  observeJob?: (report: JobReport) => void;
  /** Told the verdict of each audit object store probe this machine makes (every ten minutes). Must not throw. Absent: nothing is recorded. */
  observeArchiveStoreProbe?: (result: ArchiveStoreProbeResult) => void;
}
