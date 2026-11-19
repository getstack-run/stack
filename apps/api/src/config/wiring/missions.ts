import { safeErrorSummary, type Database, type DecisionReachedHook } from '@stack/shared';
import {
  BehavioralGenomeService,
  BehavioralDriftDetector,
  SimulationDivergenceDetector,
  TwinRunsRepository,
  TwinOrchestrationService,
  MissionRepository,
  MissionService,
  createMissionPassportRevoker,
  REVOCATION_CHANNEL,
  IntentSimulationService,
  IntentApprovalRepository,
  IntentApprovalService,
  ApprovalGateService,
  type MissionActionCounter,
  type AgentService,
  type ClaimRegistryService,
  type DetectorService,
  type EntitlementResolver,
  type KmsService,
  type MissionLookup,
  type MissionSpendSource,
  type NotificationService,
  type PassportService,
  type SecurityEventService,
  type AuditService,
} from '@stack/vault';
import type { ActionMeter } from '../../lib/action-meter.js';
import { decisionAnnouncer } from '../../lib/decision-reached.js';
import type { EngineRegistries } from '../registries.js';
import type { CoreRepositories } from './repositories.js';
import type { RedisClient } from './infra.js';

export interface MissionServices {
  /**
   * Passport-scoped behavioral fingerprint producer. Constructed the same way in
   * the worker, which runs the daily UTC rollup.
   */
  behavioralGenome: BehavioralGenomeService;
  twinOrchestration: TwinOrchestrationService;
  missionRepo: MissionRepository;
  /**
   * What PassportService reads to require exactly one live Mission per agent
   * Passport. A thin adapter over `mission`, so PassportService never imports
   * MissionService.
   */
  missionLookup: MissionLookup;
  /**
   * Mission lifecycle owner. Every agent Passport is bound to exactly one
   * Mission, and complete()/revoke() revoke the Mission's Passports in the same
   * transaction.
   */
  mission: MissionService;
}

type MissionRevocationPublisher = ConstructorParameters<
  typeof MissionService
>[0]['publishMissionRevocation'];

/**
 * Publishes a bulk_mission RevocationEvent on the canonical revocation channel.
 * Subscribers (the proxy gate cache, the dashboard activity feed, the worker)
 * see the revoke and the list of passports the forward cascade killed.
 */
function createMissionRevocationPublisher(redis: RedisClient): MissionRevocationPublisher {
  return async (event) => {
    try {
      await redis.publish(
        REVOCATION_CHANNEL,
        JSON.stringify({
          type: 'bulk_mission',
          operator_id: event.operator_id,
          mission_id: event.mission_id,
          revoke_reason: event.revoke_reason,
          cascaded_passport_jtis: event.cascaded_passport_jtis,
          at: Date.now(),
        }),
      );
    } catch (err) {
      console.error('[MissionService] redis publish bulk_mission failed:', safeErrorSummary(err));
    }
  };
}

/**
 * Missions, the twin runtime, and the detectors that react to claims written
 * under a mission. A Mission's end revokes its Passports; a Passport revoke
 * never ends its Mission, so lifecycle flows one way and there is no cycle.
 */
export function createMissionServices(deps: {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  repos: CoreRepositories;
  passport: PassportService;
  claimRegistry: ClaimRegistryService;
  securityEvent: SecurityEventService;
  /** What a Mission has spent on credit, for its cost cap. */
  missionSpend: MissionSpendSource;
  /** Counts a Mission's action limits per Mission, atomically. Null: an install, where the gate counts intent claims. */
  missionActions: MissionActionCounter | null;
  /** The owner is told when a cap pauses a Mission (`mission.paused`): their review is waiting. */
  notification: Pick<NotificationService, 'publishEvent'>;
  /** The pause and the owner's review each leave a row in the audit chain. */
  audit: Pick<AuditService, 'write'>;
  /** Where the owner's decision on a paused Mission is announced, for the agent it was opened for. */
  registries: Pick<EngineRegistries, 'decisionReached'>;
}): MissionServices {
  const { db, redis, kms, repos, passport, claimRegistry, securityEvent, missionSpend, missionActions, notification, audit, registries } = deps;
  const { agentRepo, passportRepo, passportClaimsRepo, llmUsageRepo } = repos;

  const behavioralGenome = new BehavioralGenomeService({
    db,
    claimRegistry,
    passportClaimsRepo,
  });

  // Twin runtime orchestration substrate. The intent-claim mirror hook below
  // is its only trigger.
  const twinRunsRepo = new TwinRunsRepository(db);
  const twinOrchestration = new TwinOrchestrationService({
    repo: twinRunsRepo,
    passportService: passport,
    passportRepo,
    claimRegistry,
    // evaluateDivergence loads paired outcome payloads
    // + per-side detector_signal claims through passportClaimsRepo.
    passportClaimsRepo,
    // agentRepo for resolveTwinInvocationContext to read agent.twin_llm_model.
    agentRepo,
  });

  // MissionRepository wraps the missions table (denormalized cache for the
  // proxy gate hot path). MissionService owns the open/complete/revoke
  // transitions, each emitting a new signed mission claim via claimRegistry.
  const missionRepo = new MissionRepository(db);
  const mission = new MissionService({
    repo: missionRepo,
    claimRegistry,
    kms,
    // baseline snapshot at open + mission-window diff at complete()/revoke().
    behavioralGenome,
    // Redis for genome_drift_fired:<jti> del on open
    // (re-arm the drift detector for the new baseline window).
    redis,
    // gross-cost sum for coverage_cap_cents. The mission cap counts the FULL
    // LLM bill under the mission (provider cost plus any fee, as recorded on
    // llm_usage), not just a fee slice.
    llmUsageRepo,
    missionSpend,
    ...(missionActions ? { missionActions } : {}),
    // twin runtime opt-in. agentRepo + passportRepo resolve agent.twin_policy
    // from the open() input's passportJti; twinOrchestration fires
    // startTwinForMission when the policy resolves true. All three are
    // best-effort wired (set together) — if any is null, MissionService.open
    // silently skips the twin step, preserving legacy behavior.
    agentRepo,
    passportRepo,
    twinOrchestration,
    // a Mission's end (complete, expiry, every revoke reason)
    // revokes every Passport bound to it, plus delegated descendants, in
    // the transaction that records the terminal state. A failure rolls
    // the Mission transition back; nothing is log-and-continue.
    passportRevoker: createMissionPassportRevoker({ redis, passportClaimsRepo }),
    publishMissionRevocation: createMissionRevocationPublisher(redis),
    // A cap pauses its Mission by default: the owner is told, reviews it, and the agent hears the decision.
    audit,
    onPaused: async (event) => {
      await notification.publishEvent({
        operatorId: event.operatorId,
        eventType: 'mission.paused',
        severity: 'warning',
        payload: {
          mission_id: event.missionId,
          agent_id: event.agentId,
          cap: event.cap,
          service: event.service,
          message: 'A Mission reached one of its limits and is paused. Raise the limit, let it continue or close it.',
        },
      });
    },
    onDecision: decisionAnnouncer(registries),
  });

  // simulation_divergence detector. A post-persist hook on
  // ClaimRegistryService.registerClaim: every intent_outcome registration fires
  // the divergence check against the paired intent_simulation (if any).
  claimRegistry.setSimulationDivergenceHook(
    new SimulationDivergenceDetector({ repo: passportClaimsRepo, securityEvent }),
  );

  // Behavioral drift detector. A post-persist hook on behavioral_genome claims;
  // fires `genome_drift` security event + paired detector_signal claim on
  // threshold breach. The worker constructs the same detector for the claims its
  // daily cron emits, with its own ClaimRegistry.
  claimRegistry.setBehavioralDriftHook(
    new BehavioralDriftDetector({
      passportClaimsRepo,
      passportRepo,
      securityEvent,
      behavioralGenome,
      redis,
    }),
  );

  // Twin intent-claim mirror hook. Fires post-persist on every intent_claim; if
  // the passport has an active twin run, mirrors the intent under the twin
  // passport. Best-effort throughout — failure logs + swallows.
  claimRegistry.setTwinMirrorHook({
    async fire(args) {
      const twinRun = await twinRunsRepo.findByRealPassportJti(args.passportJti);
      if (!twinRun || twinRun.status !== 'running') return;
      await twinOrchestration.mirrorIntent({
        twinRunId: twinRun.id,
        operatorId: args.operatorId,
        twinPassportJti: twinRun.twin_passport_jti,
        realIntentClaim: args.realIntentClaim,
        realClaimId: args.realClaimId,
      });
    },
  });

  return {
    behavioralGenome,
    twinOrchestration,
    missionRepo,
    missionLookup: createMissionLookup(mission),
    mission,
  };
}

/**
 * The MissionLookup PassportService reads so issue(), delegate() and refresh()
 * can require exactly one live Mission. A thin adapter over MissionService,
 * kept here so PassportService never imports MissionService.
 */
function createMissionLookup(mission: MissionService): MissionLookup {
  return {
    async findById(missionId: string) {
      const view = await mission.findById(missionId);
      if (!view) return null;
      return {
        mission_id: view.mission_id,
        operator_id: view.operator_id,
        intent_services: view.intent_services,
        // The undeclared_target flag treats these as already-known so an
        // operator who declares counterparties up front is not flagged on first
        // touch.
        expected_counterparties: view.expected_counterparties,
        expires_at: view.expires_at,
        completed_at: view.completed_at,
        revoked_at: view.revoked_at,
        assigned_agent_id: view.assigned_agent_id ?? null,
      };
    },
  };
}

type IntentApprovalHooks = Pick<
  ConstructorParameters<typeof IntentApprovalService>[0],
  'onSubmit' | 'onReject'
>;

function createIntentApprovalHooks(deps: {
  notification: NotificationService;
  passport: PassportService;
  agent: AgentService;
}): IntentApprovalHooks {
  const { notification, passport, agent } = deps;
  return {
    onSubmit: async (row) => {
      await notification.publishEvent({
        operatorId: row.operator_id,
        eventType: 'intent_approval.pending',
        severity: 'warning',
        payload: {
          approval_id: row.id,
          agent_id: row.agent_id,
          passport_jti: row.passport_jti,
          intent_claim_id: row.intent_claim_id,
          simulated_claim_id: row.simulated_claim_id,
        },
      });
    },
    onReject: async (row) => {
      // Auto-revoke the passport. Rejection means the agent's
      // submitted Intent was unacceptable — every credential it could
      // use under this passport is now suspect.
      await passport.revoke({
        jti: row.passport_jti,
        operatorId: row.operator_id,
        reason: 'Intent rejected by operator',
      });
      if (row.block_future) {
        await agent.updateStatus(row.agent_id, 'blocked');
      }
    },
  };
}

export interface IntentGate {
  /**
   * Pre-execution dry-run producer. Mirrors the proxy policy chain statically
   * (scope + constraints + accountability + tier_limit) and emits a signed
   * intent_simulation claim.
   */
  intentSimulation: IntentSimulationService;
  /**
   * Pre-execution approval gate: submit() registers the intent_claim and writes
   * a pending intent_approvals row; approve()/reject() transition via atomic CAS.
   */
  intentApproval: IntentApprovalService;
  /**
   * Universal producer-side gate over the approvals above. Producer routes
   * (proxy, skills, a2a) call check() to skip, continue with an approved
   * IntentClaim, or 403 with a signed intent_denial.
   */
  approvalGate: ApprovalGateService;
}

/** Intent simulation, approval, and the producer-side approval gate. */
export function createIntentGate(deps: {
  db: Database;
  kms: KmsService;
  passportClaimsRepo: CoreRepositories['passportClaimsRepo'];
  passport: PassportService;
  agent: AgentService;
  claimRegistry: ClaimRegistryService;
  entitlements: Pick<EntitlementResolver, 'resolve'>;
  /** What one more action would do to the plan behind it, read without counting it. */
  meter: Pick<ActionMeter, 'peek'>;
  detector: DetectorService;
  mission: MissionService;
  notification: NotificationService;
  /** Told when an intent approval or a fleet review ends, so the agent waiting on it hears how it ended. */
  onDecision?: DecisionReachedHook;
}): IntentGate {
  const {
    db,
    kms,
    passportClaimsRepo,
    passport,
    agent,
    claimRegistry,
    entitlements,
    meter,
    detector,
    mission,
    notification,
  } = deps;
  const intentSimulation = new IntentSimulationService({
    passportService: passport,
    claimRegistry,
    // A tenant simulates against its partner's plan, exactly as it is metered.
    resolveOperatorTier: async (operatorId: string) =>
      (await entitlements.resolve(operatorId)).tier,
    // The meter's read-only counterpart of counting an action.
    peekOverage: async (operatorId, _tier, simulated) => meter.peek(operatorId, simulated),
    // detector_block coverage in dryRun mode.
    detector,
    // undeclared_target reads prior entity_observation claims attached to the
    // passport's subject.
    passportClaimsRepo,
    // Seed the bound mission's expected_counterparties into the observed set so
    // pre-declaration suppresses the first-touch flag.
    missionLookup: {
      findById: (missionId: string) => mission.findById(missionId),
    },
  });

  // onSubmit fires notification dispatch (operator's configured channels pick up
  // via `intent_approval.pending` events). onReject auto-revokes the passport —
  // once an enforced Intent is rejected, the agent has gone off-script and
  // continued issuance is unsafe; block_future=true additionally suspends the
  // agent to stop subsequent passports. Both hooks are fire-and-forget; their
  // failures log and swallow so a notification outage doesn't fail a decision.
  const intentApprovalRepo = new IntentApprovalRepository(db);
  const intentApproval = new IntentApprovalService({
    repo: intentApprovalRepo,
    kms,
    passportService: passport,
    claimRegistry,
    intentSimulation,
    ...createIntentApprovalHooks({ notification, passport, agent }),
    ...(deps.onDecision ? { onDecision: deps.onDecision } : {}),
  });

  const approvalGate = new ApprovalGateService({
    approvalRepo: intentApprovalRepo,
    claimRegistry,
    passportClaimsRepo,
  });

  return { intentSimulation, intentApproval, approvalGate };
}
