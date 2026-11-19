import {
  BehavioralDriftDetector,
  BehavioralGenomeService,
  MissionRepository,
  MissionService,
  REVOCATION_CHANNEL,
  createMissionPassportRevoker,
  type ClaimRegistryService,
  type PassportClaimsRepository,
  type PassportRepository,
  type SecurityEventService,
} from '@stack/vault';
import type { WorkerDb, WorkerRedis } from '../redis.js';

/**
 * Missions, the behavioral genome and drift detection, all wired to the
 * worker's claim registry so expiry and rollups emit signed claims.
 */
export function buildMissionServices(deps: {
  db: WorkerDb;
  redis: WorkerRedis;
  claimRegistry: ClaimRegistryService;
  passportClaimsRepo: PassportClaimsRepository;
  passportRepo: PassportRepository;
  securityEvent: SecurityEventService;
}) {
  const { db, redis, claimRegistry, passportClaimsRepo, passportRepo, securityEvent } = deps;
  const missionRepo = new MissionRepository(db);
  // BehavioralGenomeService for the daily genome rollup. The daily cron
  // (maybeRunBehavioralGenomeRollup) invokes emitForWindow per passport with
  // audit activity in the previous UTC calendar day. Constructed
  // before MissionService, which uses it for the baseline snapshot and the
  // mission-window diff.
  const behavioralGenome = new BehavioralGenomeService({
    db,
    claimRegistry,
    passportClaimsRepo,
  });

  // MissionService with claimRegistry wired so MissionService.complete()
  // emits a signed `mission` claim envelope on every auto-expiry
  // transition. An expired Mission's Passports are revoked in that same
  // transition (passportRevoker), and the revocation is broadcast on
  // stack:revoked like an API-side Mission end.
  //
  // behavioralGenome + redis are wired so the worker's mission-expiry sweep
  // (maybeRunMissionExpirySweep) computes behavioral_diff on the way out. complete() reads passport_jti from
  // the missions row (no JTI context needed at the worker call site).
  const missionService = new MissionService({
    repo: missionRepo,
    claimRegistry,
    behavioralGenome,
    redis,
    passportRevoker: createMissionPassportRevoker({ redis, passportClaimsRepo }),
    publishMissionRevocation: async (event) => {
      await redis.publish(REVOCATION_CHANNEL, JSON.stringify({ type: 'bulk_mission', ...event, at: Date.now() }));
    },
  });

  // Wire the behavioral drift detector into the worker's ClaimRegistry.
  // Critical: the worker emits the bulk of behavioral_genome claims via the
  // daily cron, so without this worker-side hook those emissions would never
  // trigger drift detection. Same detector shape as the API-side instance
  // (apps/api/src/config/wiring/), with identical thresholds and the same
  // SecurityEventService for the dual-write. SecurityEventService is wired
  // with the claim registry below, the same way the API wires it.
  const behavioralDrift = new BehavioralDriftDetector({
    passportClaimsRepo,
    passportRepo,
    securityEvent,
    behavioralGenome,
    redis,
  });
  claimRegistry.setBehavioralDriftHook(behavioralDrift);

  // The worker's SecurityEventService needs the claim registry wired so
  // that detector_signal claims emitted by the drift detector dual-write
  // the signed envelope alongside the legacy security_events row.
  // Mirror of the API's `securityEvent.setClaimRegistryService(claimRegistry)`
  // in apps/api/src/config/wiring/. Until this is set,
  // SecurityEventService.record() only writes the legacy row (claim emission is
  // best-effort and falls through to the legacy row on a missing registry).
  securityEvent.setClaimRegistryService(claimRegistry);

  return { missionRepo, behavioralGenome, missionService };
}
