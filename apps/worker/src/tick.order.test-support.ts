import type { WorkerRuntime } from './runtime.js';

/** A runtime with every optional part present, so a missing job is a failing assertion and not a skipped branch. */
export function fullRuntime(): WorkerRuntime {
  return {
    db: {},
    redis: {},
    state: { cmekTickLastRanAt: null },
    cmekMigrationWorker: {},
    payoutService: { current: () => ({}) },
    digest: { email: {}, to: 'ops@example.test' },
  } as unknown as WorkerRuntime;
}

export const ENGINE_ORDER = [
  'maybeRunArchiveStoreProbe',
  'expireDropoffs',
  'expireIntentApprovals',
  'runOAuthRetryCleanup',
  'runOperatorErasureRetry',
  'runEmailChangeRetry',
  'detectCheckpointSilence',
  'detectExpiredNoCheckout',
  'autoRevokeExpiredClaims',
  'recoverFleets',
  'runProxyMaintenance',
  'runCmekMigrationTick',
  'runAuditRetention',
  'maybeRunClaimRetentionPrune',
  'runBehavioralGenomeRollup',
  'maybeRunMissionExpirySweep',
  'runInboundRetention',
  'maybeRunAuditChainVerifier',
];
