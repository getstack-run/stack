// Sentry init must precede any other imports.
import * as Sentry from '@sentry/node';
import './secret-files.js';
import { assertEngineEntryAllowed, installSafeConsoleTelemetry, safeSentryRelease, sanitizeSentryEvent, deployment, staging } from '@stack/shared';
import { pathToFileURL } from 'node:url';

installSafeConsoleTelemetry();
const sentryDsn = process.env['SENTRY_DSN'];
if (sentryDsn) {
  Sentry.init({
    dsn: sentryDsn,
    environment: process.env['NODE_ENV'] ?? 'development',
    tracesSampleRate: 0,
    sendDefaultPii: false,
    // `stack-worker@<40-hex>` from the deploy workflow, or unset.
    release: safeSentryRelease('worker', process.env['STACK_RELEASE_SHA']),
    initialScope: { tags: { site: 'worker' } },
    beforeSend: sanitizeSentryEvent,
  });
}

import { createDb } from '@stack/shared';
import { DropoffRepository, DropoffService } from '@stack/dropoff';
import {
  AgentRepository,
  AuthorityRepository,
  ContractPlanEntitlements,
  InboundWebhookReceiptsRepository,
  EmailChangeService,
  FleetRepository,
  NO_PROXY_HOLDS,
  OperatorRepository,
  PassportClaimsRepository,
  PassportRepository,
  ProxyAccountingReconciler,
  ProxyOperationRepository,
  ProxyOperationService,
  ProxyPostResponseService,
  RuntimeAuthorityCompletionService,
  SecurityEventRepository,
  SecurityEventService,
} from '@stack/vault';
import { buildAuditArchive } from './boot/audit-archive.js';
import { createRuntimeAuthorityUseClaimIssuer } from './boot/authority-claims.js';
import { startCmekMigration } from './boot/cmek.js';
import { buildWorkerEmail } from './boot/email.js';
import { startHealthServer } from './boot/health.js';
import { buildMissionServices } from './boot/missions.js';
import { buildClaimSigning } from './boot/signing.js';
import { createDevKms } from './dev-kms.js';
import { createDeploymentKms } from './deployment-kms.js';
import type { EngineWorkerRuntime, ProxyAnalytics, WorkerCore, WorkerExtension, WorkerOverrides } from './extension.js';
import { maybeRunArchiveStoreProbe } from './jobs/archive-store-probe.js';
import { createEmailChangeDeliveryRetryGate } from './email-change-delivery-retry.js';
import { createPoll, POLL_INTERVAL_MS, startGuardedInterval } from './loop.js';
import { createTickObserver } from './tick-observer.js';
import { createOAuthRefreshPruneGate, createOAuthRetryCleanupGate } from './oauth-retry-cleanup.js';
import { createOperatorErasureRetryGate } from './operator-erasure-retry.js';
import { createRedis, runBootWithRedisRetry, waitForRedis, type WorkerDb, type WorkerRedis } from './redis.js';
import type { WorkerRuntime, WorkerState } from './runtime.js';
import { runTick } from './tick.js';

// Re-exported so the entry point stays the import surface for the loop helper
// and for the email-preview script, which renders the digest through it.
export { startGuardedInterval } from './loop.js';

const DATABASE_URL = process.env['DATABASE_URL'] ?? '';

// The Redis client of the boot attempt in flight, so a retried boot can drop it.
let bootRedis: WorkerRedis | null = null;

/** What the proxy's post-response work reports to when the deployment names no analytics: nothing. */
const NO_ANALYTICS: ProxyAnalytics = {
  async fireOnce() {},
  capture() {},
};

/**
 * Builds the worker and runs one `poll()` immediately and every
 * `POLL_INTERVAL_MS` after that. With no extension it runs the engine's jobs
 * alone; a deployment passes its own parts and jobs.
 */
export async function startWorker<Parts extends object = object>(ext: WorkerExtension<Parts> | null): Promise<void> {
  console.log('STACK Worker starting...');
  if (!DATABASE_URL) throw new Error('[BOOT] DATABASE_URL is required');
  // A staging deployment with no allow-list, or an unreadable STACK_STAGING, refuses to start. Its email to anyone
  // off the allow-list is skipped in the senders themselves (packages/vault/src/services/staging-email-guard.ts).
  if (staging().enabled) console.log('Worker: staging deployment; email only to STAGING_SIGNIN_ALLOWLIST.');

  // A deployment's tables are merged into the one handle, so its relational queries can read them; the
  // engine alone never reads a table outside its own, whatever the handle's type says.
  const db = (ext ? createDb(DATABASE_URL, ext.dbSchema) : createDb(DATABASE_URL)) as unknown as WorkerDb;
  const redisUrl = process.env['REDIS_URL'] ?? 'redis://localhost:6380';
  bootRedis?.disconnect();
  const redis = await createRedis(redisUrl);
  bootRedis = redis;
  const state: WorkerState = { cmekTickLastRanAt: null };
  // Up before anything can wait on Redis, so a Redis that is down keeps the
  // worker alive (and visible to the platform) while it retries instead of exiting it.
  startHealthServer(state);
  await waitForRedis(redis);
  const stackSystemOperatorId = process.env['STACK_SYSTEM_OPERATOR_ID'] ?? '';
  // An erased account's rows go in one transaction; a deployment's own statements join it at their named points.
  const operatorRepo = new OperatorRepository(db, {
    deleteSteps: () => ext?.operatorDeleteSteps ?? [],
    ...(ext?.monthlyActionLimit ? { monthlyActionLimit: ext.monthlyActionLimit } : {}),
  });

  // CMEK migration tick. Needs real AWS KMS; boot fails when prod-shaped but
  // the env is missing, and the tick is skipped in dev.
  const cmekMigrationWorker = await startCmekMigration({ db, redis, operatorRepo, ...(ext?.cmekSteps ? { extraSteps: ext.cmekSteps } : {}) });

  // Drop-off paths only ever delete the ciphertext they hold, so they run on
  // the dev KMS. Anything that re-encrypts or persists customer data must use
  // the real KmsService.
  const devKms = createDevKms();
  const dropoffService = new DropoffService(new DropoffRepository(db), devKms);

  // Audit service and cold archive. Exports and evidence packs see the whole
  // chain, not just the hot window.
  const { audit, archive, operatorErasure, archiveStore } = await buildAuditArchive({ db, operatorRepo, erasureSteps: ext?.erasureSteps?.({ db }) ?? [], extraErasePrefixes: ext?.archiveErasePrefixes ?? [] });
  // Boot-time probe of the object store (the tick repeats it every ten minutes).
  await maybeRunArchiveStoreProbe({ archiveStore, redis });

  // Security signal detection.
  const passportRepo = new PassportRepository(db);
  const agentRepo = new AgentRepository(db);
  const securityEventRepo = new SecurityEventRepository(db);
  const securityEvent = new SecurityEventService(securityEventRepo, agentRepo);
  // Same Redis dedup gate as the API: a warning suppressed API-side stays
  // suppressed for worker-side fires too and vice versa (shared
  // stack:sec_event_dedup:* keys).
  securityEvent.setDedupStore(redis);
  const passportClaimsRepo = new PassportClaimsRepository(db);

  // Deployment KMS: real when configured, otherwise the dev mock. Signing and
  // vault credential reads go through it.
  const deploymentKms = createDeploymentKms(devKms, stackSystemOperatorId);

  const proxyOperationRepository = new ProxyOperationRepository(db);
  const proxyOperations = new ProxyOperationService(proxyOperationRepository, deploymentKms);

  // Whether an account has controls on: the deployment's billing accounts, or the contract plan (always on).
  const entitlements = ext ? ext.entitlements({ operatorRepo, db }) : new ContractPlanEntitlements(operatorRepo);
  const { claimRegistry, signerForOperator } = await buildClaimSigning({
    db,
    redis,
    kms: deploymentKms,
    passportClaimsRepo,
    stackSystemOperatorId,
  });
  const { missionRepo, behavioralGenome, missionService } = buildMissionServices({
    db,
    redis,
    claimRegistry,
    passportClaimsRepo,
    passportRepo,
    securityEvent,
  });

  const runtimeAuthority = new RuntimeAuthorityCompletionService({
    repo: new AuthorityRepository(db),
    claimIssuer: createRuntimeAuthorityUseClaimIssuer(claimRegistry),
  });
  const proxyPostResponse = new ProxyPostResponseService({
    proxyOperation: proxyOperations,
    redis,
    audit,
    claimRegistry,
    authority: runtimeAuthority,
    securityEvent,
    passportClaimsRepo,
    mission: missionService,
    analytics: (await ext?.analytics?.(redis)) ?? NO_ANALYTICS,
  });

  const email = buildWorkerEmail();
  const emailChangeDelivery = new EmailChangeService({
    db,
    email,
    rateLimitStore: null,
    audit,
    dashboardUrl: deployment().dashboardUrl,
  });

  const engine: EngineWorkerRuntime = {
    db,
    redis,
    stackSystemOperatorId,
    state,
    gates: {
      oauthRetryCleanup: createOAuthRetryCleanupGate(),
      oauthRefreshPrune: createOAuthRefreshPruneGate(),
      operatorErasureRetry: createOperatorErasureRetryGate(operatorErasure),
      emailChangeRetry: createEmailChangeDeliveryRetryGate(emailChangeDelivery),
      reviewDemoRefresh: async () => {},
    },
    audit,
    archive,
    archiveStore,
    securityEvent,
    securityEventRepo,
    passportRepo,
    passportClaimsRepo,
    dropoffService,
    missionRepo,
    missionService,
    behavioralGenome,
    fleetRepo: new FleetRepository(db),
    inboundReceiptsRepo: new InboundWebhookReceiptsRepository(db),
    auditCheckSkipOperatorIds: ext?.auditCheckSkipOperatorIds ?? [],
    // The behavioural baseline is a controls feature.
    genomeEligible: (operatorId: string) => entitlements.controlsEnabled(operatorId),
    proxyOperations,
    proxyPostResponse,
    cmekMigrationWorker,
  };

  // What the deployment adds, built from what the engine just built.
  const core: WorkerCore = {
    db,
    redis,
    stackSystemOperatorId,
    deploymentKms,
    devKms,
    agentRepo,
    operatorRepo,
    audit,
    archiveStore,
    securityEvent,
    missionService,
    signerForOperator,
    email,
  };
  const parts = ext ? await ext.runtime(engine, core) : ({} as Parts & WorkerOverrides);
  const { reviewDemoRefresh, proxyAccounting: hostedAccounting, ...hostedParts } = parts;
  // The engine's proxy accounting reaches a wallet only to settle a hold; without a deployment there is none,
  // and its ledger refuses if it is ever asked.
  const proxyAccounting = hostedAccounting
    ?? new ProxyAccountingReconciler(proxyOperationRepository, NO_PROXY_HOLDS, redis);
  const runtime: WorkerRuntime & Parts = {
    ...engine,
    ...(hostedParts as unknown as Parts),
    proxyAccounting,
    gates: { ...engine.gates, reviewDemoRefresh: reviewDemoRefresh ?? engine.gates.reviewDemoRefresh },
  };

  console.log(
    'Worker ready. Polling for expired drop-offs, security signals, missions and the deployment\'s own jobs...',
  );

  const poll = createPoll({
    tick: () => runTick(runtime, ext),
    // Fire-and-forget: HTTP-only, Redis-locked to one machine per 10 minutes,
    // never rejects, and started before the DB work so a DB blip cannot skip it.
    detached: () => void runtime.gates.reviewDemoRefresh(),
    sentryDsn,
    // The heartbeat is written by the work, not by a timer of its own: a worker whose tick is stuck or failing stops looking online.
    onTick: createTickObserver(redis, ext),
  });

  // Run immediately, then on interval
  await poll();
  startGuardedInterval(poll, POLL_INTERVAL_MS);

  // Graceful shutdown
  const shutdown = () => {
    console.log('Worker shutting down...');
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

/** Runs the worker. A Redis outage during startup waits and retries; any other failure stops the worker. */
export function runWorker<Parts extends object = object>(ext: WorkerExtension<Parts> | null): void {
  runBootWithRedisRetry(() => startWorker(ext)).catch(() => {
    console.error('[worker] failed to start: diagnostic details suppressed.');
    if (sentryDsn) {
      Sentry.captureException(new Error('Worker startup failed'), {
        tags: { source: 'worker.boot' },
      });
      // Best-effort flush before exit so the boot crash actually
      // reaches Sentry.
      void Sentry.flush(2000).finally(() => process.exit(1));
    } else {
      process.exit(1);
    }
  });
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  return typeof entry === 'string' && import.meta.url === pathToFileURL(entry).href;
}

// Run directly, this is the engine's entry point: it runs the engine's jobs alone, and in production only on a
// self-managed deployment. STACK's own worker starts from an entry point of its own.
if (!process.env['VITEST'] && isMainModule()) {
  try {
    assertEngineEntryAllowed();
  } catch {
    console.error('[worker] failed to start: diagnostic details suppressed.');
    process.exit(1);
  }
  runWorker(null);
}
