import * as Sentry from '@sentry/node';
import { safeErrorSummary } from '@stack/shared';
import {
  CmekMigrationRepository,
  CmekMigrationWorker,
  KmsService,
  type CmekMigrationStep,
  type OperatorRepository,
} from '@stack/vault';
import { chooseCmekKmsForWorker } from '../cmek-kms-selector.js';
import type { WorkerDb, WorkerRedis } from '../redis.js';

/**
 * CMEK migration tick (the worker re-encrypts operator ciphertext page by page).
 *
 * Real AWS KMS is required for the migration tick: the worker re-encrypts
 * customer ciphertext page-by-page, and silently using a base64 dev mock
 * would be a confidentiality regression. `chooseCmekKmsForWorker` enforces
 * this: it hard-fails boot when prod-shaped but env-missing, and skips the tick
 * in dev (returns null). Other worker paths (drop-off, invocation, skill
 * review) use the dev KMS (`dev-kms.ts`) for data they only ever delete, never
 * surface.
 */
export async function startCmekMigration(deps: {
  db: WorkerDb;
  redis: WorkerRedis;
  operatorRepo: OperatorRepository;
  /** Stores of ciphertext the deployment adds to the engine's (its skills). */
  extraSteps?: readonly CmekMigrationStep[];
}): Promise<CmekMigrationWorker | null> {
  const { db, redis, operatorRepo, extraSteps } = deps;
  const cmekKmsSelection = chooseCmekKmsForWorker(process.env);
  let cmekMigrationWorker: CmekMigrationWorker | null = null;
  if (cmekKmsSelection.kind === 'real') {
    const cmekKms = new KmsService(cmekKmsSelection.config);
    const cmekMigrationRepo = new CmekMigrationRepository(db);

    // Per-operator resolver cache, same shape as the API's in `apps/api/src/config/wiring/`.
    // 5-minute TTL, Redis-pub/sub-invalidated on `stack:cmek-updated`, locally
    // evicted on KMS AccessDenied. Worker keeps its OWN
    // cache because the API's cache lives in a different process; pub/sub is
    // the only shared coherence channel.
    const cmekResolverCache = new Map<
      string,
      {
        state: {
          keyArn: string | null;
          status: 'none' | 'migrating' | 'active' | 'revoking' | 'revoked';
        };
        expiresAt: number;
      }
    >();
    const CMEK_CACHE_TTL_MS = 5 * 60 * 1000;
    cmekKms.setOperatorKeyHandlers({
      resolve: async (operatorId: string) => {
        const hit = cmekResolverCache.get(operatorId);
        const now = Date.now();
        if (hit && hit.expiresAt > now) return hit.state;
        const state = await operatorRepo.getCmekState(operatorId);
        cmekResolverCache.set(operatorId, { state, expiresAt: now + CMEK_CACHE_TTL_MS });
        return state;
      },
      evict: (operatorId: string) => {
        cmekResolverCache.delete(operatorId);
      },
      onLegacyFallback: () => {
        Sentry.addBreadcrumb({
          category: 'kms.legacy-fallback',
          message: 'decryptDirect succeeded without context after context-mismatch (worker)',
          level: 'info',
        });
      },
    });

    // pub/sub invalidation. The duplicate Redis connection is required —
    // ioredis subscribe-mode prohibits regular commands on the same client.
    const cmekSubscriber = redis.duplicate();
    await cmekSubscriber.subscribe('stack:cmek-updated');
    cmekSubscriber.on('message', (channel: string, message: string) => {
      if (channel === 'stack:cmek-updated' && message) {
        cmekResolverCache.delete(message);
      }
    });

    cmekMigrationWorker = new CmekMigrationWorker({
      db,
      kms: cmekKms,
      operatorRepo,
      migrationRepo: cmekMigrationRepo,
      stackSystemOperatorId: process.env['STACK_SYSTEM_OPERATOR_ID'] ?? '',
      ...(extraSteps ? { extraSteps } : {}),
      publishCmekUpdated: async (operatorId) => {
        try {
          await redis.publish('stack:cmek-updated', operatorId);
        } catch (err) {
          console.warn('[CMEK] publish stack:cmek-updated failed', safeErrorSummary(err));
        }
      },
      acquireLock: async (key, ttlSeconds) => {
        const acquired = await redis.set(key, new Date().toISOString(), 'EX', ttlSeconds, 'NX');
        return acquired === 'OK';
      },
      releaseLock: async (key) => {
        await redis.del(key);
      },
    });
    console.log(`Worker: CMEK migration tick enabled (region=${cmekKmsSelection.config.region}).`);
  } else {
    console.log(`Worker: ${cmekKmsSelection.reason}`);
  }

  return cmekMigrationWorker;
}
