import type { Database } from '@stack/shared';
import {
  AuditService,
  AuditArchiveService,
  SecurityEventService,
  OperatorDetectorConfigRepository,
  OperatorDetectorConfigService,
  OperatorPiiConfigRepository,
  OperatorPiiConfigService,
  DetectorService,
  type AgentRepository,
  type ArchiveErasePrefix,
  type InputScanStarter,
  type NotificationService,
  type StreamingObjectStore,
  type PassportClaimsRepository,
  type PassportService,
  type ClaimRegistryService,
  type SecurityEventRepository,
} from '@stack/vault';
import type { NetworkClientServices } from '../network-client.js';
import { env } from '../env.js';
import { createApiObjectStore } from '../object-store.js';
import {
  scanForPromptInjectionAsync,
  startPromptInjectionScan,
  type PromptInjectionScanOptions,
} from '../../detectors/prompt-injection.js';
import { createL3ClassifierSource, type L3ClassifierSource } from '../../detectors/l3-classifier.js';
import {
  scanResponseForOutputInjection,
  redactResponseBody,
} from '../../detectors/output-injection.js';
import type { RedisClient } from './infra.js';

export interface AuditTrail {
  audit: AuditService;
  auditArchive: AuditArchiveService;
  /** Cold storage the audit archive and evidence-pack export write to. */
  auditObjectStore: StreamingObjectStore;
}

/**
 * Builds the audit chain with its read-through to the cold archive. The API
 * never WRITES segments (that is the worker's daily job) but it must read them:
 * after the archive runs, most of a customer's history is not in Postgres, and
 * audit export is the one operation the published terms promise always works. A
 * hot-only export would hand back a truncated chain that looks like a complete
 * one.
 *
 * Evidence-pack export also writes exact manifest bytes to the same store. It
 * deletes only its new object when the matching database transaction fails.
 *
 * Boot refuses in production without a durable store.
 */
export async function createAuditTrail(db: Database, extraErasePrefixes: readonly ArchiveErasePrefix[] = []): Promise<AuditTrail> {
  const audit = new AuditService(db);
  const auditObjectStore = await createApiObjectStore();
  if (process.env['NODE_ENV'] === 'production' && !auditObjectStore.durable) {
    throw new Error('AUDIT_ARCHIVE_BUCKET is required in production for durable account erasure');
  }
  const auditArchive = new AuditArchiveService({
    db,
    store: auditObjectStore,
    ...(env.AUDIT_HOT_WINDOW_DAYS ? { hotWindowDays: Number(env.AUDIT_HOT_WINDOW_DAYS) } : {}),
    // What the deployment keeps in the same store (the agent drive's files) goes with the account.
    extraErasePrefixes,
  });
  audit.setArchive(auditArchive);
  await audit.initChain();
  return { audit, auditArchive, auditObjectStore };
}

/**
 * Security events. Notification dispatch is wired in so detector fires route to
 * the operator's email/SMS/webhook delivery methods (rules are configured in
 * the dashboard by subscribing to the 'security.event' event_type). Every
 * detector fire also dual-writes a signed detector_signal claim through the
 * claim registry.
 */
export function createSecurityEvents(deps: {
  securityEventRepo: SecurityEventRepository;
  agentRepo: AgentRepository;
  passport: PassportService;
  redis: RedisClient;
  notification: NotificationService;
  claimRegistry: ClaimRegistryService;
}): SecurityEventService {
  const securityEvent = new SecurityEventService(deps.securityEventRepo, deps.agentRepo);
  securityEvent.setAgentBlocker(deps.passport);
  // Redis-backed dedup gate for repeated identical warnings
  // (one event + one notification per (operator, dedupKey) per window).
  securityEvent.setDedupStore(deps.redis);
  securityEvent.setNotificationService(deps.notification);
  securityEvent.setClaimRegistryService(deps.claimRegistry);
  return securityEvent;
}

/**
 * Audit chain claim binding. AuditService auto-resolves
 * passport_claims_at_event from the repo at write time, so any audit call
 * carrying a passport_jti automatically captures the active claim set into the
 * chain hash. Legacy chains (audit calls without a passport_jti) remain valid
 * under their stored v1 version. New rows are v2 and a resolver failure denies
 * the evidence-critical action.
 */
export function bindAuditToClaims(deps: {
  audit: AuditService;
  passportClaimsRepo: PassportClaimsRepository;
  securityEvent: SecurityEventService;
}): void {
  const { audit, passportClaimsRepo, securityEvent } = deps;
  audit.setPassportClaimHashResolver(passportClaimsRepo);
  audit.onClaimBindingFailure(async (failure) => {
    await securityEvent.record({
      operatorId: failure.operatorId,
      agentId: failure.agentId,
      passportJti: failure.passportJti,
      signalType: 'audit_claim_binding_failure',
      // The action itself is denied. Keep the platform-health alarm at
      // warning so a resolver outage cannot auto-block every affected agent.
      severity: 'warning',
      message: 'Audit evidence claim binding failed; the action was denied.',
      metadata: { reason: failure.reason },
      pipeline: 'detection-chain',
    });
  });
}

export interface Detectors {
  operatorDetectorConfig: OperatorDetectorConfigService;
  operatorPiiConfig: OperatorPiiConfigService;
  /** The classifier of a scan's third layer (the deployment's own, or STACK's network one), or null when there is none. */
  l3Classifier: L3ClassifierSource | null;
  detector: DetectorService;
}

/**
 * Detector orchestration. The scanner FUNCTIONS live in apps/api/src/detectors/*;
 * DetectorService is the vault-side orchestration wrapper that fetches operator
 * overrides, calls the scanners, records security events, and returns the
 * caller's enforcement decisions. The scanners are injected so the service
 * stays in vault while the heavy pattern catalogs stay in the API.
 */
export function createDetectors(deps: {
  db: Database;
  redis: RedisClient;
  securityEvent: SecurityEventService;
  /** The deployment's own third layer, per scan (STACK's model classifier and its budget); null on an install. */
  l3Source: L3ClassifierSource | null;
  /** STACK's hosted network (self-managed installs only): live rules and the L3 classifier. */
  networkClient?: NetworkClientServices | null;
}): Detectors {
  const { db, redis, securityEvent, l3Source, networkClient } = deps;
  // The deployment's own classifier when it has one; STACK's hosted classifier
  // only fills in when an install chose it. Its calls are billed to the
  // install's STACK account, not by this install.
  // Per-operator detector customization. Service has its own Redis-backed cache
  // (60s TTL) so the detector hot path avoids a DB hit on every scan.
  // Tier-gating happens at the route layer.
  const operatorDetectorConfigRepo = new OperatorDetectorConfigRepository(db);
  const operatorDetectorConfig = new OperatorDetectorConfigService(
    operatorDetectorConfigRepo,
    redis,
  );
  const operatorPiiConfigRepo = new OperatorPiiConfigRepository(db);
  const operatorPiiConfig = new OperatorPiiConfigService(operatorPiiConfigRepo, redis);

  // Retries and repeated content reuse a verdict instead of paying for
  // (and waiting on) a second classification. Keyed per operator; stores only
  // verdict + confidence. See l3VerdictCacheKey for why it is never shared.
  const l3Classifier = createL3ClassifierSource({
    source: l3Source,
    network: networkClient?.classifier ?? null,
    cache: {
      get: (key) => redis.get(key),
      set: (key, value, ttlSeconds) => redis.set(key, value, 'EX', ttlSeconds),
    },
  });
  const detectorScanOptions = ({
    overrides,
    skipL3,
    operatorId,
    agentId,
    passportJti,
  }: Parameters<InputScanStarter>[0]): PromptInjectionScanOptions => ({
    // The LLM gateway reaches L3 through here. The deployment's classifier
    // carries its own budget per scan, so this path cannot escape the gate:
    // /v1/scan and skill invocation are capped the same way.
    l3: l3Classifier?.({
      ...(operatorId ? { operatorId } : {}),
      agentId,
      passportJti,
      reuseVerdicts: true,
    }) ?? null,
    ...(networkClient?.rules?.current().length ? { extraPatterns: networkClient.rules.current() } : {}),
    ...(overrides ? { overrides } : {}),
    ...(skipL3 ? { skipL3 } : {}),
  });
  const detector = new DetectorService({
    securityEvent,
    operatorDetectorConfig,
    inputScanner: async (args) =>
      scanForPromptInjectionAsync(args.body, args.fieldPath, detectorScanOptions(args)),
    inputScanStarter: (args) =>
      startPromptInjectionScan(args.body, args.fieldPath, detectorScanOptions(args)),
    outputScanner: scanResponseForOutputInjection,
    outputRedactor: redactResponseBody,
  });
  return { operatorDetectorConfig, operatorPiiConfig, l3Classifier, detector };
}
