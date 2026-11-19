import { evidenceAction, evidenceUrl, isHostAllowed, observedKnowsEntity, redactRequestPath, safeErrorSummary } from '@stack/shared';
import {
  postResponseRetryAt,
  type ProxyOperationService,
  type ClaimedProxyPostResponseWork,
} from './proxy-operation-service.js';
import type { AuditService } from './audit-service.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type { AuthorityService } from './authority-service.js';
import type { SecurityEventService } from './security-event-service.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

/**
 * The path a signed outcome records: the one the agent sent, before any
 * credential field was interpolated into it (a bot token can live in the
 * path), with secret-looking segments redacted. Never the resolved path.
 */
function evidencePath(originalUrl: string): string {
  try {
    return redactRequestPath(new URL(originalUrl).pathname);
  } catch {
    return '(unparseable URL)';
  }
}

interface RedisProjection {
  sadd(key: string, value: string): Promise<unknown>;
  expire(key: string, seconds: number): Promise<unknown>;
}

interface AnalyticsProjection {
  fireOnce(operatorId: string, event: string, properties?: Record<string, unknown>): Promise<void>;
  capture(operatorId: string, event: string, properties?: Record<string, unknown>): void;
}

interface MissionLookup {
  findById(id: string): Promise<{ expected_counterparties?: unknown[] } | null>;
}

export interface ProxyPostResponseDeps {
  proxyOperation: ProxyOperationService;
  redis: RedisProjection;
  audit: Pick<AuditService, 'write'>;
  claimRegistry: Pick<ClaimRegistryService, 'registerClaim'>;
  authority: Pick<AuthorityService, 'completeRuntimeAuthorityUseByHash'>;
  securityEvent: Pick<SecurityEventService, 'record'>;
  passportClaimsRepo: Pick<PassportClaimsRepository, 'findObservedContentForFlow' | 'findObservedEntitiesForAgent'>;
  mission?: MissionLookup;
  analytics: AnalyticsProjection;
}

export type ProxyPostResponseResult =
  | { state: 'idle' }
  | { state: 'completed' | 'waiting_provider'; operationId: string }
  | { state: 'retry_pending'; operationId: string; error: ReturnType<typeof safeErrorSummary> };

/**
 * Resumes only bookkeeping derived from an already-durable permitted response.
 * It has no credential, prepared-request decryptor, dispatch token, or transport
 * dependency, so this path cannot send or authorize another provider request.
 */
export class ProxyPostResponseService {
  constructor(private readonly deps: ProxyPostResponseDeps) {}

  /**
   * Claim and run one item of post-response work.
   *
   * `onRecorded` fires once the steps that make the call part of the record
   * are durable: the credential marker, the audit row, the undeclared-target
   * check and the signed claims (including the entity_observation the
   * data-flow rule reads). What remains (analytics, authority-use completion,
   * closing the item) carries on under the same lease. A caller may answer its
   * client at that point; if the process dies before the rest, the
   * lease expires and the worker resumes from the last marked step.
   */
  async processOne(
    operationId?: string,
    options: { onRecorded?: () => void } = {},
  ): Promise<ProxyPostResponseResult> {
    const work = await this.deps.proxyOperation.claimPostResponseWork(operationId);
    if (!work) return { state: 'idle' };
    try {
      return await this.processClaimed(work, options.onRecorded);
    } catch (error) {
      await this.deps.proxyOperation.releasePostResponseWork({
        operatorId: work.operation.operator_id,
        operationId: work.operation.id,
        token: work.token,
        retryAt: postResponseRetryAt(work.operation.post_response_attempts),
      }).catch(() => false);
      return {
        state: 'retry_pending',
        operationId: work.operation.id,
        error: safeErrorSummary(error),
      };
    }
  }

  async tick(limit = 100): Promise<{ completed: number; waiting: number; failed: number }> {
    const bounded = Math.max(1, Math.min(limit, 500));
    let completed = 0;
    let waiting = 0;
    let failed = 0;
    for (let i = 0; i < bounded; i += 1) {
      const result = await this.processOne();
      if (result.state === 'idle') break;
      if (result.state === 'completed') completed += 1;
      else if (result.state === 'waiting_provider') waiting += 1;
      else failed += 1;
    }
    return { completed, waiting, failed };
  }

  private async processClaimed(
    work: ClaimedProxyPostResponseWork,
    onRecorded?: () => void,
  ): Promise<ProxyPostResponseResult> {
    const { operation, context, token } = work;
    const step = async (
      name: Parameters<ProxyOperationService['markPostResponseStep']>[0]['step'],
      alreadyDone: Date | null,
      action: () => Promise<{ intentClaimId?: string; outcomeClaimId?: string } | void>,
    ) => {
      if (alreadyDone) return {};
      const produced = await action() ?? {};
      const marked = await this.deps.proxyOperation.markPostResponseStep({
        operatorId: operation.operator_id,
        operationId: operation.id,
        token,
        step: name,
        ...produced,
      });
      if (!marked) throw new Error(`Proxy post-response ${name} lease was lost`);
      return produced;
    };

    await step('credential', operation.post_response_credential_at, async () => {
      await this.deps.redis.sadd(`cred_accessed:${operation.passport_jti}`, operation.provider);
      await this.deps.redis.expire(`cred_accessed:${operation.passport_jti}`, 7200);
    });

    const providerOutcome = operation.adapter_kind === 'stripe'
      ? operation.reconciliation_state === 'confirmed'
        ? operation.reconciliation_provider_status
        : null
      : context.action.statusCode >= 200 && context.action.statusCode < 400
        ? 'succeeded'
        : 'failed';
    const businessOutcome = providerOutcome === 'succeeded'
      ? 'succeeded'
      : providerOutcome === 'failed' || providerOutcome === 'canceled'
        ? 'failed'
        : null;

    await step('audit', operation.post_response_audit_at, async () => {
      await this.deps.audit.write({
        ctx: {
          trace_id: context.audit.traceId,
          span_id: context.audit.spanId,
          ...(context.audit.parentSpanId ? { parent_span_id: context.audit.parentSpanId } : {}),
          operator_id: operation.operator_id,
          agent_id: operation.agent_id,
          passport_jti: operation.passport_jti,
        },
        layer: 'vault',
        action: 'credential.proxy',
        outcome: businessOutcome === null
          ? 'pending'
          : businessOutcome === 'succeeded' ? 'success' : 'failure',
        duration_ms: context.audit.durationMs,
        request_bytes: context.audit.requestBytes,
        response_bytes: context.audit.responseBytes,
        request_entropy: context.audit.requestEntropy,
        response_entropy: context.audit.responseEntropy,
      });
    });

    if (businessOutcome === null) {
      const released = await this.deps.proxyOperation.releasePostResponseWork({
        operatorId: operation.operator_id,
        operationId: operation.id,
        token,
        waitingForProvider: true,
      });
      if (!released) throw new Error('Proxy post-response provider wait lease was lost');
      return { state: 'waiting_provider', operationId: operation.id };
    }

    // Compare against history before this operation appends its own entity
    // observation. Retries skip this step once marked, so the decision remains
    // stable even if later claim work resumes in another process.
    await step('security', operation.post_response_security_at, async () => {
      if (businessOutcome !== 'succeeded' || context.action.undeclaredCandidates.length === 0) return;
      // The service the owner connected is never a new counterparty: the hosts its credential may be sent to
      // are known from the start.
      const connectionHosts = context.action.connectionHosts ?? [];
      let candidates = context.action.undeclaredCandidates
        .filter((entity) => connectionHosts.length === 0 || !isHostAllowed(entity, connectionHosts));
      if (candidates.length === 0) return;

      // By Mission, like the data-flow rule: a counterparty this job already
      // dealt with under an earlier Passport is not new.
      const observedRows = await this.deps.passportClaimsRepo.findObservedContentForFlow({
        operatorId: operation.operator_id,
        passportId: operation.passport_jti,
        missionId: context.action.missionRef,
      });
      const observed = new Set<string>();
      for (const row of observedRows) {
        for (const entity of row.entities ?? []) observed.add(String(entity).toLowerCase());
      }
      if (context.action.missionRef && this.deps.mission) {
        const mission = await this.deps.mission.findById(context.action.missionRef).catch(() => null);
        for (const counterparty of mission?.expected_counterparties ?? []) {
          if (typeof counterparty === 'string') observed.add(counterparty.toLowerCase());
        }
      }
      // An observation is kept as a one-way digest (or, if recorded before
      // that, as text): either form counts as dealt with.
      candidates = candidates.filter((entity) => !observedKnowsEntity(observed, entity));
      if (candidates.length === 0) return;

      // Then by agent, across Missions: a counterparty the agent dealt with in any earlier Mission is not new to
      // it, so a test run of twenty-five Missions meets each counterparty once, not twenty-five times. Read only
      // for what the cheaper checks above left, which is rare.
      const seenByAgent = await this.deps.passportClaimsRepo.findObservedEntitiesForAgent({
        operatorId: operation.operator_id,
        agentId: operation.agent_id,
      });
      const seen = new Set(seenByAgent.map((entity) => String(entity).toLowerCase()));
      const undeclared = candidates.filter((entity) => !observedKnowsEntity(seen, entity));
      if (undeclared.length === 0) return;
      await this.deps.securityEvent.record({
        operatorId: operation.operator_id,
        agentId: operation.agent_id,
        passportJti: operation.passport_jti,
        signalType: 'undeclared_target',
        severity: 'warning',
        message: `Call reached ${undeclared.length} counterparty this passport has not dealt with before: ${undeclared.slice(0, 5).join(', ')}. Declare expected counterparties on the mission to silence expected ones.`,
        metadata: {
          undeclared_entities: undeclared.slice(0, 20),
          destination_service: context.action.service,
          review_flag: true,
        },
        missionIds: context.action.missionIds,
        dedupKey: `proxy-operation:${operation.id}:undeclared-target`,
        dedupWindowSeconds: 24 * 60 * 60,
      });
    });

    let intentClaimId = operation.post_response_intent_claim_id ?? undefined;
    let outcomeClaimId = operation.post_response_outcome_claim_id ?? undefined;
    const claims = await step('claims', operation.post_response_claims_at, async () => {
      if (businessOutcome !== 'succeeded') return {};
      if (context.action.accountability !== 'standard') {
        intentClaimId = context.action.approvedIntentClaimId ?? undefined;
        if (!intentClaimId) {
          const intent = await this.deps.claimRegistry.registerClaim({
            operatorId: operation.operator_id,
            passportJti: operation.passport_jti,
            claimType: 'intent_claim',
            sourceOperationId: operation.id,
            sourceRole: 'proxy_intent',
            payload: {
              type: 'intent_claim',
              intent_type: 'http_call',
              agent_id: operation.agent_id,
              named_intent: `${context.action.service}:http:proxy`,
              target: context.action.service,
              action: evidenceAction(context.action.method, context.action.originalUrl),
              parameters: {
                service: context.action.service,
                method: context.action.method,
                url: evidenceUrl(context.action.originalUrl),
                body: context.action.originalBody,
              },
              estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
              accountability: context.action.accountability,
              reason: null,
              requires: [],
              user_subject: null,
              mission_ref: context.action.missionRef,
              submitted_at: context.action.startedAt,
            },
          });
          intentClaimId = intent.claimId;
        }
        const outcome = await this.deps.claimRegistry.registerClaim({
          operatorId: operation.operator_id,
          passportJti: operation.passport_jti,
          claimType: 'intent_outcome',
          sourceOperationId: operation.id,
          sourceRole: 'proxy_outcome',
          payload: {
            type: 'intent_outcome',
            intent_claim_ref: intentClaimId,
            status: 'succeeded',
            duration_ms: context.audit.durationMs,
            cost_actual: { wallet_cents: 0, tokens: null, gas_gwei: null },
            recorded_at: context.action.recordedAt,
            outcome_type: 'http_call',
            actual_target: context.action.resolvedHost,
            actual_method_path: `${context.action.method} ${evidencePath(context.action.originalUrl)}`,
            actual_parameters_hash: context.action.parametersHash,
            status_code: context.action.statusCode,
            response_body_hash: context.action.responseBodyHash,
            latency_ms: context.audit.durationMs,
            redactions_count: context.action.redactionsCount,
            detector_fires_count: context.action.detectorFiresCount,
            ...(context.action.missionRef ? { mission_ref: context.action.missionRef } : {}),
          },
        });
        outcomeClaimId = outcome.claimId;
      }

      if (context.action.entityObservation) {
        await this.deps.claimRegistry.registerClaim({
          operatorId: operation.operator_id,
          passportJti: operation.passport_jti,
          claimType: 'entity_observation',
          sourceOperationId: operation.id,
          sourceRole: 'proxy_entity_observation',
          payload: {
            ...context.action.entityObservation,
            ...(outcomeClaimId ? { intent_outcome_ref: outcomeClaimId } : {}),
          },
        });
      }
      return { intentClaimId, outcomeClaimId };
    });
    intentClaimId = claims.intentClaimId ?? intentClaimId;
    outcomeClaimId = claims.outcomeClaimId ?? outcomeClaimId;
    onRecorded?.();

    await step('analytics', operation.post_response_analytics_at, async () => {
      if (businessOutcome !== 'succeeded') return;
      await this.deps.analytics.fireOnce(operation.operator_id, 'first_proxy_call', {
        service: context.action.service,
        method: context.action.method,
      });
      this.deps.analytics.capture(operation.operator_id, 'proxy_call', {
        service: context.action.service,
        method: context.action.method,
        duration_ms: context.audit.durationMs,
        status_code: context.action.statusCode,
        $insert_id: `proxy-operation:${operation.id}`,
      });
    });

    await step('authority', operation.post_response_authority_at, async () => {
      if (!operation.authority_use_id || !operation.response_hash) return;
      await this.deps.authority.completeRuntimeAuthorityUseByHash({
        operatorId: operation.operator_id,
        useId: operation.authority_use_id,
        outcome: businessOutcome,
        resultHash: `sha256:${operation.response_hash}`,
        ...(intentClaimId ? { intentClaimId } : {}),
        ...(outcomeClaimId ? { outcomeClaimId } : {}),
      });
    });

    const completed = await this.deps.proxyOperation.releasePostResponseWork({
      operatorId: operation.operator_id,
      operationId: operation.id,
      token,
      complete: true,
    });
    if (!completed) throw new Error('Proxy post-response completion lease was lost');
    return { state: 'completed', operationId: operation.id };
  }
}
