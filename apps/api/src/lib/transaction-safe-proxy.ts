import {
  PROXY_RESPONSE_MAX_BYTES,
  StackError,
  canonicalize,
  collectStrings,
  contentFingerprints,
  defaultHostsForProvider,
  evidenceUrl,
  flowSourceLabel,
  isServiceMcpCall,
  serviceMcpEndpoint,
  resolveMissionRef,
  shannonEntropy,
  sha256,
  trailEntity,
  type ProxyRequestInput,
} from '@stack/shared';
import type { ProxyResult, ScanOutputResult, FleetAdmission } from '@stack/vault';
import type { AuditContext, ProxyPostResponseContext } from '@stack/vault';
import type { Services } from '../config/services.js';
import { finalizeProxyResponse } from './finalize-proxy-response.js';
import { mergeProxyEntityCandidates, proxyCallEntities } from './proxy-observation.js';
import {
  prepareProxyRequest,
  proxyEffectCorrelationHash,
  resolveProxyDestination,
  type ProxyOperationBinding,
} from './prepared-proxy-request.js';
import {
  bindStripeRefundCorrelation,
  prepareProxyProviderAdapter,
  stripeRetryPermitted,
} from './proxy-provider-adapter.js';

const RESPONSE_CAPACITY_BYTES = PROXY_RESPONSE_MAX_BYTES * 2 + 64 * 1024;

interface GateBinding {
  skipped: boolean;
  approvalId?: string;
  replayOnly?: boolean;
}

interface TransactionSafeProxyInput {
  fleetAdmission?: FleetAdmission;
  services: Services;
  requestInput: ProxyRequestInput & { method: 'POST' | 'PUT' | 'PATCH' | 'DELETE' };
  operationKey: string;
  operatorId: string;
  agentId: string;
  passportJti: string;
  authorityUseId?: string;
  authorityExecutionState?: string;
  gate: GateBinding;
  connection: {
    provider: string;
    service_id: string;
    connection_id: string;
    credential_version: number;
    proxy_enabled: boolean;
    allowed_hosts: string[] | null;
  };
  allowedConnections?: readonly string[];
  memberId?: string;
  scope: {
    scopes: string[];
    constraints?: unknown[];
    policy?: Record<string, unknown> | null;
    allow_data_from?: string[];
  };
  intentServices: string[];
  discloseTo: string[];
  authorityRefs: unknown[];
  accounting: {
    /** The billing account the receipt is filed under (a tenant's partner). */
    operatorId: string;
    /** The receipt's handle: tenant-scoped when billed to a partner. */
    operationKey: string;
    evaluationCommitmentHash: string;
    period: string;
    cents: number;
    obligationId: string;
  };
  detectorContext: Parameters<Services['detector']['scanOutput']>[0]['ctx'];
  postResponse: {
    accountability: 'standard' | 'logged' | 'enforced';
    missionIds: string[];
    approvedIntentClaimId?: string;
    auditContext: AuditContext;
    startedAt: number;
  };
}

export interface TransactionSafeProxyResult {
  operationId: string;
  result: ProxyResult;
  scan: ScanOutputResult | null;
  resolvedUrl: string;
  rawCredential: string;
  responseHash: `sha256:${string}` | null;
  replayed: boolean;
  authorityOutcome: 'succeeded' | 'failed' | null;
  /** Internal durable row id used only to resume post-response bookkeeping. */
  workOperationId?: string;
}

function publicPending(operationId: string, state: string): TransactionSafeProxyResult {
  return {
    operationId,
    result: {
      status: 202,
      headers: { 'cache-control': 'no-store' },
      body: { operation_id: operationId, delivery_state: state },
    },
    scan: null,
    resolvedUrl: '',
    rawCredential: '',
    responseHash: null,
    replayed: true,
    authorityOutcome: null,
  };
}

/**
 * Admit, fence, dispatch and retain one non-GET operation. PostgreSQL is the
 * owner of every transition; only the acquired dispatch token may cross the
 * network boundary, and the only retained response is the screened copy.
 */
export async function executeTransactionSafeProxy(
  input: TransactionSafeProxyInput,
): Promise<TransactionSafeProxyResult> {
  const { services } = input;
  if (!input.connection.proxy_enabled) throw new StackError('Proxy access disabled', 'FORBIDDEN', 403);
  if (input.fleetAdmission) await services.fleetAdmission.reserve(input.fleetAdmission, undefined, true);
  const fleetPending = async (key: string, state: string) => {
    if (input.fleetAdmission) await services.fleetAdmission.abort(input.fleetAdmission);
    return publicPending(key, state);
  };

  const credential = await services.serviceConnection.retrieveCredentialPinnedByConnectionId(
    input.operatorId,
    input.connection.connection_id,
    input.connection.credential_version,
    input.allowedConnections,
  );
  if (credential.provider !== input.requestInput.service
    || credential.service_id !== input.connection.service_id
    || credential.connection_id !== input.connection.connection_id) {
    throw new StackError('Service connection changed during proxy admission', 'CONFLICT', 409);
  }
  const rawCredential = 'credential' in credential
    ? credential.credential
    : JSON.stringify(credential.credentials);
  const resolvedUrl = resolveProxyDestination(
    input.requestInput.service,
    input.requestInput.url,
    rawCredential,
  );
  const allowedHosts = credential.allowed_hosts
    ?? defaultHostsForProvider(input.requestInput.service)
    ?? [];
  const destinationConfigHash = `sha256:${sha256(canonicalize({
    version: 1,
    service: input.requestInput.service,
    allowed_hosts: [...allowedHosts].sort(),
  }))}` as const;
  const binding: ProxyOperationBinding = {
    operatorId: input.operatorId,
    agentId: input.agentId,
    passportJti: input.passportJti,
    authorityUseId: input.authorityUseId ?? null,
    approvalId: input.gate.approvalId ?? null,
    connectionId: credential.connection_id,
    credentialVersion: credential.credential_version,
    destinationConfigHash,
  };
  const correlationPrepared = prepareProxyRequest(input.requestInput, resolvedUrl, binding);
  const effectCorrelationHash = proxyEffectCorrelationHash(correlationPrepared, binding);
  const requestWithCorrelation = bindStripeRefundCorrelation({
    request: input.requestInput,
    resolvedUrl,
    operationKey: input.operationKey,
  }) as TransactionSafeProxyInput['requestInput'];
  const preliminary = prepareProxyRequest(requestWithCorrelation, resolvedUrl, binding);
  const adapter = prepareProxyProviderAdapter({
    prepared: preliminary,
    operationKey: input.operationKey,
    operatorId: input.operatorId,
    connectionId: credential.connection_id,
    firstDispatchAt: new Date(),
  });
  const prepared = prepareProxyRequest({
    ...requestWithCorrelation,
    headers: adapter.headers,
  }, resolvedUrl, binding);
  const validationFailure = await services.proxy.validatePrepared(prepared, allowedHosts);
  if (validationFailure) {
    return {
      operationId: input.operationKey,
      result: validationFailure,
      scan: null,
      resolvedUrl,
      rawCredential,
      responseHash: null,
      replayed: false,
      authorityOutcome: null,
    };
  }

  const parsedUrl = new URL(prepared.finalUrl);
  const scopeDescriptor = {
    version: 1 as const,
    provider: input.requestInput.service,
    serviceId: credential.service_id,
    connectionId: credential.connection_id,
    scopes: [...input.scope.scopes],
    intents: [...input.intentServices],
    constraints: [...(input.scope.constraints ?? [])],
    policy: input.scope.policy ?? null,
    allowDataFrom: [...(input.scope.allow_data_from ?? [])],
    discloseTo: [...input.discloseTo],
    resource: {
      method: input.requestInput.method,
      origin: parsedUrl.origin,
      pathname: parsedUrl.pathname,
    },
    authorityRefs: [...input.authorityRefs],
  };
  const providerAccount = preliminary.headers['stripe-account'] ?? 'credential-owner';
  const operationAdapter = adapter.kind === 'stripe'
    ? { kind: 'stripe' as const, nativeIdempotencyKey: adapter.nativeIdempotencyKey!, providerAccount }
    : { kind: 'generic' as const };

  const transactionResult = await services.proxyOperation.transaction(async (transaction) => {
    const admitted = await services.proxyOperation.admit({
      operatorId: input.operatorId,
      operationKey: input.operationKey,
      agentId: input.agentId,
      passportJti: input.passportJti,
      ...(input.authorityUseId ? { authorityUseId: input.authorityUseId } : {}),
      ...(input.gate.approvalId ? { approvalId: input.gate.approvalId } : {}),
      connectionId: credential.connection_id,
      serviceId: credential.service_id,
      credentialVersion: credential.credential_version,
      provider: input.requestInput.service,
      destinationConfigHash,
      scopeDescriptor,
      preparedRequest: prepared as Parameters<Services['proxyOperation']['admit']>[0]['preparedRequest'],
      effectCorrelationHash,
      accountingPeriod: input.accounting.period,
      accountingCents: input.accounting.cents,
      accountingObligationId: input.accounting.obligationId,
      adapter: operationAdapter,
    }, transaction);
    if (admitted.state === 'conflict' || admitted.state === 'capacity_exceeded') {
      return { admitted } as const;
    }
    if (input.fleetAdmission) await services.fleetAdmission.linkProxyOperation(input.fleetAdmission, admitted.operation.id, input.operationKey, transaction);
    if (admitted.state === 'replay' && admitted.operation.delivery_state !== 'admitted') {
      return { admitted } as const;
    }

    const promoted = await services.proxyOperation.promoteEvaluationToAdmitted({
      operatorId: input.accounting.operatorId,
      operationKey: input.accounting.operationKey,
      evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
      transaction,
    });
    if (!promoted) throw new StackError('Proxy accounting admission was lost', 'CONFLICT', 409);

    const replacement = await services.proxyOperation.guardAndConsumeReplacement({
      operatorId: input.operatorId,
      replacementOperationId: admitted.operation.id,
      replacementOperationKey: input.operationKey,
      replacementRequestHash: prepared.requestHash,
      effectCorrelationHash,
      transaction,
    });
    if (replacement.state === 'authorization_required' || replacement.state === 'ambiguous') {
      return { admitted, replacement } as const;
    }

    // Replacement authorization must be resolved before an operation can own
    // dispatch. Capacity is checked next, before approval or authority is
    // consumed, and throws inside the transaction so admission, promotion and
    // any replacement acknowledgement consumption roll back together.
    const claimed = await services.proxyOperation.claimDispatch({
      operatorId: input.operatorId,
      operationId: admitted.operation.id,
      operationKey: input.operationKey,
      admissionFence: admitted.operation.admission_fence,
      capacityBytes: RESPONSE_CAPACITY_BYTES,
      requestEvidenceHash: prepared.requestHash,
      transaction,
    });
    if (claimed.state === 'capacity_exceeded') {
      throw new StackError('Proxy operation capacity exceeded', 'CAPACITY_EXCEEDED', 429);
    }
    if (claimed.state !== 'acquired' || !claimed.dispatchToken) {
      throw new StackError('Proxy dispatch ownership was not acquired', 'CONFLICT', 409);
    }

    if (!input.gate.skipped && !input.fleetAdmission) {
      if (input.gate.replayOnly || !input.gate.approvalId) {
        throw new StackError('Consumed approval cannot authorize a new operation', 'CONFLICT', 409);
      }
      const approvalOwnerHash = sha256(input.operationKey);
      const reserved = await services.approvalGate.reserveForDispatch(
        input.gate.approvalId,
        approvalOwnerHash,
        transaction,
      );
      if (!reserved) throw new StackError('Intent approval is already in use', 'CONFLICT', 409);
      const consumed = await services.approvalGate.markConsumed(
        input.gate.approvalId,
        approvalOwnerHash,
        transaction,
      );
      if (!consumed) throw new StackError('Intent approval consumption was lost', 'CONFLICT', 409);
    }

    if (input.authorityUseId) {
      if (input.authorityExecutionState !== 'authorized') {
        throw new StackError('Authority use cannot authorize a new operation', 'CONFLICT', 409);
      }
      await services.authority.claimRuntimeAuthorityDispatch(
        input.operatorId,
        input.authorityUseId,
        transaction,
      );
    }
    return { admitted, claimed } as const;
  });

  let dispatch = 'claimed' in transactionResult ? transactionResult.claimed : null;
  if (transactionResult.admitted.state === 'capacity_exceeded') {
    throw new StackError('Proxy operation capacity exceeded', 'CAPACITY_EXCEEDED', 429);
  }
  let operation = transactionResult.admitted.operation;
  if (!dispatch) {
    if (transactionResult.admitted.state === 'conflict') {
      throw new StackError('Operation handle was already used for a different request', 'CONFLICT', 409);
    }
    if ('replacement' in transactionResult && transactionResult.replacement) {
      return fleetPending(
        input.operationKey,
        transactionResult.replacement.state === 'ambiguous'
          ? 'replacement_authorization_ambiguous'
          : 'replacement_authorization_required',
      );
    }

    // A received response always wins over another transport attempt. Stripe
    // caches 500s as well as successful responses for an idempotency key, so a
    // readable stored 500 must remain an unresolved replay rather than spend
    // another attempt. Only a missing replay payload reaches provider recovery.
    const replay = await services.proxyOperation.readReplay(input.operatorId, input.operationKey);
    if (replay.state === 'available') {
      return {
        operationId: input.operationKey,
        result: { status: replay.status, headers: replay.headers, body: replay.body },
        scan: null,
        resolvedUrl,
        rawCredential,
        responseHash: operation.response_hash ? `sha256:${operation.response_hash}` : null,
        replayed: true,
        // A stored generic response is enough to repair a transient failure
        // that happened while completing the linked authority use after the
        // response was committed. The completion call is hash-idempotent and
        // does not cross the provider boundary again.
        authorityOutcome: operation.adapter_kind === 'generic'
          ? replay.status >= 200 && replay.status < 400 ? 'succeeded' : 'failed'
          : null,
        workOperationId: operation.id,
      };
    }
    if (operation.adapter_kind === 'stripe'
      && operation.retry_deadline
      && await services.proxyOperation.originalPassportAllowsRetry(
        input.operatorId,
        operation.passport_jti,
        operation.agent_id,
      )
      && stripeRetryPermitted({
        transportAttempts: operation.transport_attempts,
        retryDeadline: operation.retry_deadline,
        now: new Date(),
        deliveryState: operation.delivery_state,
        reconciliationState: operation.reconciliation_state,
        liveAuthorizationPassed: true,
      })) {
      const retry = await services.proxyOperation.claimStripeRetry({
        operatorId: input.operatorId,
        operationId: operation.id,
        capacityBytes: RESPONSE_CAPACITY_BYTES,
        requestEvidenceHash: prepared.requestHash,
      });
      if (retry.state === 'capacity_exceeded') {
        throw new StackError('Proxy operation capacity exceeded', 'CAPACITY_EXCEEDED', 429);
      }
      if (retry.state === 'acquired' && retry.dispatchToken) {
        dispatch = retry;
        operation = retry.operation;
      }
    }
    if (!dispatch) return fleetPending(input.operationKey, operation.delivery_state);
  }

  const storedPrepared = await services.proxyOperation.decryptPreparedRequest({
    operatorId: input.operatorId,
    operationKey: input.operationKey,
    dispatchToken: dispatch.dispatchToken!,
    dispatchFence: dispatch.dispatchFence,
  });
  const injectedAuthHeaders = services.proxy.resolveAuthHeaders(input.requestInput.service, rawCredential);
  if (input.fleetAdmission) await services.fleetAdmission.dispatch(input.fleetAdmission);
  // A call to the connection's own MCP endpoint is sent inside an MCP session, opened and ended around it: one operation,
  // one check, one action and one record, whatever the service needs before it takes the call.
  const mcpEndpoint = credential.mcp_url ?? serviceMcpEndpoint(input.requestInput.service);
  const egress = { operatorId: input.operatorId, agentId: input.agentId };
  const transport = isServiceMcpCall(storedPrepared, mcpEndpoint)
    ? await services.proxy.forwardMcpPrepared(storedPrepared, injectedAuthHeaders, allowedHosts, egress)
    : await services.proxy.forwardPrepared(storedPrepared, injectedAuthHeaders, allowedHosts, egress);
  if (transport.kind === 'outcome_unknown') {
    await services.proxyOperation.markOutcomeUnknown({
      operatorId: input.operatorId,
      operationId: operation.id,
      dispatchToken: dispatch.dispatchToken!,
      dispatchFence: dispatch.dispatchFence,
      transportEvidenceHash: `sha256:${sha256(canonicalize({
        request_hash: prepared.requestHash,
        reason: transport.reason,
      }))}`,
    });
    return fleetPending(input.operationKey, 'outcome_unknown');
  }

  const screeningOwned = await services.proxyOperation.markResponseScreening({
    operatorId: input.operatorId,
    operationId: operation.id,
    dispatchToken: dispatch.dispatchToken!,
    dispatchFence: dispatch.dispatchFence,
  });
  if (!screeningOwned) {
    const lateEvidenceHash = `sha256:${sha256(canonicalize({
      request_hash: prepared.requestHash,
      response_status: transport.response.status,
      reason: 'response_screening_fence_lost',
    }))}`;
    await services.proxyOperation.recordLateResponseEvidence({
      operatorId: input.operatorId,
      operationId: operation.id,
      dispatchToken: dispatch.dispatchToken!,
      dispatchFence: dispatch.dispatchFence,
      status: transport.response.status,
      evidenceHash: lateEvidenceHash,
    }).catch(() => false);
    await services.proxyOperation.markOutcomeUnknown({
      operatorId: input.operatorId,
      operationId: operation.id,
      dispatchToken: dispatch.dispatchToken!,
      dispatchFence: dispatch.dispatchFence,
      transportEvidenceHash: lateEvidenceHash,
    }).catch(() => false);
    return fleetPending(input.operationKey, 'outcome_unknown');
  }
  try {
    const finalized = await finalizeProxyResponse({
      detector: services.detector,
      detectorContext: input.detectorContext,
      response: transport.response,
      rawCredential,
      injectedAuthHeaders,
      service: input.requestInput.service,
      method: input.requestInput.method,
    });
    const transportEvidenceHash = `sha256:${sha256(canonicalize({
      request_hash: prepared.requestHash,
      status: finalized.response.status,
      headers: finalized.response.headers,
      body_hash: sha256(canonicalize(finalized.response.body)),
    }))}`;
    const stored = await services.proxyOperation.storePermittedResponse({
      operatorId: input.operatorId,
      operationId: operation.id,
      dispatchToken: dispatch.dispatchToken!,
      dispatchFence: dispatch.dispatchFence,
      status: finalized.response.status,
      rawHeaders: finalized.response.headers,
      screenedBody: finalized.response.body,
      capacityBytes: RESPONSE_CAPACITY_BYTES,
      transportEvidenceHash,
      providerRequestId: finalized.response.headers['stripe-request-id']
        ?? finalized.response.headers['request-id'],
      postResponseContext: buildPostResponseContext({
        input,
        finalized,
        resolvedUrl,
        connectionHosts: allowedHosts,
      }),
    });
    if (!stored) {
      await services.proxyOperation.recordLateResponseEvidence({
        operatorId: input.operatorId,
        operationId: operation.id,
        dispatchToken: dispatch.dispatchToken!,
        dispatchFence: dispatch.dispatchFence,
        status: finalized.response.status,
        evidenceHash: transportEvidenceHash,
      }).catch(() => false);
      await services.proxyOperation.markOutcomeUnknown({
        operatorId: input.operatorId,
        operationId: operation.id,
        dispatchToken: dispatch.dispatchToken!,
        dispatchFence: dispatch.dispatchFence,
        transportEvidenceHash,
      }).catch(() => false);
      return fleetPending(input.operationKey, 'outcome_unknown');
    }
    if (input.fleetAdmission) {
      if (operation.adapter_kind === 'generic') await services.fleetAdmission.finish(input.fleetAdmission);
      else await services.fleetAdmission.abort(input.fleetAdmission);
    }
    return {
      operationId: input.operationKey,
      result: finalized.response,
      scan: finalized.scan,
      resolvedUrl,
      rawCredential,
      responseHash: `sha256:${stored.response_hash!}`,
      replayed: false,
      authorityOutcome: operation.adapter_kind === 'stripe'
        ? null
        : finalized.response.status >= 200 && finalized.response.status < 400 ? 'succeeded' : 'failed',
      workOperationId: operation.id,
    };
  } catch {
    // The provider may already have committed the action. Keep the operation
    // unknown and make recovery explicit; never turn a detector, encryption,
    // or persistence failure into a second dispatch.
    await services.proxyOperation.markOutcomeUnknown({
      operatorId: input.operatorId,
      operationId: operation.id,
      dispatchToken: dispatch.dispatchToken!,
      dispatchFence: dispatch.dispatchFence,
      transportEvidenceHash: `sha256:${sha256(canonicalize({
        request_hash: prepared.requestHash,
        response_status: transport.response.status,
        reason: 'response_finalization_unavailable',
      }))}`,
    }).catch(() => false);
    return fleetPending(input.operationKey, 'outcome_unknown');
  }
}

function buildPostResponseContext(input: {
  input: TransactionSafeProxyInput;
  finalized: { response: ProxyResult; scan: ScanOutputResult };
  resolvedUrl: string;
  /** The hosts the connection's credential may be sent to: the service the owner connected. */
  connectionHosts: readonly string[];
}): ProxyPostResponseContext {
  const { requestInput, postResponse } = input.input;
  const { response, scan } = input.finalized;
  const requestBody = requestInput.body == null
    ? ''
    : typeof requestInput.body === 'string' ? requestInput.body : JSON.stringify(requestInput.body);
  const responseBody = response.body == null
    ? ''
    : typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
  let parsedBody: unknown = response.body;
  if (typeof response.body === 'string') {
    try { parsedBody = JSON.parse(response.body); } catch { parsedBody = response.body; }
  }
  // What the call read and what it sent, as the live proxy path records it (lib/proxy-observation.ts): the request's own
  // URL is recorded for the undeclared-counterparty check and listed in `request_entities`, which the data-flow rule leaves out.
  const { candidates, requestEntities, outbound: outboundEntities } = proxyCallEntities({
    service: requestInput.service,
    method: requestInput.method,
    resolvedUrl: input.resolvedUrl,
    requestBody: requestInput.body,
    responseHeaders: response.headers,
    responseBody: parsedBody,
  });
  const readText = collectStrings(parsedBody).join(' ');
  const fingerprints = readText ? contentFingerprints(readText) : [];
  const missionRef = resolveMissionRef(postResponse.missionIds);
  const now = Date.now();
  const url = new URL(input.resolvedUrl);
  return {
    version: 1,
    audit: {
      traceId: postResponse.auditContext.trace_id,
      spanId: postResponse.auditContext.span_id,
      ...(postResponse.auditContext.parent_span_id
        ? { parentSpanId: postResponse.auditContext.parent_span_id }
        : {}),
      durationMs: now - postResponse.startedAt,
      requestBytes: Buffer.byteLength(requestBody, 'utf8'),
      responseBytes: Buffer.byteLength(responseBody, 'utf8'),
      requestEntropy: shannonEntropy(requestBody),
      responseEntropy: shannonEntropy(responseBody),
    },
    action: {
      accountability: postResponse.accountability,
      service: requestInput.service,
      method: requestInput.method,
      // The row is a queue entry for the signed records; they carry where the
      // call went and never its query string or a credential in its path.
      originalUrl: evidenceUrl(requestInput.url) ?? '',
      originalBody: requestInput.body ?? null,
      resolvedHost: url.host,
      startedAt: postResponse.startedAt,
      recordedAt: now,
      statusCode: response.status,
      responseBodyHash: sha256(responseBody),
      // The parameters as the intent claim states them: the URL in its evidence form, with no query string.
      parametersHash: sha256(JSON.stringify({
        service: requestInput.service,
        method: requestInput.method,
        url: evidenceUrl(requestInput.url),
        body: requestInput.body,
      })),
      redactionsCount: scan.redactedBody !== null ? 1 : 0,
      detectorFiresCount: scan.match !== null ? 1 : 0,
      missionIds: postResponse.missionIds,
      missionRef,
      approvedIntentClaimId: postResponse.approvedIntentClaimId ?? null,
      entityObservation: candidates.length > 0 || fingerprints.length > 0
        ? {
            type: 'entity_observation',
            // One-way digests, as on the live proxy path.
            entities: candidates.map((candidate) => trailEntity(candidate.entity)),
            entity_types: candidates.map((candidate) => candidate.entity_type),
            ...(requestEntities.length > 0 ? { request_entities: requestEntities } : {}),
            agent_id: input.input.agentId,
            // The service and the connection the call ran on, as on the live proxy path.
            source_service: flowSourceLabel(requestInput.service, input.input.connection.connection_id),
            content_fingerprints: fingerprints,
            metadata: {
              extraction_method: 'regex',
              source: 'proxy_http_call',
              service: requestInput.service,
            },
            observed_at: now,
            ...(missionRef ? { mission_ref: missionRef } : {}),
          }
        : null,
      // A URL path is a place on a service, not a counterparty: it stays in the observation above (the data-flow
      // rule reads it) and out of the candidates the undeclared-target check judges.
      undeclaredCandidates: outboundEntities
        .filter((candidate) => candidate.entity_type !== 'url_path')
        .map((candidate) => candidate.entity.toLowerCase()),
      connectionHosts: [...input.connectionHosts],
    },
  };
}

export { mergeProxyEntityCandidates };
