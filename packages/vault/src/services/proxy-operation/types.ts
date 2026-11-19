// Request, scope, post-response and result types for the proxy operation service, and the
// dependencies its modules share. Re-exported from proxy-operation-service.ts, which stays the
// import path for every other package.

import type { KmsService } from '../../crypto/kms.js';
import {
  ProxyOperationRepository,
  type ProxyOperationRow,
} from '../../repositories/proxy-operation-repo.js';
import type { ProxyHoldLedger } from '../spend/spend-ledger.js';

export interface PreparedProxyRequest {
  version: 1;
  service: string;
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  finalUrl: string;
  headers: Record<string, string>;
  bodyBytes: string | null;
  bodyKind: 'absent' | 'text' | 'json';
  requestHash: `sha256:${string}`;
  persistence: {
    origin: string;
    pathnameHash: `sha256:${string}`;
    queryHash: `sha256:${string}`;
    destinationConfigHash: `sha256:${string}`;
    headerNames: string[];
    headersHash: `sha256:${string}`;
    bodyHash: `sha256:${string}` | null;
    bodyBytes: number;
  };
}

export interface ProxyScopeDescriptor {
  version: 1;
  provider: string;
  serviceId: string;
  connectionId: string;
  scopes: string[];
  intents: string[];
  constraints: unknown[];
  policy: Record<string, unknown> | null;
  allowDataFrom: string[];
  discloseTo: string[];
  resource: {
    method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    origin: string;
    pathname: string;
  };
  authorityRefs: unknown[];
}

export interface ProxyPostResponseContext {
  version: 1;
  audit: {
    traceId: string;
    spanId: string;
    parentSpanId?: string;
    durationMs: number;
    requestBytes: number;
    responseBytes: number;
    requestEntropy: number;
    responseEntropy: number;
  };
  action: {
    accountability: 'standard' | 'logged' | 'enforced';
    service: string;
    method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    /** Where the call went, as evidence records it: no query string, secret-looking segments redacted. A refusal's signed record never carries more. */
    originalUrl: string;
    originalBody: unknown;
    resolvedHost: string;
    startedAt: number;
    recordedAt: number;
    statusCode: number;
    responseBodyHash: string;
    parametersHash: string;
    redactionsCount: number;
    detectorFiresCount: number;
    missionIds: string[];
    missionRef: string | null;
    approvedIntentClaimId: string | null;
    entityObservation: Record<string, unknown> | null;
    undeclaredCandidates: string[];
    /**
     * The hosts the connection's credential may be sent to. The service the owner connected is never an
     * undeclared counterparty. Absent on a context stored before this was kept.
     */
    connectionHosts?: string[];
  };
}

export interface ClaimedProxyPostResponseWork {
  operation: ProxyOperationRow;
  token: string;
  context: ProxyPostResponseContext;
}

export interface FreshProxyAuthority {
  services: Array<{
    service_id: string;
    service_name: string;
    connection_id?: string;
    scopes: string[];
    constraints?: unknown[];
    policy?: Record<string, unknown> | null;
    allow_data_from?: string[];
  }>;
  intentServices?: string[];
  discloseTo?: string[];
  authorityRefs?: unknown[];
}

export interface AdmitProxyOperationInput {
  operatorId: string;
  operationKey: string;
  agentId: string;
  passportJti: string;
  authorityUseId?: string;
  approvalId?: string;
  connectionId: string;
  serviceId: string;
  credentialVersion: number;
  provider: string;
  destinationConfigHash: `sha256:${string}`;
  scopeDescriptor: ProxyScopeDescriptor;
  preparedRequest: PreparedProxyRequest;
  effectCorrelationHash: `sha256:${string}`;
  accountingPeriod: string;
  accountingCents: number;
  accountingObligationId: string;
  adapter?:
    | { kind: 'generic' }
    | { kind: 'stripe'; nativeIdempotencyKey: string; providerAccount: string };
  now?: Date;
}

export type AdmitProxyOperationResult =
  | { state: 'created'; operation: ProxyOperationRow }
  | { state: 'replay'; operation: ProxyOperationRow }
  | { state: 'conflict'; operation: ProxyOperationRow }
  | { state: 'capacity_exceeded'; limit: number; used: number };

export type ProxyReplayResult =
  | { state: 'available'; status: number; headers: Record<string, string>; body: unknown }
  | { state: 'unavailable'; reason: 'none' | 'screening' | 'expired' | 'erased' | 'outcome_unknown' };

export interface ProxyOperationMetadata {
  id: string;
  requestHash: string;
  tombstoneHash: string;
  scopeCommitmentHash: string;
  agentId: string;
  passportJti: string;
  authorityUseId: string | null;
  approvalId: string | null;
  connectionId: string;
  serviceId: string;
  credentialVersion: number;
  destinationConfigHash: string;
  provider: string;
  method: string;
  adapterKind: string;
  deliveryState: string;
  replayState: string;
  accountingState: string;
  reconciliationState: string;
  reconciliationEvidenceHash: string | null;
  reconciliationProviderStatus: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled' | null;
  transportAttempts: number;
  responseStatus: number | null;
  responseHash: string | null;
  dispatchedAt: Date | null;
  responseReceivedAt: Date | null;
  /** Set once the outcome stayed unknown for PROXY_OPERATION_UNRESOLVED_AFTER_DAYS with nothing settling it: never sent again. */
  unresolvedAt: Date | null;
  retryDeadline: Date | null;
  responseReadableUntil: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface StripeReconciliationTarget {
  metadata: ProxyOperationMetadata;
  operationKeyHash: string;
  providerMarker: string;
  stripeAccount: string | null;
}

export interface ResponseEnvelope {
  v: 1;
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

/** The collaborators every proxy operation module works through. */
export interface ProxyOperationDeps {
  repository: ProxyOperationRepository;
  kms: KmsService;
  /** The holds of an operation that crossed into paid overage. An install has no wallet, so none can be taken (NO_PROXY_HOLDS). */
  holds: ProxyHoldLedger;
}
