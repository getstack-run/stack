import type { FastifyReply, FastifyRequest } from 'fastify';
import type { ProxyRequestInput, normalizeRequest } from '@stack/shared';
import type { Services } from '../../config/services.js';
import type { ObservedRows } from '../../lib/provenance.js';
import type { WallServiceScope } from '../../lib/scope-wall.js';
import type { beginAgentRuntime, requireMissionRef } from '../../lib/agent-runtime.js';
import type { enforceRuntimeAuthority } from '../../lib/runtime-authority.js';

/**
 * Shared types for the stages of POST /v1/proxy. Each stage returns an
 * explicit typed result and the next stage destructures the fields it needs
 * back into the local names the handler always used.
 */

export type ProxyHttpRequest = FastifyRequest;
export type ProxyHttpReply = FastifyReply;

/** Step 1: the validated request body and the receiver's operation handle. */
export interface ParsedProxyRequest {
  input: ProxyRequestInput;
  isMutation: boolean;
  operationKey: string | null;
}

type VerifiedPassportDetail = Awaited<ReturnType<Services['passport']['verifyDetailed']>>;
export type PassportClaims = VerifiedPassportDetail['claims'];
export type PassportRecord = VerifiedPassportDetail['record'];

/** Step 2: the one full Passport verification and the identifiers read from it. */
export interface VerifiedProxyPassport {
  passportToken: string;
  claims: PassportClaims;
  passportRecord: PassportRecord;
  jti: string;
  agentId: string;
  operatorId: string;
  mode: string | undefined;
  missionIds: PassportClaims['stk']['mission_ids'];
  missionRef: ReturnType<typeof requireMissionRef>;
}

export type NormalizedHttpRequest = ReturnType<typeof normalizeRequest>;
export type NormalizedProxyRequest = NormalizedHttpRequest & {
  resource_type: string;
  resource_ref: string;
};
export type ResolvedConnection = Awaited<
  ReturnType<Services['serviceConnection']['resolveProxyConnection']>
>;

/** The request as normalised, and the service connection it resolves to. */
export interface ResolvedProxyTarget {
  normalizedHttpRequest: NormalizedHttpRequest;
  normalizedRequest: NormalizedProxyRequest;
  conn: ResolvedConnection;
}

export type EarlyInputScan = ReturnType<Services['detector']['beginInputScan']>;

export type AccountingReceipt = NonNullable<
  Awaited<ReturnType<Services['proxyOperation']['recordEvaluation']>>
>;

/** The allowance accounting recorded for this operation (mutations only). */
export interface ProxyAccounting {
  accountingOperatorId: string;
  accountingKey: string | null;
  evaluationCommitmentHash: string;
  accountingReceipt: AccountingReceipt | null;
  /**
   * The caller is an agent account's agent on the graduated action price: its
   * receipt charges nothing and the action is counted on the account meter.
   */
  accountPriced: boolean;
}

export type AuthorityDecision = Awaited<ReturnType<typeof enforceRuntimeAuthority>>;

type AgentRuntime = NonNullable<Awaited<ReturnType<typeof beginAgentRuntime>>>;
export type FleetAdmission = AgentRuntime['fleet'];

/** Mission admission, plus the prefetched observation read the wall consumes. */
export interface MissionAdmission {
  fleetAdmission: FleetAdmission;
  observedPrefetch: Promise<ObservedRows> | undefined;
}

type CheckedGate = Awaited<ReturnType<Services['approvalGate']['check']>>;
/** An approval gate verdict that lets the call continue. */
export type AdmittedGate = Extract<CheckedGate, { allowed: true }>;

/** The approval gate outcome the later stages act on. */
export interface ApprovalGateOutcome {
  gate: AdmittedGate;
  approvalReplay: boolean;
}

export type ServiceScope = WallServiceScope & {
  scopes: string[];
  constraints?: unknown[];
  policy?: Record<string, unknown> | null;
  allow_data_from?: string[];
};

/** Step 4: the granted and declared services the passport carries. */
export interface ServiceScopeFacts {
  intentServices: string[];
  grantedProviders: string[];
}

/** Steps 7 to 8a: what the upstream call is built from. */
export interface ProxyCredentialInjection {
  authHeaders: ReturnType<Services['proxy']['resolveAuthHeaders']>;
  resolvedUrl: string;
  connAllowedHosts: readonly string[];
  /** The connection the call resolved to: what the data trail records its reads under. */
  connectionId: string;
}

export type UpstreamResult = Awaited<ReturnType<Services['proxy']['forward']>>;
export type OutputScanResult = Awaited<ReturnType<Services['detector']['scanOutput']>>;

/** Claim ids the authority use is finalised with, on success or failure. */
export interface RuntimeClaimIds {
  intentClaimId: string | undefined;
  outcomeClaimId: string | undefined;
}

