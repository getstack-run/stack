// Types shared by the LLM gateway stages. Each stage is a function with an
// explicit input and result; the composed handler in routes/llm.ts threads
// these records from one stage to the next.

import type { FastifyReply, FastifyRequest } from 'fastify';
import type { NormalizedRequest } from '@stack/shared';
import type { FleetAdmission, GatewayAuthorization } from '@stack/vault';
import type { Services } from '../../config/services.js';
import type { ModelAccess } from '../../lib/model-access-policy.js';
import type { enforceRuntimeAuthority } from '../../lib/runtime-authority.js';
import type { LlmHandlerConfig } from './provider-configs.js';

export type PassportClaims = Awaited<ReturnType<Services['passport']['verify']>>;
export type AccountabilityMode = 'enforced' | 'logged' | 'standard';
export type AuthorityDecision = Awaited<ReturnType<typeof enforceRuntimeAuthority>>;

/** What the approval gate returns once it has let the call through. */
export type ApprovedGate = Extract<
  Awaited<ReturnType<Services['approvalGate']['check']>>,
  { allowed: true }
>;

/** The calling agent's row, which carries the per-agent redaction flag. */
export type GatewayAgent = NonNullable<Awaited<ReturnType<Services['agent']['getById']>>>;

export type LlmNormalizedRequest = NormalizedRequest & {
  resource_type: string;
  resource_ref: string;
};

/**
 * Everything resolved about the caller before any gate beyond the authority
 * decision runs: the validated body, the verified passport and the authority
 * decision for this call. Read-only from here on.
 */
export interface AdmittedCall {
  body: Record<string, unknown>;
  /** The HTTP method of the call to the provider. */
  method: string;
  isStreaming: boolean;
  passportToken: string;
  claims: PassportClaims;
  jti: string;
  agentId: string;
  operatorId: string;
  mode: AccountabilityMode | undefined;
  missionIds: PassportClaims['stk']['mission_ids'];
  missionRef: string;
  upstream: URL;
  normalizedRequest: LlmNormalizedRequest;
  /** The customer connection the call resolved to (and runs on); none for an agent account's agent. */
  connectionId: string | undefined;
  authorityConnectionId: string;
  authorityDecision: AuthorityDecision;
  /** The operator's own key, or STACK's key for an agent account's agent. */
  modelAccess: ModelAccess;
}

/**
 * What the call was authorized against and the exact bytes that will leave for the
 * provider. These calls run on the operator's own key (Anthropic and OpenAI), so
 * nothing is held. An agent account's OpenRouter calls take the passthrough in
 * `./openrouter/`, which holds and settles on its own.
 */
export interface BillingHold {
  providerBody: Record<string, unknown>;
  authorization: GatewayAuthorization;
  requestBodyStr: string;
}

/** Input to the two forwarding stages (streaming and non-streaming). */
export interface ForwardContext {
  services: Services;
  request: FastifyRequest;
  reply: FastifyReply;
  config: LlmHandlerConfig;
  start: number;
  call: AdmittedCall;
  gate: ApprovedGate;
  approvalIdHeader: string | undefined;
  fleetAdmission: FleetAdmission | null;
  hold: BillingHold;
  apiKey: string;
  /**
   * Sources whose content the request carried (the scope wall's result). The
   * response is recorded as read from them, so the trail follows a summary of
   * what the prompt held.
   */
  carriedSources: readonly string[];
  /** PII matches replaced before forward; -1 when redaction was skipped for the agent. */
  piiHits: number;
}
