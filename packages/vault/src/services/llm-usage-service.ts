import {
  ids,
  ANTHROPIC_PRICING,
  OPENAI_PRICING,
  calculateLlmCost,
  costFromProviderReported,
  type LlmCostBreakdown,
  type LlmModelPricing,
} from '@stack/shared';
import type {
  LlmUsageRepository,
  ListArgs as RepoListArgs,
  SummaryArgs as RepoSummaryArgs,
  LlmUsageRowSelect,
  SummaryBucket,
} from '../repositories/llm-usage-repo.js';
import type { SecurityEventService } from './security-event-service.js';
import type { OpenRouterPricingResolver } from './openrouter-pricing.js';
import type { LlmProvider, LlmUsage } from './llm-gateway-service.js';

/**
 * What a gateway call was authorized against: whether its cost can be bounded, the price it was computed
 * from, and the worst case something holds for it. On the customer's own key nothing is held, so the worst
 * case is zero; a deployment that runs a call on a key of its own extends this with what it holds.
 */
export interface GatewayAuthorization {
  bounded: boolean;
  denyReason: string | null;
  heldCents: number;
  pricing: LlmModelPricing | null;
}

export interface AuthorizeGatewayInput {
  operatorId: string;
  provider: LlmProvider;
  model: string;
  requestBytes: number;
  maxOutputTokens: number | null;
  completionCount: number;
  imageCount: number;
  unsupportedCostReason?: string | null;
}

export interface RecordUsageInput {
  operatorId: string;
  agentId: string;
  passportJti: string;
  missionId: string | null;
  provider: LlmProvider;
  model: string;
  usage: LlmUsage;
  streaming: boolean;
  authorization: GatewayAuthorization;
}

export interface RecordUsageResult {
  llmUsageId: string;
  cost: LlmCostBreakdown | null;
}

export interface LlmUsageServiceDeps {
  repo: LlmUsageRepository;
  securityEvent: SecurityEventService;
  openRouterPricing: OpenRouterPricingResolver;
}

/**
 * The cost ledger of the model gateway. A call on the customer's own key is priced from the provider's own
 * published price (or the cost the provider reports) and recorded; nothing is held or charged for it. A
 * deployment that also runs calls on a key of its own extends this class with the holds and charges those need.
 */
export class LlmUsageService {
  constructor(protected readonly deps: LlmUsageServiceDeps) {}

  /** Check that this request's cost can be bounded, and say what it was priced from. */
  async authorizeGateway(input: AuthorizeGatewayInput): Promise<GatewayAuthorization> {
    this.assertGatewayInput(input);
    const pricing = await this.lookup(input.provider, input.model);
    const denyReason = gatewayDenyReason(input, pricing);
    return {
      bounded: denyReason === null,
      denyReason,
      heldCents: 0,
      pricing: denyReason ? null : pricing,
    };
  }

  /** Nothing was held for a call on the customer's own key, so there is nothing to release. */
  async releaseGatewayAuthorization(
    _operatorId: string,
    _authorization: GatewayAuthorization,
  ): Promise<void> {}

  async record(input: RecordUsageInput): Promise<RecordUsageResult> {
    const reported = input.usage.provider_cost_usd;
    const pricing = reported === undefined
      ? input.authorization.pricing ?? await this.lookup(input.provider, input.model)
      : null;
    const cost = reported !== undefined
      ? costFromProviderReported(reported)
      : pricing
        ? calculateLlmCost(pricing, input.usage.prompt_tokens, input.usage.completion_tokens, {
            ...(input.usage.cached_prompt_tokens !== undefined
              ? { cached_prompt_tokens: input.usage.cached_prompt_tokens }
              : {}),
          })
        : null;

    if (reported === undefined && !pricing) await this.recordPricingMiss(input);

    const llmUsageId = ids.llmUsage();
    await this.deps.repo.insert({
      id: llmUsageId,
      operator_id: input.operatorId,
      agent_id: input.agentId,
      passport_jti: input.passportJti,
      mission_id: input.missionId,
      provider: input.provider,
      model: input.model,
      prompt_tokens: input.usage.prompt_tokens,
      completion_tokens: input.usage.completion_tokens,
      total_tokens: input.usage.total_tokens,
      provider_cost_cents: cost?.provider_cost_cents ?? null,
      markup_cents: cost?.markup_cents ?? null,
      total_cost_cents: cost?.total_cost_cents ?? null,
      provider_cost_microcents: cost?.provider_cost_microcents ?? null,
      markup_microcents: cost?.markup_microcents ?? null,
      total_cost_microcents: cost?.total_cost_microcents ?? null,
      cost_basis: cost?.basis ?? null,
      cached_prompt_tokens: input.usage.cached_prompt_tokens ?? null,
      wallet_debited: false,
      surface: 'gateway',
      provider_payer: 'customer_provider',
      stack_fee_payer: 'none',
      wallet_hold_id: null,
      wallet_fee_kind: null,
      wallet_fee_microcents: null,
      streaming: input.streaming,
    });
    return { llmUsageId, cost };
  }

  protected assertGatewayInput(input: AuthorizeGatewayInput): void {
    if (!Number.isInteger(input.requestBytes) || input.requestBytes < 0) {
      throw new Error(`requestBytes must be a non-negative integer, got ${input.requestBytes}`);
    }
    if (input.maxOutputTokens !== null &&
        (!Number.isInteger(input.maxOutputTokens) || input.maxOutputTokens <= 0)) {
      throw new Error(`maxOutputTokens must be a positive integer or null, got ${input.maxOutputTokens}`);
    }
    if (!Number.isInteger(input.completionCount) || input.completionCount <= 0) {
      throw new Error(`completionCount must be a positive integer, got ${input.completionCount}`);
    }
    if (!Number.isInteger(input.imageCount) || input.imageCount < 0) {
      throw new Error(`imageCount must be a non-negative integer, got ${input.imageCount}`);
    }
  }

  protected async recordPricingMiss(input: {
    operatorId: string;
    agentId?: string | null;
    passportJti?: string | null;
    provider: LlmProvider;
    model: string;
  }): Promise<void> {
    await this.deps.securityEvent
      .record({
        operatorId: input.operatorId,
        agentId: input.agentId ?? 'none',
        passportJti: input.passportJti ?? 'none',
        signalType: 'upstream_not_found',
        severity: 'info',
        message: `LLM pricing lookup miss for ${input.provider}/${input.model}`,
        metadata: {
          provider: input.provider,
          model: input.model,
          pricing_lookup_miss: true,
        },
      })
      .catch(() => {});
  }

  protected async lookup(provider: LlmProvider, model: string): Promise<LlmModelPricing | null> {
    if (provider === 'anthropic') return ANTHROPIC_PRICING[model] ?? null;
    if (provider === 'openai') return OPENAI_PRICING[model] ?? null;
    if (provider === 'openrouter') return this.deps.openRouterPricing.get(model);
    return null;
  }

  async list(args: RepoListArgs): Promise<{ items: LlmUsageRowSelect[]; nextCursor: string | null }> {
    return this.deps.repo.list(args);
  }

  async summary(args: RepoSummaryArgs): Promise<SummaryBucket[]> {
    return this.deps.repo.summary(args);
  }
}

/** Why a gateway request's cost cannot be bounded, or null when it can. */
export function gatewayDenyReason(input: AuthorizeGatewayInput, pricing: LlmModelPricing | null): string | null {
  return input.unsupportedCostReason
    ?? (!pricing ? 'Pricing is unavailable for this model.' : null)
    ?? (input.maxOutputTokens === null ? 'The request has no output token limit.' : null)
    ?? (input.imageCount > 0 && pricing?.image_cents === undefined
      ? 'Image pricing is unavailable for this provider and model.'
      : null);
}
