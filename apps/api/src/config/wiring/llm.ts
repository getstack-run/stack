import {
  LlmGatewayService,
  LlmUsageService,
  OpenRouterPricingResolver,
  PiiRedactor,
  type LlmUsageRepository,
  type LlmUsageServiceDeps,
  type SecurityEventService,
} from '@stack/vault';
import { OpenRouterService } from '@stack/shared';
import type { RedisClient } from './infra.js';
import type { ProviderConfigs } from './provider-config.js';

export interface LlmServices {
  /** Null when no OpenRouter credential is configured; callers skip LLM-backed work. */
  openRouter: OpenRouterService | null;
  openRouterPricing: OpenRouterPricingResolver;
  /** A model-provider key the deployment itself holds (its extension supplies it), or null: what the extension's own model calls use. The engine's gateway uses the customer's key. */
  stackOpenRouterKey: () => string | null;
  llmUsage: LlmUsageService;
  llmGateway: LlmGatewayService;
  piiRedactor: PiiRedactor;
}

/** Builds the usage ledger from the engine's parts: the deployment's own (it holds and charges the calls on its key), or the engine's. */
export type LlmUsageFactory = (deps: LlmUsageServiceDeps) => LlmUsageService;

/**
 * LLM access and its cost ledger. One ledger covers customer-key gateway calls
 * and whatever calls the deployment runs on a key of its own, so it must exist
 * before the detector, accountability and skill wiring: those paths authorize
 * provider spend before each call.
 */
export function createLlmServices(deps: {
  redis: RedisClient;
  llmUsageRepo: LlmUsageRepository;
  /** The deployment's own ledger, or null for the engine's. */
  llmUsage: LlmUsageFactory | null;
  securityEvent: SecurityEventService;
  openRouterKey: ProviderConfigs['openRouterKey'];
}): LlmServices {
  const { redis, llmUsageRepo, securityEvent, openRouterKey } = deps;
  const openRouter = openRouterKey ? new OpenRouterService({ apiKey: openRouterKey }) : null;

  const openRouterPricing = new OpenRouterPricingResolver(redis);
  const usageDeps: LlmUsageServiceDeps = { repo: llmUsageRepo, securityEvent, openRouterPricing };
  const llmUsage = deps.llmUsage ? deps.llmUsage(usageDeps) : new LlmUsageService(usageDeps);

  // LLM gateway substrate (stateless service; takes the provider API key as an
  // argument on each call). Used by the /v1/llm/<provider>/* routes. The
  // operator brings their own anthropic / openai / openrouter credentials via
  // /services. There is no system-key fallback for an ordinary agent: a call on
  // a key of the deployment's own is the deployment's to allow (ModelAccessPolicy).
  const llmGateway = new LlmGatewayService();

  const stackOpenRouterKey = () => openRouterKey || null;

  // PII redactor. Stateless; constructed once and shared. It is applied to
  // user-role messages.
  const piiRedactor = new PiiRedactor();

  return {
    openRouter,
    openRouterPricing,
    stackOpenRouterKey,
    llmUsage,
    llmGateway,
    piiRedactor,
  };
}
