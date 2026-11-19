// Per-provider configuration for the /v1/llm/<provider>/* route family.
//
// The two chat routes (Anthropic, OpenAI) share one handler; this is everything that
// differs between them: the request schema and the audit and intent labels. OpenRouter
// is a passthrough of its whole API (`./openrouter/`), whose labels are made per endpoint.

import { AnthropicMessagesRequest, LlmImageRequest, OpenAIChatCompletionsRequest } from '@stack/shared';
import { LLM_IMAGE_ENDPOINTS, type LlmProvider } from '@stack/vault';
import type { ZodTypeAny } from 'zod';

export interface LlmHandlerConfig {
  provider: LlmProvider;
  /** Provider-specific Zod schema for the request body. */
  schema: ZodTypeAny;
  /**
   * Action label used in audit_log.action + intent_claim.action. Format:
   * `llm.<provider>.<endpoint>` (e.g. `llm.anthropic.messages`).
   */
  action: string;
  /**
   * Named-intent label for intent_claim.named_intent. Format:
   * `<provider>:llm:<endpoint>` (e.g. `anthropic:llm:messages`).
   */
  namedIntent: string;
  /** The provider endpoint the call goes to, when it is not the provider's chat endpoint (images). */
  upstreamUrl?: string;
}

export const ANTHROPIC_CONFIG: LlmHandlerConfig = {
  provider: 'anthropic',
  schema: AnthropicMessagesRequest,
  action: 'llm.anthropic.messages',
  namedIntent: 'anthropic:llm:messages',
};

export const OPENAI_CONFIG: LlmHandlerConfig = {
  provider: 'openai',
  schema: OpenAIChatCompletionsRequest,
  action: 'llm.openai.chat.completions',
  namedIntent: 'openai:llm:chat.completions',
};

/** Images on the customer's own key: the same gate sequence as a chat call, to the provider's images endpoint. */
export const OPENAI_IMAGES_CONFIG: LlmHandlerConfig = {
  provider: 'openai',
  schema: LlmImageRequest,
  action: 'llm.openai.images',
  namedIntent: 'openai:llm:images',
  upstreamUrl: LLM_IMAGE_ENDPOINTS.openai.url,
};
