// OpenAI Chat Completions request schema.
//
// Mirrors https://platform.openai.com/docs/api-reference/chat/create
// wire format. Same light-validation philosophy as
// anthropic-messages.ts: accept what OpenAI accepts, fail fast on
// obviously malformed input, defer deep validation to upstream.
//
// OpenRouter reuses this exact shape (5.2.1 re-exports from
// openrouter-chat-completions.ts).

import { z } from 'zod';

// Every part is .passthrough(): providers hang extra fields off content parts
// (e.g. Anthropic `cache_control` for prompt caching, via OpenRouter) and a
// bare z.object silently STRIPS them on parse — the forwarded body must carry
// what the agent sent.
const OpenAIContentPart = z.union([
  z.object({ type: z.literal('text'), text: z.string() }).passthrough(),
  z.object({
    type: z.literal('image_url'),
    image_url: z.object({ url: z.string(), detail: z.string().optional() }).passthrough(),
  }).passthrough(),
]);

const OpenAIMessage = z.object({
  role: z.enum(['system', 'user', 'assistant', 'tool', 'function']),
  content: z.union([z.string(), z.array(OpenAIContentPart), z.null()]),
  name: z.string().optional(),
  tool_calls: z.array(z.unknown()).optional(),
  tool_call_id: z.string().optional(),
}).passthrough();

export const OpenAIChatCompletionsRequest = z.object({
  model: z.string().min(1),
  messages: z.array(OpenAIMessage).min(1),
  frequency_penalty: z.number().min(-2).max(2).optional(),
  logit_bias: z.record(z.string(), z.number()).optional(),
  logprobs: z.boolean().optional(),
  top_logprobs: z.number().int().min(0).max(20).optional(),
  max_tokens: z.number().int().positive().optional(),
  max_completion_tokens: z.number().int().positive().optional(),
  n: z.number().int().positive().optional(),
  presence_penalty: z.number().min(-2).max(2).optional(),
  response_format: z.unknown().optional(),
  seed: z.number().int().optional(),
  stop: z.union([z.string(), z.array(z.string())]).optional(),
  stream: z.boolean().optional(),
  stream_options: z.object({ include_usage: z.boolean().optional() }).passthrough().optional(),
  temperature: z.number().min(0).max(2).optional(),
  top_p: z.number().min(0).max(1).optional(),
  tools: z.array(z.unknown()).optional(),
  tool_choice: z.unknown().optional(),
  user: z.string().optional(),
}).passthrough();

export type OpenAIChatCompletionsRequest = z.infer<typeof OpenAIChatCompletionsRequest>;
