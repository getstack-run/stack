// Anthropic Messages API request schema.
//
// Mirrors https://docs.anthropic.com/en/api/messages wire format.
// Validation surface is intentionally light — we accept what Anthropic
// accepts and let their API do the deep validation. Schema rejects only
// obviously malformed input (missing model, missing messages, bad types)
// so we fail fast before paying an upstream round-trip.
//
// Drop-in compat note (5.2.6): operators replacing
// `client = new Anthropic(...)` with `client = stack.llm.anthropic`
// will pass this exact body shape. Don't tighten validation beyond
// Anthropic's own without strong reason.

import { z } from 'zod';

// Every block is .passthrough(): Anthropic hangs extra fields off content
// blocks (`cache_control` for prompt caching — including on `system` blocks,
// the primary caching surface) and a bare z.object silently STRIPS them on
// parse — the forwarded body must carry what the agent sent.
const AnthropicContentBlock = z.union([
  z.object({ type: z.literal('text'), text: z.string() }).passthrough(),
  z.object({
    type: z.literal('image'),
    source: z.object({
      type: z.string(),
      media_type: z.string(),
      data: z.string(),
    }).passthrough(),
  }).passthrough(),
  z.object({
    type: z.literal('tool_use'),
    id: z.string(),
    name: z.string(),
    input: z.unknown(),
  }).passthrough(),
  z.object({
    type: z.literal('tool_result'),
    tool_use_id: z.string(),
    content: z.union([z.string(), z.array(z.unknown())]).optional(),
    is_error: z.boolean().optional(),
  }).passthrough(),
]);

const AnthropicMessage = z.object({
  role: z.enum(['user', 'assistant']),
  content: z.union([z.string(), z.array(AnthropicContentBlock)]),
}).passthrough();

export const AnthropicMessagesRequest = z.object({
  model: z.string().min(1),
  messages: z.array(AnthropicMessage).min(1),
  // System prompt: Anthropic accepts string OR array of content blocks
  system: z.union([z.string(), z.array(AnthropicContentBlock)]).optional(),
  max_tokens: z.number().int().positive(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  stop_sequences: z.array(z.string()).optional(),
  stream: z.boolean().optional(),
  temperature: z.number().min(0).max(1).optional(),
  top_p: z.number().min(0).max(1).optional(),
  top_k: z.number().int().nonnegative().optional(),
  tools: z.array(z.unknown()).optional(),
  tool_choice: z.unknown().optional(),
}).passthrough();

export type AnthropicMessagesRequest = z.infer<typeof AnthropicMessagesRequest>;
