import { z } from 'zod';
import { GeneratedFile } from './generated-file.js';

// Image generation on the customer's own provider key, through the gateway:
// POST /v1/llm/openai/images. The body names
// what the call may carry and nothing else (`strict`): it is the whole of what
// STACK sends to the provider, so a field a provider added later cannot ride
// along. The provider bills the customer; STACK counts one action.

/** The providers the gateway has an images route for. Anthropic has no image generation endpoint, and OpenRouter's image models are called through its own API as any other model is. */
export const LLM_IMAGE_PROVIDERS = ['openai'] as const;
export type LlmImageProvider = (typeof LLM_IMAGE_PROVIDERS)[number];

/** Images one call may ask for. */
export const LLM_IMAGES_PER_CALL_MAX = 4;
export const LLM_IMAGE_PROMPT_MAX_CHARS = 4000;

export const LlmImageRequest = z
  .object({
    /** The provider's own model id (`gpt-image-1`, `dall-e-3`). */
    model: z.string().min(1).max(200),
    prompt: z.string().min(1).max(LLM_IMAGE_PROMPT_MAX_CHARS),
    /** Images to make, default 1. */
    n: z.number().int().min(1).max(LLM_IMAGES_PER_CALL_MAX).optional(),
    /** `1024x1024`, `1024x1536`, `1536x1024` or `auto` (the sizes OpenAI's models take). */
    size: z.string().regex(/^(?:auto|[0-9]{3,4}x[0-9]{3,4})$/).optional(),
    /** `low`, `medium`, `high`, `standard`, `hd` or `auto`. */
    quality: z.enum(['low', 'medium', 'high', 'standard', 'hd', 'auto']).optional(),
  })
  .strict();
export type LlmImageRequest = z.infer<typeof LlmImageRequest>;

/** What an image call returns: the files, saved to the agent's drive when it has one, and marked untrusted. */
export const LlmImageResult = z.object({
  provider: z.enum(LLM_IMAGE_PROVIDERS),
  model: z.string(),
  /** A picture a model made is content the agent reads and never follows. */
  untrusted: z.literal(true),
  /** Who pays: the customer's own provider key. STACK counted one action and charged nothing else. */
  key: z.literal('own'),
  files: z.array(GeneratedFile),
  /** The prompt as the provider reports it rewrote it, when it says so. */
  revised_prompts: z.array(z.string()),
});
export type LlmImageResult = z.infer<typeof LlmImageResult>;
