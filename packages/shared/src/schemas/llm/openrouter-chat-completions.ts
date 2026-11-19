// OpenRouter Chat Completions request schema.
//
// OpenRouter's API mimics OpenAI's Chat Completions shape exactly
// (it's the entire point — drop-in compat with the OpenAI client).
// Re-export the OpenAI schema rather than duplicate. If OpenRouter
// ever diverges in a way that matters to us, fork into a real schema
// at that point.

export {
  OpenAIChatCompletionsRequest as OpenRouterChatCompletionsRequest,
} from './openai-chat-completions.js';
