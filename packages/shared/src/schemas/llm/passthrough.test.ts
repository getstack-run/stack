import { describe, it, expect } from 'vitest';
import { OpenAIChatCompletionsRequest } from './openai-chat-completions.js';
import { AnthropicMessagesRequest } from './anthropic-messages.js';

// The gateway forwards parsed.data upstream (routes/llm.ts), so any field the
// schema doesn't pass through is silently DELETED from what the provider sees.
// These tests pin the passthrough contract at every nesting level — a bare
// z.object on a content part once stripped Anthropic `cache_control`, killing
// prompt caching for every gateway caller.

describe('OpenAIChatCompletionsRequest passthrough', () => {
  it('preserves cache_control on a text content part (system message)', () => {
    const body = {
      model: 'anthropic/claude-haiku-4.5',
      messages: [
        {
          role: 'system',
          content: [
            {
              type: 'text',
              text: 'big cached corpus',
              cache_control: { type: 'ephemeral' },
            },
          ],
        },
        { role: 'user', content: 'hi' },
      ],
      provider: { order: ['anthropic'], allow_fallbacks: false },
    };
    const parsed = OpenAIChatCompletionsRequest.parse(body);
    expect(parsed).toEqual(body);
  });
});

describe('AnthropicMessagesRequest passthrough', () => {
  it('preserves cache_control on system blocks and message content blocks', () => {
    const body = {
      model: 'claude-haiku-4-5',
      max_tokens: 400,
      system: [
        {
          type: 'text',
          text: 'big cached corpus',
          cache_control: { type: 'ephemeral' },
        },
      ],
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'hi', cache_control: { type: 'ephemeral' } },
          ],
        },
        {
          role: 'assistant',
          content: [
            {
              type: 'tool_use',
              id: 'tu_1',
              name: 'lookup',
              input: { q: 'x' },
              cache_control: { type: 'ephemeral' },
            },
          ],
        },
        {
          role: 'user',
          content: [
            {
              type: 'tool_result',
              tool_use_id: 'tu_1',
              content: 'result',
              cache_control: { type: 'ephemeral' },
            },
          ],
        },
      ],
    };
    const parsed = AnthropicMessagesRequest.parse(body);
    expect(parsed).toEqual(body);
  });
});
