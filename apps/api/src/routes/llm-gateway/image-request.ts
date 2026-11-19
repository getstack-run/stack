// Images on the customer's own OpenAI key: what the call carries to the provider, and
// how the stages written for a chat call read an image call.
//
// The provider body is built field by field from what the route accepted
// (never spread), so the whole of what leaves is what is listed here. The
// stages that scan and redact text read `messages`; an image call has one
// piece of text, the prompt, so those stages see it as one user message and
// the redacted text is read back out.

import type { LlmImageRequest } from '@stack/shared';
import type { AdmittedCall } from './types.js';

/** The prompt as the text stages read it: one user message. */
export function asChatCall(call: AdmittedCall): AdmittedCall {
  return { ...call, body: { ...call.body, messages: [{ role: 'user', content: call.body['prompt'] }] } };
}

/** The prompt after redaction, read back from the message the text stages worked on. */
export function promptOf(redactedBody: Record<string, unknown>, fallback: string): string {
  const messages = redactedBody['messages'];
  if (Array.isArray(messages)) {
    const first = messages[0] as { content?: unknown } | undefined;
    if (typeof first?.content === 'string') return first.content;
  }
  return fallback;
}

/** The body sent to the provider: only the fields the route accepted. */
export function imageProviderBody(input: LlmImageRequest, prompt: string): Record<string, unknown> {
  return {
    model: input.model,
    prompt,
    n: input.n ?? 1,
    ...(input.size !== undefined ? { size: input.size } : {}),
    ...(input.quality !== undefined ? { quality: input.quality } : {}),
    // DALL-E answers with a link unless asked for the bytes; the GPT image models always send bytes and refuse the field.
    ...(/^dall-e/i.test(input.model) ? { response_format: 'b64_json' } : {}),
  };
}

export interface ProviderImage {
  /** The bytes, when the provider sent them. */
  base64: string | null;
  /** Where the provider hosts it, when it sent a link. */
  url: string | null;
  mediaType: string;
  revisedPrompt: string | null;
}

/** The images in a provider's answer (`data[]`), at most as many as were asked for. */
export function imagesIn(body: unknown, limit: number): ProviderImage[] {
  const data = (body as { data?: unknown } | null)?.data;
  if (!Array.isArray(data)) return [];
  const out: ProviderImage[] = [];
  // At most `limit` pictures; an entry that carries none is skipped and does not count.
  for (const item of data.slice(0, 16)) {
    if (out.length >= limit) break;
    if (typeof item !== 'object' || item === null) continue;
    const record = item as Record<string, unknown>;
    const base64 = typeof record['b64_json'] === 'string' && record['b64_json'].length > 0 ? record['b64_json'] : null;
    const url = typeof record['url'] === 'string' && /^https:\/\//i.test(record['url']) && record['url'].length <= 2_000 ? record['url'] : null;
    if (!base64 && !url) continue;
    const mediaType = typeof record['media_type'] === 'string' && /^image\/[a-z0-9.+-]{1,20}$/i.test(record['media_type'])
      ? record['media_type'].toLowerCase()
      : 'image/png';
    out.push({
      base64,
      url,
      mediaType,
      revisedPrompt: typeof record['revised_prompt'] === 'string' ? record['revised_prompt'].slice(0, 2_000) : null,
    });
  }
  return out;
}
