// Pure request-shaping helpers for the LLM gateway: counting what a request
// asks for, refusing cost the gateway cannot bound, and shaping the body that
// goes upstream. No I/O, so each one is unit-testable on its own.

import type { LlmModelPricing } from '@stack/shared';
import type { LlmProvider } from '@stack/vault';

export const BILLING_ENVELOPE_BYTES = 4_096;

export function countImageInputs(body: Record<string, unknown>): number {
  const messages = Array.isArray(body.messages) ? body.messages : [];
  let count = 0;
  for (const message of messages) {
    if (!message || typeof message !== 'object') continue;
    const content = (message as { content?: unknown }).content;
    if (!Array.isArray(content)) continue;
    for (const part of content) {
      if (!part || typeof part !== 'object') continue;
      const type = (part as { type?: unknown }).type;
      if (type === 'image' || type === 'image_url') count += 1;
    }
  }
  return count;
}

export function unsupportedVariableCost(body: Record<string, unknown>): string | null {
  const model = typeof body.model === 'string' ? body.model : '';
  if (model.includes(':online')) {
    return 'Online model variants can create an unknown number of paid searches.';
  }
  if ('web_search_options' in body) {
    return 'Web search can create an unknown number of provider charges.';
  }
  const modalities = Array.isArray(body.modalities) ? body.modalities : [];
  if (modalities.includes('image') || modalities.includes('audio')) {
    return 'Generated image and audio costs are not bounded by the text token limit.';
  }
  const plugins = Array.isArray(body.plugins) ? body.plugins : [];
  if (plugins.some((plugin) =>
    plugin && typeof plugin === 'object' && (plugin as { id?: unknown }).id === 'web')) {
    return 'The web plugin can create an unknown number of provider charges.';
  }
  const tools = Array.isArray(body.tools) ? body.tools : [];
  for (const tool of tools) {
    if (!tool || typeof tool !== 'object') continue;
    const candidate = tool as { type?: unknown; name?: unknown };
    const value = typeof candidate.type === 'string'
      ? candidate.type
      : typeof candidate.name === 'string'
        ? candidate.name
        : '';
    if (value.includes('web_search') || value.includes('web_fetch')) {
      return 'Provider web tools can create an unknown number of provider charges.';
    }
  }
  return null;
}

export function maxOutputTokens(body: Record<string, unknown>): number | null {
  const value = body.max_completion_tokens ?? body.max_tokens;
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : null;
}

function lowerPrice(existing: unknown, ceiling: number): number {
  return typeof existing === 'number' && Number.isFinite(existing) && existing >= 0
    ? Math.min(existing, ceiling)
    : ceiling;
}

export function applyOpenRouterPriceCeiling(
  body: Record<string, unknown>,
  pricing: LlmModelPricing,
): Record<string, unknown> {
  const currentProvider = body.provider && typeof body.provider === 'object' && !Array.isArray(body.provider)
    ? body.provider as Record<string, unknown>
    : {};
  const currentMax = currentProvider.max_price &&
      typeof currentProvider.max_price === 'object' &&
      !Array.isArray(currentProvider.max_price)
    ? currentProvider.max_price as Record<string, unknown>
    : {};
  const maxPrice: Record<string, unknown> = {
    ...currentMax,
    prompt: lowerPrice(currentMax.prompt, pricing.input_cents_per_1m / 100),
    completion: lowerPrice(currentMax.completion, pricing.output_cents_per_1m / 100),
  };
  if (pricing.request_cents !== undefined) {
    maxPrice.request = lowerPrice(currentMax.request, pricing.request_cents / 100);
  }
  if (pricing.image_cents !== undefined) {
    maxPrice.image = lowerPrice(currentMax.image, pricing.image_cents / 100);
  }
  return {
    ...body,
    provider: {
      ...currentProvider,
      max_price: maxPrice,
    },
  };
}

export function prepareProviderBody(
  provider: LlmProvider,
  body: Record<string, unknown>,
  streaming: boolean,
  authorization?: { pricing: LlmModelPricing | null },
): Record<string, unknown> {
  let prepared = { ...body };
  if (streaming && provider !== 'anthropic') {
    const current = prepared.stream_options &&
        typeof prepared.stream_options === 'object' &&
        !Array.isArray(prepared.stream_options)
      ? prepared.stream_options as Record<string, unknown>
      : {};
    prepared = { ...prepared, stream_options: { ...current, include_usage: true } };
  }
  if (provider === 'openrouter' && authorization?.pricing) {
    prepared = applyOpenRouterPriceCeiling(prepared, authorization.pricing);
  }
  return prepared;
}
