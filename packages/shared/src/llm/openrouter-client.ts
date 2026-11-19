export interface OpenRouterConfig {
  apiKey: string;
}

export interface CompletionResult {
  content: string;
  tokens_input: number;
  tokens_output: number;
  model: string;
  /**
   * What OpenRouter actually charged, in USD. Ground truth — prefer this over
   * multiplying tokens by a local price table, which silently goes stale and
   * is wrong the moment a call routes to a different model than requested.
   * Absent on providers that do not report it.
   */
  cost_usd?: number;
  /**
   * Tokens the model spent thinking before answering. Counted inside
   * `tokens_output`, so a small max_tokens can be consumed entirely by
   * reasoning and return empty content with finish_reason 'stop' — a failure
   * that looks like success. Surfaced so callers can tell the two apart.
   */
  reasoning_tokens?: number;
}

export interface OpenRouterPriceCeiling {
  prompt: number;
  completion: number;
  request?: number;
  image?: number;
}

export class OpenRouterService {
  private baseUrl = 'https://openrouter.ai/api/v1/chat/completions';

  constructor(private config: OpenRouterConfig) {}

  async complete(
    model: string,
    systemPrompt: string,
    userInput: string,
    options?: {
      temperature?: number;
      max_tokens?: number;
      priceCeiling?: OpenRouterPriceCeiling;
      /**
       * Deadline for the WHOLE call, response body included. When it fires the
       * HTTP request is aborted, so a timed-out call stops instead of running
       * on (and being billed) after the caller has given up on it.
       */
      timeoutMs?: number;
      /** Caller cancellation. Aborts the in-flight HTTP request. */
      signal?: AbortSignal;
    },
  ): Promise<CompletionResult> {
    const body = {
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userInput },
      ],
      temperature: options?.temperature ?? 0.7,
      max_tokens: options?.max_tokens ?? 4096,
      ...(options?.priceCeiling
        ? { provider: { max_price: options.priceCeiling } }
        : {}),
    };

    // The deadline used to be cleared as soon as the response HEADERS arrived,
    // so a slow body was never cut off. It now spans the body read too, and a
    // caller's own signal cancels the same request.
    const controller = options?.timeoutMs ? new AbortController() : null;
    const timeout = controller
      ? setTimeout(() => controller.abort(new DOMException('OpenRouter request timed out', 'TimeoutError')), options!.timeoutMs)
      : null;
    const signals = [controller?.signal, options?.signal].filter((s): s is AbortSignal => s !== undefined);
    const signal = signals.length === 0 ? undefined : signals.length === 1 ? signals[0] : AbortSignal.any(signals);
    let result: {
      choices: { message: { content: string } }[];
      usage: {
        prompt_tokens: number;
        completion_tokens: number;
        cost?: number;
        completion_tokens_details?: { reasoning_tokens?: number };
      };
      model: string;
    };
    try {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://getstack.run',
          'X-Title': 'STACK Skills',
        },
        body: JSON.stringify(body),
        ...(signal ? { signal } : {}),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`OpenRouter API error (${response.status}): ${error}`);
      }

      result = await response.json() as typeof result;
    } finally {
      if (timeout) clearTimeout(timeout);
    }

    const reasoning = result.usage?.completion_tokens_details?.reasoning_tokens;
    return {
      content: result.choices[0]?.message?.content ?? '',
      tokens_input: result.usage?.prompt_tokens ?? 0,
      tokens_output: result.usage?.completion_tokens ?? 0,
      model: result.model,
      ...(typeof result.usage?.cost === 'number' ? { cost_usd: result.usage.cost } : {}),
      ...(typeof reasoning === 'number' ? { reasoning_tokens: reasoning } : {}),
    };
  }
}
