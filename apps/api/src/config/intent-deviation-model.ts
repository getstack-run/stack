import type { ReviewFlag } from '@stack/shared';
import {
  INTENT_DEVIATION_MAX_OUTPUT_TOKENS,
  INTENT_DEVIATION_SYSTEM_PROMPT,
  declaredAndObservedOf,
  intentDeviationFlagOf,
  intentDeviationUserInput,
  parseIntentDeviationResponse,
  type IntentDeviationGrader,
  type IntentDeviationInput,
} from '@stack/vault';

/**
 * intent_deviation on a self-hosted install, graded by the install's own model. The install names an OpenAI-compatible
 * chat completions endpoint (the API of OpenAI, of Azure's OpenAI service, of a gateway, or of a model the install runs
 * itself) and the model to ask there:
 *
 *   STACK_INTENT_MODEL_URL   the endpoint's base URL, https (http only on this machine), for example https://api.openai.com/v1;
 *                            the call is a POST to <url>/chat/completions
 *   STACK_INTENT_MODEL_NAME  the model to ask, in that endpoint's own name for it
 *   STACK_INTENT_MODEL_KEY   the key it takes as a bearer token; optional, for an endpoint that takes none
 *
 * The prompt, the answer format and the thresholds are the ones a hosted checkout is graded with
 * (`packages/vault/src/services/accountability/intent-deviation-prompt.ts`). What is sent to the endpoint is the passport's
 * declared intent and what the agent did (the services it used, its tool calls, the action count and the checkout's
 * summary); no passport, operator or agent identifier leaves the install. Best-effort like every grader: a refusal, a
 * timeout or an answer that cannot be read adds no flag.
 */
export interface IntentModelConfig {
  /** The base URL, without a trailing slash. */
  url: string;
  model: string;
  key: string | null;
}

/** How long a checkout waits for the model before it carries on without a grade. */
const INTENT_MODEL_TIMEOUT_MS = 15_000;

export function readIntentModelConfig(env: Record<string, string | undefined>): IntentModelConfig | null {
  const url = env['STACK_INTENT_MODEL_URL']?.trim();
  const model = env['STACK_INTENT_MODEL_NAME']?.trim();
  const key = env['STACK_INTENT_MODEL_KEY']?.trim();
  if (!url && !model && !key) return null;
  if (!url || !model) {
    throw new Error('[BOOT] STACK_INTENT_MODEL_URL and STACK_INTENT_MODEL_NAME are set together (STACK_INTENT_MODEL_KEY is optional) or not at all');
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('[BOOT] STACK_INTENT_MODEL_URL is not a valid URL');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('[BOOT] STACK_INTENT_MODEL_URL must be an https URL (http only for this machine) with no credentials, query or fragment');
  }
  return { url: `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`, model, key: key || null };
}

/**
 * The grader an install uses: its own model when one is configured, else STACK's network grader (which exists only when
 * the install switched the hosted classifier on), else none: intent_deviation is off.
 */
export function chooseInstallIntentGrader(own: IntentModelConfig | null, network: IntentDeviationGrader | null): IntentDeviationGrader | null {
  return own ? new OwnModelIntentDeviationGrader(own) : network;
}

export class OwnModelIntentDeviationGrader implements IntentDeviationGrader {
  constructor(
    private readonly config: IntentModelConfig,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async grade(input: IntentDeviationInput): Promise<ReviewFlag[]> {
    const read = declaredAndObservedOf(input);
    if (!read) return [];
    try {
      const response = await this.fetchImpl(`${this.config.url}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          ...(this.config.key ? { authorization: `Bearer ${this.config.key}` } : {}),
        },
        body: JSON.stringify({
          model: this.config.model,
          temperature: 0,
          max_tokens: INTENT_DEVIATION_MAX_OUTPUT_TOKENS,
          messages: [
            { role: 'system', content: INTENT_DEVIATION_SYSTEM_PROMPT },
            { role: 'user', content: intentDeviationUserInput(read) },
          ],
        }),
        redirect: 'error',
        signal: AbortSignal.timeout(INTENT_MODEL_TIMEOUT_MS),
      });
      if (!response.ok) return [];
      const body = (await response.json()) as { choices?: Array<{ message?: { content?: unknown } }> };
      const content = body.choices?.[0]?.message?.content;
      if (typeof content !== 'string') return [];
      const parsed = parseIntentDeviationResponse(content);
      const flag = parsed ? intentDeviationFlagOf(parsed) : null;
      return flag ? [flag] : [];
    } catch {
      return [];
    }
  }
}
