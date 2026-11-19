import type { HttpClient } from '../client.js';
import type { PiiConfig, PiiConfigUpdate } from '../types.js';

/**
 * Per-operator PII redaction config for the LLM gateway.
 *
 * The gateway scores every candidate identifier rather than trusting a check
 * digit, and these are the two dials over that scoring:
 *
 * - `threshold` — confidence needed before redacting, 0 to 1. HIGHER redacts
 *   LESS. The built-in default is 0.4.
 * - `countries` — which countries' identifier schemes to run. `null` means
 *   every country: safe, and noisy. Email, card, IBAN and IP addresses are
 *   country-neutral and always scan whatever this is set to.
 *
 * Use them together. Scoping to the countries you actually operate in is what
 * lets you lower the threshold safely — bare-format personal numbers start
 * redacting without every order number in your traffic going with them.
 *
 * Every change applies at once and asks no one, loosening included (redaction
 * off, a higher threshold, a narrower country list). `direction` in the answer
 * says which way it went.
 *
 * @example
 * ```ts
 * // A Nordic operator: only run SE/NO/DK schemes, and demand less
 * // confidence because there is far less to confuse them with.
 * await stack.piiConfig.update({ countries: ['SE', 'NO', 'DK'], threshold: 0.2 });
 *
 * const cfg = await stack.piiConfig.get();
 * // { configured: true, enabled: true, threshold: 0.2, countries: ['SE','NO','DK'] }
 * ```
 */
export class PiiConfigService {
  constructor(private client: HttpClient) {}

  /**
   * Read the config in force. Never 404s: an operator who has set nothing
   * gets the built-in defaults with `configured: false`, because the caller's
   * next question is always "so what IS it".
   */
  async get(): Promise<PiiConfig> {
    return this.client.get<PiiConfig>('/v1/pii/config');
  }

  /**
   * Partial update. Omit a field to leave it untouched; pass `null` for
   * `threshold` or `countries` to clear it back to the built-in default.
   */
  async update(input: PiiConfigUpdate): Promise<PiiConfig> {
    return this.client.put<PiiConfig>('/v1/pii/config', input);
  }

  /** Delete the row and fall back to built-in defaults. Applies at once. */
  async reset(): Promise<{ success: boolean }> {
    return this.client.delete<{ success: boolean }>('/v1/pii/config');
  }
}
