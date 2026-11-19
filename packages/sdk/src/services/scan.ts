import type { HttpClient } from '../client.js';
import type { ScanRequest, ScanResponse, ScanUsage } from '../types.js';

/**
 * Content-scanning service. Use to scan retrieved content (emails,
 * documents, web pages, API responses) for prompt-injection markers
 * BEFORE feeding it into your LLM.
 *
 * Reuses the same detector chain that runs on /v1/proxy and
 * /v1/skills/:id/invoke — L1 regex catalog + L2 encoding-aware
 * normalization. Returns a verdict with optional match details so
 * your agent can decide whether to proceed.
 *
 * @example
 * ```ts
 * const result = await stack.scan.scan({
 *   content: emailBody,
 *   context: 'email',
 *   source: senderAddress,
 * });
 * if (result.verdict === 'critical') {
 *   throw new Error(`Indirect injection caught: ${result.match?.pattern_id}`);
 * }
 * ```
 */
export class ScanService {
  constructor(private client: HttpClient) {}

  /** Scan retrieved content for prompt-injection markers. */
  async scan(input: ScanRequest, options?: { passportToken?: string }): Promise<ScanResponse> {
    const headers: Record<string, string> = {};
    if (options?.passportToken) {
      headers['X-Passport-Token'] = options.passportToken;
    }
    return this.client.post<ScanResponse>('/v1/scan', input, { headers });
  }

  /** Current month's scan usage against the account's allowance; `plan` names the plan it is on. */
  async usage(): Promise<ScanUsage> {
    return this.client.get<ScanUsage>('/v1/scan/usage');
  }
}
