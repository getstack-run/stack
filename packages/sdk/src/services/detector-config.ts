import type { HttpClient } from '../client.js';
import type { DetectorConfig, DetectorConfigUpsert } from '../types.js';

/**
 * Per-operator detector customization (L7 of STACK's prompt-injection
 * defense stack).
 *
 * A customer with controls can customize how each detector behaves for
 * their traffic:
 *   - **custom_patterns** — additional regex specific to your domain
 *     (e.g. `"ignore the rules of our employee handbook"`)
 *   - **whitelist_patterns** — suppress matched_text false positives
 *     (e.g. `"DAN"` if DAN is a real customer name)
 *   - **severity_overrides** — remap built-in pattern severities
 *   - **enabled** — master switch (set false to disable the detector
 *     entirely for this operator)
 *
 * Reads are open (404 when no row exists, which means the detector is
 * running on built-in defaults). Writes are a controls feature: they
 * apply at once with no approval, and without controls they throw a
 * `StackError` with code `CONTROLS_REQUIRED` (402). A self-managed
 * install has every controls feature.
 *
 * @example
 * ```ts
 * await stack.detectorConfig.upsert('prompt_injection', {
 *   custom_patterns: [
 *     { id: 'handbook', regex: 'employee handbook', severity: 'warning', description: 'domain term' },
 *   ],
 *   whitelist_patterns: [
 *     { id: 'real_dan', regex: 'DAN', description: 'real customer name' },
 *   ],
 * });
 * ```
 */
export class DetectorConfigService {
  constructor(private client: HttpClient) {}

  /** List every detector config row this operator has set. Empty list
   * means every detector is on built-in defaults. */
  async list(): Promise<{ configs: DetectorConfig[] }> {
    return this.client.get<{ configs: DetectorConfig[] }>('/v1/detectors/config');
  }

  /** Get one detector's config. Throws on 404 when no row exists —
   * absence means the detector is running on built-in defaults. */
  async get(detectorKey: string): Promise<DetectorConfig> {
    return this.client.get<DetectorConfig>(`/v1/detectors/${encodeURIComponent(detectorKey)}/config`);
  }

  /** Upsert this operator's customization for the named detector.
   * Returns the row as stored. Needs controls (402 CONTROLS_REQUIRED).
   * `governanceApprovalId` is no longer needed (a change asks no
   * approval); it is still accepted so existing calls keep working. */
  async upsert(
    detectorKey: string,
    input: DetectorConfigUpsert,
    opts?: { governanceApprovalId?: string },
  ): Promise<DetectorConfig> {
    return this.client.put<DetectorConfig>(
      `/v1/detectors/${encodeURIComponent(detectorKey)}/config`,
      input,
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }

  /** Reset this detector to defaults — deletes the row so the next
   * scan reads built-in patterns only. Needs controls (402
   * CONTROLS_REQUIRED). `governanceApprovalId` is no longer needed (a
   * reset asks no approval); it is still accepted so existing calls keep
   * working. */
  async reset(detectorKey: string, opts?: { governanceApprovalId?: string }): Promise<void> {
    await this.client.delete(
      `/v1/detectors/${encodeURIComponent(detectorKey)}/config`,
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }
}
