import {
  ids,
  StackError,
  classifyDetectorConfigDelta,
  DETECTOR_CONFIG_DEFAULTS,
  type DetectorConfigDelta,
  type DetectorConfigState,
  type OperatorCustomPattern,
  type OperatorWhitelistPattern,
} from '@stack/shared';
import type { OperatorDetectorConfigRepository, DetectorConfigRow } from '../repositories/operator-detector-config-repo.js';

class DetectorConfigValidationError extends StackError {
  constructor(message: string) {
    super(message, 'DETECTOR_CONFIG_INVALID', 400);
  }
}

/**
 * Per-operator detector customization (L7 of the prompt-injection
 * defense stack). Operators can:
 *
 *   - Add custom regex patterns specific to their domain
 *     ("ignore the rules of our employee handbook")
 *   - Whitelist matched-text strings the built-ins false-positive on
 *     ("DAN" when DAN is a real customer's name)
 *   - Override the default severity on built-in patterns
 *   - Disable the detector entirely (master switch)
 *
 * Tier-gated at the API layer to studio+. Service itself does NOT
 * enforce the tier — that's the route's job — so the service can
 * also be called from background workers (compliance audits etc.)
 * regardless of operator tier.
 *
 * Caching: a thin in-memory cache fronts Redis. Both have ~60s TTL.
 * Writes invalidate both. The detector hot path reads through this
 * cache so a config change shows up within ~60s on every API node.
 */

interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

const CACHE_TTL_S = 60;

function cacheKey(operatorId: string): string {
  return `op_detector_config:${operatorId}`;
}

export class OperatorDetectorConfigService {
  constructor(
    private repo: OperatorDetectorConfigRepository,
    private redis: RedisLike,
  ) {}

  /** Validate a single regex pattern. Returns null on valid, an
   * error message on invalid. */
  private validateRegex(pattern: string, label: string): string | null {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      return `${label}: regex must be a non-empty string`;
    }
    if (pattern.length > 512) {
      return `${label}: regex must be ≤512 chars`;
    }
    try {
      // Compile to verify syntax. Using JS regex (not RE2) is
      // intentional — operators can already use lookbehind / etc.
      // Risk of catastrophic backtracking exists; mitigated by:
      //   (1) regex length cap above
      //   (2) detector hot path runs each op-pattern with a 100ms
      //       per-pattern timeout (TODO: enforce in scanner)
      new RegExp(pattern, 'i');
    } catch (err) {
      return `${label}: invalid regex — ${err instanceof Error ? err.message : 'unknown'}`;
    }
    return null;
  }

  /** Validate a custom_patterns array. Throws ValidationError on
   * the first invalid entry. */
  private validateCustomPatterns(patterns: unknown): OperatorCustomPattern[] {
    if (!Array.isArray(patterns)) {
      throw new DetectorConfigValidationError('custom_patterns must be an array');
    }
    if (patterns.length > 50) {
      throw new DetectorConfigValidationError('custom_patterns: max 50 patterns per detector');
    }
    const out: OperatorCustomPattern[] = [];
    const seen = new Set<string>();
    for (const p of patterns) {
      if (!p || typeof p !== 'object') {
        throw new DetectorConfigValidationError('custom_patterns: each entry must be an object');
      }
      const obj = p as Record<string, unknown>;
      if (typeof obj.id !== 'string' || obj.id.length === 0 || obj.id.length > 64) {
        throw new DetectorConfigValidationError('custom_patterns: id must be a 1-64 char string');
      }
      if (seen.has(obj.id)) {
        throw new DetectorConfigValidationError(`custom_patterns: duplicate id '${obj.id}'`);
      }
      seen.add(obj.id);
      const regexErr = this.validateRegex(obj.regex as string, `custom_patterns[${obj.id}]`);
      if (regexErr) throw new DetectorConfigValidationError(regexErr);
      if (obj.severity !== 'warning' && obj.severity !== 'critical') {
        throw new DetectorConfigValidationError(`custom_patterns[${obj.id}]: severity must be 'warning' or 'critical'`);
      }
      if (typeof obj.description !== 'string' || obj.description.length > 256) {
        throw new DetectorConfigValidationError(`custom_patterns[${obj.id}]: description must be a string ≤256 chars`);
      }
      out.push({
        id: obj.id,
        regex: obj.regex as string,
        severity: obj.severity,
        description: obj.description,
      });
    }
    return out;
  }

  private validateWhitelistPatterns(patterns: unknown): OperatorWhitelistPattern[] {
    if (!Array.isArray(patterns)) {
      throw new DetectorConfigValidationError('whitelist_patterns must be an array');
    }
    if (patterns.length > 50) {
      throw new DetectorConfigValidationError('whitelist_patterns: max 50 entries per detector');
    }
    const out: OperatorWhitelistPattern[] = [];
    const seen = new Set<string>();
    for (const p of patterns) {
      if (!p || typeof p !== 'object') {
        throw new DetectorConfigValidationError('whitelist_patterns: each entry must be an object');
      }
      const obj = p as Record<string, unknown>;
      if (typeof obj.id !== 'string' || obj.id.length === 0 || obj.id.length > 64) {
        throw new DetectorConfigValidationError('whitelist_patterns: id must be a 1-64 char string');
      }
      if (seen.has(obj.id)) {
        throw new DetectorConfigValidationError(`whitelist_patterns: duplicate id '${obj.id}'`);
      }
      seen.add(obj.id);
      const regexErr = this.validateRegex(obj.regex as string, `whitelist_patterns[${obj.id}]`);
      if (regexErr) throw new DetectorConfigValidationError(regexErr);
      if (typeof obj.description !== 'string' || obj.description.length > 256) {
        throw new DetectorConfigValidationError(`whitelist_patterns[${obj.id}]: description must be a string ≤256 chars`);
      }
      out.push({ id: obj.id, regex: obj.regex as string, description: obj.description });
    }
    return out;
  }

  private validateSeverityOverrides(input: unknown): Record<string, 'warning' | 'critical'> {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new DetectorConfigValidationError('severity_overrides must be an object');
    }
    const out: Record<string, 'warning' | 'critical'> = {};
    for (const [key, val] of Object.entries(input as Record<string, unknown>)) {
      if (val !== 'warning' && val !== 'critical') {
        throw new DetectorConfigValidationError(`severity_overrides[${key}]: must be 'warning' or 'critical'`);
      }
      out[key] = val;
    }
    return out;
  }

  /** Read all configs for an operator. Cache-fronted. */
  async getAllForOperator(operatorId: string): Promise<DetectorConfigRow[]> {
    const cached = await this.redis.get(cacheKey(operatorId));
    if (cached !== null) {
      try {
        const parsed = JSON.parse(cached) as Array<DetectorConfigRow & { created_at: string; updated_at: string }>;
        return parsed.map((r) => ({
          ...r,
          created_at: new Date(r.created_at),
          updated_at: new Date(r.updated_at),
        }));
      } catch {
        // Corrupted cache — fall through to DB and rewrite.
      }
    }
    const rows = await this.repo.findByOperator(operatorId);
    await this.redis.set(
      cacheKey(operatorId),
      JSON.stringify(rows),
      'EX',
      CACHE_TTL_S,
    );
    return rows;
  }

  /** Read one detector's config for an operator. Convenience over
   * getAllForOperator — the cache is keyed at the operator level so
   * either method warms the same cache. */
  async getForDetector(operatorId: string, detectorKey: string): Promise<DetectorConfigRow | undefined> {
    const all = await this.getAllForOperator(operatorId);
    return all.find((r) => r.detector_key === detectorKey);
  }

  /**
   * classify the DIRECTION of a proposed upsert against the
   * current (authoritative, uncached) row. Partial-update semantics:
   * fields absent from the input keep their prior values, so the delta
   * is computed over the EFFECTIVE next state. The route layer gates on
   * this (agents: tightening only; Bearer humans: loosening needs a
   * governance approval) and the audit row records it — finally making
   * the route's "records what changed at the field level" claim true.
   */
  async classifyUpsert(input: {
    operator_id: string;
    detector_key: string;
    custom_patterns?: unknown;
    whitelist_patterns?: unknown;
    severity_overrides?: unknown;
    enabled?: boolean;
  }): Promise<{ delta: DetectorConfigDelta; prior: DetectorConfigState | undefined }> {
    const priorRow = await this.repo.findByOperatorAndDetector(
      input.operator_id,
      input.detector_key,
    );
    const prior: DetectorConfigState | undefined = priorRow
      ? {
          enabled: priorRow.enabled,
          custom_patterns: priorRow.custom_patterns,
          whitelist_patterns: priorRow.whitelist_patterns,
          severity_overrides: priorRow.severity_overrides,
        }
      : undefined;
    const from = prior ?? DETECTOR_CONFIG_DEFAULTS;
    const next: DetectorConfigState = {
      enabled: input.enabled !== undefined ? input.enabled : from.enabled,
      custom_patterns:
        input.custom_patterns !== undefined
          ? this.validateCustomPatterns(input.custom_patterns)
          : from.custom_patterns,
      whitelist_patterns:
        input.whitelist_patterns !== undefined
          ? this.validateWhitelistPatterns(input.whitelist_patterns)
          : from.whitelist_patterns,
      severity_overrides:
        input.severity_overrides !== undefined
          ? this.validateSeverityOverrides(input.severity_overrides)
          : from.severity_overrides,
    };
    return { delta: classifyDetectorConfigDelta(prior, next), prior };
  }

  /** Upsert. Validates input and invalidates cache. */
  async upsert(input: {
    operator_id: string;
    detector_key: string;
    custom_patterns?: unknown;
    whitelist_patterns?: unknown;
    severity_overrides?: unknown;
    enabled?: boolean;
  }): Promise<DetectorConfigRow> {
    if (!input.detector_key || typeof input.detector_key !== 'string') {
      throw new DetectorConfigValidationError('detector_key required');
    }
    const customPatterns = input.custom_patterns !== undefined
      ? this.validateCustomPatterns(input.custom_patterns)
      : undefined;
    const whitelistPatterns = input.whitelist_patterns !== undefined
      ? this.validateWhitelistPatterns(input.whitelist_patterns)
      : undefined;
    const severityOverrides = input.severity_overrides !== undefined
      ? this.validateSeverityOverrides(input.severity_overrides)
      : undefined;

    const row = await this.repo.upsert({
      id: ids.session(), // reuse session-id generator for new rows
      operator_id: input.operator_id,
      detector_key: input.detector_key,
      ...(customPatterns !== undefined ? { custom_patterns: customPatterns } : {}),
      ...(whitelistPatterns !== undefined ? { whitelist_patterns: whitelistPatterns } : {}),
      ...(severityOverrides !== undefined ? { severity_overrides: severityOverrides } : {}),
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
    });
    await this.redis.del(cacheKey(input.operator_id));
    return row;
  }

  /** Delete one detector's config (reset to defaults). */
  async reset(operatorId: string, detectorKey: string): Promise<boolean> {
    const deleted = await this.repo.delete(operatorId, detectorKey);
    await this.redis.del(cacheKey(operatorId));
    return deleted;
  }
}
