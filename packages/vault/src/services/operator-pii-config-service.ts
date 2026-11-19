// Per-operator PII redaction config (2026-08-05).
//
// The operator's half of score-based PII scanning: which countries to scan
// for, and how much confidence to demand before redacting. Reads sit on the
// LLM gateway hot path, so they are cache-fronted on the same ~60s Redis TTL
// as OperatorDetectorConfigService, which this is modelled on.
//
// Absence of a row means built-in defaults. Nothing is inserted on read.

import { ids, StackError, PII_DEFAULT_THRESHOLD, type PiiScanOptions } from '@stack/shared';
import type { OperatorPiiConfigRepository, PiiConfigRow } from '../repositories/operator-pii-config-repo.js';

interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

const CACHE_TTL_S = 60;

/** Cached as a literal so "no row" is a cache hit too. Without it, every
 *  request from an operator who has never configured PII would fall through
 *  to Postgres, which is most operators on the busiest path we have. */
const CACHE_MISS_SENTINEL = 'null';

function cacheKey(operatorId: string): string {
  return `op_pii_config:${operatorId}`;
}

class PiiConfigValidationError extends StackError {
  constructor(message: string) {
    super(message, 'PII_CONFIG_INVALID', 400);
  }
}

/** ISO 3166-1 alpha-2. Deliberately a shape check, not a registry check: a
 *  code we do not have a pattern for is harmless (it scopes to nothing extra)
 *  and hard-coding the member list here would rot. */
const COUNTRY_CODE = /^[A-Z]{2}$/;

export class OperatorPiiConfigService {
  constructor(
    private repo: OperatorPiiConfigRepository,
    private redis: RedisLike,
  ) {}

  /** Read an operator's row. Cache-fronted, including the absent case. */
  async getForOperator(operatorId: string): Promise<PiiConfigRow | undefined> {
    const cached = await this.redis.get(cacheKey(operatorId));
    if (cached !== null) {
      if (cached === CACHE_MISS_SENTINEL) return undefined;
      try {
        const r = JSON.parse(cached) as PiiConfigRow & { created_at: string; updated_at: string };
        return { ...r, created_at: new Date(r.created_at), updated_at: new Date(r.updated_at) };
      } catch {
        // Corrupted cache — fall through to DB and rewrite.
      }
    }
    const row = await this.repo.findByOperator(operatorId);
    await this.redis.set(
      cacheKey(operatorId),
      row ? JSON.stringify(row) : CACHE_MISS_SENTINEL,
      'EX',
      CACHE_TTL_S,
    );
    return row;
  }

  /**
   * Resolve an operator's row into the options scanForPii takes.
   *
   * Returns null when redaction is switched off for the account, which the
   * caller must treat as "do not redact" rather than "use defaults" — the
   * two are opposite answers and collapsing them would silently re-enable a
   * control the operator turned off.
   */
  async resolveScanOptions(operatorId: string): Promise<PiiScanOptions | null> {
    const row = await this.getForOperator(operatorId);
    if (!row) return {};
    if (!row.enabled) return null;
    return {
      ...(row.threshold !== null ? { threshold: row.threshold } : {}),
      ...(row.countries !== null && row.countries.length ? { countries: row.countries } : {}),
    };
  }

  /**
   * Uppercase and de-duplicate before validating, not after. The route's Zod
   * schema accepts [A-Za-z]{2} and the CLI uppercases on the way in, but an
   * SDK or MCP caller sending "se" was being told it is not a country code,
   * which is both wrong and unhelpful. Case is a formatting question.
   */
  private normalizeCountries(countries: string[]): string[] {
    return [...new Set(countries.map((c) => c.trim().toUpperCase()))];
  }

  private validate(input: { threshold?: number | null; countries?: string[] | null }): void {
    if (input.threshold !== undefined && input.threshold !== null) {
      if (!Number.isFinite(input.threshold) || input.threshold < 0 || input.threshold > 1) {
        throw new PiiConfigValidationError(
          `threshold must be between 0 and 1 (got ${input.threshold}); the built-in default is ${PII_DEFAULT_THRESHOLD}`,
        );
      }
    }
    if (input.countries !== undefined && input.countries !== null) {
      if (input.countries.length > 64) {
        throw new PiiConfigValidationError('countries accepts at most 64 codes');
      }
      for (const c of input.countries) {
        if (!COUNTRY_CODE.test(c)) {
          throw new PiiConfigValidationError(
            `"${c}" is not an ISO 3166-1 alpha-2 country code (two uppercase letters, e.g. SE)`,
          );
        }
      }
    }
  }

  /**
   * Does this change reduce how much gets redacted? Mirrors
   * classifyDetectorConfigDelta's purpose without its vocabulary: the API
   * layer uses this to decide whether a human has to approve.
   *
   * Loosening is: turning redaction off, RAISING the threshold (fewer matches
   * clear it), or narrowing the country list. Note the direction on threshold
   * is the opposite of what reads naturally — a higher number redacts less.
   */
  isLoosening(
    prior: PiiConfigRow | undefined,
    next: { enabled?: boolean; threshold?: number | null; countries?: string[] | null },
  ): boolean {
    const priorEnabled = prior?.enabled ?? true;
    const priorThreshold = prior?.threshold ?? PII_DEFAULT_THRESHOLD;
    const priorCountries = prior?.countries ?? null;

    if (next.enabled === false && priorEnabled) return true;
    if (next.threshold !== undefined) {
      const t = next.threshold ?? PII_DEFAULT_THRESHOLD;
      if (t > priorThreshold) return true;
    }
    if (next.countries !== undefined) {
      const n = next.countries;
      // null (all countries) is the widest setting; moving to a list narrows.
      if (priorCountries === null && n !== null) return true;
      if (priorCountries !== null && n !== null) {
        const set = new Set(n.map((c) => c.toUpperCase()));
        if (priorCountries.some((c) => !set.has(c.toUpperCase()))) return true;
      }
    }
    return false;
  }

  async upsert(input: {
    operator_id: string;
    enabled?: boolean;
    threshold?: number | null;
    countries?: string[] | null;
  }): Promise<PiiConfigRow> {
    const normalized =
      input.countries !== undefined && input.countries !== null
        ? this.normalizeCountries(input.countries)
        : input.countries;
    this.validate({ ...input, ...(normalized !== undefined ? { countries: normalized } : {}) });
    const row = await this.repo.upsert({
      id: ids.session(),
      operator_id: input.operator_id,
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
      ...(input.threshold !== undefined ? { threshold: input.threshold } : {}),
      ...(normalized !== undefined ? { countries: normalized } : {}),
    });
    await this.redis.del(cacheKey(input.operator_id));
    return row;
  }

  async reset(operatorId: string): Promise<boolean> {
    const deleted = await this.repo.delete(operatorId);
    await this.redis.del(cacheKey(operatorId));
    return deleted;
  }
}
