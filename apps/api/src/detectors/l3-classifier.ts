import { createHash } from 'node:crypto';

/**
 * The third detector layer: a model that reads content the pattern layers
 * could not settle. The engine's classifier is STACK's network service, called
 * with the install's licence key (`NetworkClassifier` in
 * `config/network-client.ts`); what runs the model, and what it costs, is the
 * network's business, not the install's. The engine holds the interface, the
 * gate that decides which content is worth a classification, how a verdict
 * merges with the pattern layers' verdict, and how a long body is sampled: the
 * prompt and the model call belong to whoever runs the model.
 */
export type L3Verdict = 'clean' | 'suspicious' | 'critical';

export interface L3ClassificationResult {
  verdict: L3Verdict;
  /** 0 to 100. */
  confidence: number;
  reasoning: string;
  /** True when the call failed and the result degraded to clean; the caller records a `detector_degraded` event. */
  degraded: boolean;
  duration_ms: number;
  model: string;
  /** True when the verdict came from the cache: no call ran and nothing was billed. */
  cached?: boolean;
  /** What the call cost, when its runner knows. */
  cost_cents?: number;
  provider_cost_usd?: number;
  tokens_input?: number;
  tokens_output?: number;
}

export interface L3Classifier {
  /**
   * What a cached verdict is keyed by: the configuration the classifier runs
   * under (a changed prompt or model must retire every cached verdict) and the
   * model its cached result names. Absent: this classifier's verdicts are never cached.
   */
  readonly cacheIdentity?: { identity: string; model: string };
  /**
   * A verdict for the content, or null when this classifier declines to run
   * (no budget for the call, a cancelled scan). A failed call is not null: it
   * is a `degraded` result, so the failure is recorded.
   */
  classify(
    content: string,
    options?: { signal?: AbortSignal; timeoutMs?: number },
  ): Promise<L3ClassificationResult | null>;
}

/** No third layer: the pattern layers decide alone. */
export const NO_L3_CLASSIFIER: L3Classifier = {
  async classify() {
    return null;
  },
};

/** Whose scan this is, for a classifier that bills or reuses verdicts per operator. */
export interface L3ScanContext {
  operatorId?: string;
  agentId?: string | null;
  passportJti?: string | null;
  missionId?: string | null;
  /** The caller can reuse a verdict for identical content it already paid for. */
  reuseVerdicts?: boolean;
}

/** The classifier for one scan, or null when this deployment runs no third layer. */
export type L3ClassifierSource = (context: L3ScanContext) => L3Classifier | null;

/** How long the layer waits for its classifier before the scan degrades to the pattern layers' verdict. */
export const L3_TIMEOUT_MS = 5000;

/** Max chars sent to the classifier. Capped so a 50KB body doesn't translate into a multi-cent call. Injection payloads
 * are almost always near document boundaries, not buried mid-text: the head and the tail are sufficient. */
const HEAD_CAP_CHARS = 2500;
const TAIL_CAP_CHARS = 1500;

/** Render an oversized body for the classifier by sampling the head and the tail. Skips the middle (the
 * lowest-information region) to keep cost and the content that leaves the process bounded. */
export function sampleForLlm(content: string): string {
  if (content.length <= HEAD_CAP_CHARS + TAIL_CAP_CHARS) return content;
  const head = content.slice(0, HEAD_CAP_CHARS);
  const tail = content.slice(-TAIL_CAP_CHARS);
  return `${head}\n\n[...truncated middle of large body...]\n\n${tail}`;
}

/** Heuristic gate: should this content be sent to L3? Returns false
 * for trivially-clean inputs that don't warrant a model call.
 *
 * Tuning rationale: with only light heuristic gating the detector
 * under-fires on indirect-injection attacks that have no encoding markers
 * and don't address the AI explicitly (e.g. bare
 * "TODO: <malicious-task>" or fake-tag forms like "###(system_message) X").
 * Better to classify most non-trivial bodies than to miss the attacks.
 * The size floor (60 chars) still skips empty / single-token traffic, which
 * is the bulk of legitimate API payloads. */
export function shouldRunL3(content: string, l1l2Verdict: 'clean' | 'warning' | 'critical'): boolean {
  // Always skip if L1+L2 already returned critical — we have a verdict.
  if (l1l2Verdict === 'critical') return false;

  // Always run if L1+L2 returned warning — escalate to confirm or upgrade.
  if (l1l2Verdict === 'warning') return true;

  // For clean L1+L2: fire L3 on any body with a meaningful chunk of
  // content. Sub-60-char bodies (short greetings, ID strings, simple
  // queries) skip — they're either trivial-clean or trivial-already-
  // caught by L1.
  return content.length >= 60;
}

/**
 * Merge an L1+L2 verdict with the L3 verdict. The merge logic:
 *
 * - L3 critical (>70 conf) → final critical (regardless of L1+L2)
 * - L3 suspicious (30-70 conf) AND L1+L2 was warning → final critical
 * - L3 suspicious AND L1+L2 was clean → final warning
 * - L3 clean (<30 conf) → keep L1+L2 verdict (the classifier didn't see anything
 *   regex didn't already)
 * - L3 degraded → keep L1+L2 verdict (don't penalise the request when
 *   the classifier is broken)
 */
export function mergeVerdicts(
  l1l2: 'clean' | 'warning' | 'critical',
  llm: L3ClassificationResult,
): { verdict: 'clean' | 'warning' | 'critical'; reason: string } {
  if (llm.degraded) return { verdict: l1l2, reason: 'l3_degraded' };

  if (llm.verdict === 'critical') {
    return { verdict: 'critical', reason: 'l3_critical' };
  }
  if (llm.verdict === 'suspicious') {
    if (l1l2 === 'warning') return { verdict: 'critical', reason: 'l3_suspicious_x_l2_warning' };
    return { verdict: 'warning', reason: 'l3_suspicious' };
  }
  // llm.verdict === 'clean'
  return { verdict: l1l2, reason: 'l3_concur_clean' };
}

/** How long a verdict is reused for identical content. */
export const L3_VERDICT_CACHE_TTL_SECONDS = 3600;

/**
 * Where reused verdicts live. Redis in production. The key is a hash, and the
 * value carries only `verdict` and `confidence`: never the content, never the
 * classifier's reasoning (which can quote the content).
 */
export interface L3VerdictCache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<unknown>;
}

/**
 * Cache key for one classification.
 *
 * `scope` is the operator the scan runs for. Verdicts are deliberately NOT
 * shared across tenants: a hit is visibly faster and unbilled, so a shared
 * cache would let one tenant test whether another recently sent a given text.
 * Within a tenant, retries and repeated content are what the cache is for.
 */
export function l3VerdictCacheKey(scope: string, identity: string, sampledContent: string): string {
  const digest = createHash('sha256')
    .update(`${scope}\u0000${identity}\u0000${sampledContent}`)
    .digest('hex');
  return `l3v:v1:${digest}`;
}

/** Serialise a verdict for the cache. Degraded results are never cached. */
export function encodeCachedVerdict(result: L3ClassificationResult): string | null {
  if (result.degraded || result.cached) return null;
  return JSON.stringify({ v: result.verdict, c: result.confidence });
}

/** Parse a cached verdict, refusing anything that is not exactly the shape we write. */
export function decodeCachedVerdict(raw: string | null, model: string, startedAt: number): L3ClassificationResult | null {
  if (!raw) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { return null; }
  if (!parsed || typeof parsed !== 'object') return null;
  const { v, c } = parsed as { v?: unknown; c?: unknown };
  if (v !== 'clean' && v !== 'suspicious' && v !== 'critical') return null;
  if (typeof c !== 'number' || !Number.isFinite(c) || c < 0 || c > 100) return null;
  return {
    verdict: v,
    confidence: c,
    reasoning: 'cached verdict',
    degraded: false,
    duration_ms: Date.now() - startedAt,
    model,
    cached: true,
  };
}

/**
 * A classifier that reuses an earlier verdict for identical content, for one
 * tenant. A cached verdict costs no call and no allowance; a cache failure is
 * only a miss. A classifier with no `cacheIdentity` is returned unchanged.
 */
export function withVerdictCache(inner: L3Classifier, cache: { store: L3VerdictCache; scope: string }): L3Classifier {
  const identity = inner.cacheIdentity;
  if (!identity) return inner;
  return {
    cacheIdentity: identity,
    async classify(content, options) {
      const startedAt = Date.now();
      const key = l3VerdictCacheKey(cache.scope, identity.identity, sampleForLlm(content));
      const hit = decodeCachedVerdict(await cache.store.get(key).catch(() => null), identity.model, startedAt);
      if (hit) return hit;
      const result = await inner.classify(content, options);
      if (result) {
        const encoded = encodeCachedVerdict(result);
        if (encoded) await cache.store.set(key, encoded, L3_VERDICT_CACHE_TTL_SECONDS).catch(() => undefined);
      }
      return result;
    },
  };
}

/**
 * The classifier each scan uses. The deployment's own source wins; STACK's
 * network classifier fills in on an install that chose it and has no source of
 * its own. A scan that asks to reuse verdicts gets the cache around whichever it
 * is, keyed to its operator.
 */
export function createL3ClassifierSource(deps: {
  source: L3ClassifierSource | null;
  network: L3Classifier | null;
  cache: L3VerdictCache;
}): L3ClassifierSource | null {
  if (!deps.source && !deps.network) return null;
  return (context) => {
    const inner = deps.source?.(context) ?? deps.network;
    if (!inner) return null;
    return context.operatorId && context.reuseVerdicts
      ? withVerdictCache(inner, { store: deps.cache, scope: context.operatorId })
      : inner;
  };
}
