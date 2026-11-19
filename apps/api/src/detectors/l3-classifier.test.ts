import { describe, expect, it, vi } from 'vitest';
import {
  L3_VERDICT_CACHE_TTL_SECONDS,
  createL3ClassifierSource,
  l3VerdictCacheKey,
  mergeVerdicts,
  shouldRunL3,
  withVerdictCache,
  type L3ClassificationResult,
  type L3Classifier,
  type L3VerdictCache,
} from './l3-classifier.js';
import { startPromptInjectionScan } from './prompt-injection.js';

type LlmClassificationResult = L3ClassificationResult;

// shouldRunL3 — heuristic gate

describe('shouldRunL3', () => {
  it('always skips when L1+L2 returned critical (verdict already)', () => {
    expect(shouldRunL3('a'.repeat(1000), 'critical')).toBe(false);
    expect(shouldRunL3('any content here at all', 'critical')).toBe(false);
  });

  it('always runs when L1+L2 returned warning (escalation)', () => {
    // Even very short bodies escalate when L1+L2 was uncertain.
    expect(shouldRunL3('hi', 'warning')).toBe(true);
    expect(shouldRunL3('', 'warning')).toBe(true);
  });

  describe('clean L1+L2 verdict', () => {
    it('skips bodies under the size floor', () => {
      expect(shouldRunL3('hi', 'clean')).toBe(false);
      expect(shouldRunL3('a'.repeat(59), 'clean')).toBe(false);
    });

    it('runs on bodies at or above the size floor', () => {
      expect(shouldRunL3('a'.repeat(60), 'clean')).toBe(true);
      expect(shouldRunL3('a'.repeat(200), 'clean')).toBe(true);
      expect(shouldRunL3('a'.repeat(5000), 'clean')).toBe(true);
    });
  });
});

// mergeVerdicts — final-decision logic

function fakeLlm(overrides: Partial<LlmClassificationResult>): LlmClassificationResult {
  return {
    verdict: 'clean',
    confidence: 0,
    reasoning: '',
    degraded: false,
    duration_ms: 100,
    model: 'test-model',
    ...overrides,
  };
}

describe('mergeVerdicts', () => {
  it('keeps L1+L2 verdict when L3 degraded', () => {
    const m1 = mergeVerdicts('clean', fakeLlm({ degraded: true, reasoning: 'timeout' }));
    expect(m1.verdict).toBe('clean');
    expect(m1.reason).toBe('l3_degraded');

    const m2 = mergeVerdicts('warning', fakeLlm({ degraded: true }));
    expect(m2.verdict).toBe('warning');
    expect(m2.reason).toBe('l3_degraded');

    const m3 = mergeVerdicts('critical', fakeLlm({ degraded: true }));
    expect(m3.verdict).toBe('critical');
  });

  it('upgrades to critical when L3 says critical', () => {
    expect(mergeVerdicts('clean', fakeLlm({ verdict: 'critical', confidence: 95 })).verdict).toBe('critical');
    expect(mergeVerdicts('warning', fakeLlm({ verdict: 'critical', confidence: 85 })).verdict).toBe('critical');
    expect(mergeVerdicts('critical', fakeLlm({ verdict: 'critical', confidence: 90 })).verdict).toBe('critical');
  });

  it('escalates suspicious × warning to critical (compound signal)', () => {
    const m = mergeVerdicts('warning', fakeLlm({ verdict: 'suspicious', confidence: 50 }));
    expect(m.verdict).toBe('critical');
    expect(m.reason).toBe('l3_suspicious_x_l2_warning');
  });

  it('promotes clean × suspicious to warning (LLM saw something L1+L2 missed)', () => {
    const m = mergeVerdicts('clean', fakeLlm({ verdict: 'suspicious', confidence: 45 }));
    expect(m.verdict).toBe('warning');
    expect(m.reason).toBe('l3_suspicious');
  });

  it('keeps L1+L2 verdict when L3 confirms clean', () => {
    expect(mergeVerdicts('clean', fakeLlm({ verdict: 'clean', confidence: 5 })).verdict).toBe('clean');
    expect(mergeVerdicts('warning', fakeLlm({ verdict: 'clean', confidence: 10 })).verdict).toBe('warning');
  });
});

// The engine's scan, with a classifier of its own

const BODY = 'Weekly report attached, numbers are up 4% on last month, see the appendix.';

function classifier(result: L3ClassificationResult | null): L3Classifier & { calls: Array<{ content: string; signal?: AbortSignal }> } {
  const calls: Array<{ content: string; signal?: AbortSignal }> = [];
  return {
    calls,
    async classify(content, options) {
      calls.push({ content, ...(options?.signal ? { signal: options.signal } : {}) });
      return result;
    },
  };
}

function verdict(overrides: Partial<L3ClassificationResult> = {}): L3ClassificationResult {
  return { verdict: 'clean', confidence: 5, reasoning: '', degraded: false, duration_ms: 3, model: 'm', ...overrides };
}

describe('the scan with a third layer', () => {
  it('runs no third layer without a classifier', () => {
    const handle = startPromptInjectionScan(BODY, 'body', { l3: null });
    expect(handle.l3).toBeNull();
    expect(handle.l1l2.verdict).toBe('clean');
  });

  it('hands the classifier the sampled content and merges its verdict with the pattern layers', async () => {
    const third = classifier(verdict({ verdict: 'suspicious', confidence: 55 }));
    const handle = startPromptInjectionScan(BODY, 'body', { l3: third });
    const full = await handle.l3!;
    expect(full.verdict).toBe('warning');
    expect(full.llm?.verdict).toBe('suspicious');
    expect(third.calls).toHaveLength(1);
    expect(third.calls[0]!.content).toBe(BODY);
    expect(third.calls[0]!.signal).toBeDefined();
  });

  it('never sends more than the head and the tail of a large body', async () => {
    const third = classifier(verdict());
    await startPromptInjectionScan('a'.repeat(50_000), 'body', { l3: third }).l3!;
    expect(third.calls[0]!.content.length).toBeLessThan(5000);
    expect(third.calls[0]!.content).toContain('truncated middle');
  });

  it('keeps the pattern layers verdict when the classifier declines to run', async () => {
    const handle = startPromptInjectionScan(BODY, 'body', { l3: classifier(null) });
    const result = await handle.l3!;
    expect(result).toEqual(handle.l1l2);
  });

  it('keeps the pattern layers verdict and reports it when the classifier degraded', async () => {
    const result = await startPromptInjectionScan(BODY, 'body', {
      l3: classifier(verdict({ degraded: true, reasoning: 'degraded: timeout' })),
    }).l3!;
    expect(result.verdict).toBe('clean');
    expect(result.llm?.degraded).toBe(true);
  });

  it('skips the third layer for short bodies, for eval traffic and when the operator turned detection off', () => {
    const third = classifier(verdict());
    expect(startPromptInjectionScan({ text: 'hi' }, 'body', { l3: third }).l3).toBeNull();
    expect(startPromptInjectionScan(BODY, 'body', { l3: third, skipL3: true }).l3).toBeNull();
    expect(third.calls).toHaveLength(0);
  });

  it('abort cancels the classifier call', async () => {
    let seen: AbortSignal | undefined;
    const hanging: L3Classifier = {
      classify: (_content, options) => new Promise((resolve) => {
        seen = options?.signal;
        options?.signal?.addEventListener('abort', () => resolve(verdict({ degraded: true, reasoning: 'degraded: l3_aborted' })), { once: true });
      }),
    };
    const handle = startPromptInjectionScan(BODY, 'body', { l3: hanging });
    await vi.waitFor(() => expect(seen).toBeDefined());
    handle.abort();
    const result = await handle.l3!;
    expect(seen!.aborted).toBe(true);
    expect(result.llm?.degraded).toBe(true);
  });

  it('an abandoned handle whose classifier throws never surfaces an unhandled rejection', async () => {
    const throwing: L3Classifier = { classify: async () => { throw new Error('classifier unavailable'); } };
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    try {
      startPromptInjectionScan(BODY, 'body', { l3: throwing });
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(unhandled).not.toHaveBeenCalled();
    } finally {
      process.off('unhandledRejection', unhandled);
    }
  });
});

// The verdict cache around a classifier

function memoryCache() {
  const store = new Map<string, string>();
  const cache = {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    set: vi.fn(async (key: string, value: string) => { store.set(key, value); }),
  } satisfies L3VerdictCache;
  return { store, cache };
}

function cacheable(result: L3ClassificationResult | null) {
  const inner = classifier(result);
  return Object.assign(inner, { cacheIdentity: { identity: 'model-1', model: 'model-1' } });
}

describe('the verdict cache', () => {
  it('reuses a verdict for identical content of one operator: no second call', async () => {
    const inner = cacheable(verdict({ verdict: 'suspicious', confidence: 55 }));
    const { cache } = memoryCache();
    const first = await withVerdictCache(inner, { store: cache, scope: 'op_a' }).classify(BODY);
    const second = await withVerdictCache(inner, { store: cache, scope: 'op_a' }).classify(BODY);
    expect(inner.calls).toHaveLength(1);
    expect(first?.cached).not.toBe(true);
    expect(second).toMatchObject({ cached: true, verdict: 'suspicious', confidence: 55, model: 'model-1' });
  });

  it('stores only verdict and confidence under a hashed key: never content or reasoning', async () => {
    const { store, cache } = memoryCache();
    await withVerdictCache(cacheable(verdict({ reasoning: `quote: ${BODY}` })), { store: cache, scope: 'op_a' }).classify(BODY);
    expect(store.size).toBe(1);
    const [key, value] = [...store.entries()][0]!;
    expect(key).toMatch(/^l3v:v1:[0-9a-f]{64}$/);
    expect(JSON.parse(value)).toEqual({ v: 'clean', c: 5 });
    expect(key + value).not.toContain('Weekly');
    expect(cache.set).toHaveBeenCalledWith(key, value, L3_VERDICT_CACHE_TTL_SECONDS);
  });

  it('never shares a verdict across operators or across classifier configurations', async () => {
    const inner = cacheable(verdict());
    const { cache } = memoryCache();
    await withVerdictCache(inner, { store: cache, scope: 'op_a' }).classify(BODY);
    await withVerdictCache(inner, { store: cache, scope: 'op_b' }).classify(BODY);
    expect(inner.calls).toHaveLength(2);
    expect(l3VerdictCacheKey('op_a', 'm', 'x')).not.toBe(l3VerdictCacheKey('op_b', 'm', 'x'));
    expect(l3VerdictCacheKey('op_a', 'm1', 'x')).not.toBe(l3VerdictCacheKey('op_a', 'm2', 'x'));
  });

  it('never caches a degraded result or a declined call', async () => {
    const { store, cache } = memoryCache();
    await withVerdictCache(cacheable(verdict({ degraded: true })), { store: cache, scope: 'op_a' }).classify(BODY);
    await withVerdictCache(cacheable(null), { store: cache, scope: 'op_a' }).classify(BODY);
    expect(store.size).toBe(0);
  });

  it('ignores a malformed or tampered entry and classifies for real', async () => {
    const inner = cacheable(verdict({ verdict: 'critical', confidence: 95 }));
    const { store, cache } = memoryCache();
    store.set(l3VerdictCacheKey('op_a', 'model-1', BODY), JSON.stringify({ v: 'clean', c: 'zero' }));
    const result = await withVerdictCache(inner, { store: cache, scope: 'op_a' }).classify(BODY);
    expect(inner.calls).toHaveLength(1);
    expect(result?.verdict).toBe('critical');
  });

  it('a cache outage is only a miss', async () => {
    const inner = cacheable(verdict());
    const down: L3VerdictCache = {
      get: async () => { throw new Error('redis down'); },
      set: async () => { throw new Error('redis down'); },
    };
    const result = await withVerdictCache(inner, { store: down, scope: 'op_a' }).classify(BODY);
    expect(result?.degraded).toBe(false);
  });

  it('leaves a classifier with no identity uncached', () => {
    const inner = classifier(verdict());
    const { cache } = memoryCache();
    expect(withVerdictCache(inner, { store: cache, scope: 'op_a' })).toBe(inner);
  });
});

describe('the classifier of a scan', () => {
  const { cache } = memoryCache();

  it('is none without a deployment classifier or a network one', () => {
    expect(createL3ClassifierSource({ source: null, network: null, cache })).toBeNull();
  });

  it('prefers the deployment classifier and falls back to the network one', () => {
    const own = classifier(verdict());
    const network = classifier(verdict());
    expect(createL3ClassifierSource({ source: () => own, network, cache })!({})).toBe(own);
    expect(createL3ClassifierSource({ source: () => null, network, cache })!({})).toBe(network);
    expect(createL3ClassifierSource({ source: null, network, cache })!({})).toBe(network);
  });

  it('puts the cache around the classifier only for a scan of one operator that asks to reuse verdicts', () => {
    const own = cacheable(verdict());
    const source = createL3ClassifierSource({ source: () => own, network: null, cache })!;
    expect(source({ operatorId: 'op_a' })).toBe(own);
    expect(source({ reuseVerdicts: true })).toBe(own);
    expect(source({ operatorId: 'op_a', reuseVerdicts: true })).not.toBe(own);
  });
});

