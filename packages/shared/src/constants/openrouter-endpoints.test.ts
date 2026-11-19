import { describe, expect, it } from 'vitest';
import { OPENROUTER_ENDPOINTS, matchOpenRouterEndpoint, openRouterPathProblem } from './openrouter-endpoints.js';

describe('the OpenRouter endpoint table', () => {
  it('lists each method and path once', () => {
    const keys = OPENROUTER_ENDPOINTS.map((e) => `${e.method} ${e.path}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('makes only POSTs inference, only GETs discovery or job reads, and nothing else open to an account', () => {
    for (const endpoint of OPENROUTER_ENDPOINTS) {
      if (endpoint.kind === 'inference') expect(endpoint.method).toBe('POST');
      if (endpoint.kind === 'discovery' || endpoint.kind === 'job') expect(endpoint.method).toBe('GET');
    }
  });

  it('puts every endpoint that makes something on the inference list, and nothing of the OpenRouter account there', () => {
    const inference = OPENROUTER_ENDPOINTS.filter((e) => e.kind === 'inference').map((e) => e.path).sort();
    expect(inference).toEqual([
      '/api/alpha/decisions', '/audio/speech', '/audio/transcriptions', '/chat/completions', '/completions', '/cursor',
      '/embeddings', '/images', '/messages', '/rerank', '/responses', '/systemone', '/videos',
    ]);
  });

  it('keeps the OpenRouter account (keys, credits, files, batches, stored generations, presets) off the open kinds', () => {
    for (const path of ['/key', '/keys', '/credits', '/activity', '/files', '/batches', '/generation', '/presets', '/workspaces', '/guardrails', '/byok', '/models/user']) {
      expect(OPENROUTER_ENDPOINTS.filter((e) => e.path === path).every((e) => e.kind === 'account'), path).toBe(true);
    }
  });
});

describe('matching a call to an endpoint', () => {
  it('matches a fixed path and reads the segments that vary', () => {
    expect(matchOpenRouterEndpoint('POST', '/chat/completions')?.endpoint.kind).toBe('inference');
    expect(matchOpenRouterEndpoint('GET', 'model/openai/gpt-4o')).toMatchObject({ params: { author: 'openai', slug: 'gpt-4o' } });
    expect(matchOpenRouterEndpoint('GET', '/models/openai/gpt-4o/endpoints')?.endpoint.path).toBe('/models/{author}/{slug}/endpoints');
  });

  it('prefers the fixed segment over the one that varies', () => {
    expect(matchOpenRouterEndpoint('GET', '/videos/models')?.endpoint.kind).toBe('discovery');
    expect(matchOpenRouterEndpoint('GET', '/videos/gen-vid-1-abc')).toMatchObject({ endpoint: { kind: 'job' }, params: { jobId: 'gen-vid-1-abc' } });
    expect(matchOpenRouterEndpoint('GET', '/models/count')?.endpoint.path).toBe('/models/count');
    expect(matchOpenRouterEndpoint('GET', '/guardrails/assignments/keys')?.endpoint.path).toBe('/guardrails/assignments/keys');
  });

  it('knows nothing of a method or a path the table does not list', () => {
    expect(matchOpenRouterEndpoint('GET', '/chat/completions')).toBeNull();
    expect(matchOpenRouterEndpoint('POST', '/models')).toBeNull();
    expect(matchOpenRouterEndpoint('GET', '/something/new')).toBeNull();
  });
});

describe('the path below the API base', () => {
  it('lets through the paths OpenRouter uses', () => {
    for (const path of ['chat/completions', 'models/meta-llama/llama-3.1-8b-instruct:free/endpoints', 'videos/gen-vid-1700000000-abcDEF', 'model/~anthropic/claude-latest']) {
      expect(openRouterPathProblem(path), path).toBeNull();
    }
  });

  it('refuses a path that could leave the base, hide a segment or smuggle an encoding', () => {
    for (const path of ['', '../keys', 'models/../key', './models', 'models//count', 'models/%2e%2e/key', 'a\\b', 'models/ count', 'models?x=1', 'a;b', `${'a/'.repeat(13)}a`]) {
      expect(openRouterPathProblem(path), path).not.toBeNull();
    }
  });
});
