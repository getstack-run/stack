import { describe, it, expect } from 'vitest';
import {
  INTENT_REGISTRY,
  expandIntents,
  listIntents,
  UnknownIntentError,
  InvalidIntentParamsError,
} from './index.js';

describe('intent registry', () => {
  it('registry is a non-trivial, stable catalog', () => {
    // Library intentionally large. Guard against accidental regressions
    // (mass deletion, broken imports) with a floor rather than an exact
    // count so normal growth doesn't break CI.
    expect(INTENT_REGISTRY.size).toBeGreaterThanOrEqual(1000);
    expect(listIntents().length).toBe(INTENT_REGISTRY.size);
  });

  it('every intent name is namespaced (provider.verb) and unique', () => {
    const names = new Set<string>();
    for (const intent of listIntents()) {
      // provider and verb both start with a letter, allow digits/underscore
      // after (e.g., aws_s3, new_relic, ms_teams, chat_completion_v2).
      expect(intent.name).toMatch(/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/);
      expect(names.has(intent.name)).toBe(false);
      names.add(intent.name);
    }
  });

  it('every intent has a meaningful description', () => {
    for (const intent of listIntents()) {
      expect(intent.description.length).toBeGreaterThan(10);
    }
  });

  it('covers the core provider set plus extended catalog', () => {
    const providers = new Set(listIntents().map((i) => i.name.split('.')[0]));
    // v1 core - always present.
    for (const p of [
      'slack', 'github', 'notion', 'gmail', 'google_drive', 'linear',
      'jira', 'hubspot', 'stripe', 'openai', 'supabase', 'custom',
    ]) {
      expect(providers).toContain(p);
    }
    // Extended catalog floor - we ship many more than the v1 12.
    expect(providers.size).toBeGreaterThanOrEqual(80);
  });
});

describe('expandIntents: slack.post_to_channel', () => {
  it('expands single channel to eq', () => {
    const out = expandIntents([
      { name: 'slack.post_to_channel', params: { channel: 'C0123' } },
    ]);
    expect(out).toEqual([
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/chat.postMessage' },
      { path: 'body.channel', op: 'eq', value: 'C0123' },
    ]);
  });

  it('expands multi-channel to in', () => {
    const out = expandIntents([
      { name: 'slack.post_to_channel', params: { channel: ['C0123', 'C0456'] } },
    ]);
    expect(out[2]).toEqual({
      path: 'body.channel',
      op: 'in',
      value: ['C0123', 'C0456'],
    });
  });
});

describe('expandIntents: github.create_issue', () => {
  it('pins method + repo pathname', () => {
    const out = expandIntents([
      { name: 'github.create_issue', params: { repo: 'acme/support-bot' } },
    ]);
    expect(out).toContainEqual({
      path: 'url.pathname',
      op: 'eq',
      value: '/repos/acme/support-bot/issues',
    });
    expect(out).toContainEqual({ path: 'method', op: 'eq', value: 'POST' });
  });

  it('uses regex alternation for multiple repos', () => {
    const out = expandIntents([
      {
        name: 'github.create_issue',
        params: { repo: ['acme/foo', 'acme/bar'] },
      },
    ]);
    const path = out.find((c) => c.path === 'url.pathname');
    expect(path?.op).toBe('matches');
    expect(String(path?.value)).toContain('acme/foo');
    expect(String(path?.value)).toContain('acme/bar');
  });
});

describe('expandIntents: openai.chat_completion', () => {
  it('binds body.model to allowlist', () => {
    const out = expandIntents([
      {
        name: 'openai.chat_completion',
        params: { model: ['gpt-4o', 'gpt-4o-mini'] },
      },
    ]);
    const modelC = out.find((c) => c.path === 'body.model');
    expect(modelC?.op).toBe('in');
    expect(modelC?.value).toEqual(['gpt-4o', 'gpt-4o-mini']);
  });
});

describe('expandIntents: custom intents', () => {
  it('custom.host_allowlist lowercases hosts', () => {
    const out = expandIntents([
      { name: 'custom.host_allowlist', params: { hosts: ['API.Example.COM'] } },
    ]);
    expect(out[0]).toEqual({
      path: 'url.host',
      op: 'in',
      value: ['api.example.com'],
    });
  });

  it('custom.read_only pins to GET + HEAD', () => {
    const out = expandIntents([{ name: 'custom.read_only', params: {} }]);
    expect(out[0]).toEqual({ path: 'method', op: 'in', value: ['GET', 'HEAD'] });
  });
});

describe('expandIntents: error cases', () => {
  it('throws UnknownIntentError on unknown name', () => {
    expect(() =>
      expandIntents([{ name: 'nonexistent.foo', params: {} }]),
    ).toThrow(UnknownIntentError);
  });

  it('throws InvalidIntentParamsError on bad params', () => {
    expect(() =>
      expandIntents([
        // slack.post_to_channel requires `channel` — missing here.
        { name: 'slack.post_to_channel', params: {} },
      ]),
    ).toThrow(InvalidIntentParamsError);
  });

  it('validates github repo format', () => {
    expect(() =>
      expandIntents([
        // "invalid" is not owner/repo shape.
        { name: 'github.create_issue', params: { repo: 'invalid' } },
      ]),
    ).toThrow(InvalidIntentParamsError);
  });
});

describe('expandIntents: composition', () => {
  it('concatenates multiple intents (AND semantics at proxy)', () => {
    const out = expandIntents([
      { name: 'custom.host_allowlist', params: { hosts: ['slack.com'] } },
      { name: 'custom.read_only', params: {} },
    ]);
    expect(out).toHaveLength(2);
    expect(out.map((c) => c.path)).toEqual(['url.host', 'method']);
  });
});
