import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';

// A name can be used again once the agent that held it is deleted, so `GET /v1/agents` can list two agents with one name:
// the revoked one (kept in the history) and the live one. Every place the CLI turns a name into an agent has to mean the
// live one, whichever the list puts first.

vi.mock('node:process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:process')>();
  return {
    ...actual,
    env: actual.env,
    exit: (code?: number) => {
      throw new Error(`__exit__:${code ?? 0}`);
    },
    stderr: { ...actual.stderr, write: () => true },
  };
});

const REVOKED = { id: 'agt_old_tomiboss', name: 'tomiboss', status: 'revoked' };
const LIVE = { id: 'agt_new_tomiboss', name: 'tomiboss', status: 'active' };

describe('finding an agent by name', () => {
  it('finds the live agent when a revoked one holds the same name, in either order', async () => {
    const { findAgentByName } = await import('./agent-lookup.js');
    expect(findAgentByName([REVOKED, LIVE], 'tomiboss')).toBe(LIVE);
    expect(findAgentByName([LIVE, REVOKED], 'tomiboss')).toBe(LIVE);
  });

  it('finds nothing when the only agent of that name is revoked', async () => {
    const { findAgentByName } = await import('./agent-lookup.js');
    expect(findAgentByName([REVOKED], 'tomiboss')).toBeUndefined();
  });

  it('still finds a suspended or blocked agent, and one from a server that reports no status', async () => {
    const { findAgentByName } = await import('./agent-lookup.js');
    expect(findAgentByName([{ id: 'agt_s', name: 'paused', status: 'suspended' }], 'paused')?.id).toBe('agt_s');
    expect(findAgentByName([{ id: 'agt_b', name: 'held', status: 'blocked' }], 'held')?.id).toBe('agt_b');
    expect(findAgentByName([{ id: 'agt_n', name: 'plain' }], 'plain')?.id).toBe('agt_n');
  });
});

describe('resolving a name to an agent id', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('resolves to the live agent when the list puts the revoked one first', async () => {
    vi.stubEnv('STACK_API_KEY', 'sk_live_test_not_real');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([REVOKED, LIVE]), { status: 200, headers: { 'content-type': 'application/json' } })));
    const { resolveAgentId } = await import('./api.js');
    await expect(resolveAgentId('tomiboss')).resolves.toBe('agt_new_tomiboss');
  });

  it('refuses a name only a revoked agent holds', async () => {
    vi.stubEnv('STACK_API_KEY', 'sk_live_test_not_real');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([REVOKED]), { status: 200, headers: { 'content-type': 'application/json' } })));
    const { resolveAgentId } = await import('./api.js');
    await expect(resolveAgentId('tomiboss')).rejects.toThrow('__exit__:1');
  });
});

describe('every lookup of an agent by name goes through the one rule', () => {
  it('has no list search by name left in the CLI beside the helper', () => {
    const dir = fileURLToPath(new URL('.', import.meta.url));
    const offenders: string[] = [];
    for (const file of readdirSync(dir)) {
      if (!file.endsWith('.ts') || file.endsWith('.test.ts') || file === 'agent-lookup.ts') continue;
      const source = readFileSync(join(dir, file), 'utf8');
      if (/\.find\(\s*\(?\s*\w+\s*\)?\s*=>\s*\w+\.name\s*===/.test(source)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });
});
