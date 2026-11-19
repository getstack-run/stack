import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// a 403 on a write verb is easy to misread as "the CLI is broken."
// api() prints a read-only-token hint on 403. This test drives that path.
//
// api.ts does `import { env, stderr, exit } from 'node:process'`. We mock
// node:process so `exit` throws (instead of killing the vitest worker) and
// `stderr.write` is captured. `env` is passed through to the real process.env
// so STACK_API_KEY short-circuits getAccessToken() (auth.ts returns the key
// verbatim — no refresh-token file dance).

const stderrChunks: string[] = [];

vi.mock('node:process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:process')>();
  return {
    ...actual,
    env: actual.env,
    exit: (code?: number) => {
      throw new Error(`__exit__:${code ?? 0}`);
    },
    stderr: {
      ...actual.stderr,
      write: (chunk: string | Uint8Array): boolean => {
        stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
        return true;
      },
    },
  };
});

beforeEach(() => {
  stderrChunks.length = 0;
  process.env['STACK_API_KEY'] = 'sk_live_test_readonly';
});

afterEach(() => {
  delete process.env['STACK_API_KEY'];
  vi.unstubAllGlobals();
});

describe('api() 403 handling', () => {
  it('prints a read-only-token hint on 403 and exits 1', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: 'forbidden', message: 'nope' } }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );

    const { api } = await import('./api.js');

    await expect(api('POST', '/v1/passports/issue', { body: { agent_id: 'agt_x' } })).rejects.toThrow(
      '__exit__:1',
    );

    const out = stderrChunks.join('');
    // The original error line is preserved...
    expect(out).toContain('error: API 403 POST /v1/passports/issue');
    // ...and the new guardrail hint is appended.
    expect(out.toLowerCase()).toContain('read-only');
    expect(out).toContain('auth login');
    expect(out).toContain('STACK_OAUTH_SCOPE');
    // Never leak the token in the hint.
    expect(out).not.toContain('sk_live_test_readonly');
  });

  it('says the team role cannot make the change on a role refusal, and gives no scope advice', async () => {
    for (const role of ['standard', 'admin']) {
      stderrChunks.length = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn(async () =>
          new Response(JSON.stringify({ error: { code: 'FORBIDDEN', message: `This action requires ${role} access or higher` } }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
      );
      const { api } = await import('./api.js');
      await expect(api('POST', '/v1/missions', { body: {} })).rejects.toThrow('__exit__:1');
      const out = stderrChunks.join('');
      expect(out).toContain('error: API 403 POST /v1/missions');
      expect(out).toContain(`This action requires ${role} access or higher`);
      expect(out).toContain('hint: your team role cannot make this change.');
      expect(out).not.toContain('STACK_OAUTH_SCOPE');
      expect(out).not.toContain('auth login');
      expect(out).not.toContain('may be read-only');
    }
  });

  it('does NOT print the read-only hint on a non-403 error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: 'not_found', message: 'gone' } }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );

    const { api } = await import('./api.js');

    await expect(api('GET', '/v1/agents/agt_missing')).rejects.toThrow('__exit__:1');

    const out = stderrChunks.join('');
    expect(out).toContain('error: API 404');
    expect(out.toLowerCase()).not.toContain('read-only');
  });

  it('lists the connections an ambiguous call could have named', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: 'CONNECTION_AMBIGUOUS', message: 'acme has several connections. Pass connection.', details: { connections: [{ id: 'scon_a', name: 'Work' }, { id: 'scon_b', name: 'Personal' }] } } }), {
          status: 409,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    const { api } = await import('./api.js');
    await expect(api('POST', '/v1/proxy', { body: {} })).rejects.toThrow('__exit__:1');
    const out = stderrChunks.join('');
    expect(out).toContain('Work (scon_a)');
    expect(out).toContain('Personal (scon_b)');
    expect(out).toContain('--connection');
  });

  it('does not hide a non-2xx response when expectEmpty is true', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: 'not_found', message: 'gone' } }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );

    const { api } = await import('./api.js');

    await expect(
      api('DELETE', '/v1/services/svc_missing/disconnect', { expectEmpty: true }),
    ).rejects.toThrow('__exit__:1');
    expect(stderrChunks.join('')).toContain('error: API 404');
  });
});

describe('a controls feature without controls', () => {
  it("prints the API's CONTROLS_REQUIRED message for a read of the record, and no read-only hint", async () => {
    const message = 'Reading the record needs controls. STACK keeps the record either way.';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: 'CONTROLS_REQUIRED', message, details: { feature: 'record' } } }), {
          status: 402,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    const { api } = await import('./api.js');
    await expect(api('GET', '/v1/audit')).rejects.toThrow('__exit__:1');
    const out = stderrChunks.join('');
    // Every API error prints its code before its message.
    expect(out).toContain(`error: API 402 GET /v1/audit: CONTROLS_REQUIRED: ${message}`);
    expect(out.toLowerCase()).not.toContain('read-only');
  });
});
