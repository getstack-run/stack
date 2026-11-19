import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// `--control-ref <ref>` is the retry of an action the owner approved. api.ts takes it out of argv and every write of the
// run then carries X-Control-Ref; a run without it sends none. node:process is mocked so `exit` throws and stderr is read.

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

interface Sent {
  method: string;
  headers: Record<string, string>;
}

function stubFetch(): Sent[] {
  const sent: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_url: string, init: { method?: string; headers?: Record<string, string> }) => {
      sent.push({ method: init.method ?? 'GET', headers: init.headers ?? {} });
      return new Response('{}', { status: 200 });
    }),
  );
  return sent;
}

beforeEach(async () => {
  stderrChunks.length = 0;
  process.env['STACK_API_KEY'] = 'sk_live_test';
  (await import('./api.js')).setControlRef(undefined);
});

afterEach(() => {
  delete process.env['STACK_API_KEY'];
  vi.unstubAllGlobals();
});

describe('--control-ref', () => {
  it('is taken out of argv wherever it stands and sent as X-Control-Ref on a write', async () => {
    const { requestApi, takeControlRefFlag, currentControlRef } = await import('./api.js');
    const sent = stubFetch();
    const args = ['accounts', 'email', 'send', '--control-ref', 'cref_approved', '--to', 'ada@example.com'];
    takeControlRefFlag(args);
    expect(args).toEqual(['accounts', 'email', 'send', '--to', 'ada@example.com']);
    expect(currentControlRef()).toBe('cref_approved');

    await requestApi('POST', '/v1/accounts/acct_1/email/send', { body: { to: 'ada@example.com' } });
    expect(sent[0]?.headers['X-Control-Ref']).toBe('cref_approved');
    expect(sent[0]?.headers['Authorization']).toBe('Bearer sk_live_test');
  });

  it('is not sent on a read', async () => {
    const { requestApi, setControlRef } = await import('./api.js');
    const sent = stubFetch();
    setControlRef('cref_approved');
    await requestApi('GET', '/v1/accounts');
    expect(sent[0]?.headers['X-Control-Ref']).toBeUndefined();
  });

  it('sends nothing when the flag was not given', async () => {
    const { requestApi, takeControlRefFlag, currentControlRef } = await import('./api.js');
    const sent = stubFetch();
    const args = ['accounts', 'list'];
    takeControlRefFlag(args);
    expect(args).toEqual(['accounts', 'list']);
    expect(currentControlRef()).toBeUndefined();
    await requestApi('POST', '/v1/accounts/acct_1/email/send', { body: {} });
    expect(sent[0]?.headers['X-Control-Ref']).toBeUndefined();
  });

  it('refuses a flag with no ref', async () => {
    const { takeControlRefFlag } = await import('./api.js');
    expect(() => takeControlRefFlag(['accounts', 'list', '--control-ref'])).toThrow('__exit__:2');
    expect(stderrChunks.join('')).toContain('--control-ref needs the ref');
    expect(() => takeControlRefFlag(['accounts', '--control-ref', '--json'])).toThrow('__exit__:2');
  });
});
