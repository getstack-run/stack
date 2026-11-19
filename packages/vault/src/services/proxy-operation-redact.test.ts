import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalize, evidenceUrl } from '@stack/shared';
import { redactQueuedPostResponseContexts } from './proxy-operation/post-response.js';
import { postResponseAad } from './proxy-operation/envelope.js';
import type { ProxyOperationDeps, ProxyPostResponseContext } from './proxy-operation/types.js';

// Work queued before the signed records stopped carrying a query string holds the full URL in its encrypted context. The
// one-off pass rewrites it to the evidence form, with the parameters hash taken over the same form.

const QUERY_SECRET = ['q', 'secret', 'value', '5521'].join('-');
const sha = (text: string) => createHash('sha256').update(text).digest('hex');

function contextOf(url: string, body: unknown = { text: 'hello' }): ProxyPostResponseContext {
  return {
    version: 1,
    audit: {},
    action: {
      service: 'telegram',
      method: 'POST',
      originalUrl: url,
      originalBody: body ?? null,
      parametersHash: sha(JSON.stringify({ service: 'telegram', method: 'POST', url, body })),
    },
  } as unknown as ProxyPostResponseContext;
}

/** A store of queued contexts, sealed with a reversible stand-in that checks the context it is opened under. */
function fixture(contexts: Array<{ id: string; context: ProxyPostResponseContext }>) {
  const rows = new Map(contexts.map(({ id, context }) => [id, {
    id, operator_id: 'op_one', post_response_context_encrypted: `sealed:${JSON.stringify(postResponseAad('op_one', id))}:${canonicalize(context)}`,
  }]));
  const kms = {
    encrypt: async (plaintext: string, aad: Record<string, string>) => ({ ciphertext: `sealed:${JSON.stringify(aad)}:${plaintext}`, keyRef: 'key_new' }),
    decrypt: async (ciphertext: string, aad: Record<string, string>) => {
      const prefix = `sealed:${JSON.stringify(aad)}:`;
      if (!ciphertext.startsWith(prefix)) throw new Error('wrong context');
      return ciphertext.slice(prefix.length);
    },
  };
  const repository = {
    listQueuedPostResponseContexts: async (input: { afterId?: string; limit: number }) =>
      [...rows.values()].filter((r) => !input.afterId || r.id > input.afterId).sort((a, b) => a.id.localeCompare(b.id)).slice(0, input.limit),
    replacePostResponseContext: async (input: { operationId: string; expectedCiphertext: string; ciphertext: string }) => {
      const row = rows.get(input.operationId);
      if (!row || row.post_response_context_encrypted !== input.expectedCiphertext) return false;
      row.post_response_context_encrypted = input.ciphertext;
      return true;
    },
  };
  const deps = { repository, kms, holds: {} } as unknown as ProxyOperationDeps;
  const read = async (id: string) => JSON.parse(await kms.decrypt(rows.get(id)!.post_response_context_encrypted, postResponseAad('op_one', id))) as ProxyPostResponseContext;
  return { deps, rows, read };
}

describe('queued post-response contexts without their query strings', () => {
  it('rewrites a stored URL to its evidence form and the parameters hash with it', async () => {
    const url = `https://api.telegram.org/{{bot_token}}/sendMessage?chat_id=${QUERY_SECRET}`;
    const f = fixture([{ id: 'pop_a', context: contextOf(url) }]);
    expect(await redactQueuedPostResponseContexts(f.deps)).toEqual({ scanned: 1, redacted: 1, unreadable: 0 });
    const after = await f.read('pop_a');
    expect(JSON.stringify(after)).not.toContain(QUERY_SECRET);
    expect(after.action.originalUrl).toBe(evidenceUrl(url));
    expect(after.action.parametersHash).toBe(sha(JSON.stringify({ service: 'telegram', method: 'POST', url: evidenceUrl(url), body: { text: 'hello' } })));
  });

  it('is idempotent: a second pass finds nothing to change', async () => {
    const f = fixture([{ id: 'pop_a', context: contextOf(`https://api.example.test/v1/send?to=${QUERY_SECRET}`) }]);
    await redactQueuedPostResponseContexts(f.deps);
    expect(await redactQueuedPostResponseContexts(f.deps)).toEqual({ scanned: 1, redacted: 0, unreadable: 0 });
  });

  it('leaves a context already in evidence form, and counts one it cannot read without stopping', async () => {
    const f = fixture([
      { id: 'pop_a', context: contextOf('https://api.example.test/v1/send') },
      { id: 'pop_b', context: contextOf(`https://api.example.test/v1/send?to=${QUERY_SECRET}`) },
    ]);
    f.rows.get('pop_a')!.post_response_context_encrypted = 'not sealed under this context';
    expect(await redactQueuedPostResponseContexts(f.deps)).toEqual({ scanned: 2, redacted: 1, unreadable: 1 });
  });

  it('does not write over a context that changed while it was being read', async () => {
    const f = fixture([{ id: 'pop_a', context: contextOf(`https://api.example.test/v1/send?to=${QUERY_SECRET}`) }]);
    const original = f.deps.repository.replacePostResponseContext.bind(f.deps.repository);
    f.deps.repository.replacePostResponseContext = (async (input: never) => {
      f.rows.get('pop_a')!.post_response_context_encrypted = 'claimed and rewritten elsewhere';
      return original(input);
    }) as never;
    expect(await redactQueuedPostResponseContexts(f.deps)).toMatchObject({ redacted: 0 });
    expect(f.rows.get('pop_a')!.post_response_context_encrypted).toBe('claimed and rewritten elsewhere');
  });

  it('works through more rows than one batch', async () => {
    const f = fixture(Array.from({ length: 7 }, (_, i) => ({ id: `pop_${i}`, context: contextOf(`https://api.example.test/v1/send?to=${QUERY_SECRET}${i}`) })));
    expect(await redactQueuedPostResponseContexts(f.deps, { batch: 3 })).toEqual({ scanned: 7, redacted: 7, unreadable: 0 });
  });
});
