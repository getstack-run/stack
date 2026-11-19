import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { flowSource } from '../routes/stage-flow/flow-source.js';
import { classifyOutboundFetches, STALE_MESSAGE, UNCLASSIFIED_MESSAGE, type PinTable } from './egress-mediation.checks.js';

/**
 * I11 — there is no second way out.
 *
 * Everything the epic built decides what a call may carry. None of it matters
 * for a call that does not pass through it. So the question this file asks is
 * not "is the wall correct" but "how many ways are there out of the building",
 * and it answers it by enumeration rather than by memory.
 *
 * Three properties, each of which has already failed at least once:
 *
 *   1. Every outbound `fetch` in server-side code is either GUARDED (the
 *      destination can be influenced by a caller, so `assertPublicUrl` runs on
 *      it) or PINNED (the host is a compile-time constant in that file). A new
 *      file that fetches somewhere and does neither fails here. Before this
 *      epic, `assertPublicUrl` had three call sites in the whole repo, and
 *      notification webhook dispatch and the OAuth token endpoint were not
 *      among them.
 *
 *   2. The LLM gateway runs the scope wall, and runs it before it decrypts a
 *      credential. It ran no constraint check at all until Shift 3, so a scope
 *      that was closed for /v1/proxy was open for /v1/llm.
 *
 *   3. The streaming output scan runs ahead of the bytes. It used to run after
 *      the stream closed, which made `stream: true` a way around a control the
 *      non-streaming path enforced.
 *
 * PINNED entries carry the literal they pin to and the test re-reads it from
 * the file, so the classification cannot quietly become false: delete the
 * constant and the claim about it fails with it.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..', '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf8');

/** The engine's server-side trees that can reach the network on someone's behalf. A deployment that extends the engine checks its own in its own tests. */
const OUTBOUND_ROOTS = [
  'packages/shared/src/llm',
  'packages/vault/src',
  'apps/api/src/routes',
  'apps/worker/src',
];

/**
 * Files whose destination is a compile-time constant, with the literal that
 * makes it so. A constant host cannot be steered by an injected agent, which
 * is the whole reason the guard exists.
 */
const PINNED: PinTable = {
  'packages/vault/src/services/openrouter-pricing.ts': 'https://openrouter.ai/api/v1/models',
  'packages/vault/src/services/resend-email-service.ts': 'https://api.resend.com/emails',
  'packages/shared/src/llm/openrouter-client.ts': 'https://openrouter.ai/api/v1/chat/completions',
  // The provider catalogue is the pin: LLM_PROVIDERS holds three literal URLs
  // and forwardStreaming/forward can only reach LLM_PROVIDERS[provider].url.
  'packages/vault/src/services/llm-gateway-service.ts': 'https://api.anthropic.com/v1/messages',
  // The OpenRouter passthrough: the caller names a path and a query below the API base and nothing else
  // (`request.ts` builds the URL from OPENROUTER_API_BASE and refuses a path that leaves it); the call refuses any
  // other host or scheme once more, and follows no redirect.
  'apps/api/src/routes/llm-gateway/openrouter/upstream.ts': "const OPENROUTER_HOST = 'openrouter.ai'",
};

describe('egress mediation', { timeout: 30_000 }, () => {
  it('classifies every outbound fetch as guarded or pinned', () => {
    const { unclassified, stale, dead } = classifyOutboundFetches({ repo: REPO, roots: OUTBOUND_ROOTS, pinned: PINNED, skipHosted: true });
    expect(unclassified, UNCLASSIFIED_MESSAGE).toEqual([]);
    expect(stale, STALE_MESSAGE).toEqual([]);
    expect(dead, 'PINNED entries for files that no longer make an outbound fetch').toEqual([]);
  });

  it('the LLM gateway runs the scope wall, before it decrypts a credential', () => {
    const src = flowSource('llm');
    const wall = src.indexOf('enforceScopeWall(');
    const credential = src.indexOf('retrieveCredentialByConnectionId(');
    expect(wall, '/v1/llm/* no longer runs the scope wall — its constraints are off').toBeGreaterThan(-1);
    expect(credential).toBeGreaterThan(-1);
    expect(
      wall < credential,
      'the scope wall runs after credential retrieval — a refused call has already had its ' +
        'credential decrypted',
    ).toBe(true);
  });

  it('the streaming output scan runs before the bytes are written', () => {
    const src = flowSource('llm');
    const scan = src.indexOf('scanOutput(');
    const emit = src.indexOf('emitStreamChunk(event.bytes)');
    expect(
      emit,
      'the streaming forward loop no longer writes event.bytes — if the shape changed, re-pin ' +
        'this ordering against whatever writes to the client now',
    ).toBeGreaterThan(-1);
    expect(src).toContain('else reply.raw.write(bytes)');
    expect(scan).toBeGreaterThan(-1);
    expect(
      scan < emit,
      'the output scan now runs after the client write. A warning about bytes that already left ' +
        'is a notice, not a control — and the non-streaming path redacts on the same verdict.',
    ).toBe(true);
  });

  it('the streaming forward does not tee the upstream', () => {
    // A tee is what made the old scan post-hoc: one branch was piped to the
    // client while the other was still being parsed, so the text was known only
    // after the bytes had gone. Reintroducing it silently undoes the fix.
    const src = read('packages/vault/src/services/llm-gateway-service.ts');
    expect(
      src.includes('.tee('),
      'forwardStreaming tees the upstream again — the caller cannot scan text it only learns ' +
        'about after the bytes have been forwarded',
    ).toBe(false);
  });
});
