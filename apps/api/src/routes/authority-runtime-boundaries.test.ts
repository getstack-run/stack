import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { flowSource } from './stage-flow/flow-source.js';

function source(name: string): string {
  // The LLM gateway and proxy handlers are composed from stage modules; read them in execution order.
  if (name === 'llm') return flowSource('llm');
  if (name === 'proxy') return flowSource('proxy');
  return readFileSync(new URL(`./${name}.ts`, import.meta.url), 'utf8');
}

/** The routes that call the shared runtime authority chokepoint. */
const BOUNDARY_ROUTES = [
  'proxy',
  'llm',
  'a2a',
];

describe('authority runtime boundary wiring', () => {
  for (const route of BOUNDARY_ROUTES) {
    it(`${route} delegates to the shared runtime authority chokepoint`, () => {
      const text = source(route);
      expect(text).toContain('enforceRuntimeAuthority(services.authority');
      expect(text).toContain('runtimeAuthorityRequestIdFromHeaders(request.headers)');
      expect(text).toContain('markRuntimeAuthorityDispatched(');
      expect(text).toContain('completeRuntimeAuthorityUse(');
      expect(text).not.toMatch(/request\.body\s*\.\s*(?:request_hash|receiver_id|profile_id|action_uri)/);
    });
  }

  it('authorizes proxy before credential retrieval and forwarding', () => {
    const text = source('proxy');
    const gate = text.indexOf('enforceRuntimeAuthority(services.authority');
    expect(gate).toBeGreaterThan(text.indexOf('resolveProxyConnection('));
    expect(gate).toBeLessThan(text.indexOf('retrieveCredentialPinnedByConnectionId(', gate));
    expect(gate).toBeLessThan(text.indexOf('services.proxy.forward', gate));
    expect(gate).toBeLessThan(text.indexOf('await meterAction(', gate));
  });

  it('authorizes LLM before credential retrieval and provider forwarding', () => {
    const text = source('llm');
    const gate = text.indexOf('enforceRuntimeAuthority(services.authority');
    expect(gate).toBeGreaterThan(text.indexOf('resolveProxyConnection('));
    expect(gate).toBeLessThan(text.indexOf('retrieveCredentialByConnectionId(', gate));
    expect(gate).toBeLessThan(text.indexOf('forward', gate));
    expect(gate).toBeLessThan(text.indexOf('await meterAction(', gate));
  });

  it('authorizes A2A before allocating or depositing a dropoff', () => {
    const text = source('a2a');
    const gate = text.indexOf('enforceRuntimeAuthority(services.authority');
    expect(gate).toBeLessThan(text.indexOf('services.dropoff.create(', gate));
    expect(gate).toBeLessThan(text.indexOf('services.dropoff.deposit(', gate));
    expect(gate).toBeLessThan(text.indexOf('await meterAction(', gate));
    expect(gate).toBeLessThan(text.indexOf('await services.agent.getById(toAgent', gate));
  });

  it.each([
    ['proxy', 'services.proxy.forward'],
    ['a2a', 'services.dropoff.create'],
  ])('marks %s dispatched immediately before its protected side effect', (route, sideEffect) => {
    const text = source(route);
    const mark = text.indexOf('markRuntimeAuthorityDispatched(');
    const effect = text.indexOf(sideEffect, mark);
    expect(mark).toBeGreaterThan(-1);
    expect(effect).toBeGreaterThan(mark);
    expect(text.slice(mark, effect)).not.toMatch(/services\.(?:proxy|invocation|dropoff)\.[a-zA-Z]+\(/);
  });

  it('withholds authority-protected LLM stream bytes until durable completion', () => {
    const text = source('llm');
    const buffered = text.indexOf('bufferUntilAuthorityFinalized');
    const completion = text.indexOf('await completeRuntimeAuthorityUse(', buffered);
    const hijackAfterCompletion = text.indexOf('hijackReply();', completion);
    expect(buffered).toBeGreaterThan(-1);
    expect(text).toContain('Buffer.concat(bufferedResponseChunks)');
    expect(completion).toBeGreaterThan(buffered);
    expect(hijackAfterCompletion).toBeGreaterThan(completion);
    expect(text).toContain('AUTHORITY_STREAM_RESPONSE_TOO_LARGE');
  });

  it('server-hashes exact terminal results and structural failures at every boundary', () => {
    for (const route of BOUNDARY_ROUTES) {
      const text = source(route);
      expect(text).toContain('runtimeAuthorityFailureResult(err)');
      expect(text).not.toMatch(/completeRuntimeAuthorityUse\([\s\S]{0,500}request\.body\.(?:result_hash|intent_claim_id|outcome_claim_id)/);
    }
  });
});
