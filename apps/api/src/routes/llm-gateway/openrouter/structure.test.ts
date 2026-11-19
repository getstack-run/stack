// The order of the passthrough's gates, read from its source the way the other composed routes are (stage-flow/): the
// meter before Mission admission, Mission admission before anything that costs or sends, the customer's decider before the
// hold, the hold before the key is read, the key before the call, and the call is made in one place only.

import { describe, expect, it } from 'vitest';
import { routeSource } from '../../stage-flow/flow-source.js';
import { flowSource } from '../../stage-flow/flow-source.js';

const handler = routeSource('llm-gateway/openrouter/handler.ts');
const at = (text: string, needle: string, from = 0) => {
  const index = text.indexOf(needle, from);
  expect(index, `${needle} not found`).toBeGreaterThan(-1);
  return index;
};

describe('the OpenRouter passthrough gate order', () => {
  it('admits the caller, then counts the action, then admits the Mission, then the approval gate and the scope wall', () => {
    const admit = at(handler, 'await admitCaller(');
    const meter = at(handler, 'await meterLlmCall(');
    const mission = at(handler, 'await beginAgentRuntime(');
    const approval = at(handler, 'await enforceApprovalGate(');
    const wall = at(handler, 'await enforceProviderScope(');
    expect([admit, meter, mission, approval, wall]).toEqual([...[admit, meter, mission, approval, wall]].sort((a, b) => a - b));
  });

  it('asks the decider and takes the hold after Mission admission, and reads no key before the hold', () => {
    const mission = at(handler, 'await beginAgentRuntime(');
    const decider = at(handler, 'await decideControl(');
    const hold = at(handler, 'await services.modelAccessPolicy.hold(');
    const stackKey = at(handler, 'services.modelAccessPolicy.stackKey(');
    const customerKey = at(handler, 'await retrieveProviderCredential(');
    const call = at(handler, 'await callOpenRouter(');
    expect(mission).toBeLessThan(decider);
    expect(decider).toBeLessThan(hold);
    expect(hold).toBeLessThan(stackKey);
    expect(hold).toBeLessThan(customerKey);
    expect(stackKey).toBeLessThan(call);
    expect(customerKey).toBeLessThan(call);
  });

  it('marks the authority use dispatched right before the call, with nothing that spends between', () => {
    const mark = at(handler, 'await markRuntimeAuthorityDispatched(');
    const call = at(handler, 'await callOpenRouter(', mark);
    expect(handler.slice(mark, call)).not.toMatch(/services\.(?:accountModelBilling|llmUsage|modelAccessPolicy)\./);
  });

  it('gives the hold back only when the call never ran, and settles what ran', () => {
    const call = at(handler, 'await callOpenRouter(');
    const release = at(handler, 'services.modelAccessPolicy.release(');
    const settle = at(handler, 'accountModelBilling.settleCall(');
    expect(release).toBeGreaterThan(call);
    // The release is in the handler of a failure before an answer exists; the settlement is past the delivery's setup.
    expect(handler.slice(call, release)).toContain('catch (err)');
    expect(settle).toBeGreaterThan(release);
  });

  it('reaches OpenRouter, and reads a credential, in one place each', () => {
    const flow = flowSource('openrouter');
    expect(flow.match(/await fetch\(|\bfetch\(/g)?.length ?? 0).toBeLessThanOrEqual(1);
    const upstream = routeSource('llm-gateway/openrouter/upstream.ts');
    expect(upstream).toContain('fetch(url, init)');
    for (const stage of ['delivery.ts', 'handler.ts', 'policy.ts', 'request.ts', 'tap.ts']) {
      const text = routeSource(`llm-gateway/openrouter/${stage}`).replace(/\/\/.*$/gm, '');
      expect(text, `${stage} reaches OpenRouter`).not.toMatch(/\bfetch\(/);
      expect(text, `${stage} reads a credential`).not.toMatch(/retrieveCredential(?:Pinned)?(?:ByConnectionId)?\(/);
    }
  });

  it('settles the charge, and writes the record, before the answer ends', () => {
    const delivery = routeSource('llm-gateway/openrouter/delivery.ts');
    const finalize = at(delivery, 'await input.finalize(');
    const end = at(delivery, 'raw.end()', finalize);
    expect(finalize).toBeLessThan(end);
  });
});
