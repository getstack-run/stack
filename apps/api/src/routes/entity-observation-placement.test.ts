import { describe, it, expect } from 'vitest';
import { flowSource } from './stage-flow/flow-source.js';

/**
 * The data-flow rule reads `entity_observation` claims. If the emission of
 * those claims sits inside the `enforced || logged` gate, then in STANDARD
 * mode — which is the default — nothing is ever recorded, the rule has
 * nothing to compare against, and the guestbook attack simply succeeds.
 *
 * That failure is completely silent. No error, no denial, no missing test:
 * the rule runs, finds an empty observed set, and permits everything. So the
 * placement gets a structural guard rather than trusting a future reader to
 * notice why the emission is where it is.
 *
 * The triple (intent_claim + intent_outcome + entity_observation) staying
 * gated for cost reasons is deliberate and unchanged; only the single
 * observation claim is hoisted.
 */

/** The proxy handler is composed from stage modules; read it in execution order. */
const PROXY = flowSource('proxy');

/** Character range of the block opened by the accountability-mode gate. */
function modeGateRange(src: string): { start: number; end: number } {
  const marker = "if ((mode === 'enforced' || mode === 'logged')";
  const start = src.indexOf(marker);
  expect(start, 'the accountability-mode gate is no longer recognisable').toBeGreaterThan(-1);

  const open = src.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return { start, end: i };
    }
  }
  throw new Error('unbalanced braces after the accountability-mode gate');
}

describe('entity_observation emission placement', () => {
  it('emits entity_observation OUTSIDE the enforced/logged gate', () => {
    const { start, end } = modeGateRange(PROXY);
    const inGate = PROXY.slice(start, end);

    expect(
      inGate.includes("claimType: 'entity_observation'"),
      'entity_observation is emitted inside the enforced/logged gate again — in standard mode, ' +
        'which is the DEFAULT, nothing would be recorded and the data-flow rule would silently ' +
        'permit everything',
    ).toBe(false);
  });

  it('still emits entity_observation somewhere on the success path', () => {
    // Guards the opposite mistake: removing the emission entirely would also
    // make the rule inert, and would also be silent.
    expect(PROXY.includes("claimType: 'entity_observation'")).toBe(true);
  });

  it('keeps the intent_claim / intent_outcome pair gated', () => {
    const { start, end } = modeGateRange(PROXY);
    const inGate = PROXY.slice(start, end);
    expect(inGate.includes("claimType: 'intent_outcome'")).toBe(true);
  });
});
