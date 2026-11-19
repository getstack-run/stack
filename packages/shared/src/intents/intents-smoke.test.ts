import { describe, it, expect } from 'vitest';
import { Constraint } from '../schemas/passport.js';
import { listIntents, expandIntents } from './index.js';
import { SAMPLE_PARAM_OVERRIDES as OVERRIDES, minimalValue } from './support/sample-params.js';

// Smoke test: walk every intent, synthesize plausible params from its zod
// schema, call expand(), and validate each produced Constraint against the
// Constraint zod. Catches broken expand functions, invalid constraint
// paths, wrong ops, value/op mismatches — structural rot, not API-endpoint
// correctness.
//
// Params generation is best-effort. For intents whose params have
// bespoke regex constraints (e.g., github requires "owner/repo"), an
// override map provides a known-good sample. Everything else is walked
// generically from the zod definition.

describe('intent smoke test: every intent expands to valid constraints', () => {
  const intents = listIntents();
  const failures: Array<{ name: string; reason: string }> = [];
  const skipped: Array<{ name: string; reason: string }> = [];
  let passed = 0;

  for (const intent of intents) {
    it(`${intent.name}`, () => {
      // Determine params: override or synthesize.
      const params =
        OVERRIDES[intent.name] ?? (minimalValue(intent.params) as Record<string, unknown>);

      if (params === undefined) {
        skipped.push({ name: intent.name, reason: 'could not synthesize params (complex schema)' });
        return;
      }

      // Validate params pass the intent's own schema.
      const parsed = intent.params.safeParse(params);
      if (!parsed.success) {
        skipped.push({
          name: intent.name,
          reason: `synthesized params failed schema: ${JSON.stringify(parsed.error.issues).slice(0, 120)}`,
        });
        return;
      }

      // Call expand. If it throws, that's a hard failure.
      let produced;
      try {
        produced = expandIntents([{ name: intent.name, params }]);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        failures.push({ name: intent.name, reason: `expand threw: ${msg}` });
        throw err;
      }

      // Every produced constraint must pass the Constraint zod.
      for (const c of produced) {
        const r = Constraint.safeParse(c);
        if (!r.success) {
          failures.push({
            name: intent.name,
            reason: `invalid constraint ${JSON.stringify(c)}: ${JSON.stringify(r.error.issues).slice(0, 200)}`,
          });
          throw new Error(`${intent.name}: invalid constraint ${JSON.stringify(c)}`);
        }
      }

      passed++;
    });
  }

  it('summary', () => {
    // Informational: how many passed / skipped / failed.
    // Never fails on its own; real failures are reported by per-intent
    // tests above.
    console.log(
      `\n[intents-smoke] total=${intents.length} passed=${passed} skipped=${skipped.length} failed=${failures.length}`,
    );
    if (skipped.length > 0) {
      console.log(`[intents-smoke] skipped (${skipped.length}):`);
      for (const s of skipped) {
        console.log(`  - ${s.name}: ${s.reason.slice(0, 100)}`);
      }
    }
    expect(true).toBe(true);
  });
});
