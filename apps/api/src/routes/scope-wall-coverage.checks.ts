import { describe, it, expect } from 'vitest';
import type { RouteScanner } from '../test/route-scan.js';

/**
 * Complete mediation.
 *
 * The three gates that decide what a call may CARRY (closed-operation policy,
 * the data-flow rule, parameter constraints) ran on /v1/proxy and nowhere
 * else. The LLM gateway is the higher-volume door and checked only which
 * provider the passport could reach, so a scope that was closed for proxy
 * calls was open for LLM calls.
 *
 * Both routes now call `enforceScopeWall`. Two things can silently undo that,
 * and neither would fail an ordinary test:
 *
 *   1. Deleting the call from one route. The route keeps working. It just
 *      stops enforcing.
 *   2. Moving the call BELOW credential retrieval or the upstream forward.
 *      The gate still runs, but the credential has already been decrypted or
 *      the request has already left. A refusal after the fact is not a
 *      refusal.
 *
 * So the placement is pinned structurally, the same way the entity_observation
 * emission is. The checks that classify every route are written once, here, and
 * run by both scanners: `scope-wall-coverage.test.ts` for the engine's routes
 * and the deployment's own test for its own routes.
 */

/** What one scanner's routes are classified against. */
export interface ScopeWallClassification {
  /** Every route file that reaches an external service on a passport's behalf. */
  walled: readonly string[];
  /** Every route that hands content from one agent to another: it carries provenance. */
  provenance: readonly string[];
  /** Files that admit an agent action and do neither, each with the reason. */
  other: Record<string, string>;
  /** Files that verify a passport and reach no upstream through it, each with the reason. */
  exempt: Record<string, string>;
  /** Files the classification of admitting routes leaves out (a route classified by its own placement test). */
  skipAdmits?: readonly string[];
  /** A route file's source when the handlers do not live in it (the authority routes are declared in one file and handled in another). */
  sourceOf?: (file: string) => string | undefined;
}

export function defineScopeWallClassification(scanner: RouteScanner, classification: ScopeWallClassification): void {
  describe(`scope wall classification (${scanner.name})`, () => {
    // Every file that admits an agent action is a door. It runs the wall,
    // carries provenance, or says here why it does not, so a new one cannot hide.
    it('classifies every route that admits an agent action', () => {
      const admits = scanner
        .files()
        .filter((f) => scanner.read(f).includes('beginAgentRuntime('))
        .filter((f) => !(classification.skipAdmits ?? []).includes(f));
      const unclassified = admits.filter(
        (f) => !classification.walled.includes(f) && !classification.provenance.includes(f) && !(f in classification.other),
      );
      expect(
        unclassified,
        `these routes admit an agent action but are neither walled, carrying provenance nor classified: ${unclassified.join(', ')}`,
      ).toEqual([]);
    });

    it('names every route that reaches an upstream on a passport, so a new one cannot hide', () => {
      // A new route that verifies a passport and then calls an external service
      // is a new door. It has to be classified - either it runs the wall,
      // or this list records why it does not.
      const passportRoutes = scanner
        .files()
        .filter((f) => {
          const src = classification.sourceOf?.(f) ?? scanner.read(f);
          return src.includes('x-passport-token') || src.includes('passport.verify(');
        });

      const unclassified = passportRoutes.filter(
        (f) => !classification.walled.includes(f) && !classification.provenance.includes(f) && !(f in classification.exempt),
      );

      expect(
        unclassified,
        `these routes verify a passport but are neither walled nor exempted: ${unclassified.join(', ')}. ` +
          'If the route reaches an external service, call enforceScopeWall. If it does not, say so in EXEMPT.',
      ).toEqual([]);
    });
  });
}
