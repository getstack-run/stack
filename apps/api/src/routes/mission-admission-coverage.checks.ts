import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it, expect } from 'vitest';
import { REPO_ROOT, type RouteScanner } from '../test/route-scan.js';

/**
 * Every agent action runs ONE Mission admission check: `beginAgentRuntime`
 * (apps/api/src/lib/agent-runtime.ts). It refuses an agent with no Passport,
 * a Passport without exactly one Mission, and any Mission that is revoked,
 * completed, expired, out of scope or at a cap.
 *
 * Three things can silently undo that, and none of them fails an ordinary
 * test:
 *
 *   1. A new route that verifies a Passport or serves an agent principal and
 *      acts, without calling the check. It works; it just is not gated.
 *   2. Deleting the call from an existing action route.
 *   3. Moving the call BELOW credential retrieval, the upstream forward or the
 *      execution. A refusal after the request left is not a refusal.
 *
 * So the coverage is pinned structurally, the same way an earlier change pins agent
 * denial on governance routes (middleware/require-platform.test.ts).
 *
 * The checks are written once, here, and run by two scanners over two sets of
 * tables: `mission-admission-coverage.test.ts` for the engine's routes and
 * the deployment's own test for its own routes.
 */

/**
 * Action routes. Each calls beginAgentRuntime inside `region` (the handler, or
 * the helper/factory it delegates to) BEFORE the first of its `sinks`: the
 * point where a credential is decrypted, a request leaves, or work executes.
 */
export interface Admitted {
  file: string;
  region: string;
  sinks: string[];
  gate?: string;
}

/** What one scanner is checked against. */
export interface MissionAdmissionTables {
  admitted: Record<string, Admitted>;
  /**
   * Routes that serve an agent principal or touch a Passport but are NOT an
   * action under a Mission. Each says why. A new route lands here only with a
   * reason a reviewer can check.
   */
  exempt: Record<string, string>;
  /**
   * Files whose auth model never admits an agent principal (scope gates,
   * signature-authed receivers, cookie-only or platform-staff surfaces). Files that MIX agent routes with such
   * routes (a2a.ts, authority.ts, proxy-operations.ts) are deliberately NOT here.
   */
  notAgentReachable: ReadonlySet<string>;
}

const DECL = /app\.(post|put|patch|delete|get)\b/g;
const PASSPORT_SIGNAL = /x-passport-token|passport\.verify\(|passportContext|findByJti\(|passport_jti|passport_id|beginAgentRuntime\(/;

interface Route { file: string; key: string; preamble: string; body: string }

/** The handler region an entry names: from the marker to the next route or top-level function. */
export function handlerRegion(scanner: RouteScanner, file: string, marker: string): string {
  const src = scanner.readLf(file);
  const start = src.indexOf(marker);
  if (start === -1) return '';
  const rest = src.slice(start + marker.length);
  const ends = [rest.search(/\n {2}app\.(post|put|patch|delete|get)\b/), rest.search(/\n(?:export )?(?:async )?function /)]
    .filter((i) => i !== -1);
  return src.slice(start, start + marker.length + (ends.length ? Math.min(...ends) : rest.length));
}

function routesOf(scanner: RouteScanner): Route[] {
  const out: Route[] = [];
  for (const file of scanner.files()) {
    const src = scanner.readLf(file);
    const decls = [...src.matchAll(DECL)];
    decls.forEach((m, i) => {
      const at = m.index ?? 0;
      const nextDecl = decls[i + 1]?.index ?? src.length;
      const fn = src.slice(at).search(/\n(?:export )?(?:async )?function /);
      const next = fn === -1 ? nextDecl : Math.min(nextDecl, at + fn);
      const slice = src.slice(at, next);
      const pathMatch = slice.match(/['"`](\/[^'"`]*)['"`]/);
      const path = pathMatch?.[1] ?? '(unparsed)';
      const handlerAt = slice.search(/async\s*\(|makeLlmHandler\(/);
      const preamble = handlerAt === -1 ? slice.slice(0, 400) : slice.slice(0, handlerAt);
      const key = `${String(m[1]).toUpperCase()} ${path.startsWith('/v1/llm/') && m[1] === 'post' ? '/v1/llm/*' : path}`;
      out.push({ file, key, preamble, body: slice });
    });
  }
  return out;
}

const agentDenied = (preamble: string) =>
  preamble.includes('denyAgentContexts') || preamble.includes('requireOperatorAdmin') ||
  preamble.includes('enrollmentAuth') || preamble.includes('requireDashboardSession') || preamble.includes('requireBrowserSession');

export function defineMissionAdmissionCoverage(scanner: RouteScanner, tables: MissionAdmissionTables): void {
  describe(`mission admission coverage (${scanner.name})`, () => {
    for (const [route, spec] of Object.entries(tables.admitted)) {
      it(`${route} runs beginAgentRuntime before it acts`, () => {
        const body = handlerRegion(scanner, spec.file, spec.region);
        expect(body, `${spec.file}: cannot find region ${spec.region}`).not.toBe('');
        const gate = body.indexOf(spec.gate ?? 'beginAgentRuntime(');
        expect(
          gate,
          `${route} (${spec.file}) no longer calls beginAgentRuntime. Agent actions on it are not Mission-gated: ` +
            'a revoked, completed or capped Mission, or a Passport without one, gets through.',
        ).toBeGreaterThan(-1);
        for (const sink of spec.sinks) {
          const at = body.indexOf(sink);
          expect(at, `${spec.file}: sink ${sink} not found; update this test with the real call`).toBeGreaterThan(-1);
          expect(
            gate < at,
            `${route}: beginAgentRuntime now runs AFTER ${sink}. A refusal after that point is not a refusal.`,
          ).toBe(true);
        }
      });
    }

    it('classifies every route that serves an agent or touches a Passport', () => {
      const unclassified: string[] = [];
      const seen = new Set<string>();
      for (const r of routesOf(scanner)) {
        seen.add(r.key);
        if (tables.notAgentReachable.has(r.file)) continue;
        // Agent-denied routes never serve an agent principal.
        if (agentDenied(r.preamble)) continue;
        const mutating = !r.key.startsWith('GET ');
        if (!mutating && !PASSPORT_SIGNAL.test(r.body)) continue;
        if (r.key in tables.admitted || r.key in tables.exempt) continue;
        unclassified.push(`${r.file} ${r.key}`);
      }
      expect(
        unclassified,
        'unclassified agent routes: call beginAgentRuntime before acting (and add to ADMITTED), ' +
          'or add to EXEMPT with the reason it is not an action under a Mission',
      ).toEqual([]);
      // Stale entries hide drift: every listed route must still exist.
      const stale = [...Object.keys(tables.admitted), ...Object.keys(tables.exempt)].filter((k) => !seen.has(k));
      expect(stale, 'listed routes that no longer exist').toEqual([]);
    });

    it('exempts no route that actually calls the admission check', () => {
      const contradictory = routesOf(scanner).filter((r) => r.key in tables.exempt && r.body.includes('beginAgentRuntime('));
      expect(contradictory.map((r) => r.key)).toEqual([]);
    });
  });
}

/**
 * resolveMissionRef without `{ required: true }` returns null for a Passport
 * with no Mission, which is how Mission-less actions used to slip through.
 * Only attribution AFTER admission (or on safety paths that must work without
 * a live Mission) may use the lenient form.
 */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist') continue;
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(p));
    else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') && !entry.name.endsWith('.checks.ts') && !entry.name.endsWith('.d.ts')) out.push(p);
  }
  return out;
}

/**
 * Lenient `resolveMissionRef` calls under `roots` (from the repository root) that are not in `attributionOnly`, and the
 * allowlisted files that no longer make one.
 */
export function lenientMissionRefProblems(
  roots: readonly string[],
  attributionOnly: Record<string, string>,
): { lenient: string[]; stale: string[] } {
  const lenient: string[] = [];
  for (const root of roots) {
    let files: string[];
    try { files = sourceFiles(join(REPO_ROOT, root)); } catch { continue; }
    for (const file of files) {
      const rel = relative(REPO_ROOT, file).replace(/\\/g, '/');
      const src = readFileSync(file, 'utf8');
      for (const m of src.matchAll(/resolveMissionRef\(/g)) {
        const call = src.slice(m.index ?? 0, (m.index ?? 0) + 300);
        const close = call.indexOf(');');
        const args = close === -1 ? call : call.slice(0, close);
        if (args.includes('required: true')) continue;
        if (rel in attributionOnly) continue;
        lenient.push(rel);
      }
    }
  }
  const stale = Object.keys(attributionOnly).filter((rel) => {
    try { return !readFileSync(join(REPO_ROOT, rel), 'utf8').includes('resolveMissionRef('); } catch { return true; }
  });
  return { lenient, stale };
}

export function defineResolveMissionRefCoverage(roots: readonly string[], attributionOnly: Record<string, string>): void {
  describe('resolveMissionRef fails closed outside attribution', () => {
    it('every lenient call is attribution-only and listed', () => {
      expect(
        lenientMissionRefProblems(roots, attributionOnly).lenient,
        'resolveMissionRef without { required: true } outside the attribution allowlist. Use requireMissionRef ' +
          '(lib/agent-runtime.ts) or beginAgentRuntime so a Passport without a Mission is refused',
      ).toEqual([]);
    });

    it('the attribution allowlist has no stale entries', () => {
      expect(lenientMissionRefProblems(roots, attributionOnly).stale).toEqual([]);
    });
  });
}
