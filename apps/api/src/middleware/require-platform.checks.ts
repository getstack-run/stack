import type { RouteScanner } from '../test/route-scan.js';

/**
 * The structural checks of `require-platform.test.ts`, written once and run by both scanners: the engine's test over
 * `routes/**`, and the deployment's own test over its own route files.
 * Each returns what is wrong, so a test can name it.
 */

/** A route file's source without its comments, so a description of a forbidden pattern does not trip a check for it. */
export function withoutComments(src: string): string {
  return src
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, ''))
    .join('\n')
    .replace(/\/\*[\s\S]*?\*\//g, '');
}

/**
 * Route files that read `request.isAdmin`. The property is the operator account's admin flag, never a platform-staff
 * check, and a privilege gate written inline in a handler is the fragility `requireOperatorAdmin` replaced.
 */
export function isAdminReaders(scanner: RouteScanner): { file: string; lines: number[] }[] {
  const violators: { file: string; lines: number[] }[] = [];
  for (const file of scanner.files()) {
    const hits: number[] = [];
    scanner.read(file).split('\n').forEach((line, idx) => {
      // Only count uses that read the property: the declare-module typing additions in middleware/auth.ts are
      // fine, and comments are too.
      const stripped = line.replace(/\/\/.*$/, '').replace(/\/\*.*?\*\//g, '');
      if (/\brequest\.isAdmin\b/.test(stripped)) hits.push(idx + 1);
    });
    if (hits.length > 0) violators.push({ file, lines: hits });
  }
  return violators;
}

/** What the mutating-route check is told: files whose scope or auth model excludes watched agents, and the paths agents legitimately call. */
export interface MutatingRouteClassification {
  scopeOrPublicFiles: ReadonlySet<string>;
  operationalMutating: ReadonlySet<string>;
}

/**
 * Mutating routes (POST, PUT, PATCH, DELETE) that neither deny agent contexts nor are classified as part of the
 * agents' operational surface. A new route lands here until it is one or the other deliberately.
 */
export function unclassifiedMutatingRoutes(scanner: RouteScanner, classification: MutatingRouteClassification): string[] {
  const files = scanner.files().filter((file) => !classification.scopeOrPublicFiles.has(file));
  const violations: string[] = [];
  for (const file of files) {
    const src = scanner.read(file);
    for (const m of src.matchAll(/app\.(post|put|patch|delete)\b/g)) {
      const at = m.index ?? 0;
      // Slice from the declaration to the handler arrow - contains the path string and the options object.
      const handlerAt = src.indexOf('async', at);
      const slice = src.slice(at, handlerAt === -1 ? at + 400 : handlerAt + 5);
      const pathMatch = slice.match(/['"`](\/[^'"`]*)['"`]/);
      const path = pathMatch?.[1] ?? '(unparsed)';
      const denied =
        slice.includes('denyAgentContexts') ||
        slice.includes('requireOperatorAdmin') ||
        slice.includes('enrollmentAuth') ||
        // This exact route has a stronger direct-owner + recent-browser gate at the start of its handler. Do not
        // exempt sibling routes. admin-billing-attribution.test.ts exercises every excluded principal class and
        // proves denial precedes service access.
        (file === 'admin-billing-attribution.ts' && m[1] === 'post'
          && path === '/billing-attribution/payouts/:payoutId/confirm'
          && /^async\s*\(request, reply\)\s*=>\s*\{\s*ownerSession\(request, reply, true\);/.test(src.slice(handlerAt)));
      // LLM gateway paths are prefix-matched (provider wildcard files).
      const allowlisted = classification.operationalMutating.has(path) || path.startsWith('/v1/llm/');
      if (!denied && !allowlisted) violations.push(`${file} ${String(m[1]).toUpperCase()} ${path}`);
    }
  }
  return violations;
}

/** The platform-staff route files that set up auth of their own instead of inheriting the gate of their scope. */
export function perRouteAuthSetups(scanner: RouteScanner, files: readonly string[]): string[] {
  const problems: string[] = [];
  for (const file of files) {
    const stripped = withoutComments(scanner.read(file));
    if (/createAuthMiddleware\s*\(/.test(stripped)) problems.push(`${file} calls createAuthMiddleware`);
    if (/preHandler:\s*auth\b/.test(stripped)) problems.push(`${file} declares a per-route preHandler: auth`);
    if (/\brequireRole\s*\(/.test(stripped)) problems.push(`${file} calls requireRole`);
    if (/request\.isPlatformStaff/.test(stripped)) problems.push(`${file} checks request.isPlatformStaff inline (the gate is at scope)`);
  }
  return problems;
}
