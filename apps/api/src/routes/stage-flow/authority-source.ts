import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { routeSource } from './flow-source.js';

/**
 * Reading the authority routes as text.
 *
 * `routes/authority.ts` declares every authority route with its auth options
 * and calls one handler per route; the handler bodies and shared helpers live
 * in `routes/authority-flows/`. Structural tests that used to scan one file
 * for handler text read it through here. The modules are not a pipeline, so
 * unlike a stage flow their order carries no meaning: they are listed sorted.
 *
 * Test-only: nothing at runtime imports this file.
 */

const FLOWS_DIR = 'authority-flows';
const ROUTES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Every module under authority-flows/, as paths relative to routes/, sorted. */
export function authorityFlowModules(): string[] {
  return readdirSync(join(ROUTES_DIR, FLOWS_DIR), { recursive: true, encoding: 'utf8' })
    .map((f) => f.replace(/\\/g, '/'))
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    .sort()
    .map((f) => `${FLOWS_DIR}/${f}`);
}

/** The text of every authority-flows module, joined. */
export function authorityFlowSource(): string {
  return authorityFlowModules().map((file) => routeSource(file)).join('\n');
}

/** The registrar followed by every authority-flows module. */
export function authoritySource(): string {
  return [routeSource('authority.ts'), authorityFlowSource()].join('\n');
}

/**
 * The text of the exported function `name` in authority-flows/, from its
 * declaration to its closing brace. Throws when it is missing so a rename
 * cannot make a structural check pass vacuously.
 */
export function authorityHandlerSource(name: string): string {
  const flows = authorityFlowSource();
  const start = flows.search(new RegExp(`export (?:async )?function ${name}\\(`));
  if (start === -1) throw new Error(`authority-flows has no exported function ${name}`);
  const end = flows.indexOf('\n}\n', start);
  return flows.slice(start, end === -1 ? flows.length : end + 3);
}
