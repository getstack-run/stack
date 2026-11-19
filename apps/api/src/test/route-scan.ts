import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Which route files a structural (source-reading) test scans.
 *
 * The coverage tests read route source and pin what it must contain: that an
 * agent route admits its Mission before it acts, that a mutating route denies
 * agent contexts, that a send runs the scope wall. Each check is written once
 * and run by two scanners:
 *
 *  - the engine scanner reads `routes/**`, the routes an install of the
 *    engine serves;
 *  - the hosted scanner reads `hosted/routes/**`, STACK's own.
 *
 * A route file is scanned by exactly one of them (the deployment's own guard test
 * walks every file that registers a route and proves it).
 */

export type ScannerName = 'engine' | 'hosted';

const here = dirname(fileURLToPath(import.meta.url));
/** `apps/api/src`. */
export const API_SRC = join(here, '..');
/** The repository root. */
export const REPO_ROOT = join(API_SRC, '..', '..', '..');

const ROUTES_DIR = 'routes';
/** The engine's own route registrations outside `routes/`, as a path from it. */
const ENGINE_ENTRY = '../start.ts';
const HOSTED_ROUTES_DIR = join('hosted', 'routes');

// A `*.checks.ts` file holds the checks themselves, which quote the patterns they look for: they are not routes.
const isSource = (name: string) =>
  name.endsWith('.ts') && !name.endsWith('.test.ts') && !name.endsWith('.d.ts') && !name.endsWith('.checks.ts');

function topLevelSources(dir: string): string[] {
  const abs = join(API_SRC, dir);
  if (!existsSync(abs)) return [];
  return readdirSync(abs, { withFileTypes: true })
    .filter((entry) => entry.isFile() && isSource(entry.name))
    .map((entry) => entry.name)
    .sort();
}

/** A route file or folder's text as the structural tests read it. */
export interface RouteScanner {
  readonly name: ScannerName;
  /** The route files (top level, not tests) this scanner owns, by file name. */
  files(): string[];
  /** The path of a file this scanner owns, or of a file or stage module beside it (`llm-gateway/stream-forward.ts`). */
  pathOf(name: string): string | undefined;
  /** Its text; throws when there is no such file. Line endings as on disk. */
  read(name: string): string;
  /** Its text with every line ending as `\n`. */
  readLf(name: string): string;
  /** The files of a stage-module folder beside the routes (`llm-gateway`), by name. */
  folder(name: string): string[];
  /** Every source file this scanner owns under its route folders, at any depth, as a path from them (`proxy-call/gate.ts`). */
  allFiles(): string[];
}

function makeScanner(name: ScannerName): RouteScanner {
  // Where the scanner looks for a file: its own folder.
  const roots = name === 'engine' ? [ROUTES_DIR] : [HOSTED_ROUTES_DIR];

  const files = (): string[] => {
    const owned = new Set<string>();
    for (const dir of roots) {
      for (const file of topLevelSources(dir)) owned.add(file);
    }
    // The engine's own entry registers the health check beside the routes; it is the engine's to scan.
    if (name === 'engine') owned.add(ENGINE_ENTRY);
    return [...owned].sort();
  };

  const pathOf = (target: string): string | undefined => {
    for (const dir of roots) {
      const candidate = join(API_SRC, dir, target);
      if (existsSync(candidate)) return candidate;
    }
    return undefined;
  };

  const read = (target: string): string => {
    const path = pathOf(target);
    if (!path) throw new Error(`${name} scanner: no route file ${target}`);
    return readFileSync(path, 'utf8');
  };

  return {
    name,
    files,
    pathOf,
    read,
    readLf: (target) => read(target).replace(/\r\n/g, '\n'),
    allFiles: () => {
      const found = new Set<string>();
      const walk = (dir: string, rel: string): void => {
        for (const entry of readdirSync(join(API_SRC, dir, rel), { withFileTypes: true })) {
          const next = rel ? `${rel}/${entry.name}` : entry.name;
          if (entry.isDirectory()) walk(dir, next);
          else if (isSource(entry.name)) found.add(next);
        }
      };
      for (const dir of roots) if (existsSync(join(API_SRC, dir))) walk(dir, '');
      return [...found].sort();
    },
    folder: (folder) => {
      const found = new Set<string>();
      for (const dir of roots) {
        const abs = join(API_SRC, dir, folder);
        if (!existsSync(abs)) continue;
        for (const entry of readdirSync(abs, { withFileTypes: true })) {
          if (entry.isFile() && isSource(entry.name)) found.add(entry.name);
        }
      }
      return [...found].sort();
    },
  };
}

export const engineRoutes: RouteScanner = makeScanner('engine');
export const hostedRoutes: RouteScanner = makeScanner('hosted');

/** `apps/api/src`-relative path, forward slashes. */
export const relativeToApiSrc = (absolute: string): string => relative(API_SRC, absolute).replace(/\\/g, '/');

// ─── Which file registers a route ───────────────────────────────────

const REGISTRATION = /\b(?:app|instance)\.(?:get|post|put|patch|delete|route|all|head)\s*(?:<[^()]*>)?\s*\(/;

/** Every non-test source file under `apps/api/src` that registers a Fastify route, as a path under `apps/api/src`. */
export function routeRegistrars(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (isSource(entry.name) && !entry.name.endsWith('.test-support.ts')) {
        if (REGISTRATION.test(readFileSync(path, 'utf8'))) out.push(relativeToApiSrc(path));
      }
    }
  };
  walk(API_SRC);
  return out.sort();
}

/** The files each scanner scans, as paths under `apps/api/src`. */
export function scannedBy(scanner: ScannerName): string[] {
  const scan = scanner === 'engine' ? engineRoutes : hostedRoutes;
  return scan.files().map((file) => relativeToApiSrc(scan.pathOf(file)!));
}

/** Every non-test source file under `apps/api/src` (the test helpers, the command-line `scripts` folders and `*.checks.ts` left out) with its text, line endings folded to LF, by path under `apps/api/src`. */
export function apiSourceFiles(): Array<{ path: string; text: string }> {
  const out: Array<{ path: string; text: string }> = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'scripts' || (dir === API_SRC && entry.name === 'test')) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (isSource(entry.name) && !entry.name.endsWith('.test-support.ts')) {
        out.push({ path: relativeToApiSrc(path), text: readFileSync(path, 'utf8').replace(/\r\n/g, '\n') });
      }
    }
  };
  walk(API_SRC);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}
