// Proves that a package's `dist/` was built from the source it sits beside.
//
// The API, the vault and other packages import their workspace dependencies
// from built output, so an edit that was not followed by a build makes a test
// run exercise the OLD code and pass or fail for the wrong reason. File times
// cannot tell the two apart: a restored turbo cache gives `dist/` fresh times
// and a checkout or merge gives `src/` fresh times, so both false alarms and
// misses follow. This compares CONTENT instead.
//
// How: a package's build ends by running this file, which hashes the package's
// source and writes the result into `dist/.build-stamp.json`. The stamp lives in
// `dist/`, so turbo caches and restores it together with the output it vouches
// for. The test guard hashes the source again and compares: equal means `dist/`
// was built from exactly this source (a cache hit, a rebuild, or a checkout that
// only touched file times), different means it was not.
//
// Line endings are normalised before hashing, because a Windows checkout turns
// LF into CRLF and a build restored from a Linux cache must still match it.
//
// This lives in `tooling/` and not in `scripts/` because the Docker build
// context excludes `scripts/`, and every package build runs this file.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const STAMP_FILE = '.build-stamp.json';
const STAMP_VERSION = 1;

// Files that never change what a consumer imports from `dist/`: tests, their
// helpers and declaration files. Editing one does not make a build stale.
const NOT_BUILT_INPUT = /(?:\.test|\.test-support|\.d)\.(?:ts|tsx|mts|cts)$/;
const SKIPPED_DIRECTORIES = new Set(['node_modules', '__tests__']);

function* inputFiles(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) yield* inputFiles(path);
    } else if (!NOT_BUILT_INPUT.test(entry.name)) {
      yield path;
    }
  }
}

function contentHash(path) {
  const bytes = readFileSync(path);
  // A file with a NUL byte is binary: hash it as it is. Text is hashed with
  // CRLF folded to LF (latin1 maps bytes one to one, so no byte is altered).
  const normalised = bytes.includes(0) ? bytes : Buffer.from(bytes.toString('latin1').replace(/\r\n/g, '\n'), 'latin1');
  return createHash('sha256').update(normalised).digest('hex');
}

/**
 * The hash of every input a package's build reads: its `src/` tree, its own
 * `tsconfig.json` and the shared `tsconfig.base.json`. Returns the combined hash
 * and each file's hash (so a mismatch can name the files that differ).
 *
 * @param {string} packageDir absolute path of the package
 * @returns {{ hash: string, files: Record<string, string> }}
 */
export function hashBuildInputs(packageDir) {
  const root = resolve(packageDir);
  const sources = [...inputFiles(join(root, 'src'))];
  for (const config of [join(root, 'tsconfig.json'), resolve(root, '..', '..', 'tsconfig.base.json')]) {
    if (existsSync(config)) sources.push(config);
  }
  const files = {};
  for (const path of sources) {
    // The base config sits above the package, so its key keeps the `..` segments.
    files[relative(root, path).split(sep).join('/')] = contentHash(path);
  }
  const keys = Object.keys(files).sort();
  const combined = createHash('sha256');
  for (const key of keys) combined.update(`${key}\0${files[key]}\n`);
  return { hash: combined.digest('hex'), files: Object.fromEntries(keys.map((key) => [key, files[key]])) };
}

/** Writes `dist/.build-stamp.json` for the package; call it after a successful compile. */
export function writeBuildStamp(packageDir) {
  const root = resolve(packageDir);
  const { hash, files } = hashBuildInputs(root);
  const dist = join(root, 'dist');
  mkdirSync(dist, { recursive: true });
  writeFileSync(join(dist, STAMP_FILE), `${JSON.stringify({ version: STAMP_VERSION, hash, files })}\n`);
  return hash;
}

function readStamp(packageDir) {
  const path = join(packageDir, 'dist', STAMP_FILE);
  if (!existsSync(path)) return null;
  try {
    const stamp = JSON.parse(readFileSync(path, 'utf8'));
    if (stamp?.version !== STAMP_VERSION || typeof stamp.hash !== 'string' || typeof stamp.files !== 'object' || stamp.files === null) return null;
    return stamp;
  } catch {
    return null;
  }
}

/**
 * Packages whose `dist/` was not built from their current source. `reason` is
 * `unbuilt` (no readable stamp: never built, built another way, or a build that
 * failed before it finished) or `changed` (source differs from what was built;
 * `files` names up to the differing files).
 *
 * @param {string} packagesDir absolute path of the `packages/` directory
 * @param {readonly string[]} packages package directory names under it
 * @returns {{ pkg: string, reason: 'unbuilt' | 'changed', files: string[] }[]}
 */
export function findStaleBuilds(packagesDir, packages) {
  const stale = [];
  for (const pkg of packages) {
    const root = join(packagesDir, pkg);
    if (!existsSync(join(root, 'src'))) continue;
    const stamp = readStamp(root);
    if (!stamp) {
      stale.push({ pkg, reason: 'unbuilt', files: [] });
      continue;
    }
    const now = hashBuildInputs(root);
    if (now.hash === stamp.hash) continue;
    const names = new Set([...Object.keys(now.files), ...Object.keys(stamp.files)]);
    const files = [...names].filter((name) => now.files[name] !== stamp.files[name]).sort();
    stale.push({ pkg, reason: 'changed', files });
  }
  return stale;
}

/** The refusal text for a run against stale builds, naming the files and the command. */
export function staleBuildMessage(stale, buildCommand) {
  const lines = stale.map(({ pkg, reason, files }) => {
    if (reason === 'unbuilt') return `  packages/${pkg}: no build stamp (never built, or the last build did not finish)`;
    const shown = files.slice(0, 3).join(', ');
    return `  packages/${pkg}: ${files.length} file${files.length === 1 ? '' : 's'} differ from the build (${shown}${files.length > 3 ? ', ...' : ''})`;
  });
  return [
    'The built output of a workspace package does not match its source, so these tests would run the old code:',
    ...lines,
    `Build first: ${buildCommand}`,
    '(STACK_SKIP_BUILD_CHECK=1 skips this check.)',
  ].join('\n');
}

/**
 * Throws when a package the tests import is not built from its current source.
 * Skipped when `STACK_SKIP_BUILD_CHECK` is set, and in CI, which builds before
 * it tests (every workflow that runs vitest runs `turbo build` first).
 *
 * @param {{ packages: readonly string[], buildCommand: string, packagesDir?: string, env?: Record<string, string | undefined> }} options
 */
export function assertBuiltDependenciesFresh(options) {
  const env = options.env ?? process.env;
  if (env.CI || env.STACK_SKIP_BUILD_CHECK) return;
  const packagesDir = options.packagesDir ?? fileURLToPath(new URL('../packages', import.meta.url));
  const stale = findStaleBuilds(packagesDir, options.packages);
  if (stale.length > 0) throw new Error(staleBuildMessage(stale, options.buildCommand));
}

// `node ../../tooling/build-stamp.mjs` from a package directory, as its last build step.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeBuildStamp(process.cwd());
}
