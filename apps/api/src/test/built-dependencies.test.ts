import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  assertBuiltDependenciesFresh,
  findStaleBuilds,
  hashBuildInputs,
  staleBuildMessage,
  STAMP_FILE,
  writeBuildStamp,
} from '../../../../tooling/build-stamp.mjs';

// The guard compares what a package's source says now with what it said when
// `dist/` was built. These tests build a throwaway `packages/` tree and stamp it
// the way a package build does.

let root: string;
let packagesDir: string;
beforeEach(() => {
  // A package sits at <root>/packages/<name>, so its base config is <root>/tsconfig.base.json.
  root = mkdtempSync(join(tmpdir(), 'stack-built-deps-'));
  packagesDir = join(root, 'packages');
  mkdirSync(packagesDir);
  writeFileSync(join(root, 'tsconfig.base.json'), '{}');
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function write(path: string, content: string): string {
  const full = join(packagesDir, path);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
  return full;
}

function pkgDir(name: string): string {
  return join(packagesDir, name);
}

function build(name: string): void {
  write(`${name}/dist/index.js`, 'compiled');
  writeBuildStamp(pkgDir(name));
}

describe('refusing to test against a build that does not match its source', () => {
  it('passes right after a build, and when only file times moved', () => {
    const edited = write('shared/src/index.ts', 'export const a = 1;\n');
    write('shared/src/utils/hash.ts', 'export const h = 2;\n');
    write('shared/tsconfig.json', '{}');
    build('shared');
    expect(findStaleBuilds(packagesDir, ['shared'])).toEqual([]);

    // A checkout, merge or restored turbo cache changes times and not content.
    utimesSync(edited, 4_000_000_000, 4_000_000_000);
    utimesSync(join(pkgDir('shared'), 'dist', 'index.js'), 1, 1);
    expect(findStaleBuilds(packagesDir, ['shared'])).toEqual([]);
  });

  it('names the file when its content changed after the build', () => {
    write('vault/src/a.ts', 'export const a = 1;\n');
    write('vault/src/services/b.ts', 'export const b = 1;\n');
    build('vault');
    write('vault/src/services/b.ts', 'export const b = 2;\n');
    const stale = findStaleBuilds(packagesDir, ['vault']);
    expect(stale).toEqual([{ pkg: 'vault', reason: 'changed', files: ['src/services/b.ts'] }]);
    const message = staleBuildMessage(stale, 'pnpm exec turbo build --filter=@stack/api^...');
    expect(message).toMatch(/packages\/vault: 1 file differ from the build \(src\/services\/b\.ts\)/);
    expect(message).toMatch(/pnpm exec turbo build --filter=@stack\/api\^\.\.\./);
  });

  it('catches an added file, a removed file and an edited compiler config', () => {
    write('shared/src/a.ts', 'export const a = 1;\n');
    write('shared/src/gone.ts', 'export const g = 1;\n');
    write('shared/tsconfig.json', '{}');
    build('shared');

    write('shared/src/new.ts', 'export const n = 1;\n');
    rmSync(join(pkgDir('shared'), 'src', 'gone.ts'));
    write('shared/tsconfig.json', '{"compilerOptions":{"target":"ES2020"}}');
    expect(findStaleBuilds(packagesDir, ['shared'])).toEqual([
      { pkg: 'shared', reason: 'changed', files: ['src/gone.ts', 'src/new.ts', 'tsconfig.json'] },
    ]);
  });

  it('does not mind a CRLF checkout of the same content', () => {
    write('shared/src/a.ts', 'export const a = 1;\nexport const b = 2;\n');
    build('shared');
    write('shared/src/a.ts', 'export const a = 1;\r\nexport const b = 2;\r\n');
    expect(findStaleBuilds(packagesDir, ['shared'])).toEqual([]);
  });

  it('treats a package with no stamp, an unreadable stamp or a stamp of another version as unbuilt', () => {
    write('shared/src/a.ts', 'export const a = 1;\n');
    expect(findStaleBuilds(packagesDir, ['shared'])).toEqual([{ pkg: 'shared', reason: 'unbuilt', files: [] }]);

    write(`shared/dist/${STAMP_FILE}`, 'not json');
    expect(findStaleBuilds(packagesDir, ['shared'])).toEqual([{ pkg: 'shared', reason: 'unbuilt', files: [] }]);

    write(`shared/dist/${STAMP_FILE}`, JSON.stringify({ version: 0, hash: 'x', files: {} }));
    expect(findStaleBuilds(packagesDir, ['shared'])).toEqual([{ pkg: 'shared', reason: 'unbuilt', files: [] }]);
    expect(staleBuildMessage(findStaleBuilds(packagesDir, ['shared']), 'build')).toMatch(/packages\/shared: no build stamp/);
  });

  it('ignores tests, their helpers, declaration files, __tests__ and a package that has no source', () => {
    write('shared/src/a.ts', 'export const a = 1;\n');
    build('shared');
    write('shared/src/a.test.ts', 'new test');
    write('shared/src/helpers.test-support.ts', 'new helper');
    write('shared/src/types.d.ts', 'declare const x: 1;');
    write('shared/src/__tests__/x.ts', 'new');
    expect(findStaleBuilds(packagesDir, ['shared', 'absent'])).toEqual([]);
  });

  it('hashes the same inputs to the same value and writes the stamp into dist', () => {
    write('shared/src/a.ts', 'export const a = 1;\n');
    const first = hashBuildInputs(pkgDir('shared'));
    expect(hashBuildInputs(pkgDir('shared')).hash).toBe(first.hash);
    expect(Object.keys(first.files)).toEqual(['../../tsconfig.base.json', 'src/a.ts']);
    const written = writeBuildStamp(pkgDir('shared'));
    expect(written).toBe(first.hash);
    expect(JSON.parse(readFileSync(join(pkgDir('shared'), 'dist', STAMP_FILE), 'utf8')).hash).toBe(first.hash);
  });

  it('throws before a run when stale, and can be skipped in CI or on request', () => {
    write('shared/src/a.ts', 'export const a = 1;\n');
    build('shared');
    write('shared/src/a.ts', 'export const a = 2;\n');
    const options = { packages: ['shared'], buildCommand: 'build it', packagesDir };
    expect(() => assertBuiltDependenciesFresh({ ...options, env: {} })).toThrow(/would run the old code/);
    expect(() => assertBuiltDependenciesFresh({ ...options, env: { CI: 'true' } })).not.toThrow();
    expect(() => assertBuiltDependenciesFresh({ ...options, env: { STACK_SKIP_BUILD_CHECK: '1' } })).not.toThrow();
  });
});
