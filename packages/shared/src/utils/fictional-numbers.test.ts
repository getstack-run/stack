import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { FICTIONAL_SE_MOBILE_COUNT, fictionalSwedishMobile, isFictionalSwedishMobile } from './fictional-numbers.js';

describe('the numbers reserved for fiction', () => {
  it('start at 070-174 06 05, end at 070-174 06 99 and number 95', () => {
    expect(fictionalSwedishMobile(0)).toBe('+46701740605');
    expect(fictionalSwedishMobile(FICTIONAL_SE_MOBILE_COUNT - 1)).toBe('+46701740699');
    expect(FICTIONAL_SE_MOBILE_COUNT).toBe(95);
    expect(() => fictionalSwedishMobile(FICTIONAL_SE_MOBILE_COUNT)).toThrow(RangeError);
    expect(() => fictionalSwedishMobile(-1)).toThrow(RangeError);
  });

  it('are told from numbers outside the block, however they are written', () => {
    for (const ok of ['+46701740605', '+46 70 174 06 99', '070-174 06 50', '0046701740650']) expect(isFictionalSwedishMobile(ok)).toBe(true);
    for (const no of ['+46701740604', '+46701740700', '+46701740', '+4670174060', '+14155550123', 'hello']) expect(isFictionalSwedishMobile(no)).toBe(false);
  });
});

const ROOT = (() => {
  let dir = dirname(fileURLToPath(import.meta.url));
  while (!existsSync(join(dir, 'pnpm-workspace.yaml'))) {
    const up = dirname(dir);
    if (up === dir) throw new Error('the repository root was not found');
    dir = up;
  }
  return dir;
})();

const SKIP_DIRS = new Set(['node_modules', 'dist', '__pycache__', 'benchmarks', 'public', 'coverage']);
// Hidden folders are tools' caches and a developer's own scratch folders (some are unreadable to this process), not
// the repository's; `.github` is the one the repository keeps.
const skipped = (name: string) => SKIP_DIRS.has(name) || (name.startsWith('.') && name !== '.github');
const SCANNED = /\.(?:ts|tsx|mjs|py|md)$/;

function walk(dir: string, acc: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (skipped(name)) continue;
    const full = join(dir, name);
    const info = statSync(full);
    if (info.isDirectory()) walk(full, acc);
    else if (SCANNED.test(name) && info.size < 2_000_000) acc.push(full);
  }
  return acc;
}

/**
 * The files the repository holds: what git tracks in a checkout (a developer's ignored notes and scratch files are
 * not the repository's), the whole folder in an exported tree, which has no git and no ignored files.
 */
function files(): string[] {
  if (existsSync(join(ROOT, '.git'))) {
    const listed = spawnSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (listed.status === 0) {
      return listed.stdout
        .split('\0')
        .filter((path) => path !== '' && SCANNED.test(path) && !path.split('/').some(skipped))
        .map((path) => resolve(ROOT, path))
        .filter((path) => existsSync(path) && statSync(path).size < 2_000_000);
    }
  }
  return walk(ROOT);
}

describe('every Swedish number in the repository', () => {
  it('is in the block reserved for fiction, or invalid by construction', () => {
    const NUMBER = /\+46[ -]?\d(?:[ -]?\d){7,10}/g;
    const stray: string[] = [];
    for (const file of files()) {
      if (file === fileURLToPath(import.meta.url)) continue; // its own examples of what is not reserved
      const text = readFileSync(file, 'utf8');
      for (const match of text.matchAll(NUMBER)) {
        const value = match[0];
        const national = value.replace(/[ -]/g, '').slice(3);
        if (national.startsWith('0') || isFictionalSwedishMobile(value)) continue;
        stray.push(`${relative(ROOT, file).replaceAll('\\', '/')}: ${value}`);
      }
    }
    expect(stray).toEqual([]);
  }, 120_000);
});
