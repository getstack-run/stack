import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SRC = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(SRC, '../../..');
const HOSTED_LIST = join(REPO, 'scripts/public-repo/hosted-files-today.txt');

/** The worker files that are STACK's own: under a hosted folder, or still listed as hosted where they were written. */
function hostedFiles(): Set<string> {
  if (!existsSync(HOSTED_LIST)) return new Set();
  return new Set(
    readFileSync(HOSTED_LIST, 'utf8').split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#')),
  );
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

/** The code of a TypeScript file, without its comments. */
function codeOf(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

// The private repository's export manifest lists what must never reach the public tree. It is not part of that tree,
// so the terms are read from it here when it is present (a private run) and the engine's own invariant below is
// checked either way.
const MANIFEST = join(REPO, 'scripts/public-repo/manifest.json');

function manifestTerms(): RegExp[] {
  if (!existsSync(MANIFEST)) return [];
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')) as { forbidden_terms?: string[]; pending_forbidden_terms?: string[] };
  return [...(manifest.forbidden_terms ?? []), ...(manifest.pending_forbidden_terms ?? [])].map((term) => new RegExp(term, 'i'));
}

/** The worker's own files: not under a hosted folder and not still listed as hosted where they were written. */
function engineFiles(): { file: string; path: string }[] {
  const hosted = hostedFiles();
  return walk(SRC)
    .map((file) => ({ file, path: relative(REPO, file).split(sep).join('/') }))
    .filter(({ path }) => !path.includes('/hosted/') && !hosted.has(path));
}

describe('the engine worker', () => {
  it('writes no host into what it reads or defaults to, but the loopback', () => {
    // The worker has no one configuration module: each boot reads its own variables. An address that is not the
    // machine's own comes from the install's configuration, never from a default written here.
    const offenders = engineFiles()
      .filter(({ file }) => {
        const hosts = [...codeOf(file).matchAll(/https?:\/\/([^/'"`\s:]+)/gi)].map((m) => m[1]);
        return hosts.some((host) => host !== 'localhost' && host !== '127.0.0.1');
      })
      .map(({ path }) => path);
    expect(offenders).toEqual([]);
  });

  it('names nothing the export manifest forbids (read when the manifest is present)', () => {
    const terms = manifestTerms();
    const offenders = engineFiles()
      .filter(({ file }) => terms.some((term) => term.test(codeOf(file))))
      .map(({ path }) => path);
    expect(offenders).toEqual([]);
  });
});
