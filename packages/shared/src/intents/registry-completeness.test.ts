import { describe, it, expect } from 'vitest';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { INTENT_REGISTRY, expandIntents } from './index.js';

/**
 * Seven provider files sat on disk and were never imported into the
 * registry: bitbucket, fly_io, gitlab, netlify, railway, render, vercel.
 * 108 intents that threw UnknownIntentError the moment anyone named one, and
 * nothing failed until a customer tried. The published "2,199 intents" figure
 * counted files on disk; the registry actually held 2,090.
 *
 * This asserts the two can never drift apart again.
 */

const HERE = dirname(fileURLToPath(import.meta.url));

/** Provider slugs that have a catalogue file. */
function providerFilesOnDisk(): string[] {
  return readdirSync(HERE)
    .filter((f) => f.endsWith('.ts') && !f.includes('.test.'))
    .map((f) => f.replace(/\.ts$/, ''))
    .filter((n) => !['index', 'types'].includes(n));
}

describe('intent registry completeness', () => {
  // INTENT_REGISTRY is a Map, not a plain object.
  const names = [...INTENT_REGISTRY.keys()];
  const registered = new Set(names.map((k) => k.split('.')[0]));

  it('registers an intent for every provider catalogue file', () => {
    // A file's intents are named after the provider, not always the filename
    // (e.g. ms_teams.ts declares ms_teams.*), so the check is that the file
    // contributes SOMETHING rather than that the slug matches exactly.
    const orphans = providerFilesOnDisk().filter((file) => {
      const slug = file.toLowerCase();
      return !registered.has(slug) && !registered.has(slug.replace(/_/g, ''));
    });
    expect(orphans, `provider files with no registered intents: ${orphans.join(', ')}`).toEqual([]);
  });

  it.each(['bitbucket', 'fly_io', 'gitlab', 'netlify', 'railway', 'render', 'vercel'])(
    'resolves %s intents rather than throwing UnknownIntentError',
    (slug) => {
      const name = names.find((k) => k.startsWith(`${slug}.`));
      expect(name, `no intent registered for ${slug}`).toBeDefined();
    },
  );

  it('expands a formerly-orphaned intent into real constraints', () => {
    const constraints = expandIntents([{ name: 'gitlab.create_issue', params: { project: '1' } }]);
    expect(constraints.length).toBeGreaterThan(0);
    expect(constraints.some((c) => c.path === 'method')).toBe(true);
  });
});
