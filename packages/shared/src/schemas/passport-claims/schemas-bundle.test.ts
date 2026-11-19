import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { zodToJsonSchema } from 'zod-to-json-schema';
import { canonicalize } from '../../utils/json-canonicalize.js';
import { ClaimEnvelope } from './envelope.js';
import { PASSPORT_CLAIM_SCHEMAS } from './index.js';

/**
 * The published claim schemas back the `schema_versions` pins of every
 * evidence pack, so their hashes have to be a pure function of the Zod
 * definitions:
 *
 *   SB1: the committed bundle holds exactly the envelope + every registered claim type
 *   SB2: regenerating from the Zod definitions reproduces the committed bundle (run
 *        `pnpm run schemas:publish` after a claim schema changes)
 *   SB3: every content_hash is sha256 of the canonicalised body, none is the zero placeholder
 *   SB4: (the copy served from the dashboard is byte-identical; the deployment's own test checks it)
 *   SB5: regenerating twice gives the same bytes (nothing time- or order-dependent)
 */

type BundleEntry = { $schema: string; content_hash: string; json_schema: Record<string, unknown> };

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..', '..', '..');
const bundlePath = join(repoRoot, 'packages', 'shared', 'src', 'generated', 'schemas-bundle.json');

const hashOf = (body: unknown): string =>
  `sha256:${createHash('sha256').update(canonicalize(body), 'utf8').digest('hex')}`;

/** Mirrors the publishing script: same conversion options, same envelope wrapping. */
function regenerate(): Record<string, BundleEntry> {
  const bundle: Record<string, BundleEntry> = {};
  const targets: Record<string, unknown> = { envelope: ClaimEnvelope, ...PASSPORT_CLAIM_SCHEMAS };
  for (const [key, zodSchema] of Object.entries(targets)) {
    const converted = zodToJsonSchema(zodSchema as never, { name: key, $refStrategy: 'none' }) as {
      definitions?: Record<string, Record<string, unknown>>;
      $ref?: string;
    };
    const inner = converted.definitions?.[key] ?? (converted.$ref ? undefined : converted);
    const body = (inner ?? converted) as Record<string, unknown>;
    bundle[key] = {
      $schema: 'http://json-schema.org/draft-07/schema#',
      content_hash: hashOf(body),
      json_schema: body,
    };
  }
  return bundle;
}

const committedText = readFileSync(bundlePath, 'utf8');
const committed = JSON.parse(committedText) as Record<string, BundleEntry>;

describe('published claim schema bundle', () => {
  it('SB1 holds exactly the envelope and every registered claim type', () => {
    expect(Object.keys(committed).sort()).toEqual(
      ['envelope', ...Object.keys(PASSPORT_CLAIM_SCHEMAS)].sort(),
    );
  });

  it('SB2 matches what the Zod definitions generate today', () => {
    // JSON round trip drops `undefined` the way the published file does.
    const fresh = JSON.parse(JSON.stringify(regenerate())) as Record<string, BundleEntry>;
    const stale = Object.keys(fresh).filter(
      (key) => canonicalize(committed[key]) !== canonicalize(fresh[key]),
    );
    expect(stale, `stale published schemas, run \`pnpm run schemas:publish\`: ${stale.join(', ')}`)
      .toEqual([]);
  });

  it('SB3 pins every schema to the sha256 of its canonicalised body', () => {
    for (const [key, entry] of Object.entries(committed)) {
      expect(entry.content_hash, key).toBe(hashOf(entry.json_schema));
      expect(entry.content_hash, key).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(entry.content_hash, key).not.toBe(`sha256:${'0'.repeat(64)}`);
    }
  });

  it('SB5 regenerates to identical bytes every time', () => {
    expect(canonicalize(regenerate())).toBe(canonicalize(regenerate()));
  });
});
