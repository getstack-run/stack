import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '@stack/shared';
import { resolveInlineSchemas } from './schemas-bundle.js';

/**
 * The inline schema catalog an evidence pack is built from.
 *
 *   SBW1: the envelope and each requested claim type come back, and each
 *         content_hash is the sha256 of its canonicalised body
 *   SBW2: a claim type the bundle does not know is simply absent (the pack
 *         builder refuses the export; it never invents a placeholder)
 *   SBW3: the production image carries the bundle, or every export is refused
 */

const here = dirname(fileURLToPath(import.meta.url));

describe('resolveInlineSchemas', () => {
  it('SBW1 returns the envelope and the requested claim types with real hashes', async () => {
    const catalog = await resolveInlineSchemas(new Set(['intent_claim', 'mission']));
    expect(Object.keys(catalog).sort()).toEqual(['envelope', 'intent_claim', 'mission']);
    for (const [key, entry] of Object.entries(catalog)) {
      const recomputed = `sha256:${createHash('sha256').update(canonicalize(entry.json_schema), 'utf8').digest('hex')}`;
      expect(entry.content_hash, key).toBe(recomputed);
      expect(entry.content_hash, key).not.toBe(`sha256:${'0'.repeat(64)}`);
    }
  });

  it('SBW2 leaves out a claim type that has no published schema', async () => {
    const catalog = await resolveInlineSchemas(new Set(['not_a_claim_type']));
    expect(Object.keys(catalog)).toEqual(['envelope']);
  });
});

describe('API runtime image', () => {
  it('SBW3 copies the published schema bundle next to the built shared package', () => {
    // The hosted API image, or in the engine tree the engine's own image: both carry the bundle.
    const root = join(here, '..', '..', '..');
    const dockerfile = readFileSync([join(root, 'Dockerfile'), join(root, '..', '..', 'deploy', 'docker', 'Dockerfile')].find((p) => existsSync(p))!, 'utf8');
    expect(dockerfile).toMatch(
      /COPY --from=builder \/app\/packages\/shared\/src\/generated\/schemas-bundle\.json\s+packages\/shared\/src\/generated\/schemas-bundle\.json/,
    );
  });
});
