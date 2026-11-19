import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

/**
 * The classification of every outbound `fetch`, shared by the engine's egress test and the hosted one: a file that
 * reaches the network is either GUARDED (`assertPublicUrl` runs on its destination) or PINNED (the host is a
 * compile-time constant in that file, which the test re-reads). A stale pin and a pin for a file that no longer
 * fetches are failures too.
 */

/** `fetch(` not preceded by a dot or word character: the global, not a method. */
const FETCH_CALL = /(^|[^.\w])fetch\(/;

const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export type ImportedPin = { literal: string; exportedFrom: string; name: string };
export type PinTable = Record<string, string | ImportedPin>;

function walk(dir: string, skipHosted: boolean, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (skipHosted && entry === 'hosted') continue;
      walk(full, skipHosted, out);
    } else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) {
      out.push(full);
    }
  }
  return out;
}

export function classifyOutboundFetches(options: { repo: string; roots: readonly string[]; pinned: PinTable; skipHosted: boolean }) {
  const { repo, roots, pinned, skipHosted } = options;
  const unclassified: string[] = [];
  const stale: string[] = [];
  const seen = new Set<string>();

  for (const root of roots) {
    for (const file of walk(join(repo, root), skipHosted)) {
      const src = readFileSync(file, 'utf8');
      if (!FETCH_CALL.test(src)) continue;
      const rel = relative(repo, file).split('\\').join('/');
      seen.add(rel);
      if (src.includes('assertPublicUrl')) continue; // guarded
      const pin = pinned[rel];
      if (pin === undefined) {
        unclassified.push(rel);
      } else if (typeof pin !== 'string') {
        // Follow the named import through its literal const definition and
        // direct fetch operand. A matching URL in an unrelated file is not a pin.
        const definition = readFileSync(join(dirname(file), pin.exportedFrom.replace(/\.js$/, '.ts')), 'utf8');
        const imports = [...src.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]/g)];
        const binding = imports.some((match) => match[2] === pin.exportedFrom
          && match[1]!.split(',').map((name) => name.trim()).includes(pin.name));
        const calls = [...src.matchAll(/(^|[^.\w])fetch\(\s*([^,)]*)/g)];
        const literalDefinition = new RegExp(
          `export\\s+const\\s+${escapeRegex(pin.name)}\\s*=\\s*['"]${escapeRegex(pin.literal)}['"]\\s*;`,
        ).test(definition);
        if (!binding || !literalDefinition
          || calls.length === 0 || calls.some((call) => call[2]!.trim() !== pin.name)) {
          stale.push(`${rel} (imported destination is no longer pinned)`);
        }
      } else if (!src.includes(pin)) {
        stale.push(`${rel} (no longer contains ${pin})`);
      }
    }
  }

  // Guard against the map rotting the other way: an entry for a file that no
  // longer fetches anything is a stale exemption waiting to cover a new one.
  const dead = Object.keys(pinned).filter((k) => !seen.has(k));
  return { unclassified, stale, dead };
}

export const UNCLASSIFIED_MESSAGE =
  'these files reach the network but neither guard the destination with assertPublicUrl nor ' +
  'pin it to a constant host. If the URL can be influenced by a caller, guard it. If it ' +
  'cannot, add it to PINNED with the literal that makes it constant.';
export const STALE_MESSAGE =
  'these files are classified PINNED against a literal they no longer contain: the pin moved, ' +
  'and the classification is now a claim about nothing';
