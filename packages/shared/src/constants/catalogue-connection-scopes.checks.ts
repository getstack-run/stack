import { readFileSync } from 'node:fs';
import { invalidChildScopes } from '../utils/constraints.js';

/** One catalogue row, as the seeds write it. */
export interface CatalogueRow {
  provider: string;
  scopes: string[];
}

export function words(list: string): string[] {
  return [...list.matchAll(/'([^']*)'/g)].map((m) => m[1]!);
}

/** The engine's own seed (packages/shared/src/db/seed.ts): the OAuth services every install starts with. */
export function engineSeedRows(): CatalogueRow[] {
  const source = readFileSync(new URL('../db/seed.ts', import.meta.url), 'utf8');
  return [...source.matchAll(/provider: '([^']+)',[\s\S]*?scopes_available: \[([\s\S]*?)\],/g)].map((m) => ({
    provider: m[1]!,
    scopes: words(m[2]!),
  }));
}

/** Whether some scope an agent could be granted is within what the connection stores. */
export function grantable(connectionScopes: string[]): boolean {
  return connectionScopes.some((scope) => invalidChildScopes([scope], connectionScopes).length === 0);
}
