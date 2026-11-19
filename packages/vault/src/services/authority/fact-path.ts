/** Safe traversal of nested fact objects by dotted path. */
import { ForbiddenError } from '@stack/shared';

/**
 * Walks `path` through own, non-array object properties only. Prototype-chain
 * keys and any non-object step end the walk with `found: false`.
 */
export function valueAtPath(value: unknown, path: string): { found: boolean; value?: unknown } {
  let cursor = value;
  for (const segment of path.split('.')) {
    if (
      !segment ||
      segment === '__proto__' ||
      segment === 'prototype' ||
      segment === 'constructor' ||
      !cursor ||
      typeof cursor !== 'object' ||
      Array.isArray(cursor) ||
      !Object.prototype.hasOwnProperty.call(cursor, segment)
    )
      return { found: false };
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return { found: true, value: cursor };
}

/** Reads a required proof fact; an absent path is a refusal, never `undefined`. */
export function readFact(facts: Record<string, unknown>, path: string): unknown {
  const resolved = valueAtPath(facts, path);
  if (!resolved.found) throw new ForbiddenError('requested proof fact is unavailable');
  return resolved.value;
}
