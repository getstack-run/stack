// Canonical JSON as the specifications define it: object keys sorted
// lexicographically at every depth, no whitespace, array order preserved,
// strings and numbers as JSON.stringify writes them, undefined omitted.

import { createHash } from 'node:crypto';

export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  const t = typeof value;
  if (t === 'number' || t === 'string' || t === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (t === 'object') {
    const parts = [];
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) continue;
      parts.push(JSON.stringify(key) + ':' + canonicalize(value[key]));
    }
    return '{' + parts.join(',') + '}';
  }
  return 'null';
}

export const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');
