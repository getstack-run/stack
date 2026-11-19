// The Merkle rule of spec/record/SPEC.md section 6, from the specification:
// SHA-256 over the concatenated hex of two nodes; an odd node at the end of a
// level is promoted unchanged; one leaf is its own root; the empty list's root
// is the SHA-256 of the empty string. The root is prefixed `sha256:`.

import { createHash } from 'node:crypto';

export function merkleRoot(leaves) {
  for (const leaf of leaves) {
    if (!/^[0-9a-f]{64}$/.test(leaf)) throw new Error('every leaf is 64 lower-case hex characters');
  }
  if (leaves.length === 0) return `sha256:${createHash('sha256').update('').digest('hex')}`;
  let level = [...leaves];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const right = level[i + 1];
      next.push(right === undefined ? level[i] : createHash('sha256').update(level[i] + right).digest('hex'));
    }
    level = next;
  }
  return `sha256:${level[0]}`;
}
