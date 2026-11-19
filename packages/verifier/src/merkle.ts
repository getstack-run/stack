/**
 * Pure SHA-256 binary Merkle tree. Mirrors
 * `@stack/shared/utils/merkle.ts` — duplicated here intentionally so
 * this package stays standalone.
 *
 * Layout: pairs of nodes concatenated and hashed. Odd-leaf level
 * promotes the last node UNCHANGED (rejects Bitcoin's last-leaf
 * duplication; that rule introduces a second-preimage attack against
 * single-leaf trees). Single-leaf tree's root is the leaf itself.
 * Empty tree's root is `sha256:` of the empty string per RFC 6234.
 *
 * Leaves are 64-hex sha256 strings; output carries the `sha256:`
 * prefix to match the pack manifest's content-hash convention.
 */

import { createHash } from 'node:crypto';

const EMPTY_TREE_ROOT_HEX = createHash('sha256').update('').digest('hex');

export function computeMerkleRoot(leaves: readonly string[]): string {
  for (const leaf of leaves) {
    if (!/^[0-9a-f]{64}$/.test(leaf)) {
      throw new Error(
        `computeMerkleRoot: every leaf must be a 64-hex-char sha256 string (got '${leaf.slice(0, 16)}...')`,
      );
    }
  }

  if (leaves.length === 0) return `sha256:${EMPTY_TREE_ROOT_HEX}`;
  if (leaves.length === 1) return `sha256:${leaves[0]}`;

  let level: string[] = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1];
      if (right === undefined) {
        next.push(left);
      } else {
        next.push(createHash('sha256').update(left + right).digest('hex'));
      }
    }
    level = next;
  }

  return `sha256:${level[0]}`;
}
