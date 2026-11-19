/**
 * Pure SHA-256 binary Merkle tree over an ordered list of leaf
 * hashes. — used by `EvidencePackService.export` to
 * commit to the pack's claim set via a single root hash carried in
 * `EvidencePackClaim.merkle_root`.
 *
 * Layout rule: at each level, pairs of nodes are concatenated and
 * hashed. When a level has an odd number of nodes, the last node is
 * promoted unchanged to the next level (Bitcoin's last-leaf-
 * duplication rule is rejected here — duplication introduces a
 * second-preimage attack vector against single-leaf trees with
 * malicious padding). The single-leaf tree's root is the leaf itself.
 *
 * Empty-tree convention: `claim_count === 0` packs use the canonical
 * empty-root sha256 of the empty input, mirroring RFC 6234's
 * empty-string hash. This is what the 5.4.3 EvidencePackClaim schema
 * documents as the empty pack root.
 *
 * Input shape: each leaf is a hex sha256 string (64 lowercase hex
 * chars, no `sha256:` prefix). Output carries the `sha256:` prefix to
 * match the pack-manifest schema's content-hash convention.
 *
 * Determinism: leaf order is significant. Producers and verifiers
 * MUST agree on the leaf ordering (the producer in 5.4.4 emits
 * claim_hashes in `(issued_at_ms ASC, claim_id ASC)` order — locked
 * by the pack format).
 */

import { createHash } from 'node:crypto';

const EMPTY_TREE_ROOT_HEX = createHash('sha256').update('').digest('hex');

/**
 * Compute the Merkle root over an ordered list of 64-hex-char leaf
 * hashes. Returns `sha256:<64 hex>`.
 *
 * Throws if any leaf is not a 64-hex string (caller error — caller
 * should always pass already-hashed values).
 */
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
        // Odd-leaf promotion — last node carries unchanged into the
        // next level. Avoids the duplicate-last-leaf second-preimage
        // vector.
        next.push(left);
      } else {
        next.push(createHash('sha256').update(left + right).digest('hex'));
      }
    }
    level = next;
  }

  return `sha256:${level[0]}`;
}
