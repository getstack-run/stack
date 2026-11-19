/**
 * Shannon entropy of a byte sequence, in bits per byte.
 *
 * H = -Σ p(x) · log₂(p(x))
 *
 * where p(x) is the empirical probability of byte value x in the input.
 * Result is in [0, 8] inclusive: 0 = constant input (zero information),
 * 8 = uniform distribution across all 256 byte values (maximum
 * information). Mid-range values (~3-5) typify natural-language text;
 * ~7-8 typifies compressed or encrypted content.
 *
 * Used by the behavioral-genome producer to record an
 * entropy fingerprint per proxied HTTP call. Drift in mean entropy
 * across genome windows catches shape changes that byte-size metrics
 * miss — e.g. agent shifts from sending structured JSON (~5 bits) to
 * base64-encoded blobs (~6 bits) to raw binary (~7-8 bits).
 *
 * Accepts Buffer, Uint8Array, or string. Strings are encoded as UTF-8
 * before histogramming. Empty input returns 0 (entropy of the empty
 * distribution is undefined; the convention here is "no information").
 *
 * Deterministic for any given input: the float result depends only on
 * the byte histogram, which is JSON.stringify-stable for audit-hash
 * chain integrity.
 */
export function shannonEntropy(input: Buffer | Uint8Array | string): number {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  const length = bytes.length;
  if (length === 0) return 0;

  const histogram = new Uint32Array(256);
  for (let i = 0; i < length; i++) {
    histogram[bytes[i]!]!++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const count = histogram[i]!;
    if (count === 0) continue;
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
