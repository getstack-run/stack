/**
 * Recursive canonical JSON serialiser. Mirrors the producer-side
 * helper in `@stack/shared/utils/json-canonicalize.ts` — duplicated
 * here intentionally so this package has zero STACK runtime deps.
 *
 * Object keys sorted lexicographically at every depth; arrays
 * preserve order; primitives use `JSON.stringify` for natural
 * quoting/encoding. Output is a single-line string with no
 * whitespace.
 *
 * RFC 8785 JCS approximation for the value shapes STACK emits
 * (integers + strings + booleans + nulls + arrays + objects). Floats
 * would need additional ECMAScript ToString handling per JCS Section
 * 3.2.2.3; not used in any STACK claim payload schema today.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  const t = typeof value;
  if (t === 'number' || t === 'string' || t === 'boolean') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + canonicalize(v));
    }
    return '{' + parts.join(',') + '}';
  }
  return 'null';
}
