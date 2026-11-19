import { describe, it, expect } from 'vitest';
import { canonicalize } from './json-canonicalize.js';

describe('canonicalize', () => {
  it('J1 primitives — string', () => {
    expect(canonicalize('hello')).toBe('"hello"');
  });

  it('J2 primitives — integer', () => {
    expect(canonicalize(42)).toBe('42');
  });

  it('J3 primitives — boolean', () => {
    expect(canonicalize(true)).toBe('true');
    expect(canonicalize(false)).toBe('false');
  });

  it('J4 primitives — null', () => {
    expect(canonicalize(null)).toBe('null');
  });

  it('J5 undefined returns whatever JSON.stringify returns (undefined value)', () => {
    // JSON.stringify(undefined) returns the JS value `undefined`, not the
    // string "undefined". Our canonicaliser mirrors that for the top-level
    // input case. Object/array element handling strips undefined entirely
    // (covered in J10).
    expect(canonicalize(undefined)).toBeUndefined();
  });

  it('J6 array preserves order (semantic: arrays are sequences)', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('J7 object keys sorted lexicographically', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('J8 nested object — every depth sorted', () => {
    const value = { z: { y: 1, x: 2 }, a: { c: 3, b: 4 } };
    expect(canonicalize(value)).toBe('{"a":{"b":4,"c":3},"z":{"x":2,"y":1}}');
  });

  it('J9 same logical object, different insertion order → identical output', () => {
    const a = canonicalize({ a: 1, b: 2, c: 3 });
    const b = canonicalize({ c: 3, a: 1, b: 2 });
    expect(a).toBe(b);
  });

  it('J10 undefined values in objects are filtered (mirrors JSON.stringify)', () => {
    expect(canonicalize({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
  });

  it('J11 deeply nested array of objects sorts at every depth', () => {
    const value = [{ z: 1, a: 2 }, { y: 3, b: 4 }];
    expect(canonicalize(value)).toBe('[{"a":2,"z":1},{"b":4,"y":3}]');
  });

  it('J12 strings with quotes are JSON-escaped', () => {
    expect(canonicalize('"quote"')).toBe('"\\"quote\\""');
  });

  it('J13 functions become null (parseable output)', () => {
    expect(canonicalize(() => 1)).toBe('null');
  });

  it('J14 round-trip — pack manifest-shape value canonicalises to the same string twice', () => {
    const obj = {
      pack_version: 1,
      claim: 'cose_bytes',
      claims: [
        { claim_hash: 'a'.repeat(64), envelope_cose: 'x', revoked_at_ms: null },
      ],
      verification_material: {
        operator_jwks_url: 'https://api.getstack.run/v1/operators/op_abc/jwks.json',
        operator_jwks_inline: { keys: [] },
        stack_system_jwks_url: 'https://api.getstack.run/v1/.well-known/jwks.json',
        stack_system_jwks_inline: { keys: [] },
      },
    };
    expect(canonicalize(obj)).toBe(canonicalize(obj));
  });
});
