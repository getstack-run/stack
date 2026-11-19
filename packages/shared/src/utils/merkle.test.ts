import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { computeMerkleRoot } from './merkle.js';

const HEX_64_ZERO = '0'.repeat(64);
const HEX_64_ONE = '1'.repeat(64);
const HEX_64_TWO = '2'.repeat(64);
const HEX_64_THREE = '3'.repeat(64);

function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

describe('computeMerkleRoot', () => {
  it('M1 empty tree → canonical empty-input sha256 with sha256: prefix', () => {
    const root = computeMerkleRoot([]);
    expect(root).toBe('sha256:' + sha256Hex(''));
  });

  it('M2 single-leaf tree → leaf as root (no extra hashing)', () => {
    const root = computeMerkleRoot([HEX_64_ZERO]);
    expect(root).toBe(`sha256:${HEX_64_ZERO}`);
  });

  it('M3 two-leaf tree → hash(left + right)', () => {
    const root = computeMerkleRoot([HEX_64_ZERO, HEX_64_ONE]);
    const expected = sha256Hex(HEX_64_ZERO + HEX_64_ONE);
    expect(root).toBe(`sha256:${expected}`);
  });

  it('M4 three-leaf tree → odd-leaf promotion (no last-leaf duplication)', () => {
    const root = computeMerkleRoot([HEX_64_ZERO, HEX_64_ONE, HEX_64_TWO]);
    // Level 0: [zero, one, two]
    // Level 1: [hash(zero+one), two]  ← two is promoted unchanged
    // Level 2: [hash(hash(zero+one)+two)]
    const pairHash = sha256Hex(HEX_64_ZERO + HEX_64_ONE);
    const expected = sha256Hex(pairHash + HEX_64_TWO);
    expect(root).toBe(`sha256:${expected}`);
  });

  it('M5 four-leaf tree → balanced binary tree', () => {
    const root = computeMerkleRoot([HEX_64_ZERO, HEX_64_ONE, HEX_64_TWO, HEX_64_THREE]);
    const left = sha256Hex(HEX_64_ZERO + HEX_64_ONE);
    const right = sha256Hex(HEX_64_TWO + HEX_64_THREE);
    const expected = sha256Hex(left + right);
    expect(root).toBe(`sha256:${expected}`);
  });

  it('M6 different leaf order → different root (order is significant)', () => {
    const a = computeMerkleRoot([HEX_64_ZERO, HEX_64_ONE]);
    const b = computeMerkleRoot([HEX_64_ONE, HEX_64_ZERO]);
    expect(a).not.toBe(b);
  });

  it('M7 throws on non-64-hex input', () => {
    expect(() => computeMerkleRoot(['too_short'])).toThrow(/64-hex/);
  });

  it('M8 throws on uppercase hex (canonical lowercase only)', () => {
    // 'A' through 'F' actually case-shift; '0'-'9' do not. Use a letter.
    const uppercaseHex = 'AB' + 'cd'.repeat(31);
    expect(() => computeMerkleRoot([uppercaseHex])).toThrow(/64-hex/);
  });

  it('M9 throws on non-hex chars in correct length', () => {
    expect(() => computeMerkleRoot(['g'.repeat(64)])).toThrow(/64-hex/);
  });

  it('M10 deterministic — same input twice → same root', () => {
    const a = computeMerkleRoot([HEX_64_ZERO, HEX_64_ONE, HEX_64_TWO]);
    const b = computeMerkleRoot([HEX_64_ZERO, HEX_64_ONE, HEX_64_TWO]);
    expect(a).toBe(b);
  });

  it('M11 single leaf with .toLowerCase() input round-trips', () => {
    const leaf = sha256Hex('arbitrary data');
    expect(leaf).toMatch(/^[0-9a-f]{64}$/);
    expect(computeMerkleRoot([leaf])).toBe(`sha256:${leaf}`);
  });
});
