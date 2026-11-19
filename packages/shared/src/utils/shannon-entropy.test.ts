import { describe, it, expect } from 'vitest';
import { shannonEntropy } from './shannon-entropy.js';

describe('shannonEntropy', () => {
  it('empty input returns 0', () => {
    expect(shannonEntropy(Buffer.alloc(0))).toBe(0);
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy(new Uint8Array(0))).toBe(0);
  });

  it('single byte (constant input) returns 0', () => {
    expect(shannonEntropy(Buffer.from([0x41]))).toBe(0);
    expect(shannonEntropy('a')).toBe(0);
  });

  it('all-same byte returns 0 regardless of length', () => {
    expect(shannonEntropy(Buffer.alloc(1024, 0x41))).toBe(0);
    expect(shannonEntropy('a'.repeat(1000))).toBe(0);
  });

  it('uniform distribution across all 256 byte values returns 8.0', () => {
    const uniform = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) uniform[i] = i;
    expect(shannonEntropy(uniform)).toBeCloseTo(8.0, 10);
  });

  it('two equally-likely bytes returns 1.0', () => {
    // 50/50 split between two byte values → 1 bit of entropy
    expect(shannonEntropy(Buffer.from([0x00, 0xff]))).toBeCloseTo(1.0, 10);
    expect(shannonEntropy(Buffer.from([0x00, 0x00, 0xff, 0xff]))).toBeCloseTo(1.0, 10);
  });

  it('four equally-likely bytes returns 2.0', () => {
    // 25/25/25/25 split → 2 bits of entropy
    expect(shannonEntropy(Buffer.from([0, 1, 2, 3]))).toBeCloseTo(2.0, 10);
  });

  it('returns mid-range value (~3-5) for natural-language text', () => {
    const text = 'the quick brown fox jumps over the lazy dog. ' .repeat(20);
    const h = shannonEntropy(text);
    expect(h).toBeGreaterThan(3);
    expect(h).toBeLessThan(5);
  });

  it('accepts Buffer, Uint8Array, and string interchangeably for same content', () => {
    const text = 'hello world';
    const fromString = shannonEntropy(text);
    const fromBuffer = shannonEntropy(Buffer.from(text, 'utf8'));
    const fromUint8 = shannonEntropy(new Uint8Array(Buffer.from(text, 'utf8')));
    expect(fromBuffer).toBeCloseTo(fromString, 10);
    expect(fromUint8).toBeCloseTo(fromString, 10);
  });

  it('result is bounded above by 8.0 even for adversarial inputs', () => {
    // 1024 random-like bytes — entropy approaches but does not exceed 8
    const buf = Buffer.alloc(1024);
    for (let i = 0; i < 1024; i++) buf[i] = i % 256;
    const h = shannonEntropy(buf);
    expect(h).toBeGreaterThan(7.9);
    expect(h).toBeLessThanOrEqual(8.0);
  });

  it('is deterministic across repeated calls (audit-hash chain stability)', () => {
    const input = Buffer.from('deterministic test fixture content here, repeat many times. '.repeat(50), 'utf8');
    const a = shannonEntropy(input);
    const b = shannonEntropy(input);
    const c = shannonEntropy(input);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('snapshot value for "hello world"', () => {
    // pinned so changes to the algorithm fail CI loudly
    // 'hello world' has 11 chars: h-1, e-1, l-3, o-2, ' '-1, w-1, r-1, d-1 (8 unique)
    // H = -[(1/11)log2(1/11)*5 + (3/11)log2(3/11) + (2/11)log2(2/11)]
    expect(shannonEntropy('hello world')).toBeCloseTo(2.8453509, 6);
  });
});
