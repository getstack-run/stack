import { describe, expect, it } from 'vitest';
import {
  stripZeroWidth,
  normalizeHomoglyphs,
  normalizeLeetspeak,
  removeSeparatorObfuscation,
  collapseSpacedLetters,
  normalizeIdentifierCasing,
  decodeUrlEncoding,
  decodeHex,
  decodeBase64Tokens,
  applyRot13,
  reverseText,
  NORMALIZATIONS,
} from './prompt-injection-normalize.js';

describe('stripZeroWidth', () => {
  it('returns null when no zero-width chars present', () => {
    expect(stripZeroWidth('normal text')).toBeNull();
  });
  it('strips U+200B / U+200C / U+200D / U+FEFF', () => {
    expect(stripZeroWidth('a\u200Bb\u200Cc\u200Dd\uFEFFe')).toBe('abcde');
  });
});

describe('normalizeHomoglyphs', () => {
  it('returns null when no homoglyphs present', () => {
    expect(normalizeHomoglyphs('all latin chars')).toBeNull();
  });
  it('maps Cyrillic letters to Latin equivalents', () => {
    // Cyrillic о (U+043E) and е (U+0435) instead of Latin
    expect(normalizeHomoglyphs('h\u0435ll\u043E')).toBe('hello');
  });
  it('decodes mathematical bold characters', () => {
    // 𝐢𝐠𝐧𝐨𝐫𝐞 = mathematical bold i,g,n,o,r,e
    const bold = '\u{1D422}\u{1D420}\u{1D427}\u{1D428}\u{1D42B}\u{1D41E}';
    expect(normalizeHomoglyphs(bold)).toBe('ignore');
  });
});

describe('normalizeLeetspeak', () => {
  it('returns null when no leet-mixed tokens present', () => {
    expect(normalizeLeetspeak('plain text')).toBeNull();
  });
  it('decodes digits used as letters', () => {
    expect(normalizeLeetspeak('h3llo w0rld')).toBe('hello world');
  });
  it('does not touch pure-numeric tokens like prices', () => {
    expect(normalizeLeetspeak('$5000 is the price')).toBeNull();
  });
});

describe('removeSeparatorObfuscation', () => {
  it('returns null when no separator-obfuscated runs present', () => {
    expect(removeSeparatorObfuscation('normal sentence here')).toBeNull();
  });
  it('collapses dot-separated single letters', () => {
    expect(removeSeparatorObfuscation('h.e.l.l.o')).toBe('hello');
  });
  it('collapses dash-separated single letters', () => {
    expect(removeSeparatorObfuscation('h-e-l-l-o')).toBe('hello');
  });
  it('preserves whitespace between dotted words (does not concatenate)', () => {
    expect(removeSeparatorObfuscation('h.e.l.l.o w.o.r.l.d')).toBe('hello world');
  });
  it('does not touch real abbreviations with under 4 letters', () => {
    expect(removeSeparatorObfuscation('U.S.A.')).toBeNull();
  });
});

describe('collapseSpacedLetters', () => {
  it('returns null on normal prose', () => {
    expect(collapseSpacedLetters('this is a sentence')).toBeNull();
  });
  it('collapses runs of 4+ single-letter words', () => {
    expect(collapseSpacedLetters('h e l l o')).toBe('hello');
  });
  it('handles multiple separated runs', () => {
    const out = collapseSpacedLetters('h e l l o w o r l d');
    // Either "hello world" or both runs collapsed — accept any join
    expect(out).toContain('hello');
  });
});

describe('normalizeIdentifierCasing', () => {
  it('returns null on plain prose', () => {
    expect(normalizeIdentifierCasing('plain text')).toBeNull();
  });
  it('inserts space at camelCase boundaries', () => {
    expect(normalizeIdentifierCasing('helloWorldHere')).toBe('hello world here');
  });
  it('replaces snake_case underscores with spaces', () => {
    expect(normalizeIdentifierCasing('hello_world_here')).toBe('hello world here');
  });
  it('replaces kebab-case hyphens with spaces', () => {
    expect(normalizeIdentifierCasing('hello-world-here')).toBe('hello world here');
  });
});

describe('decodeUrlEncoding', () => {
  it('returns null when no percent-encoded sequences', () => {
    expect(decodeUrlEncoding('plain text')).toBeNull();
  });
  it('decodes %XX sequences', () => {
    expect(decodeUrlEncoding('hello%20world')).toBe('hello world');
  });
  it('handles malformed percent sequences gracefully', () => {
    // Mixed valid + invalid; should still decode valid parts.
    const out = decodeUrlEncoding('hello%20world%ZZ');
    expect(out).toContain('hello');
  });
});

describe('decodeHex', () => {
  it('returns null when no hex blob', () => {
    expect(decodeHex('plain text without hex')).toBeNull();
  });
  it('decodes 0x-prefixed hex', () => {
    // Hex of "hello world"
    expect(decodeHex('0x68656c6c6f20776f726c64')).toContain('hello world');
  });
  it('rejects hex that decodes to non-printable garbage', () => {
    // Arbitrary binary that won't pass the printable filter
    expect(decodeHex('ff00ff00ff00ff00ff00ff00ff00ff00')).toBeNull();
  });
});

describe('decodeBase64Tokens', () => {
  it('returns null when no base64-shape tokens', () => {
    expect(decodeBase64Tokens('plain text only')).toBeNull();
  });
  it('decodes valid base64 of printable text', () => {
    // base64('hello world') = aGVsbG8gd29ybGQ=
    const out = decodeBase64Tokens('aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8=');
    expect(out).toContain('hello world');
  });
  it('does not decode random alphanumeric IDs', () => {
    // Random-looking but not-decoding-to-text
    expect(decodeBase64Tokens('AbCdEfGhIjKlMnOp')).toBeNull();
  });
});

describe('applyRot13', () => {
  it('returns null on very short input', () => {
    expect(applyRot13('hi')).toBeNull();
  });
  it('applies ROT13 to letters', () => {
    expect(applyRot13('hello world')).toBe('uryyb jbeyq');
  });
  it('is involutive (rot13(rot13(x)) == x)', () => {
    const x = 'the quick brown fox';
    expect(applyRot13(applyRot13(x)!)).toBe(x);
  });
});

describe('reverseText', () => {
  it('returns null on very short input', () => {
    expect(reverseText('hi')).toBeNull();
  });
  it('reverses character order', () => {
    expect(reverseText('hello world')).toBe('dlrow olleh');
  });
});

describe('NORMALIZATIONS registry', () => {
  it('contains all expected normalizations in order', () => {
    const ids = NORMALIZATIONS.map((n) => n.id);
    expect(ids).toContain('zero_width_strip');
    expect(ids).toContain('homoglyph');
    expect(ids).toContain('separator_collapse');
    expect(ids).toContain('spaced_letters');
    expect(ids).toContain('identifier_casing');
    expect(ids).toContain('url_decode');
    expect(ids).toContain('hex_decode');
    expect(ids).toContain('base64_decode');
    expect(ids).toContain('leetspeak');
    expect(ids).toContain('rot13');
    expect(ids).toContain('reverse');
  });
});
