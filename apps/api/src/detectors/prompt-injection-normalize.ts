/**
 * L2 — encoding-aware normalization for prompt-injection detection.
 *
 * Each function takes a raw text string and returns either:
 *   - null  if the function can't normalize the input (no encoding
 *           detected, or decoded result is garbage)
 *   - a string  with the decoded/normalized form to be re-scanned
 *               by L1 patterns
 *
 * The L2 chain runs each normalization independently. If the
 * normalized text matches a pattern that the raw text didn't, the
 * scanner attributes the match with `encoding: '<normalize_id>'`.
 *
 * Defensive design: a normalization that produces non-printable or
 * mostly-non-ASCII output is treated as "no decoding" — better to
 * miss an attack than to flood the corpus with garbage matches.
 *
 * Performance: each normalization runs in <1ms on bodies up to 32KB.
 * The chain runs sequentially per candidate string. Total L1+L2 cost
 * for a typical proxy body: <5ms.
 */

const PRINTABLE_RATIO_THRESHOLD = 0.85;

/**
 * After decoding, we want the output to look "language-like" — mostly
 * printable ASCII. If the decode produces >15% non-printable bytes
 * (or >15% high-unicode), we treat it as garbage and return null.
 *
 * This prevents false positives where a random binary blob happens
 * to base64-decode into a string that contains "ignore" by accident.
 */
function looksLikeText(s: string): boolean {
  if (s.length < 4) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    // Allow tab, newline, carriage return, plus printable ASCII
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) {
      printable++;
    }
  }
  return printable / s.length >= PRINTABLE_RATIO_THRESHOLD;
}

// ── Strip invisible / control characters ──────────────────────────
//
// Removes characters that render as zero-width (or are otherwise
// invisible) when displayed but break substring-match regex by
// interrupting a continuous attack token. Covers:
//
//   - ZWSP family: U+200B, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM
//   - C0 control chars (except tab/newline/CR): U+0001-U+0008,
//     U+000B, U+000C, U+000E-U+001F
//   - C1 control chars: U+0080-U+009F
//   - Soft hyphen: U+00AD

// The class lists the control and invisible code points to strip, so the control escapes and the joiner are deliberate.
// eslint-disable-next-line no-control-regex, no-misleading-character-class -- explicit escapes for characters removed from untrusted text
const INVISIBLE_CHARS = /[\u0001-\u0008\u000B\u000C\u000E-\u001F\u0080-\u009F\u00AD\u200B\u200C\u200D\uFEFF]/g;

export function stripZeroWidth(text: string): string | null {
  if (!INVISIBLE_CHARS.test(text)) return null;
  INVISIBLE_CHARS.lastIndex = 0;
  return text.replace(INVISIBLE_CHARS, '');
}

/**
 * Variant: replace invisible chars with a SPACE rather than removing
 * them. When the attacker uses zero-width chars between WORDS (not
 * within a word), stripping to empty concatenates the words — the
 * regex `\s+` requirement then fails. This variant restores word
 * boundaries. Both stripZeroWidth and this run; whichever produces
 * a regex match wins.
 */
export function stripZeroWidthAsSpace(text: string): string | null {
  if (!INVISIBLE_CHARS.test(text)) return null;
  INVISIBLE_CHARS.lastIndex = 0;
  return text.replace(INVISIBLE_CHARS, ' ');
}

// ── Unicode homoglyphs → Latin ASCII ───────────────────────────────
//
// Handles the most common attack-relevant homoglyph substitutions:
// Cyrillic letters that look like Latin (а→a, е→e, о→o, etc.),
// Greek lookalikes, mathematical bold/italic letters, and small
// caps. We translate to lowercase Latin ASCII.
//
// This is targeted at attack relevance, not full unicode normalization.
// For full NFKD normalization see the standard Unicode library — but
// NFKD doesn't handle Cyrillic-to-Latin homoglyphs (different code
// points for visually identical characters), which is the most common
// attack form.

const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lowercase (most common)
  'а': 'a', 'б': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'h',
  'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x',
  'ѕ': 's', 'і': 'i', 'ј': 'j', 'ӏ': 'l',
  // Cyrillic uppercase
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
  'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
  // Greek lookalikes
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
  'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y',
  'Χ': 'X', 'Ζ': 'Z',
  'α': 'a', 'ο': 'o', 'ν': 'v',
  // Roman numeral lookalikes (U+2160 range)
  'Ⅰ': 'I', 'ⅰ': 'i', 'Ⅴ': 'V', 'ⅴ': 'v', 'Ⅹ': 'X', 'ⅹ': 'x',
  'ⅈ': 'i',
};

const HOMOGLYPH_RE = new RegExp(
  '[' + Object.keys(HOMOGLYPH_MAP).join('') + ']',
  'g',
);

// Mathematical alphanumeric symbols (U+1D400-U+1D7FF) — bold, italic,
// fraktur, etc. Each block is 26 characters mapping to A-Z or a-z.
function decodeMathSymbols(text: string): string {
  let changed = false;
  const out: string[] = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0x1D400 && cp <= 0x1D7FF) {
      const offset = (cp - 0x1D400) % 52;
      const code = offset < 26 ? 65 + offset : 97 + (offset - 26);
      out.push(String.fromCharCode(code));
      changed = true;
    } else {
      out.push(ch);
    }
  }
  return changed ? out.join('') : text;
}

export function normalizeHomoglyphs(text: string): string | null {
  let changed = false;
  let normalized = text;

  if (HOMOGLYPH_RE.test(text)) {
    HOMOGLYPH_RE.lastIndex = 0;
    normalized = normalized.replace(HOMOGLYPH_RE, (c) => HOMOGLYPH_MAP[c] || c);
    changed = true;
  }

  const afterMath = decodeMathSymbols(normalized);
  if (afterMath !== normalized) {
    normalized = afterMath;
    changed = true;
  }

  return changed ? normalized : null;
}

// ── Leetspeak ──────────────────────────────────────────────────────
//
// Map digits used as letters back to letters. Ambiguous mappings
// (e.g. '1' could be 'i' or 'l') — we pick the most attack-relevant
// substitution. This produces ONE candidate string; if multiple
// substitutions might apply, the scanner can call this then re-scan.

const LEET_MAP: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
  '6': 'g', '7': 't', '8': 'b', '@': 'a', '!': 'i', '$': 's',
};

export function normalizeLeetspeak(text: string): string | null {
  // Treat any non-whitespace run as a candidate "word". Tokens with
  // BOTH a letter AND a leet char get substitutions applied; pure-
  // numeric (prices, IDs) and pure-letter tokens are skipped. Using
  // \S+ instead of \b avoids word-boundary breaks at non-word leet
  // chars like '!', '@', '$'.
  let changed = false;
  const normalized = text.replace(/\S+/g, (token) => {
    if (!/[a-z]/i.test(token)) return token;
    if (!/[013-8@!$]/.test(token)) return token;
    const sub = token.replace(/[0134-8@!$]/g, (c) => LEET_MAP[c] ?? c);
    if (sub !== token) changed = true;
    return sub;
  });
  return changed ? normalized : null;
}

// ── Separator obfuscation: i.g.n.o.r.e / i-g-n-o-r-e ──────────────
//
// Removes intra-word punctuation separators (period, dash, slash,
// underscore, backslash) between consecutive single letters. Whitespace
// is intentionally NOT in the separator class — that's handled by
// collapseSpacedLetters below, since whitespace between dotted tokens
// is a real word boundary we must preserve.
//
// Conservative: only collapses runs of 4+ letter-separator pairs to
// avoid eating real abbreviations (e.g. "U.S.A.").

export function removeSeparatorObfuscation(text: string): string | null {
  const sepRun = /\b(?:[a-z][./\\\-_]){3,}[a-z]\b/gi;
  if (!sepRun.test(text)) return null;
  sepRun.lastIndex = 0;
  const normalized = text.replace(sepRun, (run) =>
    run.replace(/[./\\\-_]/g, ''),
  );
  return normalized === text ? null : normalized;
}

// ── Space-separated single letters: i g n o r e ───────────────────
//
// Collapse runs like "i g n o r e p r e v i o u s" into space-
// separated words: "ignore previous". Conservative: each "word" in the
// run must be a single letter, and the run must have at least 4 such
// single-letter "words" to fire (avoids treating real prose as
// obfuscation).

export function collapseSpacedLetters(text: string): string | null {
  // Match a run of 4+ single-letter "words" separated by single spaces.
  // Anchored to surrounding whitespace or string boundaries so we
  // don't slice into real words.
  const spacedRun = /(^|\s)((?:[a-z]\s){3,}[a-z])(?=\s|$)/gi;
  if (!spacedRun.test(text)) return null;
  spacedRun.lastIndex = 0;
  const normalized = text.replace(spacedRun, (_whole, lead, run) => {
    // Collapse the spaces in the run, keep the leading whitespace
    // (or empty string for start-of-string) untouched so word boundaries
    // around the run remain intact.
    return lead + run.replace(/\s/g, '');
  });
  return normalized === text ? null : normalized;
}

// ── camelCase / snake_case / kebab-case → space-separated ──────────
//
// Catches "ignorePreviousInstructions" / "ignore_previous_instructions"
// / "ignore-previous-instructions" attack variants.

export function normalizeIdentifierCasing(text: string): string | null {
  let normalized = text;
  let changed = false;

  // camelCase / PascalCase: insert space before each uppercase letter
  // that follows a lowercase letter.
  const camelOut = normalized.replace(/([a-z])([A-Z])/g, '$1 $2');
  if (camelOut !== normalized) {
    normalized = camelOut;
    changed = true;
  }

  // snake_case / kebab-case: replace underscores/hyphens between
  // identifier characters with spaces.
  const snakeOut = normalized.replace(/([a-z])[_-]([a-z])/gi, '$1 $2');
  if (snakeOut !== normalized) {
    normalized = snakeOut;
    changed = true;
  }

  return changed ? normalized.toLowerCase() : null;
}

// ── URL-encoded text ───────────────────────────────────────────────
//
// Decode %XX sequences. Targets payloads embedded in URL query
// strings or form-encoded bodies.

export function decodeUrlEncoding(text: string): string | null {
  if (!/%[0-9a-fA-F]{2}/.test(text)) return null;
  try {
    const decoded = decodeURIComponent(text);
    if (decoded === text) return null;
    if (!looksLikeText(decoded)) return null;
    return decoded;
  } catch {
    // Malformed URL encoding — try a partial decode that ignores
    // invalid sequences instead of throwing.
    const partial = text.replace(/%[0-9a-fA-F]{2}/g, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
    if (partial === text) return null;
    if (!looksLikeText(partial)) return null;
    return partial;
  }
}

// ── Hex-encoded text ───────────────────────────────────────────────
//
// Decode runs of hex bytes (with or without 0x prefix, with or without
// separators) that decode to printable text. Targets payloads like
// "0x69676e6f72652070726576696f7573".

export function decodeHex(text: string): string | null {
  // Find candidate hex blobs: 0x-prefixed or bare runs of hex digits ≥16 chars
  const hexBlob = /(?:0x)?([0-9a-fA-F]{16,})/g;
  let changed = false;
  const out = text.replace(hexBlob, (whole, hex) => {
    if (hex.length % 2 !== 0) return whole;
    const bytes: number[] = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.slice(i, i + 2), 16));
    }
    const decoded = String.fromCharCode(...bytes);
    if (!looksLikeText(decoded)) return whole;
    changed = true;
    return decoded;
  });
  return changed ? out : null;
}

// ── Base64-encoded text ────────────────────────────────────────────
//
// Find base64-shaped tokens (≥16 chars, valid base64 alphabet, length
// % 4 == 0 with at most 2 trailing '=') and decode each. Replaces
// in-place. Conservative thresholds avoid decoding random
// alphanumeric IDs.

export function decodeBase64Tokens(text: string): string | null {
  // Standard base64 alphabet, no URL-safe variant. Min length 16
  // chars (12 bytes decoded) to avoid trivial false positives.
  // Greedy matching of contiguous base64-shape runs.
  const b64Token = /[A-Za-z0-9+/]{16,}={0,2}/g;
  let changed = false;
  const out = text.replace(b64Token, (token) => {
    // Length must be multiple of 4 for valid base64.
    if (token.length % 4 !== 0) return token;
    let decoded: string;
    try {
      decoded = Buffer.from(token, 'base64').toString('utf-8');
    } catch {
      return token;
    }
    if (decoded.length === 0) return token;
    if (!looksLikeText(decoded)) return token;
    changed = true;
    // Concatenate decoded text with original separator context
    // by including a space around it — gives the L1 regex word
    // boundaries to anchor against.
    return ` ${decoded} `;
  });
  return changed ? out : null;
}

// ── ROT13 ──────────────────────────────────────────────────────────
//
// Apply ROT13 transformation. Always produces output (every input has
// a ROT13). Returns null only when the input is too short to be useful.

export function applyRot13(text: string): string | null {
  if (text.length < 8) return null;
  const out = text.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + 13) % 26) + 65);
    }
    return String.fromCharCode(((code - 97 + 13) % 26) + 97);
  });
  return out;
}

// ── Reversed text ──────────────────────────────────────────────────
//
// Reverse character order. Like ROT13, always produces output.
// Returns null only for very short inputs.

export function reverseText(text: string): string | null {
  if (text.length < 8) return null;
  return text.split('').reverse().join('');
}

// ── Normalization registry ─────────────────────────────────────────
//
// Each entry runs in order. The scanner runs L1 patterns against
// each non-null normalization output. Cheap normalizations first
// (zero-width strip, homoglyphs) so that most calls return early
// before the expensive ones (base64 decode, ROT13).

export interface NormalizationEntry {
  id: string;
  /** The normalize function. Returns null if no normalization applies. */
  normalize: (text: string) => string | null;
}

export const NORMALIZATIONS: NormalizationEntry[] = [
  { id: 'zero_width_strip',     normalize: stripZeroWidth },
  { id: 'zero_width_as_space',  normalize: stripZeroWidthAsSpace },
  { id: 'homoglyph',            normalize: normalizeHomoglyphs },
  { id: 'separator_collapse',   normalize: removeSeparatorObfuscation },
  { id: 'spaced_letters',       normalize: collapseSpacedLetters },
  { id: 'identifier_casing',    normalize: normalizeIdentifierCasing },
  { id: 'url_decode',           normalize: decodeUrlEncoding },
  { id: 'hex_decode',           normalize: decodeHex },
  { id: 'base64_decode',        normalize: decodeBase64Tokens },
  { id: 'leetspeak',            normalize: normalizeLeetspeak },
  { id: 'rot13',                normalize: applyRot13 },
  { id: 'reverse',              normalize: reverseText },
];
