// Types and scoring constants for the PII catalog.

export type PiiCategory =
  | 'email'
  | 'ssn_us'
  | 'phone_us'
  | 'phone_intl'
  | 'national_id'
  | 'credit_card'
  | 'iban'
  | 'ipv4'
  | 'ipv6';

export interface PiiPatternDef {
  id: string;
  category: PiiCategory;
  /** Pattern source — caller clones into a fresh RegExp per scan to
   * avoid lastIndex leakage across calls. */
  source: string;
  flags: string;
  /** Optional post-match validator (e.g. Luhn for credit cards). */
  validator?: (match: string) => boolean;
  /**
   * Base confidence before context, in [0,1]. Set by how much the FORMAT
   * itself proves, not by how much we care about the data: an email address
   * announces itself, a bare nine-digit run does not. Patterns scoring under
   * the threshold need a nearby keyword to redact. See PII_SCORES.
   */
  score: number;
  /**
   * ISO 3166-1 alpha-2 codes this pattern belongs to. Absent means
   * country-neutral (email, card, IBAN, IP), which always scans. An operator
   * scoping to their own countries drops every pattern not listed here.
   * A list rather than a single code because the Czech and Slovak rodné číslo
   * are one scheme across two countries.
   */
  countries?: readonly string[];
  /**
   * Words that, appearing shortly BEFORE a match, raise its score by
   * PII_CONTEXT_BOOST. Local-language spellings included, because the prompt
   * that carries a personnummer says "personnummer", not "national id".
   */
  context?: readonly string[];
}

export interface PiiMatch {
  pattern_id: string;
  category: PiiCategory;
  startOffset: number;
  endOffset: number;
  matchedText: string;
  /** Final confidence after any context boost. Always >= the threshold in
   *  use, since lower-scoring matches are dropped before returning. */
  score: number;
}

/**
 * Scores by what the format proves. Measured false-positive contribution
 * decided these, not intuition: the six patterns in WEAK caused 88% of all
 * wrong redactions on random digit runs, and every one of them is a bare
 * digit run behind a single check digit with no date, separator or letter.
 */
export const PII_SCORES = {
  /** Self-announcing: an @ sign, a Luhn-valid card, an IBAN country prefix. */
  STRONG: 0.85,
  /** Structurally distinctive but not unique to people. */
  NETWORK: 0.7,
  /** Carries a letter or a mandatory separator the scheme requires. */
  FORMATTED: 0.6,
  /** International phone: the leading + does real work. */
  PHONE_INTL: 0.5,
  /** A birth date plus a check digit, but no separator required. */
  DATED: 0.45,
  /** Ten digits in 3-3-4. Almost anything is this. */
  PHONE_US: 0.3,
  /** Bare digits and a check digit. Roughly one run in eleven passes by luck. */
  WEAK: 0.25,
} as const;

/** Added when a context keyword sits shortly before a match. Presidio's
 *  figure, and it is chosen so WEAK (0.25) clears the default threshold when
 *  labelled and misses it when not. */
export const PII_CONTEXT_BOOST = 0.35;

/** Characters before a match searched for a context keyword. Presidio looks
 *  five words back and none forward; people write "personnummer: 811218-9876",
 *  never the reverse. */
export const PII_CONTEXT_WINDOW_CHARS = 48;

/** Redact at or above this unless the operator says otherwise. Sits between
 *  WEAK and DATED on purpose: bare-format identifiers need a label, every
 *  other scheme stands on its own. */
export const PII_DEFAULT_THRESHOLD = 0.4;

/** Options for {@link scanForPii}. All optional; the defaults reproduce the
 *  built-in catalogue at the built-in threshold across every country. */
export interface PiiScanOptions {
  /** Override the catalogue itself. Mainly for tests. */
  patterns?: readonly PiiPatternDef[];
  /** Minimum score to redact. Defaults to PII_DEFAULT_THRESHOLD. */
  threshold?: number;
  /**
   * ISO 3166-1 alpha-2 codes to scan for. Country-neutral patterns always
   * run. Undefined or empty means every country, which is the safe default
   * and also the noisy one: an operator who names their countries can lower
   * the threshold and catch bare formats without the false positives.
   */
  countries?: readonly string[];
}
