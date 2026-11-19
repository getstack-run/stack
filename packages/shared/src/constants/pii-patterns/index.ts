// PII pattern catalog + scanner.
//
// Used by the LLM gateway (apps/api/src/routes/llm.ts) to redact PII
// from user messages before forwarding to the upstream model provider.
// Reusable by future audit-log / security-event / dropoff redaction
// paths (the catalog is in @stack/shared so any package can import).
//
// Design vs the existing prompt-injection scanner
// (apps/api/src/detectors/prompt-injection.ts):
//   - Prompt-injection scanner returns the single STRONGEST match (no
//     offset info) — designed for binary deny/allow.
//   - PII scanner returns ALL matches with {startOffset, endOffset} —
//     designed for positional replacement (the redactor splices each
//     match span with a placeholder).
//
// Patterns are deliberately conservative. False positives in user
// content (e.g. flagging a phone number that's actually an order
// number) are acceptable because the redaction is non-destructive —
// the upstream model just sees `[REDACTED:phone_us]` instead of the
// digits. False negatives are also acceptable for v1; we cover the
// high-signal categories.
//
// European coverage (2026-08-05). The catalog shipped US-only on the two
// identifiers that are country-shaped: a US SSN and a US phone format. We
// host in Stockholm and sell GDPR, so a Swedish personnummer reaching a US
// model provider unredacted was the gap that mattered most. All 27 EU member
// states plus the UK and Norway now redact, and an E.164 pattern covers the
// phone numbers `phone_us` never could (`+46 70 174 06 05` matched nothing).
//
// Cyprus is the one deliberate omission. Its civil registry number is a bare
// numeric string with no check digit and no distinguishing format, so a
// pattern for it would redact every eight-digit number in every prompt. An
// unredacted identifier is bad; a scanner that eats an eighth of all numeric
// content is worse, and Malta (also checkless) only earns its place because
// its category letter gives the pattern something to anchor on.
//
// THE COST, and what was done about it. Most of these schemes are bare digit
// runs behind a single check digit, so an ordinary order number passes one of
// them about once in eleven. Binary matching therefore redacted 5.0% of all
// random mid-length numbers: 13.3% of 9-digit runs, 12.4% of 11-digit. A
// redacted order number breaks the agent's actual task, so that was a real
// cost rather than a rounding error.
//
// The fix is scoring, not more regex. Every pattern carries a base score set
// by what its FORMAT proves; a keyword sitting just before a match raises it;
// anything under the threshold is not redacted. Croatia, the Netherlands,
// Portugal, Poland, Czechia/Slovakia and Bulgaria sit below the default
// threshold on their own and need a label, which is how a person writes them
// anyway ("BSN: 111222333"). An operator who names their countries can then
// lower the threshold and catch bare formats with almost no false positives,
// which is the combination that actually solves this.
//
// Prior art, checked rather than assumed: Microsoft Presidio scores each
// recognizer, boosts by +0.35 for a keyword five words BEFORE the match, and
// applies an operator threshold (default 0.4); Google Cloud DLP calls the same
// thing hotword rules over a likelihood scale. Presidio ships Finland as two
// patterns for one ID, the well-formed one at 0.5 and the loose one at 0.1.
// pii-patterns.test.ts pins the resulting false-positive rates.
//
// Every European identifier carries a check-digit validator, because the
// regexes alone are ambiguous: a Swedish personnummer (YYMMDD-NNNC) and a
// Danish CPR (DDMMYY-SSSS) are both ten digits split six-four, and both are
// matched exactly by the pre-existing `phone_us` pattern. Three consequences
// follow, and all three are handled:
//
//   1. They share ONE category, `national_id`. The pattern id records which
//      country matched; the category does not, because a bare ten-digit
//      string genuinely does not say whether it is Swedish or Danish, and a
//      placeholder claiming otherwise would be inventing precision.
//   2. Catalog ORDER is load-bearing. Validated identifiers sit before the
//      loose phone patterns so that on an identical span the specific
//      pattern wins (see scanForPii's overlap resolution).
//   3. scanForPii drops overlapping matches. Before this change no two
//      patterns could claim the same span, so the redactor's slice-and-
//      splice loop was safe; with national IDs and phone numbers competing
//      for the same digits it would have spliced one span twice and
//      corrupted the text around it.

export {
  PII_SCORES,
  PII_CONTEXT_BOOST,
  PII_CONTEXT_WINDOW_CHARS,
  PII_DEFAULT_THRESHOLD,
} from './types.js';
export type { PiiCategory, PiiPatternDef, PiiMatch, PiiScanOptions } from './types.js';
export { PII_PATTERNS } from './catalog.js';
export { scanForPii } from './scanner.js';
