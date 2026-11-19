// The PII scanner.

import { PII_PATTERNS } from './catalog.js';
import { PII_CONTEXT_BOOST, PII_CONTEXT_WINDOW_CHARS, PII_DEFAULT_THRESHOLD } from './types.js';
import type { PiiMatch, PiiScanOptions } from './types.js';

/**
 * Scan `text` against the PII catalog. Returns NON-OVERLAPPING matches,
 * sorted by `startOffset` DESCENDING — so a caller redacting via
 * slice/concat can iterate forward without offset drift.
 *
 * The regex objects are constructed fresh per call from the pattern
 * source + flags strings; the catalog itself carries no `RegExp` state
 * across calls.
 *
 * If a pattern has a `validator`, matches that fail validation are
 * dropped (e.g. Luhn-invalid 16-digit sequences won't appear in
 * results).
 *
 * Overlap resolution. Several patterns legitimately claim the same span:
 * `811218-9876` is a valid Swedish personnummer AND an exact match for the
 * US phone pattern. The redactor splices each returned match into the text
 * by offset, so two matches over one span would splice it twice and mangle
 * the surrounding characters. Winner is the highest score, then the longest
 * match, then the earlier catalog entry.
 *
 * SCORING (2026-08-05). A check digit alone is not evidence: most European
 * personal codes are a bare digit run behind one, and an ordinary order
 * number passes about one in eleven of them. So a match now carries a score
 * from its pattern, gains PII_CONTEXT_BOOST when one of that pattern's
 * keywords sits within PII_CONTEXT_WINDOW_CHARS BEFORE it, and is dropped
 * below the threshold. This is the shape Presidio and Google DLP both use,
 * and it is what lets a bare BSN redact when written "BSN: 111222333" and
 * stay put when written "order 111222333 shipped".
 *
 * A failed validator still kills a match outright. The score decides how
 * much a PASSED check digit is worth, not whether to run it.
 */
export function scanForPii(text: string, options: PiiScanOptions = {}): PiiMatch[] {
  const catalog = options.patterns ?? PII_PATTERNS;
  const threshold = options.threshold ?? PII_DEFAULT_THRESHOLD;
  const scope = options.countries?.length
    ? new Set(options.countries.map((c) => c.toUpperCase()))
    : null;

  // Country scoping. Country-neutral patterns (email, card, IBAN, IP) always
  // run: they are not anyone's national scheme and an operator narrowing to
  // Sweden still wants credit cards redacted.
  const patterns = scope
    ? catalog.filter((p) => !p.countries || p.countries.some((c) => scope.has(c)))
    : catalog;

  const haystack = text.toLowerCase();
  const found: Array<PiiMatch & { rank: number }> = [];

  patterns.forEach((pattern, rank) => {
    const re = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      // Guard against zero-width matches (none in the current catalog, but
      // defensive — would otherwise infinite-loop). Applied on every path
      // out of this iteration, including the two `continue`s below.
      const bumpLastIndex = () => {
        if (m && m.index === re.lastIndex) re.lastIndex += 1;
      };
      if (pattern.validator && !pattern.validator(m[0])) {
        // A failed validator must not consume the span: the next pattern
        // gets its own RegExp and its own pass, so nothing is skipped here.
        bumpLastIndex();
        continue;
      }

      let score = pattern.score;
      if (pattern.context && score < 1) {
        const from = Math.max(0, m.index - PII_CONTEXT_WINDOW_CHARS);
        const before = haystack.slice(from, m.index);
        if (pattern.context.some((word) => before.includes(word.toLowerCase()))) {
          score = Math.min(1, score + PII_CONTEXT_BOOST);
        }
      }

      if (score < threshold) {
        bumpLastIndex();
        continue;
      }

      found.push({
        pattern_id: pattern.id,
        category: pattern.category,
        startOffset: m.index,
        endOffset: m.index + m[0].length,
        matchedText: m[0],
        score,
        rank,
      });
      bumpLastIndex();
    }
  });

  // Score first, then longest, then catalog order, then position: a greedy
  // sweep over that ordering keeps the most confident claim on each span.
  // Score leads because a labelled personnummer should beat an unlabelled
  // phone match over the same ten digits even when they are the same length.
  found.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const lenDiff = b.endOffset - b.startOffset - (a.endOffset - a.startOffset);
    if (lenDiff !== 0) return lenDiff;
    if (a.rank !== b.rank) return a.rank - b.rank;
    return a.startOffset - b.startOffset;
  });

  const kept: PiiMatch[] = [];
  for (const c of found) {
    const clashes = kept.some((k) => c.startOffset < k.endOffset && k.startOffset < c.endOffset);
    if (clashes) continue;
    const { rank: _rank, ...match } = c;
    kept.push(match);
  }
  return kept.sort((a, b) => b.startOffset - a.startOffset);
}
