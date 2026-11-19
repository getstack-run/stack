// PII redactor.
//
// Replaces each PII match in a text with a placeholder like
// `[REDACTED:<category>]`. The match catalog lives in @stack/shared
// (packages/shared/src/constants/pii-patterns/) and is reusable.
//
// Idempotent: redacting already-redacted text is a no-op because the
// placeholder shape doesn't match any of the catalog patterns. Safe to
// call multiple times on the same content.
//
// Used by the LLM gateway route (apps/api/src/routes/llm.ts) on inbound
// user messages BEFORE the STACK system-prompt injection (5.2.2) so
// STACK content is never seen by the redactor. The order of operations
// in llm.ts is: scan(user) → redact(user) → inject(STACK) → forward.

import { scanForPii, PII_DEFAULT_THRESHOLD, type PiiScanOptions } from '@stack/shared';

export interface RedactResult {
  redactedText: string;
  hits: number;
  categories: readonly string[];
  /**
   * Matches that passed their check digit but scored under the threshold, so
   * were NOT redacted. Surfaced so the caller can tell an operator that their
   * traffic contains things which look like identifiers but are not confident
   * enough to act on — the signal that they should scope to their countries
   * and lower the threshold. Counted, never contents: this is a diagnostic,
   * and putting the near-miss text anywhere would leak the exact data the
   * redactor exists to contain.
   */
  nearMisses: number;
  nearMissCategories: readonly string[];
}

export class PiiRedactor {
  /**
   * Replace each PII match with `[REDACTED:<category>]`. Iterates
   * right-to-left over matches (scanForPii returns DESC by startOffset)
   * so prior replacements don't shift later match offsets.
   *
   * Returns the redacted text + diagnostic counts. When hits === 0 the
   * caller can skip the audit-log redaction-metadata write entirely.
   */
  redact(text: string, options: PiiScanOptions = {}): RedactResult {
    const matches = scanForPii(text, options);

    // Near-miss pass: re-scan at zero threshold and subtract. Everything the
    // real scan kept is a subset of this, so the difference is exactly the
    // set that passed a check digit and failed on confidence. Costs a second
    // regex sweep on the gateway path, which is why it only runs when the
    // threshold is actually filtering something out.
    const threshold = options.threshold ?? PII_DEFAULT_THRESHOLD;
    const nearMissCategories = new Set<string>();
    let nearMisses = 0;
    if (threshold > 0) {
      const kept = new Set(matches.map((m) => `${m.startOffset}:${m.endOffset}`));
      for (const m of scanForPii(text, { ...options, threshold: 0 })) {
        if (kept.has(`${m.startOffset}:${m.endOffset}`)) continue;
        nearMisses += 1;
        nearMissCategories.add(m.category);
      }
    }

    if (matches.length === 0) {
      return {
        redactedText: text,
        hits: 0,
        categories: [],
        nearMisses,
        nearMissCategories: Array.from(nearMissCategories),
      };
    }
    let out = text;
    const categories = new Set<string>();
    for (const m of matches) {
      categories.add(m.category);
      out =
        out.slice(0, m.startOffset) +
        `[REDACTED:${m.category}]` +
        out.slice(m.endOffset);
    }
    return {
      redactedText: out,
      hits: matches.length,
      categories: Array.from(categories),
      nearMisses,
      nearMissCategories: Array.from(nearMissCategories),
    };
  }
}
