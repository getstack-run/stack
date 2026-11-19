// US Social Security number pattern.

import { PII_SCORES } from './types.js';
import type { PiiPatternDef } from './types.js';

export const PII_SSN_US_PATTERNS: readonly PiiPatternDef[] = [
  // US SSN: 3-2-4 with non-zero leading group + non-00 mid + non-0000 last;
  // also exclude 9XX (ITIN range) and 666 leading group.
  {
    id: 'pii_ssn_us',
    category: 'ssn_us',
    score: PII_SCORES.FORMATTED,
    countries: ['US'],
    context: ['ssn', 'social security'],
    source: '\\b(?!000|666|9\\d\\d)\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b',
    flags: 'g',
  },
];
