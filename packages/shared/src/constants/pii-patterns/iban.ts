// IBAN pattern.

import { PII_SCORES } from './types.js';
import type { PiiPatternDef } from './types.js';

export const PII_IBAN_PATTERNS: readonly PiiPatternDef[] = [
  // IBAN: 2-letter country + 2 check digits + 11-30 alphanumeric.
  {
    id: 'pii_iban',
    category: 'iban',
    score: PII_SCORES.STRONG,
    context: ['iban', 'account', 'bank', 'konto', 'kontonummer'],
    source: '\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b',
    flags: 'g',
  },
];
