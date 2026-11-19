// Payment card pattern.

import { luhnValidate } from './checks.js';
import { PII_SCORES } from './types.js';
import type { PiiPatternDef } from './types.js';

export const PII_CREDIT_CARD_PATTERNS: readonly PiiPatternDef[] = [
  // Credit card: 13-19 digits, possibly separated by spaces or dashes.
  // Validated via Luhn — drops false positives like sequential digits.
  {
    id: 'pii_credit_card',
    category: 'credit_card',
    score: PII_SCORES.STRONG,
    context: ['card', 'credit card', 'visa', 'mastercard', 'amex', 'payment'],
    source: '\\b(?:\\d[ -]?){13,19}\\b',
    flags: 'g',
    validator: luhnValidate,
  },
];
