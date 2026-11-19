// Phone number patterns.

import { digitsOf } from './checks.js';
import { PII_SCORES } from './types.js';
import type { PiiPatternDef } from './types.js';

/** E.164-shaped international phone. Leading + is required: without it the
 *  pattern would swallow every long digit run in a document. */
function validatePhoneIntl(match: string): boolean {
  const d = digitsOf(match);
  return d.length >= 8 && d.length <= 15;
}

export const PII_PHONE_PATTERNS: readonly PiiPatternDef[] = [
  // US phone: tolerant of +1, parens, dashes, spaces. Anchored on word
  // boundaries to reduce false-positive on order numbers.
  {
    id: 'pii_phone_us',
    category: 'phone_us',
    score: PII_SCORES.PHONE_US,
    countries: ['US'],
    context: ['phone', 'tel', 'telephone', 'mobile', 'cell', 'call'],
    source: '(?<![\\d.])(?:\\+?1[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}(?![\\d])',
    flags: 'g',
  },
  // International phone, E.164 shaped. The leading + is required: without
  // it this swallows every long digit run in a document. Country code, then
  // 7-14 more digits in any grouping.
  {
    id: 'pii_phone_intl',
    category: 'phone_intl',
    score: PII_SCORES.PHONE_INTL,
    context: ['phone', 'tel', 'telephone', 'mobile', 'mob', 'call'],
    source: '\\+\\d{1,3}(?:[\\s.-]?\\(?\\d{1,4}\\)?){1,6}',
    flags: 'g',
    validator: validatePhoneIntl,
  },
];
