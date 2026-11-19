// The PII pattern catalog, assembled in its load-bearing order.

import { PII_CREDIT_CARD_PATTERNS } from './credit-card.js';
import { PII_EMAIL_PATTERNS } from './email.js';
import { PII_IBAN_PATTERNS } from './iban.js';
import { PII_IP_PATTERNS } from './ip.js';
import { PII_NATIONAL_ID_PATTERNS } from './national-id.js';
import { PII_PHONE_PATTERNS } from './phone.js';
import { PII_SSN_US_PATTERNS } from './ssn-us.js';
import type { PiiPatternDef } from './types.js';

/* Catalog order is load-bearing: on an identical span, scanForPii prefers
   the longer match and then the earlier catalog entry. Validated national
   identifiers therefore sit ahead of the loose phone patterns, which match
   the same ten digits with no check at all. */
export const PII_PATTERNS: readonly PiiPatternDef[] = [
  ...PII_EMAIL_PATTERNS,
  ...PII_SSN_US_PATTERNS,
  ...PII_NATIONAL_ID_PATTERNS,
  ...PII_PHONE_PATTERNS,
  ...PII_CREDIT_CARD_PATTERNS,
  ...PII_IBAN_PATTERNS,
  ...PII_IP_PATTERNS,
];
