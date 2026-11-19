// Email address pattern.

import { PII_SCORES } from './types.js';
import type { PiiPatternDef } from './types.js';

export const PII_EMAIL_PATTERNS: readonly PiiPatternDef[] = [
  // RFC 5322 lite. Close enough for chat content.
  {
    id: 'pii_email',
    category: 'email',
    score: PII_SCORES.STRONG,
    source: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b',
    flags: 'g',
  },
];
