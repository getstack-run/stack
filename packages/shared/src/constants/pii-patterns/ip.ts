// IP address patterns.

import { PII_SCORES } from './types.js';
import type { PiiPatternDef } from './types.js';

export const PII_IP_PATTERNS: readonly PiiPatternDef[] = [
  // IPv4 dotted-quad with octet bounds.
  {
    id: 'pii_ipv4',
    category: 'ipv4',
    score: PII_SCORES.NETWORK,
    context: ['ip', 'address', 'host', 'server'],
    source:
      '\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b',
    flags: 'g',
  },
  // IPv6: full or compressed forms. Catches most well-formed public
  // addresses; doesn't cover IPv4-mapped variants exhaustively.
  {
    id: 'pii_ipv6',
    category: 'ipv6',
    score: PII_SCORES.NETWORK,
    context: ['ip', 'address', 'host', 'server'],
    source:
      '\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b|\\b(?:[A-Fa-f0-9]{1,4}:){1,7}:[A-Fa-f0-9]{0,4}\\b',
    flags: 'g',
  },
];
