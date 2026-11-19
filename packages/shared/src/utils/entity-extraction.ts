// entity extraction.
//
// Deterministic, regex-based walk of JSON-like payloads. Producers
// (proxy.ts, skills.ts, a2a.ts) call this on runtime response data
// before hashing, and emit the extracted entities as an
// `entity_observation` claim attached to the active passport. The
// `undeclared_target` detector queries the union of all observed
// entities at simulation time to spot new references that weren't
// in the passport's history.
//
// Why RE2: operator-authored patterns (future expansion) are
// untrusted input; the standard `RegExp` engine is ReDoS-vulnerable.
// The internal patterns here are safe too, but they share the
// engine choice so future operator-customisable patterns stay safe
// by default.
//
// Why a closed set of `entity_type` values: the consumer
// (`undeclared_target` detector) needs to query reliably. Adding a
// new type means updating both the producer's pattern catalog AND
// the EntityObservationClaim schema's enum together.

import { createHash } from 'node:crypto';
import RE2 from 're2';

export type EntityType =
  | 'url_host'
  | 'url_path'
  | 'email'
  | 'account_id'
  | 'file_path'
  | 'arn'
  | 'gcp_resource'
  | 'azure_resource'
  | 'phone'
  | 'ip_address'
  | 'money_amount'
  | 'account_number'
  | 'other';

export interface ExtractedEntity {
  /** Normalized form (lowercased, trimmed). */
  entity: string;
  entity_type: EntityType;
  /**
   * Dotted path where this was found in the input (e.g.
   * `body.charge_id`, `headers.x-stripe-account`). Useful for
   * debugging — NOT signed into the claim.
   */
  source_path: string;
}

export interface ExtractEntitiesOptions {
  /** Hard cap on returned entities. Default 256, matches schema cap. */
  maxEntities?: number;
  /** Walk depth limit. Default 4 (e.g. body.foo.bar.baz). */
  maxDepth?: number;
  /**
   * Also recognise money amounts and account numbers.
   *
   * Set it for content read from a financial provider
   * (`isFinancialProvider`) and for outbound content the data-flow rule
   * compares against such reads. Leave it off everywhere else: a four-digit
   * number in an ordinary response is a count or an id far more often than
   * money, and the undeclared-target detector must not treat amounts as
   * counterparties.
   *
   * These two types are recorded as one-way digests (`money:<hex>`,
   * `acct:<hex>`), never the figure itself, so an observation claim does not
   * become a second copy of a bank balance.
   */
  financial?: boolean;
}

const DEFAULT_MAX_ENTITIES = 256;
const DEFAULT_MAX_DEPTH = 4;

// ─── Regex catalog ────────────────────────────────────────────────
//
// Each pattern is paired with a classifier. Patterns are intentionally
// conservative — false negatives are acceptable (the detector misses
// a fire), false positives are not (the detector spams flags).
//
// Tested against the unit suite at entity-extraction.test.ts.

const PATTERNS: Array<{ key: EntityType; re: RE2 }> = [
  // Email — pragmatic shape, not the full RFC 5322 nightmare
  { key: 'email', re: new RE2('([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})', 'g') },
  // URL — captures full http(s) URLs (host, optional port, path, query).
  // The extractor splits the match into url_host + url_path so policies
  // can match on either dimension.
  { key: 'url_host', re: new RE2('(https?://[a-zA-Z0-9.-]+(?::\\d+)?(?:/[^\\s"\'<>]*)?)', 'g') },
  // AWS ARN
  { key: 'arn', re: new RE2('(arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:\\d{0,12}:[a-zA-Z0-9_./:-]+)', 'g') },
  // GCP resource path
  { key: 'gcp_resource', re: new RE2('(projects/[a-z0-9-]+/(?:locations/[a-z0-9-]+/)?[a-z]+/[a-zA-Z0-9_-]+)', 'g') },
  // Azure resource path
  { key: 'azure_resource', re: new RE2('(/subscriptions/[a-f0-9-]+/resourceGroups/[a-zA-Z0-9_-]+/providers/[a-zA-Z0-9./_-]+)', 'g') },
  // IPv4
  { key: 'ip_address', re: new RE2('\\b((?:\\d{1,3}\\.){3}\\d{1,3})\\b', 'g') },
  // E.164-ish phone (loose; require leading + or 7+ digits run)
  { key: 'phone', re: new RE2('(\\+\\d{7,15})\\b', 'g') },
  // Generic prefix_id pattern (Stripe acct_*, ch_*, etc. — and our own pas_*, agt_*, op_*, pc_*, ia_*, ses_*)
  { key: 'account_id', re: new RE2('\\b([a-z][a-z0-9]{1,12}_[A-Za-z0-9_-]{6,})\\b', 'g') },
  // Unix-ish file path (absolute), or Windows path. Conservative: must have at least one segment after root.
  { key: 'file_path', re: new RE2('((?:/[A-Za-z0-9._-]+){2,}|[A-Z]:\\\\(?:[A-Za-z0-9._-]+\\\\)+[A-Za-z0-9._-]+)', 'g') },
];

// ─── Financial catalog (opt-in, see ExtractEntitiesOptions.financial) ─
//
// Linear-time RE2 patterns, like the rest of the catalog. Three money shapes:
// a currency marker before the figure, a marker after it, and a bare figure
// that is unmistakably money-formatted (thousands grouping, or exactly two
// decimals). A bare integer such as `2026` is never money from text: it is
// far more often a year, a count or an id.
const CURRENCY_CODES = 'USD|EUR|GBP|SEK|NOK|DKK|CHF|JPY|CAD|AUD|NZD|INR|SGD|HKD';
const CURRENCY_SYMBOLS = '[$€£¥₹]';
const AMOUNT_CORE = String.raw`(?:\d{1,3}(?:[,.'\x{00A0}\x{202F}]\d{3})+(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?)`;
const FINANCIAL_PATTERNS: Array<{ key: 'money_amount' | 'account_number'; re: RE2 }> = [
  { key: 'money_amount', re: new RE2(String.raw`(?:${CURRENCY_SYMBOLS}|\b(?:${CURRENCY_CODES})\b)\s?-?${AMOUNT_CORE}`, 'g') },
  { key: 'money_amount', re: new RE2(String.raw`${AMOUNT_CORE}\s?(?:${CURRENCY_SYMBOLS}|\b(?:${CURRENCY_CODES}|kr)\b)`, 'g') },
  { key: 'money_amount', re: new RE2(String.raw`\b(?:\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d{1,3}(?:\.\d{3})+,\d{1,2}|\d+\.\d{2})\b`, 'g') },
  // IBAN: country, check digits, then 11-30 alphanumerics, optionally grouped by four.
  { key: 'account_number', re: new RE2(String.raw`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`, 'g') },
  // Domestic account and routing numbers: a run of 8 to 17 digits.
  { key: 'account_number', re: new RE2(String.raw`\b\d{8,17}\b`, 'g') },
];

/** Money with fewer digits than this is too common to be evidence of anything. */
const MIN_MONEY_DIGITS = 4;

/**
 * One canonical form for an amount however it was written: `$12,345.67`,
 * `12.345,67 EUR` and the JSON number `12345.67` all become `12345.67`;
 * `$20,000.00` and `20000` both become `20000`. Sign and currency are
 * dropped (a balance and its negative are the same figure for this purpose).
 * Returns null when the figure has fewer than four digits, counting cents.
 */
export function canonicalMoneyAmount(raw: string): string | null {
  const span = raw.match(/\d[\d.,'\u00A0\u202F]*\d|\d/);
  if (!span) return null;
  const s = span[0].replace(/['\u00A0\u202F]/g, '');
  const lastDot = s.lastIndexOf('.');
  const lastComma = s.lastIndexOf(',');
  const lastSep = Math.max(lastDot, lastComma);
  let integer = s;
  let fraction = '';
  if (lastSep >= 0) {
    const tail = s.slice(lastSep + 1);
    const sep = s[lastSep]!;
    const otherSeparator = sep === '.' ? lastComma : lastDot;
    const occurrences = s.split(sep).length - 1;
    // One or two digits after the LAST separator is a decimal part when the
    // other separator is also present (`1.234,56`) or this one appears once
    // (`1234.56`). Three digits after it is thousands grouping (`12,345`).
    if (tail.length >= 1 && tail.length <= 2 && (otherSeparator >= 0 || occurrences === 1)) {
      integer = s.slice(0, lastSep);
      fraction = tail;
    }
  }
  integer = integer.replace(/[.,]/g, '').replace(/^0+(?=\d)/, '');
  if (!/^\d+$/.test(integer)) return null;
  fraction = fraction.padEnd(2, '0');
  if (fraction === '00') fraction = '';
  const digits = (integer === '0' ? 0 : integer.length) + fraction.length;
  if (digits < MIN_MONEY_DIGITS) return null;
  return fraction ? `${integer}.${fraction}` : integer;
}

/** Canonical amounts a JSON number may denote. An integer is read both as
 * major units and as minor units (Stripe and others send cents), so
 * `1234567` also yields `12345.67`. */
function moneyFromNumber(value: number): string[] {
  if (!Number.isFinite(value)) return [];
  const abs = Math.abs(value);
  if (abs >= 1e13) return [];
  const asMajor = canonicalFromCents(Math.round(abs * 100));
  const out = asMajor ? [asMajor] : [];
  if (Number.isInteger(value)) {
    const asMinor = canonicalFromCents(abs);
    if (asMinor && asMinor !== asMajor) out.push(asMinor);
  }
  return out;
}

function canonicalFromCents(cents: number): string | null {
  const integer = Math.floor(cents / 100).toString();
  const fraction = (cents % 100).toString().padStart(2, '0');
  return canonicalMoneyAmount(fraction === '00' ? integer : `${integer}.${fraction}`);
}

function canonicalAccountNumber(raw: string): string | null {
  const compact = raw.replace(/\s+/g, '').toUpperCase();
  if (/^\d{8,17}$/.test(compact)) return compact;
  if (/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) return compact;
  return null;
}

/** The recorded form: a domain-separated one-way digest, never the figure. */
function financialDigest(kind: 'money_amount' | 'account_number', canonical: string): string {
  const prefix = kind === 'money_amount' ? 'money' : 'acct';
  return `${prefix}:${createHash('sha256').update(`stack:${kind}:v1:${canonical}`).digest('hex').slice(0, 24)}`;
}

// ─── Public API ───────────────────────────────────────────────────

/**
 * Extract entity references from a JSON-like input. Walks the input
 * recursively up to `maxDepth`, applies the regex catalog to every
 * string value encountered, dedupes by normalized form, caps at
 * `maxEntities`.
 *
 * Returns entries in insertion order (first occurrence wins). The
 * caller projects these into the `EntityObservationClaim.entities` +
 * `entity_types` arrays before signing.
 */
export function extractEntities(
  input: unknown,
  opts: ExtractEntitiesOptions = {},
): ExtractedEntity[] {
  const maxEntities = opts.maxEntities ?? DEFAULT_MAX_ENTITIES;
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;

  // Map keyed on `${entity}::${entity_type}` so the same string can
  // legitimately appear as more than one type (rare; treat as
  // separate entries). This still dedupes within (entity, type).
  const seen = new Map<string, ExtractedEntity>();

  const financial = opts.financial === true;
  const addFinancial = (kind: 'money_amount' | 'account_number', canonical: string, path: string): boolean => {
    const entity = financialDigest(kind, canonical);
    const dedupKey = `${entity}::${kind}`;
    if (!seen.has(dedupKey)) seen.set(dedupKey, { entity, entity_type: kind, source_path: path });
    return seen.size < maxEntities;
  };

  walk(input, '', 0, maxDepth, (text, path, numeric) => {
    if (seen.size >= maxEntities) return false;
    if (financial && numeric !== undefined) {
      for (const canonical of moneyFromNumber(numeric)) {
        if (!addFinancial('money_amount', canonical, path)) return false;
      }
    }
    // file_path is overgreedy on URL strings (matches the path-part of
    // an embedded URL as a unix-style file path). When the text is a
    // URL — detectable by `://` — skip file_path; url_host + url_path
    // handle that string instead.
    const looksLikeUrl = text.includes('://');
    for (const { key, re } of PATTERNS) {
      if (looksLikeUrl && key === 'file_path') continue;
      // RE2 doesn't support iterative `.exec`; use match-all.
      const matches = text.match(re);
      if (!matches) continue;
      for (const raw of matches) {
        const entity = normalize(raw, key);
        if (!entity) continue;
        const dedupKey = `${entity}::${key}`;
        if (seen.has(dedupKey)) continue;
        seen.set(dedupKey, { entity, entity_type: key, source_path: path });
        if (seen.size >= maxEntities) return false;
        // For url_host pattern, also emit url_path for the path
        // portion so a path-prefix policy can match. Cheap.
        if (key === 'url_host') {
          const pathSegment = extractUrlPath(raw);
          if (pathSegment) {
            const pathKey = `${pathSegment}::url_path`;
            if (!seen.has(pathKey)) {
              seen.set(pathKey, { entity: pathSegment, entity_type: 'url_path', source_path: path });
              if (seen.size >= maxEntities) return false;
            }
          }
        }
      }
    }
    if (financial) {
      for (const { key, re } of FINANCIAL_PATTERNS) {
        const matches = text.match(re);
        if (!matches) continue;
        for (const raw of matches) {
          const canonical = key === 'money_amount' ? canonicalMoneyAmount(raw) : canonicalAccountNumber(raw);
          if (canonical && !addFinancial(key, canonical, path)) return false;
        }
      }
    }
    return true;
  });

  return Array.from(seen.values());
}

// ─── Internals ────────────────────────────────────────────────────

function walk(
  value: unknown,
  path: string,
  depth: number,
  maxDepth: number,
  visit: (text: string, path: string, numeric?: number) => boolean,
): boolean {
  if (depth > maxDepth) return true;
  if (value === null || value === undefined) return true;

  if (typeof value === 'string') {
    return visit(value, path || '$');
  }
  if (typeof value === 'number') {
    // Numbers can carry account ids encoded as digits; convert to
    // string and visit so the regex catalog runs. The value itself rides
    // along so the financial catalog can read a balance sent as a number.
    return visit(String(value), path || '$', value);
  }
  if (typeof value === 'boolean') {
    return visit(String(value), path || '$');
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const cont = walk(value[i], `${path}[${i}]`, depth + 1, maxDepth, visit);
      if (!cont) return false;
    }
    return true;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const subPath = path ? `${path}.${k}` : k;
      const cont = walk(v, subPath, depth + 1, maxDepth, visit);
      if (!cont) return false;
    }
    return true;
  }
  return true;
}

function normalize(raw: string, kind: EntityType): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  // For URL host pattern, the regex captured `https?://host[:port]`.
  // Normalize to just the lowercased host (drop scheme + port). The
  // path portion is emitted separately as `url_path`.
  if (kind === 'url_host') {
    try {
      const parsed = new URL(trimmed);
      return parsed.host.toLowerCase();
    } catch {
      return trimmed.toLowerCase();
    }
  }
  // Email: lowercase the whole address.
  if (kind === 'email') return trimmed.toLowerCase();
  // Everything else: lowercase only if the type isn't case-sensitive.
  // ARNs + GCP/Azure resource paths are case-sensitive in places;
  // keep them as-is. account_id, file_path, phone, ip_address stay
  // as the source text (already trimmed).
  return trimmed;
}

function extractUrlPath(rawUrl: string): string | null {
  try {
    const u = new URL(rawUrl);
    const p = u.pathname;
    if (!p || p === '/') return null;
    return p.toLowerCase().replace(/\/$/, '');
  } catch {
    return null;
  }
}
