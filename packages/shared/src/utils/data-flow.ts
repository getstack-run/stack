// Data carries its origin.
//
// THE CASE THIS EXISTS FOR. An agent is allowed one action: append a line to
// the guestbook. Doing that means reading the guestbook, so the names pass
// through it legitimately. Nothing then stopped it mailing those names to
// someone else. Both calls were individually within scope; the violation was
// the movement between them.
//
// So the rule is not about recipients. It is: content observed from service
// A may appear only in calls to service A, unless the passport declares a
// flow A to B.
//
// WHY TWO TIERS. The entity catalogue recognises emails, URLs, account ids,
// paths and phone numbers. It does not recognise `Alice Johnson`. The
// motivating example is a list of names, so an entity-only check
// would miss precisely the case that prompted the work. Content fingerprints
// cover ordinary prose by matching overlapping word runs.
//
// WHERE THIS STOPS, and it is stated in the docs as well as here: both tiers
// match COPIED text. If the model retells the guestbook in its own words,
// neither fires. Verbatim and near-verbatim reuse is caught; semantic reuse
// is not. That is a real ceiling, not a detail to bury.

import { createHash } from 'node:crypto';

/** Words per shingle. Five is long enough to be rare by chance in ordinary
 * prose, short enough to survive light editing around it. */
const SHINGLE_WORDS = 5;

/** Bytes of source text considered. Bounds cost on a 10 MB response. */
const DEFAULT_MAX_CHARS = 64 * 1024;

/** Fingerprints kept per source. Bounds what is carried per passport. */
const DEFAULT_MAX_SHINGLES = 512;

/** Distinct matching runs before copied prose is refused. Runs overlap, so
 * this is roughly an eight-word verbatim span. */
const DEFAULT_SHINGLE_THRESHOLD = 4;

export interface FingerprintOptions {
  maxChars?: number;
  maxShingles?: number;
}

/**
 * Overlapping word-run fingerprints of a piece of text.
 *
 * Normalisation is deliberately aggressive — lowercased, punctuation
 * stripped, whitespace collapsed — so that re-quoting the same content with
 * different spacing or casing still matches. It is NOT stemmed: this is a
 * copy detector, not a similarity engine.
 */
export function contentFingerprints(text: string, opts: FingerprintOptions = {}): string[] {
  const maxChars = opts.maxChars ?? DEFAULT_MAX_CHARS;
  const maxShingles = opts.maxShingles ?? DEFAULT_MAX_SHINGLES;

  const words = text
    .slice(0, maxChars)
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s@._-]/gu, ' ')
    .split(/\s+/)
    .filter(Boolean);

  if (words.length < SHINGLE_WORDS) return [];

  const out = new Set<string>();
  for (let i = 0; i + SHINGLE_WORDS <= words.length; i++) {
    out.add(hashShingle(words.slice(i, i + SHINGLE_WORDS).join(' ')));
    if (out.size >= maxShingles) break;
  }
  return [...out];
}

/** Short digest — 8 bytes is ample to make an accidental collision
 * vanishingly unlikely across a single passport's lifetime, and keeps what
 * we carry per passport small. */
function hashShingle(shingle: string): string {
  return createHash('sha256').update(shingle).digest('hex').slice(0, 16);
}

/** Collect every string in a JSON-ish value, so free-text fields anywhere in
 * a request body are fingerprinted, not just the ones we thought of. */
export function collectStrings(value: unknown, depth = 0, out: string[] = []): string[] {
  if (depth > 8) return out;
  if (typeof value === 'string') {
    out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, depth + 1, out);
    return out;
  }
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) {
      collectStrings(v, depth + 1, out);
    }
  }
  return out;
}

/** Prefix of a service connection id, which is what follows the `@` of a source label. */
const CONNECTION_ID_PREFIX = 'scon_';

/**
 * The longest service name a source label carries as it is. `source_service` of the published observation claim
 * holds 128 characters, and a label is `service@` + a connection id (`scon_` + 21 characters, 26 in all), so a
 * service name of up to 128 - 1 - 26 = 101 characters fits whole. This is 100: one character short of that, so
 * the label is never at the edge of the limit. A custom provider id is `custom_` and a slug of up to 100
 * characters (107), and a longer name from a connect link is longer still.
 */
export const FLOW_SERVICE_KEY_MAX_CHARS = 100;

/** Prefix of the stable key of a long service name. `~` is outside a provider id (letters, digits and underscores), so no provider id reads as a key. */
const FLOW_SERVICE_KEY_PREFIX = 'custom~';

/** Hex characters of the digest in a key: 160 bits, so two names never share one by chance. */
const FLOW_SERVICE_KEY_HEX_CHARS = 40;

/**
 * The name a service goes by inside a source label: the service itself, or, when it is longer than
 * `FLOW_SERVICE_KEY_MAX_CHARS`, `custom~` and the first 40 hex characters of the SHA-256 of the whole name. A key
 * is stable (the same service always has the same one) and is never a cut-off name, so two long names that start
 * alike stay two sources. Only a custom provider is ever that long.
 */
export function flowServiceKey(service: string): string {
  if (service.length <= FLOW_SERVICE_KEY_MAX_CHARS) return service;
  return `${FLOW_SERVICE_KEY_PREFIX}${createHash('sha256').update(service).digest('hex').slice(0, FLOW_SERVICE_KEY_HEX_CHARS)}`;
}

/**
 * The label content is recorded under: the service alone, or `service@scon_...`
 * when the connection it was read through is known. A provider id never holds
 * `@` (catalogue providers and sanitised custom names are letters, digits and
 * underscores) and a connection id never does either, so the label parses
 * back without ambiguity. With a connection the service part is its
 * `flowServiceKey`, so the label stays within the claim's 128 characters; a
 * label with no connection is the service as it stands.
 */
export function flowSourceLabel(service: string, connectionId?: string | null): string {
  return connectionId ? `${flowServiceKey(service)}@${connectionId}` : service;
}

/**
 * The service and connection a source label names. Splits on the LAST `@`, and
 * only when what follows is a connection id; any other label (an account's
 * mail, a legacy bare service) is the service as it stands.
 */
export function parseFlowSource(label: string): { service: string; connectionId: string | null } {
  const at = label.lastIndexOf('@');
  if (at > 0 && label.startsWith(CONNECTION_ID_PREFIX, at + 1)) {
    return { service: label.slice(0, at), connectionId: label.slice(at + 1) };
  }
  return { service: label, connectionId: null };
}

/** Something the agent has previously observed, and where it came from. */
export interface ObservedItem {
  /** Normalised entity string, or a shingle hash. */
  value: string;
  kind: 'entity' | 'shingle';
  /** The source label this was read from: a service, or `service@connection` (`flowSourceLabel`). */
  service: string;
}

/** A movement the operator has explicitly permitted. */
export interface DeclaredFlow {
  from: string;
  to: string;
}

export interface DataFlowInput {
  /** Service this request is going to. */
  destinationService: string;
  /** The connection of that service the request runs on, when it has one. */
  destinationConnectionId?: string | null;
  /** Entities extracted from the OUTBOUND request. */
  outboundEntities: string[];
  /** Free text carried by the outbound request. */
  outboundText: string[];
  /** What the agent has read, with origin. */
  observed: ObservedItem[];
  /** Flows the passport permits. */
  declaredFlows?: DeclaredFlow[];
  /**
   * Distinct shingle matches required before prose counts as carried over.
   *
   * Runs overlap, so N matching shingles means roughly an N+4 word verbatim
   * span. The default of 4 therefore asks for about eight consecutive words
   * copied from somewhere else before it will refuse.
   *
   * The known false-positive mode is boilerplate: a long stock courtesy that
   * appears both in something the agent read and in what it sends will trip
   * this. Raising the threshold trades that against a shorter quote getting
   * through. An exact entity match needs no threshold at all — an account id
   * read from one service and sent to another is not a coincidence.
   */
  shingleThreshold?: number;
}

export interface DataFlowViolation {
  /** The service the content was read from (a source label without its connection). */
  sourceService: string;
  /** The connection it was read through, when the label names one. */
  sourceConnectionId: string | null;
  destinationService: string;
  /** How it was recognised. */
  via: 'entity' | 'content';
  /** For an entity match, the entity. For prose, never the text itself —
   * only how many runs matched, because the text is the caller's data. */
  detail: string;
}

/**
 * What the agent has read, indexed by value. One value can have been read
 * from more than one service, so each maps to the SET of sources: keeping
 * only the last one seen would let a balance read from Mercury and later
 * echoed by Slack count as "from Slack" and pass straight back out to Slack.
 */
export interface ObservedIndex {
  entities: Map<string, Set<string>>;
  shingles: Map<string, Set<string>>;
}

export function indexObserved(observed: readonly ObservedItem[]): ObservedIndex {
  const entities = new Map<string, Set<string>>();
  const shingles = new Map<string, Set<string>>();
  for (const item of observed) {
    const map = item.kind === 'entity' ? entities : shingles;
    const key = item.kind === 'entity' ? item.value.toLowerCase() : item.value;
    let sources = map.get(key);
    if (!sources) {
      sources = new Set();
      map.set(key, sources);
    }
    sources.add(item.service);
  }
  return { entities, shingles };
}

/** How much of one source's content an outbound request carries. */
export interface SourceMatch {
  source: string;
  /** Distinct outbound entities that were read from this source. */
  entityHits: number;
  /** The first such entity, kept only for the violation detail. */
  firstEntity: string | null;
  /** Distinct outbound content runs that were read from this source. */
  contentHits: number;
}

export interface SourceMatchInput {
  outboundEntities: readonly string[];
  outboundText: readonly string[];
  observed: readonly ObservedItem[] | ObservedIndex;
}

/**
 * Every source whose content this outbound payload carries, with how it was
 * recognised. Pure, and never returns the content itself.
 */
export function matchObservedSources(input: SourceMatchInput): SourceMatch[] {
  const index = isObservedIndex(input.observed) ? input.observed : indexObserved(input.observed);
  const bySource = new Map<string, SourceMatch>();
  const entry = (source: string) => {
    let match = bySource.get(source);
    if (!match) {
      match = { source, entityHits: 0, firstEntity: null, contentHits: 0 };
      bySource.set(source, match);
    }
    return match;
  };

  const seenEntities = new Set<string>();
  for (const raw of input.outboundEntities) {
    const entity = raw.toLowerCase();
    if (seenEntities.has(entity)) continue;
    seenEntities.add(entity);
    for (const source of index.entities.get(entity) ?? []) {
      const match = entry(source);
      match.entityHits++;
      match.firstEntity ??= raw;
    }
  }

  if (index.shingles.size > 0) {
    const seenShingles = new Set<string>();
    for (const text of input.outboundText) {
      for (const shingle of contentFingerprints(text)) {
        if (seenShingles.has(shingle)) continue;
        seenShingles.add(shingle);
        for (const source of index.shingles.get(shingle) ?? []) entry(source).contentHits++;
      }
    }
  }
  return [...bySource.values()];
}

/**
 * The sources an outbound payload counts as carrying, by the same test the
 * rule refuses on: one exact entity, or `threshold` distinct content runs.
 * Used to pass provenance ON, e.g. an LLM response inherits the sources its
 * prompt carried.
 */
export function carriedSources(matches: readonly SourceMatch[], threshold = DEFAULT_SHINGLE_THRESHOLD): string[] {
  return matches
    .filter((m) => m.entityHits > 0 || m.contentHits >= threshold)
    .map((m) => m.source)
    .sort();
}

/**
 * Does this outbound request carry content the agent read somewhere else?
 *
 * Returns the first violation, or null when the request carries nothing from
 * another service. Content read from the SAME service it is going back to is
 * always fine — that is ordinary read-then-write — unless both sides name a
 * connection and they are different connections of that service: two
 * connections count as two sources.
 */
export function evaluateDataFlow(input: DataFlowInput): DataFlowViolation | null {
  return evaluateSourceMatches(
    input.destinationService,
    matchObservedSources(input),
    input.declaredFlows,
    input.shingleThreshold,
    input.destinationConnectionId,
  );
}

/**
 * May content recorded under this source label go to the destination? It may when it was read from the
 * destination's own service (another connection of it only when a flow names it), or when a declared flow into
 * the destination names the label (one connection) or its service (all of its connections). Services are
 * compared by their `flowServiceKey`, because that is what a label with a connection carries; a declared `from`
 * may be written with the service's name or its key.
 */
export function flowSourceAllowed(
  label: string,
  destinationService: string,
  destinationConnectionId: string | null | undefined,
  declaredFlows: readonly DeclaredFlow[],
): boolean {
  const source = parseFlowSource(label);
  const destinationKey = flowServiceKey(destinationService);
  if (
    (source.service === destinationKey || source.service === destinationService)
    && (!source.connectionId || !destinationConnectionId || source.connectionId === destinationConnectionId)
  ) return true;
  return declaredFlows.some((flow) => {
    if (flow.to !== destinationService && flow.to !== destinationKey) return false;
    const declared = parseFlowSource(flow.from);
    if (flow.from === label) return true;
    const sameService = flowServiceKey(declared.service) === source.service || declared.service === source.service;
    return sameService && (declared.connectionId === null || declared.connectionId === source.connectionId);
  });
}

/** The decision half of `evaluateDataFlow`, for a caller that already matched. */
export function evaluateSourceMatches(
  destinationService: string,
  matches: readonly SourceMatch[],
  declaredFlows: readonly DeclaredFlow[] = [],
  shingleThreshold = DEFAULT_SHINGLE_THRESHOLD,
  destinationConnectionId?: string | null,
): DataFlowViolation | null {
  const allowedFrom = (label: string) => flowSourceAllowed(label, destinationService, destinationConnectionId, declaredFlows);

  // Tier one: exact entity reuse. Decisive on a single match — an account id
  // or an email address read from one service and sent to another is not a
  // coincidence.
  for (const match of matches) {
    if (match.entityHits > 0 && !allowedFrom(match.source)) {
      return {
        sourceService: parseFlowSource(match.source).service,
        sourceConnectionId: parseFlowSource(match.source).connectionId,
        destinationService,
        via: 'entity',
        detail: match.firstEntity ?? '',
      };
    }
  }

  // Tier two: copied prose. This is what catches a list of ordinary names,
  // which the entity catalogue cannot see at all.
  for (const match of matches) {
    if (match.contentHits >= shingleThreshold && !allowedFrom(match.source)) {
      return {
        sourceService: parseFlowSource(match.source).service,
        sourceConnectionId: parseFlowSource(match.source).connectionId,
        destinationService,
        via: 'content',
        detail: `${match.contentHits} matching content runs`,
      };
    }
  }

  return null;
}

function isObservedIndex(value: SourceMatchInput['observed']): value is ObservedIndex {
  return !Array.isArray(value);
}
