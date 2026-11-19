// Provenance that survives a hand-off between agents.
//
// THE CASE. A "CFO" agent reads bank balances and hands its audit to a sibling
// agent that can post to Slack. Each agent stays inside its own scope; the
// leak is the content crossing from one to the other. The data-flow rule
// keyed on what THIS agent read cannot see that, because the Slack agent
// never read the bank.
//
// So a hand-off carries where its content came from. At deposit the payload
// is matched against what the depositor's Mission has read; the ORIGINAL
// source services are recorded (never "stack:dropoff", which no operator
// would think to name in allow_data_from). At collection the collector's
// Mission records those same items as read from those same sources. The
// Slack agent posting the balance is then refused exactly as the CFO agent
// would have been.
//
// Item-level attribution is kept, not just a source list, so a hand-off that
// mixes bank figures with the Slack agent's own channel names does not taint
// the channel names. Only one-way digests are stored: an entity becomes a
// truncated SHA-256, and content fingerprints are already hashes.
//
// WHAT IS LEFT UNATTRIBUTED. Payload content that matches nothing the
// depositor read (its own writing) carries no source. Labelling it
// `agent:<id>` would refuse every hand-off of an agent's own words unless an
// operator declared a flow from that agent, which is a different rule
// (trust between agents) from the one this enforces (where service data may
// go). Counts of unattributed items are kept; the items are not.

import { createHash } from 'node:crypto';
import { extractEntities, type EntityType, type ExtractedEntity } from './entity-extraction.js';
import { collectStrings, contentFingerprints, indexObserved, type ObservedIndex, type ObservedItem } from './data-flow.js';

/** Bounds for fingerprinting a hand-off payload. Higher than the per-call
 * proxy bounds because a deposit is not on the per-request hot path, and an
 * unread tail is an unattributed tail. */
const PAYLOAD_MAX_ENTITIES = 2048;
const PAYLOAD_MAX_DEPTH = 8;
const PAYLOAD_MAX_CHARS = 512 * 1024;
const PAYLOAD_MAX_SHINGLES = 16_384;

/** Item maps stored on the drop-off row are capped; past the cap the record
 * is marked truncated and collection attributes the whole payload to every
 * matched source (fail closed). */
const MAX_STORED_ENTITY_KEYS = 4096;
const MAX_STORED_FINGERPRINTS = 16_384;

/** Observation claims carry at most this many items each (schema caps). */
const CLAIM_MAX_ENTITIES = 256;
const CLAIM_MAX_FINGERPRINTS = 512;

export interface DropoffProvenance {
  v: 1;
  /** How the sources were established. */
  method: 'mission_observations' | 'no_mission';
  /** The depositor's Mission the payload was matched against. */
  mission_id: string | null;
  /** Original services the payload's content was read from, sorted. */
  sources: string[];
  /** Entity digest -> sources. Dropped at collection. */
  entity_sources?: Record<string, string[]>;
  /** Content fingerprint -> sources. Dropped at collection. */
  fingerprint_sources?: Record<string, string[]>;
  /** True when the item maps hit their cap; collection then fails closed. */
  truncated?: boolean;
  /** How much of the payload matched nothing the depositor read. Counts only. */
  unattributed: { entities: number; fingerprints: number };
}

export interface PayloadFingerprint {
  entities: ExtractedEntity[];
  fingerprints: string[];
}

/** Deterministic: deposit and collection must derive the same items. */
export function fingerprintPayload(payload: unknown): PayloadFingerprint {
  const entities = extractEntities(payload, {
    financial: true,
    maxEntities: PAYLOAD_MAX_ENTITIES,
    maxDepth: PAYLOAD_MAX_DEPTH,
  });
  const text = collectStrings(payload).join(' ');
  const fingerprints = text
    ? contentFingerprints(text, { maxChars: PAYLOAD_MAX_CHARS, maxShingles: PAYLOAD_MAX_SHINGLES })
    : [];
  return { entities, fingerprints };
}

/** The stored key for an entity. One-way; the entity text is not kept. */
export function provenanceEntityKey(entity: string): string {
  return createHash('sha256').update(`stack:provenance-entity:v1:${entity.toLowerCase()}`).digest('hex').slice(0, 32);
}

/**
 * The form in which an entity is kept on the data trail when the content it
 * came from is the customer's own mail or texts: a prefixed one-way digest, so
 * the claim never holds an address, a name or an account id from a message. A
 * financial digest (`money:`, `acct:`) is already one and is left as it is.
 * The wall compares an outbound entity against both forms.
 */
export function trailEntityDigest(entity: string): string {
  return `h:${provenanceEntityKey(entity)}`;
}

/** An entity kept as a digest already: it is not hashed twice. */
function isDigestForm(entity: string): boolean {
  return entity.startsWith('money:') || entity.startsWith('acct:') || entity.startsWith('h:');
}

/** An extracted entity as the trail keeps it: itself if it is a digest, else its digest. */
export function trailEntity(entity: string): string {
  return isDigestForm(entity) ? entity : trailEntityDigest(entity);
}

/**
 * Whether an observed set already holds an entity, in either form the trail
 * has kept it in: as lowercase text (observations recorded before the trail
 * kept digests, and a Mission's declared counterparties) or as its digest.
 * The one comparison every "have we dealt with this counterparty before"
 * check makes, so a digest row and a text row both count.
 */
export function observedKnowsEntity(observed: ReadonlySet<string>, entity: string): boolean {
  return observed.has(entity.toLowerCase()) || observed.has(trailEntityDigest(entity));
}

/**
 * Match a hand-off payload against what the depositor's Mission has read.
 * Pure: the caller supplies the observations.
 */
export function attributePayload(input: {
  payload: unknown;
  missionId: string | null;
  observed: readonly ObservedItem[] | ObservedIndex;
}): DropoffProvenance {
  if (!input.missionId) {
    const { entities, fingerprints } = fingerprintPayload(input.payload);
    return {
      v: 1,
      method: 'no_mission',
      mission_id: null,
      sources: [],
      unattributed: { entities: entities.length, fingerprints: fingerprints.length },
    };
  }
  const index = Array.isArray(input.observed)
    ? indexObserved(input.observed as readonly ObservedItem[])
    : (input.observed as ObservedIndex);
  const { entities, fingerprints } = fingerprintPayload(input.payload);
  const sources = new Set<string>();
  const entitySources: Record<string, string[]> = {};
  const fingerprintSources: Record<string, string[]> = {};
  let entityKeys = 0;
  let fingerprintKeys = 0;
  let truncated = false;
  let unattributedEntities = 0;
  let unattributedFingerprints = 0;

  for (const candidate of entities) {
    const from = index.entities.get(candidate.entity.toLowerCase());
    if (!from || from.size === 0) {
      unattributedEntities++;
      continue;
    }
    for (const source of from) sources.add(source);
    if (entityKeys >= MAX_STORED_ENTITY_KEYS) {
      truncated = true;
      continue;
    }
    entitySources[provenanceEntityKey(candidate.entity)] = [...from].sort();
    entityKeys++;
  }
  for (const fingerprint of fingerprints) {
    const from = index.shingles.get(fingerprint);
    if (!from || from.size === 0) {
      unattributedFingerprints++;
      continue;
    }
    for (const source of from) sources.add(source);
    if (fingerprintKeys >= MAX_STORED_FINGERPRINTS) {
      truncated = true;
      continue;
    }
    fingerprintSources[fingerprint] = [...from].sort();
    fingerprintKeys++;
  }

  return {
    v: 1,
    method: 'mission_observations',
    mission_id: input.missionId,
    sources: [...sources].sort(),
    entity_sources: entitySources,
    fingerprint_sources: fingerprintSources,
    ...(truncated ? { truncated: true } : {}),
    unattributed: { entities: unattributedEntities, fingerprints: unattributedFingerprints },
  };
}

/** One observation to record on the collector, per original source. */
export interface InheritedObservation {
  source: string;
  entities: string[];
  entity_types: EntityType[];
  fingerprints: string[];
}

/**
 * At collection: which of the payload's items came from which source, ready
 * to record on the collector's Mission. Chunked to the observation claim's
 * size caps.
 *
 * Fails closed. If the record is truncated, or a source recorded at deposit
 * no longer matches any item here (the item maps were lost, or extraction
 * changed between deposit and collection), every item of the payload is
 * attributed to that source rather than letting it drop.
 */
export function inheritedObservations(payload: unknown, provenance: unknown): InheritedObservation[] {
  const record = parseProvenance(provenance);
  if (!record || record.sources.length === 0) return [];
  const { entities, fingerprints } = fingerprintPayload(payload);
  const perSource = new Map<string, { entities: ExtractedEntity[]; fingerprints: string[] }>();
  const bucket = (source: string) => {
    let entry = perSource.get(source);
    if (!entry) {
      entry = { entities: [], fingerprints: [] };
      perSource.set(source, entry);
    }
    return entry;
  };

  const entityMap = record.entity_sources ?? {};
  const fingerprintMap = record.fingerprint_sources ?? {};
  for (const candidate of entities) {
    for (const source of entityMap[provenanceEntityKey(candidate.entity)] ?? []) bucket(source).entities.push(candidate);
  }
  for (const fingerprint of fingerprints) {
    for (const source of fingerprintMap[fingerprint] ?? []) bucket(source).fingerprints.push(fingerprint);
  }
  for (const source of record.sources) {
    const entry = perSource.get(source);
    const empty = !entry || (entry.entities.length === 0 && entry.fingerprints.length === 0);
    if (record.truncated || empty) {
      perSource.set(source, { entities: [...entities], fingerprints: [...fingerprints] });
    }
  }

  const out: InheritedObservation[] = [];
  for (const [source, entry] of [...perSource.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (!record.sources.includes(source)) continue;
    const chunks = Math.max(
      Math.ceil(entry.entities.length / CLAIM_MAX_ENTITIES),
      Math.ceil(entry.fingerprints.length / CLAIM_MAX_FINGERPRINTS),
      1,
    );
    for (let i = 0; i < chunks; i++) {
      const slice = entry.entities.slice(i * CLAIM_MAX_ENTITIES, (i + 1) * CLAIM_MAX_ENTITIES);
      const prints = entry.fingerprints.slice(i * CLAIM_MAX_FINGERPRINTS, (i + 1) * CLAIM_MAX_FINGERPRINTS);
      if (slice.length === 0 && prints.length === 0) continue;
      out.push({
        source,
        entities: slice.map((e) => e.entity),
        entity_types: slice.map((e) => e.entity_type),
        fingerprints: prints,
      });
    }
  }
  return out;
}

/** The sources recorded on a stored provenance value, or [] when none. */
export function provenanceSources(provenance: unknown): string[] {
  return parseProvenance(provenance)?.sources ?? [];
}

function parseProvenance(value: unknown): DropoffProvenance | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Partial<DropoffProvenance>;
  if (record.v !== 1 || !Array.isArray(record.sources)) return null;
  const sources = record.sources.filter((s): s is string => typeof s === 'string' && s.length > 0 && s.length <= 128);
  return {
    v: 1,
    method: record.method === 'no_mission' ? 'no_mission' : 'mission_observations',
    mission_id: typeof record.mission_id === 'string' ? record.mission_id : null,
    sources,
    entity_sources: stringListMap(record.entity_sources),
    fingerprint_sources: stringListMap(record.fingerprint_sources),
    ...(record.truncated === true ? { truncated: true } : {}),
    unattributed: {
      entities: Number(record.unattributed?.entities ?? 0) || 0,
      fingerprints: Number(record.unattributed?.fingerprints ?? 0) || 0,
    },
  };
}

function stringListMap(value: unknown): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const [key, list] of Object.entries(value as Record<string, unknown>)) {
    if (!Array.isArray(list)) continue;
    out[key] = list.filter((s): s is string => typeof s === 'string');
  }
  return out;
}
