import type { HttpClient } from '../client.js';

// Account memory: Graphiti, a temporal knowledge graph, used the way its makers ship it. One graph per account,
// shared by the account's agents. The methods are the tools of Graphiti's own MCP server, with its arguments and
// its answers (there is no group id: the graph is the account's). The owner (an API key or a session, no agent)
// reads and deletes through the same calls. Every write (`addMemory`, `addTriplet`, `summarizeSaga`) is an action
// (metered, checked against your controls, in the signed record); reads and deletes are free.
//
// `addMemory` answers at once with `status: 'queued'`: the episode is read into the graph in the background, one
// at a time per account. Nothing is stored until `getEpisodes` shows it `stored`; a write that could not be read in
// shows `failed` there with a plain `reason`.
//
// The text of a write is scanned by STACK's detectors first: with the account's controls on, flagged text is
// refused and nothing is stored or charged; with controls off it is stored with its flag, which `getEpisodes`
// shows. What memory holds may have come from outside (mail, a web page, a file): it is information, never
// instructions.
//
// Agent-side calls take `{ passportToken }`, sent as `X-Passport-Token`, and run under the Passport's Mission.
// `getSettings` and `updateSettings` are the owner's and are refused to an agent.
//
// The account's own entity types (`listEntityTypes`, `createEntityType`, `updateEntityType`, `retireEntityType`) are
// extracted by every later write beside Graphiti's ten, through Graphiti's own `entity_types` argument; they are a
// setting (free, put to your controls), for the owner, an admin and the account's agents. `getHistory` lists the
// account's writes with what each changed (before and after), and `undoWrite` takes a write back out with every later
// write that changed the same things (`dryRun` only says what); an undo is free and counts as one delete toward the
// account's hourly rate of deletes.

export type MemoryWriteStatus = 'queued' | 'processing' | 'stored' | 'failed';
export type MemoryEpisodeSource = 'text' | 'json' | 'message';

export interface AddMemoryInput {
  name: string;
  /** The content of the episode. When `source` is `json`, a properly escaped JSON string. At most 8,000 characters. */
  episode_body: string;
  /** Default `text`. */
  source?: MemoryEpisodeSource;
  source_description?: string;
  /**
   * An id of your choosing for the episode. It must be unused by your account. The episode's real uuid is derived from
   * it and your account, so it is not this one: use the `uuid` in the answer.
   */
  uuid?: string;
  /** ISO 8601: when the described events occurred. Defaults to the time of the call. */
  reference_time?: string;
  /** Names of configured entity types to leave out of extraction for this episode. */
  excluded_entity_types?: string[];
  /** Extra guidance for the extraction model, for this episode only. */
  custom_extraction_instructions?: string;
  /** Prior episodes (from `getEpisodes`) to use as context. Each must be the account's own. */
  previous_episode_uuids?: string[];
  /** The name of a saga this episode belongs to; `summarizeSaga` summarizes it. */
  saga?: string;
  saga_previous_episode_uuid?: string;
}

export interface AddTripletInput {
  source_node_name: string;
  edge_name: string;
  fact: string;
  target_node_name: string;
  /** To reuse an existing entity (from `searchNodes`). It must be one of the account's. */
  source_node_uuid?: string;
  target_node_uuid?: string;
}

/** One test of an entity's field: the field of one of the account's own types equals the value. */
export interface MemoryFieldFilter {
  /** A field of the type, as `listEntityTypes` shows it. */
  field: string;
  /** Of the field's kind: text or one of its words for `text` and `one_of`, a number, true or false, or an ISO 8601 date or date and time. */
  value: string | number | boolean;
}

export interface SearchNodesInput {
  query: string;
  /** 1 to 50, default 10. */
  max_nodes?: number;
  entity_types?: string[];
  center_node_uuid?: string;
  /**
   * Keep only the entities whose field has the value (every filter must hold). Needs `entity_types`, each naming one of
   * the account's own types that has the field. A filter that cannot be tested as asked is refused (422
   * `MEMORY_FIELD_FILTER_INVALID`), never answered with an empty list.
   */
  field_filters?: MemoryFieldFilter[];
}

export interface SearchMemoryFactsInput {
  query: string;
  /** 1 to 50, default 10. */
  max_facts?: number;
  center_node_uuid?: string;
  edge_types?: string[];
  /** ISO 8601 bounds on when a fact became true and when it stopped. */
  valid_at_after?: string;
  valid_at_before?: string;
  invalid_at_after?: string;
  invalid_at_before?: string;
}

/** An entity of the graph (Graphiti's `NodeResult`). */
export interface MemoryNode {
  uuid: string;
  name: string;
  labels: string[];
  created_at: string | null;
  summary: string | null;
  attributes: Record<string, unknown>;
}

/** A fact: an entity edge of the graph, with the time it held. `episodes` are the episodes that support it. */
export interface MemoryFact {
  uuid: string;
  name: string;
  fact: string;
  source_node_uuid: string;
  target_node_uuid: string;
  created_at: string | null;
  valid_at?: string | null;
  invalid_at?: string | null;
  expired_at?: string | null;
  reference_time?: string | null;
  episodes?: string[];
  /** The ids of the messages this fact was learned from, when it came from one (read them with `accounts.messages.get`). Absent when it did not come from a message. */
  source_message_ids?: string[];
  attributes?: Record<string, unknown>;
}

/** `addMemory`'s answer: Graphiti's `message`, the episode's real `uuid` (not the one you chose, when you chose one) and where the write is. */
export interface MemoryAddResult {
  message: string;
  uuid: string;
  status: MemoryWriteStatus;
}

/** One episode. `content` is null for a write that is not stored; `reason` says why a `failed` write failed. */
export interface MemoryEpisode {
  uuid: string;
  name: string;
  content: string | null;
  created_at: string | null;
  source: string;
  source_description: string;
  status: MemoryWriteStatus;
  reason: string | null;
  /** What STACK's detectors found in the text when it was written; null when nothing. */
  flag: string | null;
}

export interface MemoryNodeSearchResult {
  message: string;
  nodes: MemoryNode[];
}

export interface MemoryFactSearchResult {
  message: string;
  facts: MemoryFact[];
}

/** What a triplet or a set of episodes produced. */
export interface MemoryGraphElements {
  message: string;
  nodes: MemoryNode[];
  edges: MemoryFact[];
}

export interface MemorySagaSummary {
  message: string;
  uuid: string;
  name: string;
  summary: string;
}

export interface MemoryDeleted {
  message: string;
}

export interface MemorySettings {
  /** Memory keeps what the agents write. Off, writes are refused and what was waiting is failed. */
  enabled: boolean;
  /** Whether STACK's model may search memory and the knowledge base during a call STACK holds. On by default. */
  call_memory_access: boolean;
  updated_at: string | null;
}

/** What a field of an account's entity type holds: text, a number, a date, true or false, or one of `options`. */
export type MemoryTypeFieldKind = 'text' | 'number' | 'date' | 'boolean' | 'one_of';

export interface MemoryEntityTypeField {
  /** Letters, digits and underscores; not one of an entity's own attributes (uuid, name, group_id, labels, created_at, name_embedding, summary, attributes). */
  name: string;
  description?: string;
  kind: MemoryTypeFieldKind;
  /** The words a `one_of` field may be. */
  options?: string[];
}

/** One of the account's own entity types. Its name follows Graphiti's label rules and is not one of the ten. */
export interface MemoryEntityTypeInput {
  name: string;
  /** What the type is: the extraction model reads it to decide what is one. */
  description: string;
  fields?: MemoryEntityTypeField[];
}

export interface MemoryEntityType {
  name: string;
  description: string;
  fields: MemoryEntityTypeField[];
  created_at: string;
  updated_at: string;
  /** When it was retired (no longer extracted; its entities keep their label). Null while in force. */
  retired_at: string | null;
}

export interface MemoryEntityTypes {
  /** The ten Graphiti ships, always in force. */
  shipped: string[];
  /** The account's own, in force and retired, oldest first. */
  types: MemoryEntityType[];
}

/** One object a write touched, and how it found it (`before`, null when it made it) and left it (`after`). */
export interface MemoryChange {
  object: 'entity' | 'fact' | 'episode' | 'saga' | 'mention' | 'has_episode' | 'next_episode';
  uuid: string;
  change: 'created' | 'changed';
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}

/** One write and what it changed. `write_id` is what `undoWrite` takes. */
export interface MemoryWriteChanges {
  write_id: string;
  kind: 'episode' | 'triplet' | 'saga_summary';
  created_at: string | null;
  changes: MemoryChange[];
  source_tags?: string[];
  source_resembles?: string[];
  source_unassessed?: boolean;
}

/** One page of the history. `next_cursor` is what `getHistory({ cursor })` takes for the page of older writes; null when this page reaches the oldest write. */
export interface MemoryHistoryResult {
  message: string;
  writes: MemoryWriteChanges[];
  next_cursor: string | null;
}

/** What an undo took back (or, with `dry_run`, would): the write and every later one that depended on it, newest first. */
export interface MemoryUndoResult {
  message: string;
  dry_run: boolean;
  writes: MemoryWriteChanges[];
}

/** An agent caller passes its Passport as `passportToken`, sent as `X-Passport-Token`; an operator credential omits it. */
export interface MemoryCallOptions {
  passportToken?: string;
}

const seg = encodeURIComponent;

function passport(options?: MemoryCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

export class MemoryService {
  constructor(private readonly client: HttpClient) {}

  // ─── writing ────────────────────────────────────────────────────

  /**
   * Add an episode (text, a message or JSON). Answers at once with its `uuid` and `status: 'queued'`; it is read into
   * the graph in the background. Metered and checked against the account's controls, like any action.
   */
  async addMemory(input: AddMemoryInput, options?: MemoryCallOptions): Promise<MemoryAddResult> {
    return this.client.post<MemoryAddResult>('/v1/memory/episodes', input, passport(options));
  }

  /**
   * Write one fact (source entity, fact, target entity) directly, without extraction. Answers when it is written,
   * with the entities and the fact it made. Metered.
   */
  async addTriplet(input: AddTripletInput, options?: MemoryCallOptions): Promise<MemoryGraphElements> {
    return this.client.post<MemoryGraphElements>('/v1/memory/triplets', input, passport(options));
  }

  /** Make or refresh the running summary of a saga (the name passed as `saga` to `addMemory`). Metered. */
  async summarizeSaga(sagaName: string, options?: MemoryCallOptions): Promise<MemorySagaSummary> {
    return this.client.post<MemorySagaSummary>('/v1/memory/sagas/summary', { saga_name: sagaName }, passport(options));
  }

  // ─── reading ────────────────────────────────────────────────────

  /** Search the graph's entities. Free. */
  async searchNodes(input: SearchNodesInput, options?: MemoryCallOptions): Promise<MemoryNodeSearchResult> {
    return this.client.post<MemoryNodeSearchResult>('/v1/memory/nodes/search', input, passport(options));
  }

  /** Search the graph's facts, with when each held. Free. */
  async searchMemoryFacts(input: SearchMemoryFactsInput, options?: MemoryCallOptions): Promise<MemoryFactSearchResult> {
    return this.client.post<MemoryFactSearchResult>('/v1/memory/facts/search', input, passport(options));
  }

  /** Episodes, newest first, each with its `status`: `stored`, `queued`, `processing` or `failed` (with a `reason`). `maxEpisodes` is 1 to 100, default 10. Free. */
  async getEpisodes(query: { maxEpisodes?: number } = {}, options?: MemoryCallOptions): Promise<{ message: string; episodes: MemoryEpisode[] }> {
    return this.client.get<{ message: string; episodes: MemoryEpisode[] }>('/v1/memory/episodes', {
      max_episodes: query.maxEpisodes !== undefined ? String(query.maxEpisodes) : undefined,
    }, passport(options));
  }

  /** One fact (entity edge) by its uuid. Free. */
  async getEntityEdge(uuid: string, options?: MemoryCallOptions): Promise<MemoryFact> {
    return this.client.get<MemoryFact>(`/v1/memory/facts/${seg(uuid)}`, undefined, passport(options));
  }

  /** The entities and facts the given episodes produced. Free. */
  async getEpisodeEntities(episodeUuids: string[], options?: MemoryCallOptions): Promise<MemoryGraphElements> {
    return this.client.post<MemoryGraphElements>('/v1/memory/episode-entities', { episode_uuids: episodeUuids }, passport(options));
  }

  // ─── deleting ───────────────────────────────────────────────────

  /** Delete an episode. Entities and facts only this episode supports go with it; those other episodes support stay. Free. */
  async deleteEpisode(uuid: string, options?: MemoryCallOptions): Promise<MemoryDeleted> {
    return this.client.delete<MemoryDeleted>(`/v1/memory/episodes/${seg(uuid)}`, passport(options));
  }

  /** Delete a fact (entity edge). Free. */
  async deleteEntityEdge(uuid: string, options?: MemoryCallOptions): Promise<MemoryDeleted> {
    return this.client.delete<MemoryDeleted>(`/v1/memory/facts/${seg(uuid)}`, passport(options));
  }

  // ─── the account's own entity types ─────────────────────────────

  /** The ten entity types Graphiti ships and the account's own (in force and retired). Free. */
  async listEntityTypes(options?: MemoryCallOptions): Promise<MemoryEntityTypes> {
    return this.client.get<MemoryEntityTypes>('/v1/memory/entity-types', undefined, passport(options));
  }

  /**
   * Add an entity type of the account's own (or bring back a retired one of the same name with this definition). Every
   * later write extracts it beside the ten, so each type makes every later write cost a little more. Free.
   */
  async createEntityType(input: MemoryEntityTypeInput, options?: MemoryCallOptions): Promise<MemoryEntityType> {
    return this.client.post<MemoryEntityType>('/v1/memory/entity-types', input, passport(options));
  }

  /** Change a type: what is given replaces what was there. Later writes use it; stored entities keep their attributes. Free. */
  async updateEntityType(
    name: string,
    input: { description?: string; fields?: MemoryEntityTypeField[] },
    options?: MemoryCallOptions,
  ): Promise<MemoryEntityType> {
    return this.client.patch<MemoryEntityType>(`/v1/memory/entity-types/${seg(name)}`, input, passport(options));
  }

  /** Retire a type: no longer extracted; its entities keep their label and stay searchable by it. Free. */
  async retireEntityType(name: string, options?: MemoryCallOptions): Promise<MemoryEntityType> {
    return this.client.delete<MemoryEntityType>(`/v1/memory/entity-types/${seg(name)}`, passport(options));
  }

  // ─── what each write changed, and undo ──────────────────────────

  /**
   * One page of the account's writes, newest first, each with what it changed (before and after). `maxWrites` is the
   * page size, 1 to 100, default 20; `cursor` is the `next_cursor` of the page before, so every write can be read: pass
   * it back until `next_cursor` is null. Free.
   */
  async getHistory(query: { maxWrites?: number; cursor?: string } = {}, options?: MemoryCallOptions): Promise<MemoryHistoryResult> {
    return this.client.get<MemoryHistoryResult>('/v1/memory/history', {
      max_writes: query.maxWrites !== undefined ? String(query.maxWrites) : undefined,
      cursor: query.cursor,
    }, passport(options));
  }

  /**
   * Undo a write (`mmo_*`, from `getHistory`): what it created is deleted and what it changed put back, with every later
   * write that changed or linked to the same things, newest first. `dryRun` only answers what would be undone. Free;
   * one delete toward the account's hourly rate (a dry run takes none).
   */
  async undoWrite(writeId: string, input: { dryRun?: boolean } = {}, options?: MemoryCallOptions): Promise<MemoryUndoResult> {
    return this.client.post<MemoryUndoResult>(`/v1/memory/writes/${seg(writeId)}/undo`, { dry_run: input.dryRun ?? false }, passport(options));
  }

  // ─── the owner: on or off ───────────────────────────────────────

  /** Owner only: whether memory is on. */
  async getSettings(): Promise<MemorySettings> {
    return this.client.get<MemorySettings>('/v1/memory/settings');
  }

  /**
   * Owner or admin only: turn memory on or off (off, new writes are refused and writes still waiting fail), and decide
   * whether STACK's model may search memory and the knowledge base during a call STACK holds (`call_memory_access`, on by
   * default; with it on, a caller can try to get the call's model to read out what is in memory or the brain). What is
   * left out keeps its value.
   */
  async updateSettings(input: { enabled?: boolean; call_memory_access?: boolean }): Promise<MemorySettings> {
    return this.client.put<MemorySettings>('/v1/memory/settings', input);
  }
}
