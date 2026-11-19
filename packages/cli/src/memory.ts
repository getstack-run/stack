import { readFileSync } from 'node:fs';
import { api, takeFlag } from './api.js';
import { printJson } from './format.js';
import { readSecretFromStdin } from './secret-input.js';

// Account memory: Graphiti, a graph of facts with the time each held, one per
// account and shared by its agents. The commands are the tools of Graphiti's own
// MCP server with its arguments (there is no group id: the graph is the
// account's). An agent acts under its Passport; the operator signed in to the CLI
// makes the same calls and also turns memory on or off.
//
// The Passport is a secret, so it is read from stdin (piped, or typed at a hidden
// prompt) and never from argv, and only with --passport-stdin: without it the call
// runs as the operator. The text of a write comes from the argument, --file or
// --text; it is never taken from stdin, which is the Passport's.

const PASSPORT_ARGV_FLAGS = new Set(['--passport', '--passport-token', '--token']);
const SOURCES = ['text', 'json', 'message'] as const;

function flag(args: string[], name: string): string | undefined {
  const value = takeFlag(args, name);
  if (value === true) throw new Error(`${name} needs a value`);
  return typeof value === 'string' ? value : undefined;
}

function repeated(args: string[], name: string): string[] {
  const out: string[] = [];
  for (let value = flag(args, name); value !== undefined; value = flag(args, name)) out.push(value);
  return out;
}

function wholeNumber(args: string[], name: string): number | undefined {
  const value = flag(args, name);
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a whole number`);
  return Number(value);
}

/** A switch never takes a value, so it cannot swallow the positional after it. */
function takeSwitch(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

function positional(args: string[], what: string): string {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (!value) throw new Error(`Invalid input: ${what} is required`);
  return value;
}

function required(args: string[], name: string): string {
  const value = flag(args, name);
  if (value === undefined) throw new Error(`Invalid input: ${name} is required`);
  return value;
}

function refusePassportInArgv(args: string[]): void {
  if (args.some((arg) => PASSPORT_ARGV_FLAGS.has(arg.split('=')[0] ?? arg))) {
    throw new Error('Passport tokens must not be placed in argv. Pipe the token on stdin or type it at the hidden prompt.');
  }
}

async function passportHeaders(args: string[]): Promise<{ headers?: Record<string, string> }> {
  if (!takeSwitch(args, '--passport-stdin')) return {};
  const token = await readSecretFromStdin('Passport token: ');
  if (!token) throw new Error("No Passport token: pipe the account agent's Passport on stdin or type it at the prompt");
  return { headers: { 'X-Passport-Token': token } };
}

/** The text of a write: the quoted argument, or --text, or the contents of --file. */
function readText(args: string[], what: string): string {
  const file = flag(args, '--file');
  const text = flag(args, '--text');
  if (file !== undefined) return readFileSync(file, 'utf8');
  if (text !== undefined) return text;
  return positional(args, what);
}

function onOff(value: string, name: string): boolean {
  if (['on', 'true', 'yes'].includes(value)) return true;
  if (['off', 'false', 'no'].includes(value)) return false;
  throw new Error(`${name} takes on or off`);
}

function setIfPresent(body: Record<string, unknown>, key: string, value: unknown): void {
  if (value !== undefined && !(Array.isArray(value) && value.length === 0)) body[key] = value;
}

const FIELD_KINDS = ['text', 'number', 'date', 'boolean', 'one_of'] as const;

/**
 * One --where <field>=<value>. A value that reads as JSON true, false or a number is sent as that (a number or boolean
 * field), anything else as text (a date is text); quote it, as in --where 'number="5"', to send digits as text.
 */
function fieldFilter(spec: string): { field: string; value: string | number | boolean } {
  const at = spec.indexOf('=');
  if (at < 1 || at === spec.length - 1) throw new Error('Invalid input: --where takes <field>=<value>, for example --where currency=EUR');
  const raw = spec.slice(at + 1);
  let value: string | number | boolean = raw;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === 'number' || typeof parsed === 'boolean' || typeof parsed === 'string') value = parsed;
  } catch {
    // Not JSON: it is text as typed.
  }
  return { field: spec.slice(0, at), value };
}

/**
 * The fields of an entity type: a JSON list from --fields-file, or each --field <name>:<kind>[:<word>,<word>...] (a
 * one_of field lists its words after a second colon). Undefined when neither is given.
 */
function typeFields(args: string[]): unknown[] | undefined {
  const file = flag(args, '--fields-file');
  const given = repeated(args, '--field');
  if (file !== undefined && given.length > 0) throw new Error('Invalid input: give --fields-file or --field, not both');
  if (file !== undefined) {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    if (!Array.isArray(parsed)) throw new Error('Invalid input: --fields-file holds a JSON list of fields');
    return parsed;
  }
  if (given.length === 0) return undefined;
  return given.map((spec) => {
    const [name, kind, words] = spec.split(':');
    if (!name || !kind || !(FIELD_KINDS as readonly string[]).includes(kind)) {
      throw new Error(`Invalid input: --field takes <name>:<kind>, kind one of ${FIELD_KINDS.join(', ')}`);
    }
    return words !== undefined ? { name, kind, options: words.split(',').filter(Boolean) } : { name, kind };
  });
}

const typePath = (name: string) => `/v1/memory/entity-types/${encodeURIComponent(name)}`;
const episodePath = (uuid: string) => `/v1/memory/episodes/${encodeURIComponent(uuid)}`;
const factPath = (uuid: string) => `/v1/memory/facts/${encodeURIComponent(uuid)}`;

export async function cmdMemory(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  refusePassportInArgv(args);
  const sub = args.shift();

  // ─── writing: each is an action, metered and put to the account's controls ─

  if (sub === 'add') {
    const body: Record<string, unknown> = { name: required(args, '--name') };
    const source = flag(args, '--source');
    if (source !== undefined && !(SOURCES as readonly string[]).includes(source)) {
      throw new Error(`Invalid input: --source takes ${SOURCES.join(', ')}`);
    }
    setIfPresent(body, 'source', source);
    setIfPresent(body, 'source_description', flag(args, '--source-description'));
    setIfPresent(body, 'uuid', flag(args, '--uuid'));
    setIfPresent(body, 'reference_time', flag(args, '--at'));
    setIfPresent(body, 'excluded_entity_types', repeated(args, '--exclude-type'));
    setIfPresent(body, 'custom_extraction_instructions', flag(args, '--instructions'));
    setIfPresent(body, 'previous_episode_uuids', repeated(args, '--previous'));
    setIfPresent(body, 'saga', flag(args, '--saga'));
    setIfPresent(body, 'saga_previous_episode_uuid', flag(args, '--saga-previous'));
    body['episode_body'] = readText(args, 'text');
    return printJson(await api('POST', '/v1/memory/episodes', { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'triplet') {
    const body: Record<string, unknown> = {
      source_node_name: required(args, '--source'),
      edge_name: required(args, '--edge'),
      fact: required(args, '--fact'),
      target_node_name: required(args, '--target'),
    };
    setIfPresent(body, 'source_node_uuid', flag(args, '--source-uuid'));
    setIfPresent(body, 'target_node_uuid', flag(args, '--target-uuid'));
    return printJson(await api('POST', '/v1/memory/triplets', { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'summarize-saga') {
    const body = { saga_name: positional(args, 'saga name') };
    return printJson(await api('POST', '/v1/memory/sagas/summary', { body, ...(await passportHeaders(args)) }));
  }

  // ─── reading: free ──────────────────────────────────────────────

  if (sub === 'search-nodes') {
    const body: Record<string, unknown> = { query: positional(args, 'query') };
    setIfPresent(body, 'max_nodes', wholeNumber(args, '--max'));
    setIfPresent(body, 'entity_types', repeated(args, '--type'));
    setIfPresent(body, 'center_node_uuid', flag(args, '--center'));
    setIfPresent(body, 'field_filters', repeated(args, '--where').map(fieldFilter));
    return printJson(await api('POST', '/v1/memory/nodes/search', { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'search-facts') {
    const body: Record<string, unknown> = { query: positional(args, 'query') };
    setIfPresent(body, 'max_facts', wholeNumber(args, '--max'));
    setIfPresent(body, 'center_node_uuid', flag(args, '--center'));
    setIfPresent(body, 'edge_types', repeated(args, '--edge-type'));
    setIfPresent(body, 'valid_at_after', flag(args, '--valid-after'));
    setIfPresent(body, 'valid_at_before', flag(args, '--valid-before'));
    setIfPresent(body, 'invalid_at_after', flag(args, '--invalid-after'));
    setIfPresent(body, 'invalid_at_before', flag(args, '--invalid-before'));
    return printJson(await api('POST', '/v1/memory/facts/search', { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'episodes') {
    const max = wholeNumber(args, '--max');
    const query: Record<string, string> = max !== undefined ? { max_episodes: String(max) } : {};
    return printJson(await api('GET', '/v1/memory/episodes', { query, ...(await passportHeaders(args)) }));
  }

  if (sub === 'fact') return printJson(await api('GET', factPath(positional(args, 'fact uuid')), await passportHeaders(args)));

  if (sub === 'episode-entities') {
    const uuids: string[] = [];
    while (args[0] && !args[0].startsWith('--')) uuids.push(args.shift() as string);
    if (uuids.length === 0) throw new Error('Invalid input: at least one episode uuid is required');
    return printJson(await api('POST', '/v1/memory/episode-entities', { body: { episode_uuids: uuids }, ...(await passportHeaders(args)) }));
  }

  // ─── deleting: free ─────────────────────────────────────────────

  if (sub === 'delete-episode') {
    return printJson(await api('DELETE', episodePath(positional(args, 'episode uuid')), await passportHeaders(args)));
  }
  if (sub === 'delete-fact') {
    return printJson(await api('DELETE', factPath(positional(args, 'fact uuid')), await passportHeaders(args)));
  }

  // ─── the account's own entity types: a setting, free ────────────

  if (sub === 'types') return printJson(await api('GET', '/v1/memory/entity-types', await passportHeaders(args)));

  if (sub === 'type-add') {
    const body: Record<string, unknown> = { name: positional(args, 'type name'), description: required(args, '--description') };
    setIfPresent(body, 'fields', typeFields(args));
    return printJson(await api('POST', '/v1/memory/entity-types', { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'type-change') {
    const name = positional(args, 'type name');
    const body: Record<string, unknown> = {};
    setIfPresent(body, 'description', flag(args, '--description'));
    const fields = typeFields(args);
    if (fields !== undefined) body['fields'] = fields;
    if (Object.keys(body).length === 0) throw new Error('Invalid input: give --description, --field or --fields-file');
    return printJson(await api('PATCH', typePath(name), { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'type-retire') return printJson(await api('DELETE', typePath(positional(args, 'type name')), await passportHeaders(args)));

  // ─── what each write changed, and undo ──────────────────────────

  if (sub === 'history') {
    const max = wholeNumber(args, '--max');
    const cursor = flag(args, '--cursor');
    const query: Record<string, string> = {};
    if (max !== undefined) query['max_writes'] = String(max);
    if (cursor !== undefined) query['cursor'] = cursor;
    return printJson(await api('GET', '/v1/memory/history', { query, ...(await passportHeaders(args)) }));
  }

  if (sub === 'undo') {
    const id = positional(args, 'write id');
    const body = { dry_run: takeSwitch(args, '--dry-run') };
    return printJson(await api('POST', `/v1/memory/writes/${encodeURIComponent(id)}/undo`, { body, ...(await passportHeaders(args)) }));
  }

  // ─── the owner: on or off ───────────────────────────────────────

  if (sub === 'settings') {
    const enabled = flag(args, '--enabled');
    const callAccess = flag(args, '--call-memory-access');
    if (enabled === undefined && callAccess === undefined) return printJson(await api('GET', '/v1/memory/settings'));
    return printJson(await api('PUT', '/v1/memory/settings', {
      body: {
        ...(enabled !== undefined ? { enabled: onOff(enabled, '--enabled') } : {}),
        ...(callAccess !== undefined ? { call_memory_access: onOff(callAccess, '--call-memory-access') } : {}),
      },
    }));
  }

  throw new Error(
    'Invalid input: memory takes add, triplet, search-nodes, search-facts, episodes, fact, episode-entities, delete-episode, delete-fact, summarize-saga, types, type-add, type-change, type-retire, history, undo or settings',
  );
}
