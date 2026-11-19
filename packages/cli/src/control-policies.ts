import { readFileSync } from 'node:fs';
import { CONTROL_ACTION_TYPES } from '@getstackrun/sdk';
import { api, resolveAgentId, takeFlag } from './api.js';
import { flag, noExtra, positional, takeSwitch, wholeNumber } from './control-socket.js';
import { printJson } from './format.js';
import { governedApi } from './governance.js';

// Policies: the configuration behind hosted controls, and the actions they
// hold for a person. A policy only narrows what a connection grant already
// allows: it refuses, holds for a person, or limits. Setting one, deleting one
// and starting one from an agent's current access are governed writes: a
// tightening applies at once, and a loosening or a delete needs a person in a
// browser, so the API answers GOVERNANCE_APPROVAL_REQUIRED, governedApi prints
// the approval link, waits for the human, and retries with the same body.
// `simulate` and every read apply nothing and need no approval. A held action
// is decided through its ordinary governance approval, so there is no review
// decide command.
//
// Recipients can be set per job: a connection rule with `"recipients": "per_mission"`
// allows a send only to the recipients the Mission names when it opens (`missions open
// --recipients`, `--pin`, `--reply-to`). `simulate --mission <ms_id>` tries a call with what
// that Mission pinned.
//
// A scope is `default` (the account's default policy) or an agent, by name or
// id. A definition is read from --file or from stdin (--stdin): either the
// definition itself or what `policies get` prints.

const POLICIES_USAGE = 'policies takes list, get, set, delete, start, simulate or revisions';
const REVIEWS_USAGE = 'reviews takes list or get';

/** The fixed word for the account's default policy, or an agent resolved to its id. */
async function scopeOf(args: string[]): Promise<string> {
  const value = positional(args, 'the policy scope (default, or an agent name or id)');
  return value === 'default' ? value : resolveAgentId(value);
}

function scopePath(scope: string): string {
  return scope === 'default' ? '/v1/control-policies/default' : `/v1/control-policies/agents/${encodeURIComponent(scope)}`;
}

function parseJson(text: string, source: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new Error(`Invalid input: ${source} is not valid JSON: ${(error as Error).message}`, { cause: error });
  }
}

function jsonObject(value: unknown, source: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Invalid input: ${source} must hold one JSON object`);
  return value as Record<string, unknown>;
}

/** JSON from --file, or from stdin with --stdin; undefined when neither is given. */
function readInput(args: string[], fileFlag = '--file'): { value: Record<string, unknown>; source: string } | undefined {
  const file = flag(args, fileFlag);
  const stdin = fileFlag === '--file' ? takeSwitch(args, '--stdin') : false;
  if (file !== undefined && stdin) throw new Error(`Use ${fileFlag} or --stdin, not both`);
  if (file === undefined && !stdin) return undefined;
  const source = stdin ? 'stdin' : file!;
  return { value: jsonObject(parseJson(readFileSync(stdin ? 0 : file!, 'utf8'), source), source), source };
}

/** The policy definition: a definition, or what `policies get` prints (a policy, or an agent's answer holding one). */
function definitionOf(value: Record<string, unknown>, source: string): Record<string, unknown> {
  if (value['name'] !== undefined) return value;
  const policy = value['policy'];
  const view = policy && typeof policy === 'object' && !Array.isArray(policy) ? (policy as Record<string, unknown>) : value;
  const inner = view['definition'];
  return inner === undefined ? value : jsonObject(inner, `the definition in ${source}`);
}

function expectedRevision(args: string[]): number | undefined {
  return wholeNumber(args, '--expected-revision');
}

function actionType(value: string): string {
  const known: readonly string[] = CONTROL_ACTION_TYPES;
  if (!known.includes(value)) throw new Error(`Invalid input: unknown action type ${value} (one of ${CONTROL_ACTION_TYPES.join(', ')})`);
  return value;
}

async function simulateInput(args: string[]): Promise<Record<string, unknown>> {
  const input: Record<string, unknown> = {};
  const given = readInput(args);
  if (given) Object.assign(input, given.value);

  const agent = flag(args, '--agent');
  if (agent !== undefined) input['agent_id'] = await resolveAgentId(agent);
  const draft = readInput(args, '--definition');
  if (draft) input['definition'] = definitionOf(draft.value, draft.source);

  const call: Record<string, unknown> = input['call'] === undefined ? {} : jsonObject(input['call'], 'call');
  const action = flag(args, '--action');
  if (action !== undefined) call['action'] = actionType(action);
  const amount = wholeNumber(args, '--amount-cents');
  if (amount !== undefined) call['amount_cents'] = amount;
  const connection = flag(args, '--connection');
  if (connection !== undefined) call['connection_id'] = connection;
  const mission = flag(args, '--mission');
  if (mission !== undefined) {
    if (!/^ms_[\w-]+$/.test(mission)) throw new Error(`Invalid input: --mission is a Mission id (ms_...), got ${mission}`);
    call['mission_id'] = mission;
  }
  const target = flag(args, '--target');
  if (target !== undefined) call['target'] = jsonObject(parseJson(target, '--target'), '--target');
  input['call'] = call;

  if (typeof call['action'] !== 'string') throw new Error('Invalid input: the call needs an action (--action, or "call.action" in the file)');
  if (input['agent_id'] === undefined && input['definition'] === undefined) {
    throw new Error('Invalid input: name an agent (--agent) or give a draft definition (--definition)');
  }
  return input;
}

export async function cmdPolicies(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  const sub = args.shift();

  if (sub === 'list') {
    noExtra(args);
    return printJson(await api('GET', '/v1/control-policies'));
  }

  if (sub === 'get') {
    const scope = await scopeOf(args);
    noExtra(args);
    return printJson(await api('GET', scopePath(scope)));
  }

  if (sub === 'set') {
    const revision = expectedRevision(args);
    const given = readInput(args);
    if (!given) throw new Error('Invalid input: give the definition with --file <path> or --stdin');
    const scope = await scopeOf(args);
    noExtra(args);
    const body = { definition: definitionOf(given.value, given.source), ...(revision !== undefined ? { expected_revision: revision } : {}) };
    return printJson(await governedApi('PUT', scopePath(scope), { body }));
  }

  if (sub === 'delete') {
    const revision = expectedRevision(args);
    const scope = await scopeOf(args);
    noExtra(args);
    return printJson(await governedApi('DELETE', scopePath(scope), revision !== undefined ? { query: { expected_revision: revision } } : undefined));
  }

  if (sub === 'start') {
    const agent = await resolveAgentId(positional(args, 'the agent (name or id)'));
    noExtra(args);
    return printJson(await governedApi('POST', `/v1/control-policies/agents/${encodeURIComponent(agent)}/start-from-current-access`));
  }

  if (sub === 'simulate') {
    const body = await simulateInput(args);
    noExtra(args);
    return printJson(await api('POST', '/v1/control-policies/simulate', { body }));
  }

  if (sub === 'revisions') {
    const id = positional(args, 'the policy id');
    noExtra(args);
    return printJson(await api('GET', `/v1/control-policies/${encodeURIComponent(id)}/revisions`));
  }

  throw new Error(`Invalid input: ${POLICIES_USAGE}`);
}

export async function cmdReviews(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  const sub = args.shift();

  if (sub === 'list') {
    const all = takeSwitch(args, '--all');
    const limit = wholeNumber(args, '--limit');
    noExtra(args);
    const query: Record<string, string | number> = { status: all ? 'all' : 'pending' };
    if (limit !== undefined) query['limit'] = limit;
    return printJson(await api('GET', '/v1/control-reviews', { query }));
  }

  if (sub === 'get') {
    const id = positional(args, 'the review id');
    noExtra(args);
    return printJson(await api('GET', `/v1/control-reviews/${encodeURIComponent(id)}`));
  }

  throw new Error(`Invalid input: ${REVIEWS_USAGE}`);
}
