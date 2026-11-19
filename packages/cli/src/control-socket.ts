import { stderr } from 'node:process';
import { CONTROL_ACTION_TYPES } from '@getstackrun/sdk';
import { api, takeFlag } from './api.js';
import { printJson } from './format.js';
import { governedApi } from './governance.js';

// The control socket: who decides for your agents' actions, and where their
// record is streamed. Setting an address, rotating a secret, clearing an
// address, switching who decides (`mode`, and `verify` of a decision address
// that replaces hosted controls) and unchecking an action kind are governed
// writes: without a dashboard session the API answers
// GOVERNANCE_APPROVAL_REQUIRED, governedApi prints the approval link, waits
// for the human, and retries with the same body. Everything else applies at
// once, and none of it is metered.
//
// A signing secret is shown exactly once, by `set-decision` and `set-events`
// when the call creates it and by `rotate-secret`. It is printed to stdout
// with a reminder on stderr and is never written anywhere by this command.

const TARGETS = ['decision', 'events'] as const;
const MODES = ['none', 'hosted'] as const;
const VERDICTS = ['allow', 'deny', 'unavailable'] as const;

type Target = (typeof TARGETS)[number];

export function flag(args: string[], name: string): string | undefined {
  const value = takeFlag(args, name);
  if (value === true) throw new Error(`${name} needs a value`);
  return typeof value === 'string' ? value : undefined;
}

export function wholeNumber(args: string[], name: string): number | undefined {
  const value = flag(args, name);
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a whole number`);
  return Number(value);
}

/** A flag that never takes a value, so it cannot swallow the positional after it. */
export function takeSwitch(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

export function positional(args: string[], what: string): string {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (!value) throw new Error(`Invalid input: ${what} is required`);
  return value;
}

function target(args: string[]): Target {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (value !== 'decision' && value !== 'events') {
    throw new Error(`Invalid input: the target is ${TARGETS.join(' or ')}`);
  }
  return value;
}

/** A leftover argument is a typo or a flag this command does not take; a security setting must not run past it. */
export function noExtra(args: string[]): void {
  if (args.length > 0) throw new Error(`Invalid input: unexpected argument ${args[0]}`);
}

/** Print an answer that may carry a signing secret; the secret is shown only now. */
function printWithSecret(result: unknown): void {
  printJson(result);
  const shown = result as { secret?: unknown; secret_reveal?: { url?: unknown } | null } | null;
  if (typeof shown?.secret === 'string') {
    stderr.write('This signing secret is shown once. Store it now: it is not shown again, and STACK cannot show it to you later.\n');
  } else if (typeof shown?.secret_reveal?.url === 'string') {
    // A browser sign-in (OAuth) is never handed a signing secret; the person reads it in the Console.
    stderr.write(`A signing secret was created. Open it signed in to the Console to read it once, within an hour: ${shown.secret_reveal.url}\n`);
  }
}

function checkedTypes(args: string[]): string[] | null | undefined {
  const all = takeSwitch(args, '--all');
  const listed = args.splice(0).flatMap((part) => part.split(',')).map((part) => part.trim()).filter((part) => part !== '');
  if (all && listed.length > 0) throw new Error('Use --all or a list of action types, not both');
  if (all) return null;
  if (listed.length === 0) return undefined;
  const known: readonly string[] = CONTROL_ACTION_TYPES;
  const unknown = listed.filter((type) => !known.includes(type));
  if (unknown.length > 0) {
    throw new Error(`Invalid input: unknown action type ${unknown.join(', ')} (one of ${CONTROL_ACTION_TYPES.join(', ')})`);
  }
  return [...new Set(listed)];
}

export async function cmdControlSocket(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  const sub = args.shift();

  if (sub === 'get') {
    noExtra(args);
    return printJson(await api('GET', '/v1/control-socket'));
  }

  if (sub === 'set-decision') {
    const timeoutMs = wholeNumber(args, '--timeout-ms');
    const url = positional(args, 'the decision address (an https URL)');
    noExtra(args);
    const body = { url, ...(timeoutMs !== undefined ? { timeout_ms: timeoutMs } : {}) };
    return printWithSecret(await governedApi('PUT', '/v1/control-socket/decision', { body }));
  }

  if (sub === 'set-events') {
    const url = positional(args, 'the events address (an https URL)');
    noExtra(args);
    return printWithSecret(await governedApi('PUT', '/v1/control-socket/events', { body: { url } }));
  }

  if (sub === 'clear') {
    const which = target(args);
    noExtra(args);
    return printJson(await governedApi('DELETE', `/v1/control-socket/${which}`));
  }

  if (sub === 'verify') {
    const which = target(args);
    noExtra(args);
    return printJson(await governedApi('POST', `/v1/control-socket/${which}/verify`));
  }

  if (sub === 'test') {
    const which = target(args);
    noExtra(args);
    return printJson(await api('POST', `/v1/control-socket/${which}/test`));
  }

  if (sub === 'rotate-secret') {
    const which = target(args);
    noExtra(args);
    return printWithSecret(await governedApi('POST', `/v1/control-socket/${which}/secret/rotate`));
  }

  if (sub === 'mode') {
    const mode = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
    if (mode !== 'none' && mode !== 'hosted') throw new Error(`Invalid input: mode takes ${MODES.join(' or ')}`);
    noExtra(args);
    return printJson(await governedApi('PUT', '/v1/control-socket/mode', { body: { mode } }));
  }

  if (sub === 'on-unavailable') {
    const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
    noExtra(args);
    if (value === undefined) {
      const socket = await api<{ decision: { on_unavailable: string } }>('GET', '/v1/control-socket');
      return printJson({ on_unavailable: socket.decision.on_unavailable });
    }
    if (value !== 'refuse' && value !== 'allow') throw new Error('Invalid input: on-unavailable takes refuse or allow');
    return printJson(await governedApi('PUT', '/v1/control-socket/on-unavailable', { body: { on_unavailable: value } }));
  }

  if (sub === 'checked-types') {
    const types = checkedTypes(args);
    noExtra(args);
    if (types === undefined) {
      const socket = await api<{ checked_types: string[]; checks_all_types: boolean }>('GET', '/v1/control-socket');
      return printJson({ checked_types: socket.checked_types, checks_all_types: socket.checks_all_types });
    }
    return printJson(await governedApi('PUT', '/v1/control-socket/checked-types', { body: { types } }));
  }

  if (sub === 'decisions') {
    const limit = wholeNumber(args, '--limit');
    const account = flag(args, '--account');
    const verdict = flag(args, '--verdict');
    const before = flag(args, '--before');
    if (verdict !== undefined && !(VERDICTS as readonly string[]).includes(verdict)) {
      throw new Error(`--verdict must be ${VERDICTS.join(', ')}`);
    }
    noExtra(args);
    const query: Record<string, string | number> = {};
    if (limit !== undefined) query['limit'] = limit;
    if (account !== undefined) query['account_id'] = account;
    if (verdict !== undefined) query['verdict'] = verdict;
    if (before !== undefined) query['before'] = before;
    return printJson(await api('GET', '/v1/control-decisions', { query }));
  }

  if (sub === 'decision') {
    const id = positional(args, 'decision id');
    noExtra(args);
    return printJson(await api('GET', `/v1/control-decisions/${encodeURIComponent(id)}`));
  }

  throw new Error(
    'Invalid input: control-socket takes get, set-decision, set-events, clear, verify, test, rotate-secret, mode, on-unavailable, checked-types, decisions or decision',
  );
}
