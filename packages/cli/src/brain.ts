import { api, takeFlag } from './api.js';
import { printJson } from './format.js';
import { readSecretFromStdin } from './secret-input.js';

// The brain: the drive files a customer chose to make searchable, read and
// searched by a knowledge base service. One brain per account, shared by
// its agents. The owner signed in to the CLI, or an agent under its Passport,
// adds files (a file id, several file ids, or every file whose name starts with a
// prefix), searches them and lists what is in the brain.
//
// The Passport is a secret, so it is read from stdin (piped, or typed at a hidden
// prompt) and never from argv, and only with --passport-stdin: without it the call
// runs as the operator.

const PASSPORT_ARGV_FLAGS = new Set(['--passport', '--passport-token', '--token']);
const STATUSES = ['reading', 'searchable', 'unreadable'] as const;

function flag(args: string[], name: string): string | undefined {
  const value = takeFlag(args, name);
  if (value === true) throw new Error(`${name} needs a value`);
  return typeof value === 'string' ? value : undefined;
}

function wholeNumber(args: string[], name: string): number | undefined {
  const value = flag(args, name);
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a whole number`);
  return Number(value);
}

function takeSwitch(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

function positionals(args: string[]): string[] {
  const out: string[] = [];
  while (args[0] && !args[0].startsWith('--')) out.push(args.shift() as string);
  return out;
}

function positional(args: string[], what: string): string {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (!value) throw new Error(`Invalid input: ${what} is required`);
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

/** Which drive files a call names: exactly one of a prefix, one file id, or several. */
function selection(args: string[]): Record<string, unknown> {
  const prefix = flag(args, '--prefix');
  const ids = positionals(args);
  if (prefix !== undefined && ids.length > 0) throw new Error('Invalid input: give file ids or --prefix, not both');
  if (prefix !== undefined) return { name_prefix: prefix };
  if (ids.length === 1) return { file_id: ids[0] };
  if (ids.length > 1) return { file_ids: ids };
  throw new Error('Invalid input: name a drive file id, several file ids, or --prefix <name prefix>');
}

export async function cmdBrain(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  refusePassportInArgv(args);
  const sub = args.shift();

  // Adding is one action, metered and put to the account's controls.
  if (sub === 'add') {
    const body = selection(args);
    return printJson(await api('POST', '/v1/brain/files', { body, ...(await passportHeaders(args)) }));
  }

  // Removing, searching and listing are free.
  if (sub === 'remove') {
    const body = selection(args);
    return printJson(await api('POST', '/v1/brain/remove', { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'search') {
    const body = { query: positional(args, 'query') };
    return printJson(await api('POST', '/v1/brain/search', { body, ...(await passportHeaders(args)) }));
  }

  if (sub === 'list') {
    const status = flag(args, '--status');
    if (status !== undefined && !(STATUSES as readonly string[]).includes(status)) {
      throw new Error(`Invalid input: --status takes ${STATUSES.join(', ')}`);
    }
    const cursor = flag(args, '--cursor');
    const limit = wholeNumber(args, '--limit');
    const query: Record<string, string> = {};
    if (status !== undefined) query['status'] = status;
    if (cursor !== undefined) query['cursor'] = cursor;
    if (limit !== undefined) query['limit'] = String(limit);
    return printJson(await api('GET', '/v1/brain/files', { query, ...(await passportHeaders(args)) }));
  }

  throw new Error('Invalid input: brain takes add, remove, search or list');
}
