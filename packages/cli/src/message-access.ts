import { api } from './api.js';
import { flag } from './account-args.js';
import { printJson } from './format.js';

// Message access: what the account's agents may do with the customer's messages, for the account and per agent.
// Owner or admin only. `--read-teammates` (default true) lets an agent read the messages of every message account of
// the customer, false only its own. `--read-only` (default false), when true, lets an agent read but not send, reply,
// forward, text or post from any account. A change applies at once and needs no approval. `clear` removes the values
// an agent set for itself so it follows the account again.

const KEYS: Record<string, 'read_teammates' | 'messages_read_only'> = {
  'read-teammates': 'read_teammates',
  'read-only': 'messages_read_only',
};
const USAGE =
  'message-access takes get [<agent>], set [--read-teammates true|false] [--read-only true|false] [<agent>] or clear <agent> <read-teammates|read-only>...';

function agentPath(agent: string | undefined): string {
  return agent === undefined ? '/v1/message-access' : `/v1/agents/${encodeURIComponent(agent)}/message-access`;
}

function truth(args: string[], name: string): boolean | undefined {
  const value = flag(args, name);
  if (value === undefined) return undefined;
  if (value !== 'true' && value !== 'false') throw new Error(`Invalid input: ${name} takes true or false`);
  return value === 'true';
}

export async function cmdMessageAccess(argv: string[]): Promise<void> {
  const args = [...argv];
  const sub = args.shift();

  if (sub === 'get' || sub === undefined) {
    const agent = args.shift();
    if (args.length > 0) throw new Error(`Invalid input: ${USAGE}`);
    return printJson(await api('GET', agentPath(agent)));
  }

  if (sub === 'set') {
    const body: Record<string, boolean> = {};
    const readTeammates = truth(args, '--read-teammates');
    if (readTeammates !== undefined) body['read_teammates'] = readTeammates;
    const readOnly = truth(args, '--read-only');
    if (readOnly !== undefined) body['messages_read_only'] = readOnly;
    if (Object.keys(body).length === 0) throw new Error('Invalid input: set takes --read-teammates true|false and/or --read-only true|false');
    const agent = args.shift();
    if (args.length > 0) throw new Error(`Invalid input: ${USAGE}`);
    return printJson(await api('PUT', agentPath(agent), { body }));
  }

  if (sub === 'clear') {
    const agent = args.shift();
    if (agent === undefined || args.length === 0) throw new Error('Invalid input: clear takes an agent id and read-teammates and/or read-only');
    const body: Record<string, null> = {};
    for (const name of args) {
      const key = KEYS[name];
      if (key === undefined) throw new Error('Invalid input: clear takes read-teammates and/or read-only');
      body[key] = null;
    }
    return printJson(await api('PUT', agentPath(agent), { body }));
  }

  throw new Error(`Invalid input: ${USAGE}`);
}
