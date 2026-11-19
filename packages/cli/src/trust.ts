import { api } from './api.js';
import { governedApi } from './governance.js';
import { printJson } from './format.js';

// The trust switch: whether the account's agents ask first (`ask_first`) or are trusted to act (`trust_agents`), for the
// account and per agent. Owner or admin only. A change that makes a scope trust where it asked first before waits for a
// person's approval (the link opens in the browser) and is then applied; a change to `ask_first` applies at once. Every
// change is recorded in the audit log. `clear` removes an agent's own value so it follows the account again.

const VALUES = ['ask_first', 'trust_agents'] as const;
const USAGE = 'trust takes get [<agent>], set <ask_first|trust_agents> [<agent>] or clear <agent>';

function agentPath(agent: string | undefined): string {
  return agent === undefined ? '/v1/trust' : `/v1/agents/${encodeURIComponent(agent)}/trust`;
}

export async function cmdTrust(argv: string[]): Promise<void> {
  const args = [...argv];
  const sub = args.shift();

  if (sub === 'get' || sub === undefined) {
    const agent = args.shift();
    if (args.length > 0) throw new Error(`Invalid input: ${USAGE}`);
    return printJson(await api('GET', agentPath(agent)));
  }

  if (sub === 'set') {
    const value = args.shift();
    if (value === undefined || !(VALUES as readonly string[]).includes(value)) {
      throw new Error(`Invalid input: set takes ${VALUES.join(' or ')}`);
    }
    const agent = args.shift();
    if (args.length > 0) throw new Error(`Invalid input: ${USAGE}`);
    return printJson(await governedApi('PUT', agentPath(agent), { body: { trust: value } }));
  }

  if (sub === 'clear') {
    const agent = args.shift();
    if (agent === undefined || args.length > 0) throw new Error('Invalid input: clear takes an agent id');
    return printJson(await governedApi('PUT', agentPath(agent), { body: { trust: null } }));
  }

  throw new Error(`Invalid input: ${USAGE}`);
}
