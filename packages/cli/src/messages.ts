import { api } from './api.js';
import { flag, positional } from './account-args.js';
import { printJson } from './format.js';

// Messages across every account the caller may read. `search` filters on agent, channel, sender, recipient, thread, a
// time window and text, and answers a summary of each message (read one with `account messages <id> <message-id>`).
// The default window is the last 30 days; a search on --q, --sender, --recipient or --thread needs a window of at most
// 90 days. `attachment` reads a file a message carries (256 KB or less inline), through the message; the content is untrusted.

const FILTERS: ReadonlyArray<readonly [string, string]> = [
  ['--agent', 'agent_id'],
  ['--channel', 'channel'],
  ['--sender', 'sender'],
  ['--recipient', 'recipient'],
  ['--thread', 'thread_id'],
  ['--after', 'after'],
  ['--before', 'before'],
  ['--q', 'q'],
  ['--limit', 'limit'],
  ['--cursor', 'cursor'],
];
const USAGE = 'messages takes search [filters] or attachment <account> <message> <file>';

export async function cmdMessages(argv: string[]): Promise<void> {
  const args = [...argv];
  const sub = args.shift();

  if (sub === 'search' || sub === undefined) {
    const query: Record<string, string> = {};
    for (const [name, param] of FILTERS) {
      const value = flag(args, name);
      if (value !== undefined) query[param] = value;
    }
    if (args.length > 0) throw new Error(`Invalid input: unexpected ${args[0]}`);
    return printJson(await api('GET', '/v1/messages', { query }));
  }

  if (sub === 'attachment') {
    const account = positional(args, 'account id');
    const message = positional(args, 'message id');
    const file = positional(args, 'file id');
    if (args.length > 0) throw new Error(`Invalid input: ${USAGE}`);
    return printJson(
      await api('GET', `/v1/accounts/${encodeURIComponent(account)}/messages/${encodeURIComponent(message)}/attachments/${encodeURIComponent(file)}`),
    );
  }

  throw new Error(`Invalid input: ${USAGE}`);
}
