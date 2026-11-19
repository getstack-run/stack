import { api, takeFlag } from './api.js';
import { printJson } from './format.js';

// What the customer's controls do with flagged content, per severity: `withhold` (the default for both) or `deliver`
// with its flag. With controls off flagged content is always delivered with its flag. Owner or admin only; a change
// applies at once, with no approval.

const HANDLINGS = ['withhold', 'deliver'] as const;

export async function cmdFlaggedContent(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  const sub = args.shift();

  if (sub === 'get' || sub === undefined) return printJson(await api('GET', '/v1/flagged-content/settings'));

  if (sub === 'set') {
    const body: Record<string, string> = {};
    for (const severity of ['warning', 'critical'] as const) {
      const value = takeFlag(args, `--${severity}`);
      if (value === undefined) continue;
      if (typeof value !== 'string' || !(HANDLINGS as readonly string[]).includes(value)) {
        throw new Error(`Invalid input: --${severity} takes ${HANDLINGS.join(' or ')}`);
      }
      body[severity] = value;
    }
    if (Object.keys(body).length === 0) throw new Error('Invalid input: set takes --warning, --critical or both');
    return printJson(await api('PUT', '/v1/flagged-content/settings', { body }));
  }

  throw new Error('Invalid input: flagged-content takes get or set');
}
