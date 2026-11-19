// operator (self) subcommand — `me`.

import { api, takeFlag } from './api.js';
import { printJson, printRecord } from './format.js';

export async function cmdMe(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const out = await api('GET', '/v1/operators/me');
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}
