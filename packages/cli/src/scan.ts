// `scan` — prompt-injection scan of retrieved content, + usage.
//
// Scans a string (or --file contents) for prompt-injection markers via the
// full detector chain. Records a security event on a non-clean verdict.

import { stderr, exit } from 'node:process';
import { readFileSync } from 'node:fs';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printRecord } from './format.js';

export async function cmdScan(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];

  if (sub === 'usage') {
    const out = await api('GET', '/v1/scan/usage');
    if (json) return printJson(out);
    printRecord(out as Record<string, unknown>);
    return;
  }

  // Default: scan content. Content from a positional arg or --file.
  const file = takeFlag(args, '--file');
  const context = takeFlag(args, '--context');
  const source = takeFlag(args, '--source');
  let content: string | undefined;
  if (typeof file === 'string') {
    try {
      content = readFileSync(file, 'utf8');
    } catch (err) {
      stderr.write(`error: could not read --file ${file}: ${(err as Error).message}\n`);
      exit(1);
    }
  } else {
    // First non-flag positional is the content.
    content = args.find((a) => !a.startsWith('--'));
  }
  if (!content) {
    stderr.write(
      `usage: ${invokeHint('scan "<content>"')} | ${invokeHint('scan --file <path>')} | ${invokeHint('scan usage')}\n` +
        `  [--context email|document|webpage|chat_log|api_response|calendar|other] [--source <url|sender|filename>]\n`,
    );
    exit(2);
  }

  const body: Record<string, unknown> = { content };
  if (typeof context === 'string') body.context = context;
  if (typeof source === 'string') body.source = source;
  const out = await api('POST', '/v1/scan', { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}
