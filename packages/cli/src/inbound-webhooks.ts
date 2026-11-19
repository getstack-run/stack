// `stack inbound-webhook` — hosted inbound webhook surface.
//
// Operator creates a webhook + receives a STACK-hosted URL + HMAC secret
// to paste into a provider's (AgentMail / generic) webhook config. STACK
// runs the prompt-injection detector on inbound before forwarding to a
// downstream URL.

import { stdout, stderr, exit } from 'node:process';
import { api, requireToken } from './api.js';
import { invokeHint } from './auth.js';
import { printJson } from './format.js';

interface CreateResult {
  id: string;
  provider: string;
  slug: string;
  webhook_url: string;
  webhook_secret: string;
  agent_id: string | null;
  forward_url: string | null;
  created_at: string;
}

interface View {
  id: string;
  provider: string;
  slug: string;
  webhook_url: string;
  agent_id: string | null;
  forward_url: string | null;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  last_block_at: string | null;
  total_calls: number;
  total_blocked: number;
}

export async function cmdInboundWebhook(args: string[]): Promise<void> {
  const sub = args[0];
  if (!sub || sub === '--help' || sub === '-h') return printHelp();
  if (sub === 'create') return await cmdCreate(args.slice(1));
  if (sub === 'list') return await cmdList(args.slice(1));
  if (sub === 'get') return await cmdGet(args.slice(1));
  if (sub === 'revoke') return await cmdRevoke(args.slice(1));
  if (sub === 'rotate-secret') return await cmdRotateSecret(args.slice(1));
  stderr.write(`unknown subcommand: ${sub}\n`);
  printHelp();
  exit(2);
}

function printHelp(): void {
  stdout.write(`Usage: ${invokeHint('inbound-webhook <subcommand>')}

Subcommands:
  create   Create a new inbound webhook (returns URL + plaintext secret)
  list     List all inbound webhooks
  get      Get one inbound webhook by id
  revoke   Soft-delete an inbound webhook
  rotate-secret  Issue a new signing secret (shown once); the old one signs for 24 hours more

Create options:
  --provider <agentmail|generic>   (required)
  --agent <agt_*>                  (required)
  --forward-url <https://...>      (optional; log-only if omitted)
  --json                           emit raw JSON

Get / revoke:
  --id <iwh_*>                     (required)
  --json                           emit raw JSON

`);
}

function parseOpt(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i < 0 || i + 1 >= args.length) return undefined;
  return args[i + 1];
}

export function inboundWebhookCreateOptions(body: Record<string, unknown>): { body: Record<string, unknown> } {
  return { body };
}

async function cmdCreate(args: string[]): Promise<void> {
  const provider = parseOpt(args, '--provider');
  const agentId = parseOpt(args, '--agent');
  const forwardUrl = parseOpt(args, '--forward-url');
  if (!provider || !agentId) {
    stderr.write('error: --provider and --agent are required\n');
    exit(2);
  }
  await requireToken();
  const body: Record<string, unknown> = { provider, agent_id: agentId };
  if (forwardUrl) body['forward_url'] = forwardUrl;
  const result = await api<CreateResult>(
    'POST',
    '/v1/operator/inbound-webhooks',
    inboundWebhookCreateOptions(body),
  );
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(`
Created inbound webhook ${result.id}

  Provider:        ${result.provider}
  Webhook URL:     ${result.webhook_url}
  Webhook secret:  ${result.webhook_secret}
  Agent:           ${result.agent_id ?? '(none)'}
  Forward URL:     ${result.forward_url ?? '(log-only)'}

⚠  Capture the webhook secret now. It is shown ONLY ONCE.
   Paste both URL + secret into your provider's webhook config.

`);
}

async function cmdList(args: string[]): Promise<void> {
  await requireToken();
  const result = await api<{ webhooks: View[] }>('GET', '/v1/operator/inbound-webhooks');
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  if (!result.webhooks.length) {
    stdout.write(`No inbound webhooks. Create one with: ${invokeHint('inbound-webhook create')}\n`);
    return;
  }
  for (const w of result.webhooks) {
    const status = w.revoked_at ? 'revoked' : 'active';
    stdout.write(
      `  ${w.id}  ${w.provider.padEnd(10)}  ${status.padEnd(8)}  calls=${w.total_calls}  blocked=${w.total_blocked}\n`,
    );
  }
}

async function cmdGet(args: string[]): Promise<void> {
  const id = parseOpt(args, '--id') ?? args.find((a) => a.startsWith('iwh_'));
  if (!id) {
    stderr.write('error: --id <iwh_*> required\n');
    exit(2);
  }
  await requireToken();
  const result = await api<View>('GET', `/v1/operator/inbound-webhooks/${id}`);
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(JSON.stringify(result, null, 2) + '\n');
}

async function cmdRotateSecret(args: string[]): Promise<void> {
  const id = parseOpt(args, '--id') ?? args.find((a) => a.startsWith('iwh_'));
  if (!id) {
    stderr.write('error: --id <iwh_*> required\n');
    exit(2);
  }
  await requireToken();
  const result = await api<{ webhook_secret: string; previous_valid_until: string }>(
    'POST',
    `/v1/operator/inbound-webhooks/${id}/rotate-secret`,
    { body: {} },
  );
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(`New signing secret for ${id}: ${result.webhook_secret}\nThe previous secret keeps signing until ${result.previous_valid_until}.\n`);
}

async function cmdRevoke(args: string[]): Promise<void> {
  const id = parseOpt(args, '--id') ?? args.find((a) => a.startsWith('iwh_'));
  if (!id) {
    stderr.write('error: --id <iwh_*> required\n');
    exit(2);
  }
  await requireToken();
  const result = await api<{ transitioned: boolean }>('DELETE', `/v1/operator/inbound-webhooks/${id}`);
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(result.transitioned ? `Revoked ${id}\n` : `${id} was already revoked\n`);
}
