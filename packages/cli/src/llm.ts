// LLM gateway CLI commands.
//
// Subcommands:
//   stack llm usage list [--limit N] [--provider X] [--passport-jti X]
//                        [--mission-id X] [--agent-id X]
//                        [--since ISO] [--until ISO] [--cursor X] [--json]
//   stack llm usage summary [--provider X] [...filter flags...] [--json]
//   stack llm anthropic messages '<body-json>' [--stream] [--json]
//   stack llm openai chat-completions '<body-json>' [--stream] [--json]
//   stack llm openai images '<body-json>' [--json]       an image on your own OpenAI key
//   stack llm openrouter chat-completions '<body-json>' [--stream] [--json]
//
// `usage list` + `usage summary` are the primary operator-facing
// commands for "what did my agents spend on LLM tokens." Provider
// wrappers exist primarily for ad-hoc testing — operators in
// production use the SDK from inside their agent code.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag, requireToken, API_URL, CONTROL_REF_HEADER, currentControlRef } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';
import { readSecretFromStdin } from './secret-input.js';

function takeBoolFlag(args: string[], name: string): boolean {
  const v = takeFlag(args, name);
  return v === true || v === 'true';
}

interface LlmUsageRow {
  id: string;
  provider: string;
  model: string;
  passport_jti: string;
  mission_id: string | null;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  provider_cost_cents: number | null;
  markup_cents: number | null;
  total_cost_cents: number | null;
  provider_cost_microcents: number | null;
  markup_microcents: number | null;
  total_cost_microcents: number | null;
  cost_basis: 'provider_reported' | 'catalog' | null;
  surface: 'gateway' | 'sealed_execution' | 'prompt_injection_l3' | 'intent_deviation' | 'memory';
  provider_payer: 'customer_provider' | 'stack_plan' | 'stack_wallet' | 'stack_comped';
  stack_fee_payer: 'stack_plan' | 'stack_wallet' | 'stack_comped' | 'none';
  wallet_hold_id: string | null;
  wallet_debited: boolean;
  streaming: boolean;
  created_at: string;
}

interface LlmUsageSummaryBucket {
  provider: string;
  model: string | null;
  day: string;
  call_count: number;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_cents: number;
  total_markup_cents: number;
  total_cost_microcents: number;
  total_markup_microcents: number;
  cost_is_estimated: boolean;
  surface: 'gateway' | 'sealed_execution' | 'prompt_injection_l3' | 'intent_deviation' | 'memory';
  provider_payer: 'customer_provider' | 'stack_plan' | 'stack_wallet' | 'stack_comped';
  stack_fee_payer: 'stack_plan' | 'stack_wallet' | 'stack_comped' | 'none';
}

export async function cmdLlm(args: string[]): Promise<void> {
  const sub = args[0];
  const json = takeBoolFlag(args, '--json');

  if (sub === 'usage') {
    const usageSub = args[1];
    if (usageSub === 'list') {
      await cmdUsageList(args.slice(2), json);
      return;
    }
    if (usageSub === 'summary') {
      await cmdUsageSummary(args.slice(2), json);
      return;
    }
    stderr.write(`Usage: ${invokeHint('llm usage <list|summary> [...flags]')}\n`);
    exit(2);
  }

  if (sub === 'anthropic' || sub === 'openai' || sub === 'openrouter') {
    await cmdProviderCall(sub, args.slice(1), json);
    return;
  }

  printLlmHelp();
}

async function cmdUsageList(args: string[], json: boolean): Promise<void> {
  const limit = takeLlmUsageLimit(args);
  const query: Record<string, string | undefined> = {
    limit,
  };
  const flagPairs: Array<[string, string]> = [
    ['--provider', 'provider'],
    ['--passport-jti', 'passport_jti'],
    ['--mission-id', 'mission_id'],
    ['--agent-id', 'agent_id'],
    ['--since', 'since'],
    ['--until', 'until'],
    ['--cursor', 'cursor'],
  ];
  for (const [flag, param] of flagPairs) {
    const v = takeFlag(args, flag);
    if (typeof v === 'string') query[param] = v;
  }
  const out = await api<{ items: LlmUsageRow[]; next_cursor: string | null }>(
    'GET', '/v1/llm/usage', { query },
  );
  if (json) return printJson(out);
  if (out.items.length === 0) {
    stdout.write('(no LLM usage records)\n');
    return;
  }
  const rows = out.items.map((r) => [
    fmtTs(new Date(r.created_at).getTime()),
    r.provider,
    truncate(r.model, 28),
    String(r.total_tokens),
    r.total_cost_cents !== null ? fmtCents(r.total_cost_cents) : '—',
    r.wallet_debited ? fmt.ok('yes') : fmt.warn('no'),
    r.streaming ? 'stream' : '',
  ]);
  printTable(['TIME', 'PROVIDER', 'MODEL', 'TOKENS', 'TOTAL ¢', 'DEBITED', 'MODE'], rows);
  if (out.next_cursor) {
    stdout.write(`\nMore rows available. --cursor ${out.next_cursor}\n`);
  }
}

export function takeLlmUsageLimit(args: string[]): string {
  const limit = takeFlag(args, '--limit');
  return typeof limit === 'string' ? limit : '20';
}

async function cmdUsageSummary(args: string[], json: boolean): Promise<void> {
  const query: Record<string, string | undefined> = {};
  const flagPairs: Array<[string, string]> = [
    ['--provider', 'provider'],
    ['--passport-jti', 'passport_jti'],
    ['--mission-id', 'mission_id'],
    ['--agent-id', 'agent_id'],
    ['--since', 'since'],
    ['--until', 'until'],
  ];
  for (const [flag, param] of flagPairs) {
    const v = takeFlag(args, flag);
    if (typeof v === 'string') query[param] = v;
  }
  const groupByModel = takeBoolFlag(args, '--no-group-by-model') ? 'false' : undefined;
  if (groupByModel) query['group_by_model'] = groupByModel;

  const out = await api<{ buckets: LlmUsageSummaryBucket[] }>(
    'GET', '/v1/llm/usage/summary', { query },
  );
  if (json) return printJson(out);
  if (out.buckets.length === 0) {
    stdout.write('(no LLM usage in window)\n');
    return;
  }
  const rows = out.buckets.map((b) => [
    b.day,
    b.provider,
    truncate(b.model ?? '(all models)', 28),
    String(b.call_count),
    String(b.total_prompt_tokens),
    String(b.total_completion_tokens),
    fmtCents(b.total_cost_cents),
    fmtCents(b.total_markup_cents),
  ]);
  printTable(
    ['DAY', 'PROVIDER', 'MODEL', 'CALLS', 'PROMPT', 'COMPLETION', 'TOTAL ¢', 'MARKUP ¢'],
    rows,
  );
}

async function cmdProviderCall(
  provider: 'anthropic' | 'openai' | 'openrouter',
  args: string[],
  json: boolean,
): Promise<void> {
  const verb = args[0];
  const expectedVerb = provider === 'anthropic' ? 'messages' : 'chat-completions';
  // An image on your own key: only OpenAI has a route for it here (OpenRouter's image models are called through its own API; the API says so for Anthropic).
  const images = verb === 'images' && provider === 'openai';
  if (verb !== expectedVerb && !images) {
    stderr.write(`Usage: ${invokeHint(`llm ${provider} ${expectedVerb} '<body-json>' [--stream]`)}\n`);
    exit(2);
  }
  const bodyJson = args[1];
  if (!bodyJson || bodyJson.startsWith('--')) {
    stderr.write(`Usage: ${invokeHint(`llm ${provider} ${expectedVerb} '<body-json>'`)}\n`);
    exit(2);
  }
  if (args.includes('--passport')) {
    stderr.write('error: passport tokens must not be placed in argv. Pipe the token or use the hidden prompt.\n');
    exit(2);
  }
  const passport = await readSecretFromStdin('Passport token: ');
  const stream = !images && takeBoolFlag(args, '--stream');

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(bodyJson) as Record<string, unknown>;
  } catch (err) {
    stderr.write(`Invalid JSON body: ${(err as Error).message}\n`);
    exit(2);
  }
  if (stream) body.stream = true;

  const path = images
    ? `/v1/llm/${provider}/images`
    : provider === 'anthropic'
      ? '/v1/llm/anthropic/messages'
      : `/v1/llm/${provider}/chat/completions`;

  if (stream) {
    // Stream mode: write each SSE chunk to stdout. Inline raw fetch
    // since api.ts's helper is JSON-only. Bearer resolution via
    // requireToken() — same auth path as api().
    const token = await requireToken();
    const res = await fetch(`${API_URL}${path}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
        'X-Passport-Token': passport,
        ...(currentControlRef() !== undefined ? { [CONTROL_REF_HEADER]: currentControlRef() as string } : {}),
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      stderr.write(`HTTP ${res.status}: ${await res.text()}\n`);
      exit(1);
    }
    if (!res.body) {
      stderr.write('Empty response body\n');
      exit(1);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      stdout.write(decoder.decode(value));
    }
    return;
  }

  const out = await api<unknown>('POST', path, {
    body,
    headers: { 'X-Passport-Token': passport },
  });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

function fmtCents(cents: number): string {
  if (cents === 0) return '0';
  if (cents < 100) return `${cents}¢`;
  return `$${(cents / 100).toFixed(2)}`;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}

function printLlmHelp(): void {
  stdout.write(`Usage: ${invokeHint('llm <subcommand>')}

Subcommands:
  usage list      List per-call LLM usage records (cursor-paginated)
                  Flags: --limit, --cursor, --provider, --passport-jti,
                         --mission-id, --agent-id, --since, --until, --json
  usage summary   Group-by aggregate (provider [+ model] + day)
                  Flags: same filters as 'list', plus --no-group-by-model

  anthropic messages '<body-json>' [--stream]
  openai chat-completions '<body-json>' [--stream]
  openrouter chat-completions '<body-json>' [--stream]
  openai images '<body-json>'      An image on your own OpenAI key (files in the agent's drive)
  These commands read the passport token from stdin or a hidden prompt.

Examples:
  ${invokeHint('llm usage list --limit 5')}
  ${invokeHint('llm usage summary --since 2026-05-01T00:00:00Z')}
  ${invokeHint('llm anthropic messages')} '{"model":"claude-opus-4-7","messages":[{"role":"user","content":"hi"}],"max_tokens":100}'
`);
}
