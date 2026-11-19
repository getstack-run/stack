import { readFileSync } from 'node:fs';
import { api, takeFlag } from './api.js';
import { printJson } from './format.js';
import { readJsonObjectFile } from './account-args.js';
import { readSecretFromStdin } from './secret-input.js';

// Post: the customer's one US street address that receives and scans post
// (mailbox.bot), and letters and postcards out (Lob or PostGrid).
//
//   post address [start|connect|refresh|pause|resume|close]   the owner's address
//   post items [assign <item-id> --account <id>]               every item, for the owner
//   post <account-id> address|items|item|scan|forward|shred|check|send|letters|letter
//
// The address is the customer's own: it signs up at the supplier, completes
// USPS Form 1583 there and creates an agent key there. `post address connect`
// hands that key to STACK; it is read from stdin (piped, or typed at a hidden
// prompt) and never from argv. A second token on stdin is the secret of the
// webhook endpoint the customer created at the supplier, optional.
//
// A scan, forward or shred is only proposed at the supplier: the owner approves
// it there, and the supplier bills the owner's own account. A letter is held and
// charged on the account's credit at cost. The account's agent passes its
// Passport on stdin with --passport-stdin; the owner acts without one.

function flag(args: string[], name: string): string | undefined {
  const value = takeFlag(args, name);
  if (value === true) throw new Error(`${name} needs a value`);
  return typeof value === 'string' ? value : undefined;
}

function required(args: string[], name: string): string {
  const value = flag(args, name);
  if (value === undefined) throw new Error(`${name} is required`);
  return value;
}

function takeSwitch(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

function positional(args: string[], what: string): string {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (!value) throw new Error(`Invalid input: ${what} is required`);
  return value;
}

const PASSPORT_ARGV_FLAGS = new Set(['--passport', '--passport-token', '--token', '--key', '--api-key', '--webhook-secret']);

function refuseSecretsInArgv(args: string[]): void {
  if (args.some((arg) => PASSPORT_ARGV_FLAGS.has(arg.split('=')[0] ?? arg))) {
    throw new Error('Keys, secrets and Passport tokens must not be placed in argv. Pipe them on stdin or type them at the hidden prompt.');
  }
}

async function readPassport(): Promise<string> {
  const token = await readSecretFromStdin('Passport token: ');
  if (!token) throw new Error("No Passport token: pipe the account agent's Passport on stdin or type it at the prompt");
  return token;
}

function headers(passport: string | undefined, idempotencyKey: string | undefined): { headers?: Record<string, string> } {
  const out: Record<string, string> = {};
  if (passport !== undefined) out['X-Passport-Token'] = passport;
  if (idempotencyKey !== undefined) out['Idempotency-Key'] = idempotencyKey;
  return Object.keys(out).length > 0 ? { headers: out } : {};
}

/** A recipient from flags, or from a JSON file with the API's own field names. */
function readAddress(args: string[], prefix = ''): Record<string, unknown> {
  const file = flag(args, `--${prefix}address-file`);
  if (file !== undefined) return readJsonObjectFile(file);
  const out: Record<string, unknown> = {};
  const set = (field: string, name: string) => {
    const value = flag(args, `--${prefix}${name}`);
    if (value !== undefined) out[field] = value;
  };
  set('name', 'name');
  set('company', 'company');
  set('line1', 'line1');
  set('line2', 'line2');
  set('city', 'city');
  set('state', 'state');
  set('postal_code', 'postal-code');
  set('country', 'country');
  for (const needed of ['line1', 'city', 'postal_code']) {
    if (typeof out[needed] !== 'string') throw new Error(`Invalid input: --${prefix}${needed.replace('_', '-')} is required (or use --${prefix}address-file)`);
  }
  return out;
}

function readText(args: string[], name: string, fileName: string): string | undefined {
  const value = flag(args, name);
  const file = flag(args, fileName);
  if (value !== undefined && file !== undefined) throw new Error(`Use ${name} or ${fileName}, not both`);
  return file !== undefined ? readFileSync(file, 'utf8') : value;
}

function listQuery(args: string[], names: readonly string[]): Record<string, string> {
  const query: Record<string, string> = {};
  for (const name of names) {
    const value = flag(args, `--${name}`);
    if (value !== undefined) query[name] = value;
  }
  return query;
}

async function cmdAddress(args: string[]): Promise<void> {
  const action = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (action === undefined) return printJson(await api('GET', '/v1/post/address'));
  if (action === 'start') return printJson(await api('POST', '/v1/post/address'));
  if (action === 'refresh') return printJson(await api('POST', '/v1/post/address/refresh'));
  if (action === 'pause') return printJson(await api('POST', '/v1/post/address/pause'));
  if (action === 'resume') return printJson(await api('POST', '/v1/post/address/resume'));
  if (action === 'close') return printJson(await api('DELETE', '/v1/post/address'));
  if (action === 'connect') {
    takeSwitch(args, '--key-stdin');
    const input = await readSecretFromStdin('Supplier agent key (then, optionally, the webhook secret): ');
    const [apiKey, webhookSecret] = input.split(/\s+/).filter(Boolean);
    if (!apiKey) throw new Error('No key: pipe the agent key the supplier issued on stdin or type it at the prompt');
    return printJson(await api('POST', '/v1/post/address/connect', { body: { api_key: apiKey, ...(webhookSecret ? { webhook_secret: webhookSecret } : {}) } }));
  }
  throw new Error('Invalid input: address takes start, connect, refresh, pause, resume or close');
}

export async function cmdPost(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  refuseSecretsInArgv(args);
  const first = args.shift();
  if (first === undefined) throw new Error('Invalid input');

  if (first === 'address') return cmdAddress(args);
  if (first === 'items') {
    if (args[0] === 'assign') {
      args.shift();
      const itemId = positional(args, 'item id');
      const account = required(args, '--account');
      return printJson(await api('POST', `/v1/post/items/${encodeURIComponent(itemId)}/assign`, { body: { account_id: account } }));
    }
    return printJson(await api('GET', '/v1/post/items', { query: listQuery(args, ['limit', 'cursor', 'routing']) }));
  }

  // Everything else is one account's post: `post <account-id> <verb> ...`.
  if (first.startsWith('--')) throw new Error('Invalid input: account id is required');
  const path = `/v1/accounts/${encodeURIComponent(first)}/post`;
  const verb = args.shift();
  const asAgent = takeSwitch(args, '--passport-stdin');
  const idempotencyKey = flag(args, '--idempotency-key');
  const passport = asAgent ? await readPassport() : undefined;
  const call = headers(passport, idempotencyKey);

  if (verb === 'address') return printJson(await api('GET', `${path}/address`, call));
  if (verb === 'items') return printJson(await api('GET', `${path}/items`, { query: listQuery(args, ['limit', 'cursor']), ...call }));
  if (verb === 'item') return printJson(await api('GET', `${path}/items/${encodeURIComponent(positional(args, 'item id'))}`, call));
  if (verb === 'scan') {
    const itemId = positional(args, 'item id');
    const capture = flag(args, '--capture');
    return printJson(await api('POST', `${path}/items/${encodeURIComponent(itemId)}/scan`, { body: capture ? { capture } : {}, ...call }));
  }
  if (verb === 'forward') {
    const itemId = positional(args, 'item id');
    const mailClass = flag(args, '--mail-class');
    const destination = readAddress(args, 'to-');
    return printJson(await api('POST', `${path}/items/${encodeURIComponent(itemId)}/forward`, { body: { destination, ...(mailClass ? { mail_class: mailClass } : {}) }, ...call }));
  }
  if (verb === 'shred') {
    const itemId = positional(args, 'item id');
    if (!takeSwitch(args, '--confirm')) throw new Error('Shredding cannot be undone: add --confirm');
    return printJson(await api('POST', `${path}/items/${encodeURIComponent(itemId)}/shred`, { body: { confirm: true }, ...call }));
  }
  if (verb === 'check') return printJson(await api('POST', `${path}/address-check`, { body: { address: readAddress(args, 'to-') }, ...call }));
  if (verb === 'letters') return printJson(await api('GET', `${path}/letters`, { query: listQuery(args, ['limit', 'cursor']), ...call }));
  if (verb === 'letter') return printJson(await api('GET', `${path}/letters/${encodeURIComponent(positional(args, 'letter id'))}`, call));
  if (verb === 'send') {
    const useType = required(args, '--use-type');
    if (useType !== 'operational' && useType !== 'marketing') throw new Error('--use-type must be operational or marketing');
    const senderName = required(args, '--sender-name');
    const to = readAddress(args, 'to-');
    // The sender address printed on the letter, in the same form as the recipient: --return-line1 ... or --return-address-file.
    const returnAddress = args.some((a) => a.startsWith('--return-')) ? readAddress(args, 'return-') : undefined;
    const kind = flag(args, '--kind') ?? 'letter';
    const description = flag(args, '--description');
    const common = { to, sender_name: senderName, ...(returnAddress ? { return_address: returnAddress } : {}), use_type: useType, ...(description ? { description } : {}), ...(idempotencyKey ? { idempotency_key: idempotencyKey } : {}) };
    let body: Record<string, unknown>;
    if (kind === 'postcard') {
      const front = readText(args, '--front', '--front-file');
      const back = readText(args, '--back', '--back-file');
      if (front === undefined || back === undefined) throw new Error('A postcard needs --front and --back (or their -file forms)');
      const size = flag(args, '--size');
      body = { ...common, kind: 'postcard', front: { text: front }, back: { text: back }, ...(size ? { size } : {}) };
    } else if (kind === 'letter') {
      const text = readText(args, '--text', '--text-file');
      const pdf = flag(args, '--pdf-file');
      if ((text === undefined) === (pdf === undefined)) throw new Error('A letter needs exactly one of --text/--text-file or --pdf-file');
      const content = text !== undefined ? { text } : { pdf_base64: readFileSync(pdf!).toString('base64') };
      const extra = flag(args, '--extra-service');
      const mailClass = flag(args, '--mail-class');
      body = {
        ...common,
        content,
        ...(takeSwitch(args, '--color') ? { color: true } : {}),
        ...(takeSwitch(args, '--single-sided') ? { double_sided: false } : {}),
        ...(mailClass ? { mail_class: mailClass } : {}),
        ...(extra ? { extra_service: extra } : {}),
      };
    } else {
      throw new Error('--kind must be letter or postcard');
    }
    // The idempotency key is in the body already; the header would repeat it.
    return printJson(await api('POST', `${path}/letters`, { body, ...headers(passport, undefined) }));
  }
  throw new Error('Invalid input: post takes address, items, or an account id with address, items, item, scan, forward, shred, check, send, letters or letter');
}
