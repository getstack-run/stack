import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { API_URL, api } from './api.js';
import { printJson } from './format.js';
import {
  flag,
  passportHeaders,
  positional,
  readPassport,
  required,
  takeSwitch,
  wholeNumber,
} from './account-args.js';

// An agent account's website and getting paid, under `account website <id>`
// and `account payments <id>`.
//
// The account's agent builds the site and asks to be paid under its Passport.
// The Passport is a secret, so it is read from stdin (piped, or typed at a
// hidden prompt) and never from argv. The agent's own actions (publish, add or
// remove a domain, set prices, create or deactivate a payment link) always read
// it, after the flags are checked; reads and a domain check read it only with
// --passport-stdin and otherwise run as the operator. Suspending a site and
// disconnecting Stripe are the owner's alone.
//
// The restricted Stripe key is never a command argument: `payments stripe`
// prints the address of the customer's connect page, where it is pasted.

/** Folders that are never part of a site. */
const SKIPPED_DIRECTORIES = new Set(['.git', 'node_modules']);

interface BundleFile {
  path: string;
  content?: string;
  content_base64?: string;
}

function listFiles(root: string): string[] {
  const found: string[] = [];
  const walk = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      if (SKIPPED_DIRECTORIES.has(name)) continue;
      const full = join(directory, name);
      const info = statSync(full);
      if (info.isDirectory()) walk(full);
      else if (info.isFile()) found.push(full);
    }
  };
  walk(root);
  return found;
}

/** Text as `content`, anything else as `content_base64`, so the file arrives exactly as it was. */
function toBundleFile(path: string, bytes: Buffer): BundleFile {
  if (!bytes.includes(0)) {
    try {
      return { path, content: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) };
    } catch {
      // Not UTF-8 text: send the bytes.
    }
  }
  return { path, content_base64: bytes.toString('base64') };
}

/** Every file under `directory`, with `/`-rooted paths such as `/index.html`. */
export function readBundleDirectory(directory: string): BundleFile[] {
  if (!statSync(directory).isDirectory()) throw new Error(`${directory} is not a directory`);
  const files = listFiles(directory).map((full) =>
    toBundleFile(`/${relative(directory, full).split(sep).join('/')}`, readFileSync(full)),
  );
  if (files.length === 0) throw new Error(`${directory} has no files`);
  return files;
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`Invalid input: ${file} is not JSON (${(error as Error).message})`, { cause: error });
  }
}

function readPrices(file: string): unknown[] {
  const value = readJson(file);
  const prices = Array.isArray(value) ? value : (value as { prices?: unknown } | null)?.prices;
  if (!Array.isArray(prices)) throw new Error('Invalid input: --file must hold a list of prices, or an object with a prices list');
  return prices;
}

/** The agent's own action: the Passport is always read, once the flags are valid. */
async function agentHeaders(args: string[]): Promise<{ headers?: Record<string, string> }> {
  takeSwitch(args, '--passport-stdin');
  return passportHeaders(await readPassport());
}

/** A read or an owner-or-agent action: the Passport only when asked for. */
async function optionalHeaders(args: string[]): Promise<{ headers?: Record<string, string> }> {
  return passportHeaders(takeSwitch(args, '--passport-stdin') ? await readPassport() : undefined);
}

export async function cmdAccountWebsite(path: string, args: string[]): Promise<void> {
  const site = `${path}/website`;
  const action = args[0] && !args[0].startsWith('--') ? args.shift() : 'get';

  if (action === 'get') return printJson(await api('GET', site, await optionalHeaders(args)));

  if (action === 'publish') {
    const directory = required(args, '--dir');
    const serverFile = flag(args, '--server-file');
    const files = readBundleDirectory(directory);
    const body: Record<string, unknown> = { files };
    if (serverFile !== undefined) body['server'] = { source: readFileSync(serverFile, 'utf8') };
    return printJson(await api('POST', `${site}/deploys`, { body, ...(await agentHeaders(args)) }));
  }

  if (action === 'deploys') {
    const deployId = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
    const limit = wholeNumber(args, '--limit');
    const headers = await optionalHeaders(args);
    if (deployId !== undefined) return printJson(await api('GET', `${site}/deploys/${encodeURIComponent(deployId)}`, headers));
    return printJson(await api('GET', `${site}/deploys`, { query: limit !== undefined ? { limit } : {}, ...headers }));
  }

  if (action === 'hostnames') return printJson(await api('GET', `${site}/hostnames`, await optionalHeaders(args)));

  if (action === 'hostname-add') {
    const hostname = required(args, '--hostname');
    return printJson(await api('POST', `${site}/hostnames`, { body: { hostname }, ...(await agentHeaders(args)) }));
  }

  if (action === 'hostname-check') {
    const id = positional(args, 'hostname id');
    return printJson(await api('POST', `${site}/hostnames/${encodeURIComponent(id)}/check`, await optionalHeaders(args)));
  }

  if (action === 'hostname-remove') {
    const id = positional(args, 'hostname id');
    await api('DELETE', `${site}/hostnames/${encodeURIComponent(id)}`, { expectEmpty: true, ...(await agentHeaders(args)) });
    return printJson({ removed: true });
  }

  if (action === 'prices') return printJson(await api('GET', `${site}/prices`, await optionalHeaders(args)));

  if (action === 'prices-set') {
    const prices = readPrices(required(args, '--file'));
    return printJson(await api('PUT', `${site}/prices`, { body: { prices }, ...(await agentHeaders(args)) }));
  }

  if (action === 'suspend') {
    const reason = required(args, '--reason');
    return printJson(await api('POST', `${site}/suspension`, { body: { reason } }));
  }

  if (action === 'resume') return printJson(await api('DELETE', `${site}/suspension`));

  throw new Error(
    'Invalid input: website takes get, publish, deploys, hostnames, hostname-add, hostname-check, hostname-remove, prices, prices-set, suspend or resume',
  );
}

export async function cmdAccountPayments(path: string, args: string[]): Promise<void> {
  const payments = `${path}/payments`;
  const action = args[0] && !args[0].startsWith('--') ? args.shift() : 'list';

  if (action === 'stripe') return printJson(await api('POST', `${payments}/stripe`, { body: {}, ...(await optionalHeaders(args)) }));

  if (action === 'stripe-get') return printJson(await api('GET', `${payments}/stripe`, await optionalHeaders(args)));

  if (action === 'stripe-disconnect') {
    await api('DELETE', `${payments}/stripe`, { expectEmpty: true });
    return printJson({ disconnected: true });
  }

  if (action === 'link-create' || action === 'checkout-create') {
    const body: Record<string, unknown> = { name: required(args, '--name') };
    const amount = wholeNumber(args, '--amount-minor');
    if (amount === undefined) throw new Error('--amount-minor is required (a whole number in the currency\'s smallest unit)');
    body['amount_minor'] = amount;
    for (const [name, key] of [
      ['--currency', 'currency'],
      ['--item', 'item'],
    ] as const) {
      const value = flag(args, name);
      if (value !== undefined) body[key] = value;
    }
    if (action === 'link-create') {
      const after = flag(args, '--after-payment-url');
      if (after !== undefined) body['after_payment_url'] = after;
    } else {
      body['success_url'] = required(args, '--success-url');
      const cancel = flag(args, '--cancel-url');
      if (cancel !== undefined) body['cancel_url'] = cancel;
    }
    const route = action === 'link-create' ? 'links' : 'checkout-sessions';
    return printJson(await api('POST', `${payments}/${route}`, { body, ...(await agentHeaders(args)) }));
  }

  if (action === 'links') {
    const limit = wholeNumber(args, '--limit');
    const headers = await optionalHeaders(args);
    return printJson(await api('GET', `${payments}/links`, { query: limit !== undefined ? { limit } : {}, ...headers }));
  }

  if (action === 'link-deactivate') {
    const id = positional(args, 'link id');
    return printJson(await api('POST', `${payments}/links/${encodeURIComponent(id)}/deactivate`, await agentHeaders(args)));
  }

  if (action === 'list') {
    const query: Record<string, string | number> = {};
    const rail = flag(args, '--rail');
    if (rail !== undefined) {
      if (rail !== 'stripe' && rail !== 'x402') throw new Error('--rail must be stripe or x402');
      query['rail'] = rail;
    }
    const limit = wholeNumber(args, '--limit');
    if (limit !== undefined) query['limit'] = limit;
    const cursor = flag(args, '--cursor');
    if (cursor !== undefined) query['cursor'] = cursor;
    return printJson(await api('GET', payments, { query, ...(await optionalHeaders(args)) }));
  }

  if (action === 'get') {
    const id = positional(args, 'payment id');
    return printJson(await api('GET', `${payments}/${encodeURIComponent(id)}`, await optionalHeaders(args)));
  }

  throw new Error(
    'Invalid input: payments takes stripe, stripe-get, stripe-disconnect, link-create, checkout-create, links, link-deactivate, list or get',
  );
}

/** Suspend every site of the account at once. Owner or admin. */
export async function cmdWebsitesSuspendAll(args: string[]): Promise<void> {
  const reason = required(args, '--reason');
  return printJson(await api('POST', '/v1/websites/suspend-all', { body: { reason } }));
}

/**
 * Report a page on a STACK-hosted site. Anyone may: it sends no credential and
 * needs no sign-in, so it does not go through `api`.
 */
export async function cmdWebsiteReport(args: string[]): Promise<void> {
  const body: Record<string, unknown> = {
    url: required(args, '--url'),
    category: required(args, '--category'),
    description: required(args, '--description'),
  };
  const email = flag(args, '--email');
  if (email !== undefined) body['reporter_email'] = email;
  const response = await fetch(`${API_URL}/v1/public/site-reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`The report was refused (${response.status}): ${text.slice(0, 300)}`);
  return printJson(text ? JSON.parse(text) : { accepted: true });
}
