import { readFileSync, statSync } from 'node:fs';
import { basename } from 'node:path';
import { env } from 'node:process';
import { api } from './api.js';
import { printJson } from './format.js';
import { governedApi } from './governance.js';
import { readSecretFromStdin } from './secret-input.js';
import { flag, passportHeaders, positional, readJsonObjectFile, readPassport, required, takeSwitch, wholeNumber } from './account-args.js';

// Making on an agent account: the account's agent uploads a design, gets
// quotes, orders and tracks; the customer approves what their own supplier
// account will pay for.
//
//   accounts <id> making upload <file> [--description T]
//   accounts <id> making upload --drive-file <drive file id> [--name file.ext] [--description T]
//   accounts <id> making designs [<design id>]
//   accounts <id> making quote --design <id> --recipient-file r.json [--supplier S] [--quantity N]
//                              [--process P] [--material M] [--finish F] [--color C] [--unit mm|cm|in]
//                              [--product ID] [--placement P] [--page-count N] [--shipping cheapest|fastest]
//                              [--spec-file spec.json]
//   accounts <id> making quote-get <quote id>
//   accounts <id> making order <quote id>
//   accounts <id> making orders [<order id>]
//   accounts <id> making cancel <order id>
//   accounts <id> making approve <order id>      governed: a person approves in a browser
//   accounts <id> making reject <order id>
//   making-suppliers | making-connect-supplier <supplier> | making-disconnect-supplier <supplier>
//
// Upload, quote and order act as the account's agent, so they always read its
// Passport (stdin or the hidden prompt, never argv). Reads read it only with
// --passport-stdin and otherwise run as the operator. A supplier key is read the
// same way and never from an argument: from MAKING_SUPPLIER_KEY (and
// MAKING_SUPPLIER_SECRET for Lulu), else piped on stdin or typed at the hidden
// prompt, as a bare key or as JSON {"api_key", "api_secret", "store_id"}.

const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

function guardedPassport(args: string[]): Promise<string> {
  takeSwitch(args, '--passport-stdin');
  return readPassport();
}

async function optionalPassport(args: string[]): Promise<string | undefined> {
  return takeSwitch(args, '--passport-stdin') ? readPassport() : undefined;
}

function buildSpec(args: string[]): Record<string, unknown> {
  const file = flag(args, '--spec-file');
  const spec: Record<string, unknown> = file !== undefined ? readJsonObjectFile(file) : {};
  const quantity = wholeNumber(args, '--quantity');
  if (quantity !== undefined) spec['quantity'] = quantity;
  const pageCount = wholeNumber(args, '--page-count');
  if (pageCount !== undefined) spec['page_count'] = pageCount;
  for (const [name, key] of [
    ['--process', 'process'], ['--material', 'material'], ['--finish', 'finish'], ['--color', 'color'],
    ['--unit', 'unit'], ['--product', 'product'], ['--placement', 'placement'], ['--shipping', 'shipping'],
  ] as const) {
    const value = flag(args, name);
    if (value !== undefined) spec[key] = value;
  }
  return spec;
}

async function readSupplierCredential(): Promise<Record<string, string>> {
  const fromEnv = env['MAKING_SUPPLIER_KEY'];
  if (fromEnv) {
    const secret = env['MAKING_SUPPLIER_SECRET'];
    return { api_key: fromEnv, ...(secret ? { api_secret: secret } : {}) };
  }
  const raw = await readSecretFromStdin('Supplier API key (or JSON with api_key and api_secret): ');
  if (!raw) throw new Error('No supplier key: set MAKING_SUPPLIER_KEY, pipe it on stdin, or type it at the prompt');
  if (raw.startsWith('{')) {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid input: the supplier credential JSON must be an object');
    const record = parsed as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const key of ['api_key', 'api_secret', 'store_id']) {
      if (typeof record[key] === 'string') out[key] = record[key] as string;
    }
    if (!out['api_key']) throw new Error('Invalid input: the supplier credential JSON needs api_key');
    return out;
  }
  return { api_key: raw };
}

/** The operator's own supplier accounts: not tied to one agent account. */
export async function cmdMakingSuppliers(sub: string, args: string[]): Promise<void> {
  if (sub === 'making-suppliers') return printJson(await api('GET', '/v1/accounts/making/suppliers'));
  // Printful by signing in at Printful: prints the address to open; the tokens are stored when Printful sends the browser back.
  if (sub === 'making-connect-printful') return printJson(await api('POST', '/v1/accounts/making/suppliers/printful/connect'));
  const supplier = positional(args, 'supplier');
  const path = `/v1/accounts/making/suppliers/${encodeURIComponent(supplier)}`;
  if (sub === 'making-connect-supplier') return printJson(await api('PUT', path, { body: await readSupplierCredential() }));
  await api('DELETE', path, { expectEmpty: true });
  return printJson({ disconnected: true, supplier });
}

export async function cmdAccountMaking(path: string, args: string[]): Promise<void> {
  const action = args.shift();
  const base = `${path}/making`;

  if (action === 'upload') {
    const driveFile = flag(args, '--drive-file');
    const description = flag(args, '--description');
    let body: Record<string, unknown>;
    if (driveFile !== undefined) {
      // A file already on the agent's drive: nothing is read here, and the file is streamed to the supplier from the drive.
      const name = flag(args, '--name');
      body = {
        drive_file_id: driveFile,
        ...(name !== undefined ? { file_name: name } : {}),
        ...(description !== undefined ? { description } : {}),
      };
    } else {
      const file = positional(args, 'design file path');
      if (statSync(file).size > MAX_UPLOAD_BYTES) {
        throw new Error('Invalid input: a design file sent in a request is up to 20 MB; put a larger file on the drive and use --drive-file <drive file id>');
      }
      body = {
        file_name: basename(file),
        content_base64: readFileSync(file).toString('base64'),
        ...(description !== undefined ? { description } : {}),
      };
    }
    const passport = await guardedPassport(args);
    return printJson(await api('POST', `${base}/designs`, { body, ...passportHeaders(passport) }));
  }

  if (action === 'designs') {
    const id = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
    const passport = await optionalPassport(args);
    if (id) return printJson(await api('GET', `${base}/designs/${encodeURIComponent(id)}`, passportHeaders(passport)));
    const limit = flag(args, '--limit');
    return printJson(await api('GET', `${base}/designs`, { query: limit !== undefined ? { limit } : {}, ...passportHeaders(passport) }));
  }

  if (action === 'quote') {
    const design = required(args, '--design');
    const recipient = readJsonObjectFile(required(args, '--recipient-file'));
    const supplier = flag(args, '--supplier');
    const body = { design_id: design, ...(supplier !== undefined ? { supplier } : {}), spec: buildSpec(args), recipient };
    const passport = await guardedPassport(args);
    return printJson(await api('POST', `${base}/quotes`, { body, ...passportHeaders(passport) }));
  }

  if (action === 'quote-get') {
    const id = positional(args, 'quote id');
    const passport = await optionalPassport(args);
    return printJson(await api('GET', `${base}/quotes/${encodeURIComponent(id)}`, passportHeaders(passport)));
  }

  if (action === 'order') {
    const quoteId = positional(args, 'quote id');
    const passport = await guardedPassport(args);
    return printJson(await api('POST', `${base}/orders`, { body: { quote_id: quoteId }, ...passportHeaders(passport) }));
  }

  if (action === 'orders') {
    const id = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
    const passport = await optionalPassport(args);
    if (id) return printJson(await api('GET', `${base}/orders/${encodeURIComponent(id)}`, passportHeaders(passport)));
    const limit = flag(args, '--limit');
    return printJson(await api('GET', `${base}/orders`, { query: limit !== undefined ? { limit } : {}, ...passportHeaders(passport) }));
  }

  if (action === 'cancel') {
    const id = positional(args, 'order id');
    const passport = await optionalPassport(args);
    return printJson(await api('POST', `${base}/orders/${encodeURIComponent(id)}/cancel`, passportHeaders(passport)));
  }

  if (action === 'approve') {
    const id = positional(args, 'order id');
    return printJson(await governedApi('POST', `${base}/orders/${encodeURIComponent(id)}/approve`));
  }

  if (action === 'reject') {
    const id = positional(args, 'order id');
    return printJson(await api('POST', `${base}/orders/${encodeURIComponent(id)}/reject`));
  }

  throw new Error('Invalid input: making takes upload, designs, quote, quote-get, order, orders, cancel, approve or reject');
}
