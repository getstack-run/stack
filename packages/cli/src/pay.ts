import { readFileSync, writeFileSync } from 'node:fs';
import { env, stderr, stdout } from 'node:process';
import {
  assertPayableUrl,
  loadAgentWalletKey,
  payX402,
  x402WalletOf,
  type AgentWalletKey,
  type X402StackPayment,
} from '@getstackrun/sdk';
import { api } from './api.js';
import { flag, positional, readPassport, refusePassportInArgv, takeSwitch, wholeNumber } from './account-args.js';
import { noExtra } from './control-socket.js';

// `stack pay <account> <url>`: buy from an x402 seller in one command. It asks the URL; when the seller answers 402 it
// makes the payment the seller asks for, signs it with the agent's own wallet key, pays through STACK (the wallet's
// caps, the account budget and the customer's controls, as `stack_request_wallet_payment`), and asks again with the
// payment attached. What the seller answers is written to stdout (or --out); what was paid goes to stderr.
//
// This is the one command that holds the agent's wallet key. It is read from the file --wallet-key-file names, or
// from STACK_AGENT_WALLET_KEY, never from argv; it stays in this process and is never printed. The SDK refuses to load it
// inside STACK's sandbox. Only USDC on Base with x402's exact scheme can be paid, and only over https.

export const PAY_USAGE =
  'pay <account> <url> --passport-stdin [--wallet-key-file <path>] [--max-cents <n>] [--method <m>] [--header "Name: value"]... [--data <text>] [--out <file>]';

const KEY_ARGV_FLAGS = new Set(['--wallet-key', '--key', '--private-key']);

function readKey(file: string | undefined): AgentWalletKey {
  const text = file !== undefined ? readFileSync(file, 'utf8').trim() : env['STACK_AGENT_WALLET_KEY']?.trim();
  if (!text) {
    throw new Error("Invalid input: pay needs the agent's wallet key: --wallet-key-file <path>, or STACK_AGENT_WALLET_KEY in the environment");
  }
  return loadAgentWalletKey(text);
}

function headersOf(args: string[]): Record<string, string> {
  const headers: Record<string, string> = {};
  for (let value = flag(args, '--header'); value !== undefined; value = flag(args, '--header')) {
    const at = value.indexOf(':');
    if (at <= 0) throw new Error(`Invalid input: --header takes "Name: value", not ${JSON.stringify(value)}`);
    headers[value.slice(0, at).trim()] = value.slice(at + 1).trim();
  }
  return headers;
}

export async function cmdPay(argv: string[], deps: { fetch?: typeof fetch } = {}): Promise<void> {
  const args = [...argv];
  refusePassportInArgv(args);
  if (args.some((arg) => KEY_ARGV_FLAGS.has(arg.split('=')[0] ?? arg))) {
    throw new Error('The wallet key must not be placed in argv: give --wallet-key-file <path> or set STACK_AGENT_WALLET_KEY');
  }
  const account = positional(args, 'the account id');
  const url = positional(args, 'the URL to buy from');
  assertPayableUrl(url);
  const maxCents = wholeNumber(args, '--max-cents');
  const method = flag(args, '--method') ?? 'GET';
  const body = flag(args, '--data');
  const out = flag(args, '--out');
  const keyFile = flag(args, '--wallet-key-file');
  const headers = headersOf(args);
  if (!takeSwitch(args, '--passport-stdin')) {
    throw new Error("Invalid input: pay acts as the account's agent: pass --passport-stdin and pipe the agent's Passport on stdin");
  }
  noExtra(args);

  const key = readKey(keyFile);
  // The Passport is the credential of every call here: the wallet payment route accepts only an agent, so it is the bearer
  // as well as the header the server reads first, and no sign-in is needed.
  const passportToken = await readPassport();
  const passport = { headers: { 'X-Passport-Token': passportToken }, bearer: passportToken };
  const accountPath = `/v1/accounts/${encodeURIComponent(account)}`;
  const read = (await api('GET', accountPath, passport)) as { pieces?: Array<{ kind: string; state: string; details: Record<string, unknown> }> };

  const result = await payX402(url, {
    key,
    wallet: x402WalletOf(read.pieces ?? []),
    pay: async (input) => (await api('POST', `${accountPath}/wallet/payments`, { body: input, ...passport })) as X402StackPayment,
    method,
    headers,
    ...(body === undefined ? {} : { body }),
    ...(maxCents === undefined ? {} : { maxCents }),
    ...(deps.fetch ? { fetch: deps.fetch } : {}),
  });

  const bytes = Buffer.from(await result.response.arrayBuffer());
  if (out !== undefined) writeFileSync(out, bytes);
  else stdout.write(bytes);
  const summary = {
    paid: result.paid,
    status: result.response.status,
    ...(result.payment ? { payment_id: result.payment.payment_id, amount_cents: result.payment.amount_cents } : {}),
    ...(result.settlement === undefined ? {} : { settlement: result.settlement }),
  };
  stderr.write(`${JSON.stringify(summary)}\n`);
  if (!result.response.ok) {
    throw new Error(
      result.paid
        ? `Paid (${result.payment?.payment_id}), but the seller answered ${result.response.status}. The payment settles only if the seller collects it; check it with the account's wallet record.`
        : `The seller answered ${result.response.status}; nothing was paid.`,
    );
  }
}
