import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { env, stderr, stdin } from 'node:process';
import {
  InstallClient,
  InstallKey,
  Stack,
  StackError,
  passportDigest,
  verifyVerifiedStatement,
  type NetworkRevocationKind,
  type NetworkRevocationReason,
} from '@getstackrun/sdk';
import { API_URL, api, takeFlag } from './api.js';
import { printJson } from './format.js';
import { governedApi } from './governance.js';
import { flag, noExtra, positional, wholeNumber } from './control-socket.js';
import { readSecretFromStdin } from './secret-input.js';

// The STACK network: self-hosted installs, their keys, revocation across
// companies, and the checks any counterparty can run.
//
// Owner commands (install, key, subscription, revoke without a key file) use
// your account credential. Registering a key lets an install have passports
// countersigned in your name, so it waits for a person to approve it in a
// browser, exactly as a control-socket address change does. Revoking a key or
// an install never waits.
//
// Install commands (rules, classify, intent-deviation, countersign, and revoke with --key-file)
// hold no account credential: they sign each request with the install's own
// key, read from the file `key add` wrote (mode 0600, never printed).
//
// verify, verified, revocations and jwks need no credential at all.

const KINDS = ['passport', 'agent', 'key', 'install'] as const;
const REASONS = ['unspecified', 'key_compromise', 'agent_decommissioned', 'superseded', 'policy_violation', 'owner_request'] as const;

function reasonFlag(args: string[]): NetworkRevocationReason | undefined {
  const reason = flag(args, '--reason');
  if (reason === undefined) return undefined;
  if (!(REASONS as readonly string[]).includes(reason)) throw new Error(`--reason must be one of ${REASONS.join(', ')}`);
  return reason as NetworkRevocationReason;
}

/** The install an install-signed command acts as: `--install` or STACK_INSTALL_ID, and its key file. */
async function loadInstall(args: string[]): Promise<InstallClient> {
  const installId = flag(args, '--install') ?? env['STACK_INSTALL_ID'];
  const keyFile = flag(args, '--key-file') ?? env['STACK_INSTALL_KEY_FILE'];
  if (!installId) throw new Error('Invalid input: --install <id> (or STACK_INSTALL_ID) is required');
  if (!keyFile) throw new Error('Invalid input: --key-file <path> (or STACK_INSTALL_KEY_FILE) is required');
  const key = await InstallKey.fromPem(readFileSync(keyFile, 'utf8'));
  return new InstallClient({ installId, key, baseUrl: API_URL });
}

/** The install's own errors, printed the way `api()` prints the API's. */
async function asInstall<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof StackError) {
      stderr.write(`error: ${error.status} ${error.code}: ${error.message}\n`);
      process.exitCode = 1;
      throw new Error(error.message, { cause: error });
    }
    throw error;
  }
}

/** A passport or content given as text, as `@file`, or `-` for standard input. */
async function textInput(value: string): Promise<string> {
  if (value === '-') {
    const chunks: Buffer[] = [];
    for await (const chunk of stdin) chunks.push(Buffer.from(chunk as Buffer));
    return Buffer.concat(chunks).toString('utf8').trim();
  }
  if (value.startsWith('@')) return readFileSync(value.slice(1), 'utf8').trim();
  return value;
}

function publicStack(): Stack {
  return new Stack({ baseUrl: API_URL });
}

/** Write a new private key file readable by its owner only, or load the one already there. */
async function keyFromFile(path: string): Promise<{ key: InstallKey; created: boolean }> {
  if (existsSync(path)) return { key: await InstallKey.fromPem(readFileSync(path, 'utf8')), created: false };
  const key = await InstallKey.generate();
  writeFileSync(path, await key.toPem(), { mode: 0o600, flag: 'wx' });
  chmodSync(path, 0o600);
  return { key, created: true };
}

export async function cmdNetwork(argv: string[]): Promise<void> {
  const args = [...argv];
  takeFlag(args, '--json');
  const sub = args.shift();

  if (sub === 'install') return cmdInstall(args);
  if (sub === 'subscription' || sub === 'subscriptions') return cmdSubscription(args);
  if (sub === 'licence' || sub === 'licences') return cmdLicence(args);

  if (sub === 'revoke') {
    const reason = reasonFlag(args);
    const owner = flag(args, '--for-install');
    const signing = args.includes('--key-file') || env['STACK_INSTALL_KEY_FILE'] !== undefined;
    const client = signing ? await loadInstall(args) : null;
    const kind = positional(args, `the kind (${KINDS.join(', ')})`);
    if (!(KINDS as readonly string[]).includes(kind)) throw new Error(`Invalid input: the kind is one of ${KINDS.join(', ')}`);
    const subject = positional(args, 'the subject (a passport digest, agent id, key thumbprint or install id)');
    noExtra(args);
    if (!client && !owner) throw new Error('Invalid input: network revoke needs --for-install <id> (every revocation names the install it belongs to), or --key-file for the install\'s own request');
    if (client) {
      return printJson(await asInstall(() => client.publishRevocation({ kind: kind as NetworkRevocationKind, subject, ...(reason ? { reason } : {}) })));
    }
    return printJson(await api('POST', '/v1/network/revocations', {
      body: { kind, subject, install: owner, ...(reason ? { reason } : {}) },
    }));
  }

  if (sub === 'rules') {
    const held = wholeNumber(args, '--held-revision');
    const client = await loadInstall(args);
    noExtra(args);
    const rules = await asInstall(() => client.rules(held !== undefined ? { heldRevision: held } : {}));
    return printJson({
      version: rules.version,
      revision: rules.revision,
      expires_at: rules.expiresAt.toISOString(),
      packs: rules.packs.map((pack) => ({ id: pack.id, direction: pack.direction, rules: pack.rules.length })),
      statement: rules.statement,
    });
  }

  if (sub === 'classify') {
    const client = await loadInstall(args);
    const context = flag(args, '--context');
    const content = await textInput(positional(args, 'the content (text, @file, or - for standard input)'));
    noExtra(args);
    return printJson(await asInstall(() => client.classify(content, context as never)));
  }

  if (sub === 'intent-deviation') {
    const client = await loadInstall(args);
    const raw = await textInput(positional(args, 'the checkout to grade as JSON (text, @file, or - for standard input)'));
    noExtra(args);
    let input: unknown;
    try {
      input = JSON.parse(raw);
    } catch {
      throw new Error('Invalid input: the checkout to grade is not JSON ({"declared": {...}, "observed": {...}})');
    }
    return printJson(await asInstall(() => client.gradeIntentDeviation(input as never)));
  }

  if (sub === 'countersign') {
    const client = await loadInstall(args);
    const agent = flag(args, '--agent');
    const passportId = flag(args, '--passport-id');
    const ttl = wholeNumber(args, '--ttl-seconds');
    const passport = await textInput(positional(args, 'the passport (a token, @file, or - for standard input)'));
    noExtra(args);
    return printJson(await asInstall(() => client.countersign({
      passport,
      ...(agent ? { agent } : {}),
      ...(passportId ? { passportId } : {}),
      ...(ttl !== undefined ? { ttlSeconds: ttl } : {}),
    })));
  }

  if (sub === 'verify') {
    const passport = flag(args, '--passport');
    const countersignature = await textInput(positional(args, 'the countersignature (a token, @file, or - for standard input)'));
    noExtra(args);
    return printJson(await publicStack().network.verify({ countersignature, ...(passport ? { passport: await textInput(passport) } : {}) }));
  }

  if (sub === 'verified') {
    const digest = flag(args, '--passport-digest');
    const passport = flag(args, '--passport');
    const install = flag(args, '--install');
    const agent = flag(args, '--agent');
    noExtra(args);
    const stack = publicStack();
    const passportDigestValue = digest ?? (passport ? passportDigest(await textInput(passport)) : undefined);
    if (passportDigestValue === undefined && !(install && agent)) {
      throw new Error('Invalid input: give --passport-digest <digest>, --passport <token>, or --install <id> with --agent <id>');
    }
    const answer = await stack.network.verified(passportDigestValue !== undefined ? { passportDigest: passportDigestValue } : { install: install!, agent: agent! });
    const statement = await verifyVerifiedStatement(answer.statement, { jwks: await stack.network.jwks() });
    return printJson({
      status: statement.status,
      mark: statement.status === 'live' ? statement.mark : null,
      subject: statement.subject,
      install: statement.install,
      valid_until: statement.validUntil.toISOString(),
      statement_expires_at: statement.expiresAt.toISOString(),
      statement: answer.statement,
    });
  }

  if (sub === 'revocations') {
    const after = wholeNumber(args, '--after');
    const limit = wholeNumber(args, '--limit');
    const install = flag(args, '--install');
    noExtra(args);
    const list = await publicStack().network.revocations({
      ...(after !== undefined ? { after } : {}),
      ...(limit !== undefined ? { limit } : {}),
      ...(install ? { install } : {}),
    });
    return printJson({ after: list.after, head: list.head, resume_from: list.resumeFrom, entries: list.entries });
  }

  if (sub === 'jwks') {
    noExtra(args);
    return printJson(await publicStack().network.jwks());
  }

  throw new Error('Invalid input: network takes install, subscription, licence, revoke, rules, classify, intent-deviation, countersign, verify, verified, revocations or jwks');
}

async function cmdInstall(args: string[]): Promise<void> {
  const verb = args.shift();

  if (verb === 'register') {
    const name = positional(args, 'the install name');
    noExtra(args);
    return printJson(await api('POST', '/v1/network/installs', { body: { name } }));
  }
  if (verb === 'list') {
    noExtra(args);
    return printJson(await api('GET', '/v1/network/installs'));
  }
  if (verb === 'show') {
    const id = positional(args, 'the install id');
    noExtra(args);
    return printJson(await api('GET', `/v1/network/installs/${encodeURIComponent(id)}`));
  }
  if (verb === 'revoke') {
    const reason = reasonFlag(args);
    const id = positional(args, 'the install id');
    noExtra(args);
    return printJson(await api('POST', `/v1/network/installs/${encodeURIComponent(id)}/revoke`, { body: reason ? { reason } : {} }));
  }
  if (verb === 'key') {
    const action = args.shift();
    if (action === 'add') {
      const keyFile = flag(args, '--key-file');
      const rollover = wholeNumber(args, '--rollover-seconds');
      if (!keyFile) throw new Error('Invalid input: --key-file <path> is required: the private key is written there, readable by you only');
      const id = positional(args, 'the install id');
      noExtra(args);
      const { key, created } = await keyFromFile(keyFile);
      if (created) stderr.write(`A new key was written to ${keyFile}. It never leaves this machine: back it up as you would any private key.\n`);
      const challenge = await governedApi<{ nonce: string }>('POST', `/v1/network/installs/${encodeURIComponent(id)}/key-challenges`, { body: {} });
      return printJson(await api('POST', `/v1/network/installs/${encodeURIComponent(id)}/keys`, {
        body: {
          public_jwk: key.publicJwk,
          proof: await key.signKeyProof(id, challenge.nonce),
          ...(rollover !== undefined ? { rollover_seconds: rollover } : {}),
        },
      }));
    }
    if (action === 'revoke') {
      const reason = reasonFlag(args);
      const id = positional(args, 'the install id');
      const keyId = positional(args, 'the key id (ink_...)');
      noExtra(args);
      return printJson(await api('POST', `/v1/network/installs/${encodeURIComponent(id)}/keys/${encodeURIComponent(keyId)}/revoke`, { body: reason ? { reason } : {} }));
    }
    throw new Error('Invalid input: network install key takes add or revoke');
  }
  throw new Error('Invalid input: network install takes register, list, show, revoke or key');
}

/**
 * The licence keys STACK issued to the account. The key is a bearer secret, so it
 * is never an argument: it is read from `--licence-file`, or from standard input
 * (piped, or typed with echo off).
 */
async function cmdLicence(args: string[]): Promise<void> {
  const verb = args.shift();

  if (verb === 'revoke') {
    const reason = reasonFlag(args);
    const file = flag(args, '--licence-file');
    noExtra(args);
    const licenceKey = file ? readFileSync(file, 'utf8').trim() : await readSecretFromStdin('Licence key to revoke: ');
    if (!licenceKey) throw new Error('Invalid input: no licence key was given (--licence-file <path>, or the key on standard input)');
    return printJson(await api('POST', '/v1/network/licences/revoke', { body: { licence_key: licenceKey, ...(reason ? { reason } : {}) } }));
  }
  if (verb === 'list') {
    noExtra(args);
    return printJson(await api('GET', '/v1/network/licences/revoked'));
  }
  throw new Error('Invalid input: network licence takes revoke or list');
}

async function cmdSubscription(args: string[]): Promise<void> {
  const verb = args.shift();
  if (verb === 'list') {
    noExtra(args);
    return printJson(await api('GET', '/v1/network/subscriptions'));
  }
  if (verb === 'create') {
    const installs: string[] = [];
    for (let install = flag(args, '--install'); install !== undefined; install = flag(args, '--install')) installs.push(install);
    const url = positional(args, 'the address (an https URL)');
    noExtra(args);
    return printJson(await api('POST', '/v1/network/subscriptions', { body: { url, ...(installs.length > 0 ? { installs } : {}) } }));
  }
  if (verb === 'delete') {
    const id = positional(args, 'the subscription id');
    noExtra(args);
    return printJson(await api('DELETE', `/v1/network/subscriptions/${encodeURIComponent(id)}`));
  }
  if (verb === 'resume') {
    const id = positional(args, 'the subscription id');
    noExtra(args);
    return printJson(await api('POST', `/v1/network/subscriptions/${encodeURIComponent(id)}/resume`, { body: {} }));
  }
  if (verb === 'rotate-secret') {
    const id = positional(args, 'the subscription id');
    noExtra(args);
    return printJson(await api('POST', `/v1/network/subscriptions/${encodeURIComponent(id)}/rotate-secret`, { body: {} }));
  }
  throw new Error('Invalid input: network subscription takes create, list, delete, resume or rotate-secret');
}
