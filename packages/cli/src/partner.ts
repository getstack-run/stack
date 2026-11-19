// `stack partner` — partner-managed accounts.
//
// Platform partners (operators with is_partner=true) use this command to open
// and manage an isolated account for each of their customers, under their own
// reference for the customer. An account holds no address of the customer: the
// customer can be invited to see it (read-only) and, when the relationship
// ends, the account is released to them through a claim link.
//
// Every account has its own plan, free amounts and usage like any customer's,
// and the partner's wallet pays for it. The partner does not choose a plan for
// an account, which is why `account create` takes no --tier. Controls are the
// account's own switch (`account controls`).

import { stdout, stderr, exit } from 'node:process';
import { api, requireToken } from './api.js';
import { invokeHint } from './auth.js';
import { printJson } from './format.js';
import { resolveSingleMissionId } from './passports.js';

export async function cmdPartner(args: string[]): Promise<void> {
  const sub = args[0];
  if (!sub || sub === '--help' || sub === '-h') return printHelp();
  if (sub === 'account' || sub === 'accounts') return await cmdAccount(args.slice(1));
  if (sub === 'release' || sub === 'releases') return await cmdReleases();
  stderr.write(`unknown subcommand: ${sub}\n`);
  printHelp();
  exit(2);
}

function printHelp(): void {
  stdout.write(`Usage: ${invokeHint('partner <subcommand>')}

Subcommands:
  account create        Open an account for a customer under your own reference
  account list          List your accounts with month-to-date usage
  account get           Get one account by id
  account revoke        Close an account, its webhooks, and its passports
  account rotate-key    Replace an account's API key (printed once)
  account invite        Invite the customer to see the account, read-only
  account controls      Switch hosted controls on or off for one account
  account release       Release the account to its customer (claim link by mail)
  account webhook       Provision an inbound webhook under an account
  account issue-passport  Issue a passport for an agent under an account
  releases              List the releases you have a record of

`);
}

async function cmdAccount(args: string[]): Promise<void> {
  const sub = args[0];
  if (!sub) return printHelp();
  if (sub === 'create') return cmdAccountCreate(args.slice(1));
  if (sub === 'list') return cmdAccountList(args.slice(1));
  if (sub === 'get') return cmdAccountGet(args.slice(1));
  if (sub === 'revoke') return cmdAccountRevoke(args.slice(1));
  if (sub === 'rotate-key') return cmdAccountRotateKey(args.slice(1));
  if (sub === 'invite') return cmdAccountInvite(args.slice(1));
  if (sub === 'controls') return cmdAccountControls(args.slice(1));
  if (sub === 'release') return cmdAccountRelease(args.slice(1));
  if (sub === 'webhook') return cmdAccountWebhook(args.slice(1));
  if (sub === 'issue-passport') return cmdAccountIssuePassport(args.slice(1));
  stderr.write(`unknown account subcommand: ${sub}\n`);
  exit(2);
}

function parseOpt(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i < 0 || i + 1 >= args.length) return undefined;
  return args[i + 1];
}

/** The account id: `--id`, or the first argument that looks like one. */
function accountIdOf(args: string[]): string {
  const id = parseOpt(args, '--id') ?? args.find((a) => a.startsWith('op_'));
  if (!id) {
    stderr.write('error: --id <op_*> required\n');
    exit(2);
  }
  return id;
}

const account = (id: string) => `/v1/partner/accounts/${encodeURIComponent(id)}`;

interface AccountView {
  account_id: string;
  status: string;
  external_ref: string | null;
  billing: string;
  created_at: string;
  invite: { status: string };
  /** The account's own month-to-date actions. */
  usage?: { period: string; actions: number };
  /** The account's own plan, paid from the partner's wallet. */
  plan?: AccountPlan;
}

interface AccountPlan {
  monthly_cents: number;
  status: string;
  renews_on: string | null;
  controls: { monthly_cents: number; status: string; renews_on: string | null };
}

interface ReleaseRecord {
  account_id: string;
  external_ref: string | null;
  status: string;
  requested_by: string;
  requested_at: string;
  expires_at: string;
  completed_at: string | null;
}

/** "1,234 actions (2026-09)", or "-" when the API sent no usage block. */
function accountUsage(a: AccountView): string {
  return a.usage ? `${a.usage.actions.toLocaleString('en-US')} actions (${a.usage.period})` : '-';
}

/** "active, renews 2026-11-30", or "-" when the API sent no plan block. */
function planLine(plan: AccountPlan | undefined): string {
  if (!plan) return '-';
  return `${plan.status}${plan.renews_on ? `, renews ${plan.renews_on}` : ''}`;
}

function controlsLine(plan: AccountPlan | undefined): string {
  if (!plan) return '-';
  const c = plan.controls;
  return c.status === 'off' ? 'off' : `${c.status}${c.renews_on ? `, renews ${c.renews_on}` : ''}`;
}

async function cmdAccountControls(args: string[]): Promise<void> {
  const id = accountIdOf(args);
  const on = args.includes('--on');
  const off = args.includes('--off');
  if (on === off) {
    stderr.write(`usage: ${invokeHint('partner account controls <id> --on|--off')}\n`);
    exit(2);
  }
  await requireToken();
  const result = await api<{ account_id: string; plan?: AccountPlan }>('PUT', `${account(id)}/controls`, { body: { enabled: on } });
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(`Controls for ${result.account_id} are ${controlsLine(result.plan)}.\n`);
}

async function cmdAccountIssuePassport(args: string[]): Promise<void> {
  const accountId = parseOpt(args, '--account');
  const agentId = parseOpt(args, '--agent');
  const intent = parseOpt(args, '--intent');
  const servicesRaw = parseOpt(args, '--services');
  const ttl = parseOpt(args, '--ttl');
  const usage =
    `usage: ${invokeHint('partner account issue-passport --account <op_*> --agent <agt_*> --mission <ms_*> ')}` +
    '[--intent "<summary>"] [--services a,b] [--ttl 900]\n';
  if (!accountId || !agentId) {
    stderr.write(usage);
    exit(2);
  }
  // A Passport is issued for exactly one live Mission of the account.
  const mission = resolveSingleMissionId(parseOpt(args, '--mission'), parseOpt(args, '--missions'));
  if ('error' in mission) {
    stderr.write(`error: ${mission.error}\n${usage}`);
    exit(2);
  }
  await requireToken();
  const body: Record<string, unknown> = { agent_id: agentId, mission_ids: [mission.missionId] };
  if (intent || servicesRaw) {
    body['intent'] = {
      summary: intent ?? '',
      services: servicesRaw ? servicesRaw.split(',').map((s) => s.trim()).filter(Boolean) : [],
    };
  }
  if (ttl) body['ttl_seconds'] = Number.parseInt(ttl, 10);
  const result = await api('POST', `${account(accountId)}/passports/issue`, { body });
  printJson(result);
}

async function cmdAccountCreate(args: string[]): Promise<void> {
  if (args.includes('--tier')) {
    stderr.write(
      'error: --tier is not supported. An account\'s plan is not chosen by the partner; ' +
        'your wallet pays for it.\n',
    );
    exit(2);
  }
  const ref = parseOpt(args, '--ref');
  if (!ref) {
    stderr.write(`usage: ${invokeHint('partner account create --ref <your-reference> [--controls]')}\n`);
    exit(2);
  }
  await requireToken();
  const result = await api<{
    account_id: string;
    external_ref: string;
    status: string;
    billing: string;
    created: boolean;
    created_at: string;
    api_key?: string;
  }>('POST', '/v1/partner/accounts', { body: { external_ref: ref, ...(args.includes('--controls') ? { controls: true } : {}) } });
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  if (!result.created) {
    stdout.write(`\nYou already have account ${result.account_id} under the reference ${result.external_ref}. Nothing was made.\n`);
    stdout.write(`If its key was lost: ${invokeHint(`partner account rotate-key ${result.account_id}`)}\n\n`);
    return;
  }
  stdout.write(`
Opened account ${result.account_id}

  Reference:          ${result.external_ref}
  Billing:            ${result.billing} (paid from your wallet)
  Account API key:    ${result.api_key ?? ''}

⚠  Capture the API key now. It is shown ONLY ONCE.

`);
}

async function cmdAccountList(args: string[]): Promise<void> {
  await requireToken();
  const ref = parseOpt(args, '--ref');
  const query = ref ? `?external_ref=${encodeURIComponent(ref)}` : '';
  const result = await api<{ accounts: AccountView[] }>('GET', `/v1/partner/accounts${query}`);
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  if (!result.accounts.length) {
    stdout.write(`No accounts. Open one with: ${invokeHint('partner account create --ref <your-reference>')}\n`);
    return;
  }
  for (const a of result.accounts) {
    stdout.write(
      `  ${a.account_id}  ${a.status.padEnd(8)}  ${('invite: ' + a.invite.status).padEnd(16)}  ${accountUsage(a).padEnd(24)}  ${a.external_ref ?? '(no reference)'}\n`,
    );
  }
}

async function cmdAccountGet(args: string[]): Promise<void> {
  const id = accountIdOf(args);
  await requireToken();
  const result = await api<AccountView>('GET', account(id));
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(`
Account ${result.account_id}

  Status:             ${result.status}
  Reference:          ${result.external_ref ?? '(none)'}
  Customer invited:   ${result.invite.status}
  Billing:            ${result.billing} (paid from your wallet)
  Plan:               ${planLine(result.plan)}
  Controls:           ${controlsLine(result.plan)}
  Usage this month:   ${accountUsage(result)}
  Created:            ${result.created_at}

`);
}

async function cmdAccountRevoke(args: string[]): Promise<void> {
  const id = accountIdOf(args);
  await requireToken();
  const result = await api<{
    transitioned: boolean;
    webhooks_revoked: number;
    passports_revoked: number;
  }>('DELETE', account(id));
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(result.transitioned ? `Closed ${id}\n` : `${id} was already closed\n`);
  stdout.write(
    `  Webhooks revoked:   ${result.webhooks_revoked}\n` +
      `  Passports revoked:  ${result.passports_revoked}\n`,
  );
}

async function cmdAccountRotateKey(args: string[]): Promise<void> {
  const id = accountIdOf(args);
  await requireToken();
  const result = await api<{ account_id: string; api_key: string }>('POST', `${account(id)}/rotate-key`, { body: {} });
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(`\nNew API key for ${result.account_id}: ${result.api_key}\n\n⚠  Capture the key now. It is shown ONLY ONCE; the old one has stopped working.\n\n`);
}

async function cmdAccountInvite(args: string[]): Promise<void> {
  const id = accountIdOf(args);
  const email = parseOpt(args, '--email');
  if (!email) {
    stderr.write(`usage: ${invokeHint('partner account invite <id> --email <email> [--name <name>]')}\n`);
    exit(2);
  }
  await requireToken();
  const body: Record<string, unknown> = { email };
  const name = parseOpt(args, '--name');
  if (name) body['name'] = name;
  const result = await api<{ status: string; expires_at: string | null }>('POST', `${account(id)}/invite`, { body });
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(`Invited the customer to see ${id} (read-only). The invitation was mailed to ${email}.\n`);
}

async function cmdAccountRelease(args: string[]): Promise<void> {
  const id = accountIdOf(args);
  await requireToken();
  const path = `${account(id)}/release`;
  if (args.includes('--cancel')) {
    printJson(await api('DELETE', path));
    return;
  }
  if (args.includes('--status')) {
    printJson(await api('GET', path));
    return;
  }
  const email = parseOpt(args, '--email');
  const result = await api<{ release: ReleaseRecord }>('POST', path, { body: email ? { email } : {} });
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(
    `Release of ${id} is ${result.release.status}: the customer was mailed a claim link, which works until ${result.release.expires_at}.\n` +
      `Until they complete it the account stays yours; when they do, everything you set up in it (service connections, the Stripe key, bot tokens, supplier and OAuth app keys, control socket, notification, wake and webhook addresses and secrets) is removed and they start with none.\n` +
      `Read where it stands with: ${invokeHint(`partner account release ${id} --status`)}\n`,
  );
}

async function cmdReleases(): Promise<void> {
  await requireToken();
  printJson(await api('GET', '/v1/partner/releases'));
}

async function cmdAccountWebhook(args: string[]): Promise<void> {
  const accountId = parseOpt(args, '--account');
  const provider = parseOpt(args, '--provider');
  const agentId = parseOpt(args, '--agent');
  const forwardUrl = parseOpt(args, '--forward-url');
  if (!accountId || !provider || !agentId) {
    stderr.write('error: --account, --provider, --agent are required\n');
    exit(2);
  }
  await requireToken();
  const body: Record<string, unknown> = { provider, agent_id: agentId };
  if (forwardUrl) body['forward_url'] = forwardUrl;
  const result = await api<{
    webhook_url: string;
    webhook_secret: string;
  }>('POST', `${account(accountId)}/inbound-webhooks`, { body });
  if (args.includes('--json')) {
    printJson(result);
    return;
  }
  stdout.write(`
Created webhook under account ${accountId}

  Webhook URL:    ${result.webhook_url}
  Webhook secret: ${result.webhook_secret}

⚠  Capture the secret now. It is shown ONLY ONCE.

`);
}
