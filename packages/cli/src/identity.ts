// identity subcommands.

import { stdout, stderr, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { governedApi } from './governance.js';
import { printJson, printTable, printRecord, fmt, fmtTs } from './format.js';
import { readSecretFromStdin } from './secret-input.js';

interface IdentityClaim {
  id: string;
  provider_key: string;
  layer: string;
  claim_type: string;
  assurance_level: string;
  verified_at?: string;
  expires_at?: string;
  revoked_at?: string | null;
}

async function cmdSettings(json: boolean): Promise<void> {
  const out = await api('GET', '/v1/operators/me/identity-settings');
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdUpdateSettings(args: string[], json: boolean): Promise<void> {
  const inheritance = takeFlag(args, '--inheritance');
  const ttl = takeFlag(args, '--ttl');
  const autoRevoke = takeFlag(args, '--auto-revoke');
  const body: Record<string, unknown> = {};
  if (typeof inheritance === 'string') body.identity_claim_inheritance = inheritance;
  if (typeof ttl === 'string') body.identity_claim_ttl = ttl;
  if (autoRevoke !== undefined) body.identity_auto_revoke = autoRevoke === true || autoRevoke === 'true';
  if (Object.keys(body).length === 0) {
    stderr.write(
      `usage: ${invokeHint('identity update-settings [--inheritance auto|opt_in] [--ttl 30d|90d|180d|1y] [--auto-revoke true|false]')}\n`,
    );
    exit(2);
  }
  // A change that makes identity proof last longer or reach more Passports asks a person to confirm it.
  const out = await governedApi('PATCH', '/v1/operators/me/identity-settings', { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdProviders(json: boolean): Promise<void> {
  const out = await api<unknown[]>('GET', '/v1/identity/providers');
  if (json) return printJson(out);
  printJson(out);
}

async function cmdClaims(json: boolean): Promise<void> {
  const out = await api<IdentityClaim[]>('GET', '/v1/identity/claims');
  const list = Array.isArray(out) ? out : ((out as unknown as { claims?: IdentityClaim[] })?.claims ?? []);
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no claims)\n');
    return;
  }
  const rows = list.map((c) => [
    c.id,
    c.provider_key,
    c.layer,
    c.assurance_level,
    c.revoked_at ? fmt.dim('revoked') : fmt.ok('active'),
    fmtTs(c.verified_at ?? null),
  ]);
  printTable(['ID', 'PROVIDER', 'LAYER', 'ASSURANCE', 'STATUS', 'VERIFIED'], rows);
}

interface VerificationSession {
  session_id: string;
  provider_key: string;
  status: string;
  requested_claims: string[];
  created_at: string;
  expires_at: string;
  completed_at: string | null;
}

/** One verification session: pending, or its end (completed, failed, or expired when nobody finished it in time). */
async function cmdSession(id: string, json: boolean): Promise<void> {
  const out = await api<VerificationSession>('GET', `/v1/identity/verify/sessions/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  printRecord({
    session_id: out.session_id,
    provider_key: out.provider_key,
    status: out.status,
    requested_claims: out.requested_claims.join(', '),
    created_at: out.created_at,
    expires_at: out.expires_at,
    completed_at: out.completed_at ?? '-',
  });
}

async function cmdRevokeClaim(id: string, json: boolean): Promise<void> {
  const out = await api('DELETE', `/v1/identity/claims/${encodeURIComponent(id)}`);
  if (json) return printJson(out);
  stdout.write(`revoked ${id}\n`);
}

async function readJsonObject(path: string): Promise<Record<string, unknown>> {
  const { readFile } = await import('node:fs/promises');
  const parsed = JSON.parse(await readFile(path, 'utf8')) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    stderr.write('error: the JSON file must contain one object.\n');
    exit(2);
  }
  return parsed as Record<string, unknown>;
}

function requiredArg(value: string | undefined, usage: string): string {
  if (value) return value;
  stderr.write(`usage: ${invokeHint(usage)}\n`);
  exit(2);
}

function requiredStringFlag(args: string[], flag: string, usage: string): string {
  const value = takeFlag(args, flag);
  if (typeof value === 'string') return value;
  stderr.write(`usage: ${invokeHint(usage)}\n`);
  exit(2);
}

async function cmdOidc(args: string[], json: boolean): Promise<void> {
  const sub = args[0] ?? 'status';
  if (sub === 'status' || sub === 'show') {
    const out = await api<{ config: Record<string, unknown> | null }>('GET', '/v1/identity/oidc/config');
    if (json) return printJson(out);
    if (!out.config) {
      stdout.write('(OIDC is not configured)\n');
      return;
    }
    return printRecord(out.config);
  }
  if (sub === 'create') {
    const file = requiredStringFlag(
      args,
      '--from-file',
      'identity oidc create --from-file config.json --secret-stdin',
    );
    if (!args.includes('--secret-stdin')) {
      stderr.write('error: --secret-stdin is required. The client secret must not be placed in argv or JSON.\n');
      exit(2);
    }
    const body = await readJsonObject(file);
    if ('client_secret' in body) {
      stderr.write('error: remove client_secret from the JSON file and use --secret-stdin.\n');
      exit(2);
    }
    body['client_secret'] = await readSecretFromStdin('OIDC client secret: ');
    return printJson(await api('POST', '/v1/identity/oidc/config', { body }));
  }
  const id = requiredArg(args[1], `identity oidc ${sub} <config-id>`);
  const path = `/v1/identity/oidc/config/${encodeURIComponent(id)}`;
  if (sub === 'test') return printJson(await api('POST', `${path}/test`, { body: {} }));
  if (sub === 'delete') {
    await api('DELETE', path);
    stdout.write(`deleted ${id}\n`);
    return;
  }
  if (sub === 'update') {
    const file = requiredStringFlag(
      args,
      '--from-file',
      'identity oidc update <config-id> --from-file update.json [--secret-stdin]',
    );
    const body = await readJsonObject(file);
    if ('client_secret' in body) {
      stderr.write('error: remove client_secret from the JSON file and use --secret-stdin.\n');
      exit(2);
    }
    if (args.includes('--secret-stdin')) body['client_secret'] = await readSecretFromStdin('OIDC client secret: ');
    return printJson(await api('PATCH', path, { body }));
  }
  stderr.write('error: use identity oidc status | create | update | test | delete\n');
  exit(2);
}

interface SsoDomain {
  id: string;
  domain: string;
  status: string;
  record: { type: string; name: string; value: string };
  verified_at: string | null;
  last_checked_at: string | null;
  last_check: string | null;
}

function printSsoDomainRecord(domain: SsoDomain): void {
  stdout.write(
    `${domain.domain} (${domain.id}): ${domain.status}\n`
    + `  publish a ${domain.record.type} record at ${domain.record.name}\n`
    + `  with the value ${domain.record.value}\n`,
  );
}

// Verified e-mail domains of single sign-on (spec/sso-login/SPEC.md 9.5): the account proves it controls a domain with a
// DNS TXT record, and an address at it counts as verified when the provider's ID token has no email_verified claim.
async function cmdSsoDomains(args: string[], json: boolean): Promise<void> {
  const sub = args[0] ?? 'list';
  if (sub === 'list' || sub === 'ls') {
    const out = await api<{ domains: SsoDomain[] }>('GET', '/v1/identity/sso-domains');
    if (json) return printJson(out);
    if (out.domains.length === 0) {
      stdout.write('(no domains: add one with identity sso-domains add <domain>)\n');
      return;
    }
    printTable(
      ['ID', 'DOMAIN', 'STATUS', 'LAST CHECK', 'CHECKED'],
      out.domains.map((d) => [d.id, d.domain, d.status === 'verified' ? fmt.ok(d.status) : fmt.dim(d.status), d.last_check ?? '', fmtTs(d.last_checked_at)]),
    );
    return;
  }
  if (sub === 'add') {
    const domain = requiredArg(args[1], 'identity sso-domains add <domain>');
    // Adding one needs a person to approve the exact domain in a browser; the governance flow asks and retries.
    const out = await governedApi<SsoDomain>('POST', '/v1/identity/sso-domains', { body: { domain } });
    if (json) return printJson(out);
    printSsoDomainRecord(out);
    stdout.write(`then run: ${invokeHint(`identity sso-domains verify ${out.id}`)}\n`);
    return;
  }
  const id = requiredArg(args[1], `identity sso-domains ${sub} <domain-id>`);
  const path = `/v1/identity/sso-domains/${encodeURIComponent(id)}`;
  if (sub === 'verify') {
    const out = await api<{ domain: SsoDomain; check: string }>('POST', `${path}/verify`, { body: {} });
    if (json) return printJson(out);
    if (out.check === 'confirmed') stdout.write(`${out.domain.domain} is verified\n`);
    else if (out.check === 'missing') stdout.write(`the record is not there yet; ${out.domain.status === 'verified' ? 'the domain stays verified until the record has been gone for seven days' : 'publish it, then check again'}\n`);
    else stdout.write('the lookup got no answer, which proves nothing either way; try again shortly\n');
    if (out.check !== 'confirmed' && out.domain.status !== 'verified') printSsoDomainRecord(out.domain);
    return;
  }
  if (sub === 'remove' || sub === 'rm' || sub === 'delete') {
    await api('DELETE', path);
    stdout.write(`removed ${id}\n`);
    return;
  }
  stderr.write('error: use identity sso-domains list | add | verify | remove\n');
  exit(2);
}

async function cmdConfigCollection(kind: 'spiffe' | 'wimse', args: string[]): Promise<void> {
  const sub = args[0] ?? 'list';
  const base = kind === 'spiffe'
    ? '/v1/identity/spiffe/trust-domains'
    : '/v1/identity/wimse/issuers';
  if (sub === 'list') return printJson(await api('GET', base));
  if (sub === 'create') {
    const file = requiredStringFlag(
      args,
      '--from-file',
      `identity ${kind} create --from-file config.json`,
    );
    return printJson(await api('POST', base, { body: await readJsonObject(file) }));
  }
  const id = requiredArg(args[1], `identity ${kind} ${sub} <id>`);
  const path = `${base}/${encodeURIComponent(id)}`;
  if (sub === 'get' || sub === 'show') return printJson(await api('GET', path));
  if (sub === 'delete') {
    await api('DELETE', path);
    stdout.write(`deleted ${id}\n`);
    return;
  }
  if (sub === 'update') {
    const file = requiredStringFlag(
      args,
      '--from-file',
      `identity ${kind} update <id> --from-file update.json`,
    );
    return printJson(await api('PATCH', path, { body: await readJsonObject(file) }));
  }
  stderr.write(`error: use identity ${kind} list | get | create | update | delete\n`);
  exit(2);
}

async function cmdRequirements(args: string[]): Promise<void> {
  const sub = args[0];
  const serviceId = requiredArg(args[1], `identity requirements ${sub ?? 'list'} <service-id>`);
  const base = `/v1/services/${encodeURIComponent(serviceId)}/requirements`;
  if (sub === 'list' || sub === 'show') return printJson(await api('GET', base));
  if (sub === 'create' || sub === 'replace') {
    const file = requiredStringFlag(
      args,
      '--from-file',
      `identity requirements ${sub} <service-id> --from-file requirement.json`,
    );
    const requirement = await readJsonObject(file);
    const body = sub === 'replace' ? { requirement } : requirement;
    // Replacing with a weaker requirement asks a person to confirm it; adding or strengthening one does not.
    return printJson(await (sub === 'replace' ? governedApi : api)(sub === 'replace' ? 'PUT' : 'POST', base, { body }));
  }
  if (sub === 'clear') return printJson(await governedApi('PUT', base, { body: { requirement: null } }));
  if (sub === 'delete') {
    const requirementId = requiredArg(args[2], 'identity requirements delete <service-id> <requirement-id>');
    await governedApi('DELETE', `${base}/${encodeURIComponent(requirementId)}`);
    stdout.write(`deleted ${requirementId}\n`);
    return;
  }
  stderr.write('error: use identity requirements list | create | replace | clear | delete\n');
  exit(2);
}

// `identity send-code` was removed: it called POST /v1/identity/verification-codes
// which doesn't exist on the API. Verification codes for notification
// destinations are issued via /v1/notifications/destinations/:id/send-code
// (use `notifications methods send-code <id>`); identity-claim verification
// is initiated via the dashboard's identity verification flow per provider.

export async function cmdIdentity(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'settings' || sub === 'get-settings') return cmdSettings(json);
  if (sub === 'update-settings') return cmdUpdateSettings(args.slice(1), json);
  if (sub === 'providers') return cmdProviders(json);
  if (sub === 'claims' || sub === 'list') return cmdClaims(json);
  if (sub === 'session') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('identity session <session-id>')}\n`);
      exit(2);
    }
    return cmdSession(arg1, json);
  }
  if (sub === 'oidc') return cmdOidc(args.slice(1), json);
  if (sub === 'sso-domains') return cmdSsoDomains(args.slice(1), json);
  if (sub === 'spiffe') return cmdConfigCollection('spiffe', args.slice(1));
  if (sub === 'wimse') return cmdConfigCollection('wimse', args.slice(1));
  if (sub === 'requirements') return cmdRequirements(args.slice(1));
  if (sub === 'revoke-claim') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('identity revoke-claim <claim-id>')}\n`);
      exit(2);
    }
    return cmdRevokeClaim(arg1, json);
  }
  if (sub === 'send-code') {
    stderr.write(
      `error: \`identity send-code\` is no longer available (no matching API endpoint).\n`
      + `For notification destination verification, use: ${invokeHint('notifications methods send-code <id>')}\n`
      + `For identity-claim verification, start the flow in the dashboard at /identity.\n`,
    );
    exit(2);
  }
  stderr.write(
    `error: unknown identity subcommand "${sub ?? ''}".\n` +
      `Use settings | update-settings | providers | claims | session | revoke-claim | oidc | sso-domains | spiffe | wimse | requirements\n`,
  );
  exit(2);
}
