// services subcommands — thin wrappers over /v1/services/* + /v1/credentials/*.

import { stdout, stderr, stdin, exit } from 'node:process';
import { api, takeFlag, resolveAgentId } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printTable, printRecord, fmt } from './format.js';
import { governedApi } from './governance.js';
import { cmdServiceMcp } from './rentahuman.js';

interface Service {
  id: string;
  provider: string;
  name: string;
  description?: string;
  available?: boolean;
}

interface ServiceConnection {
  id: string;
  provider: string;
  name?: string;
  status: string;
  scopes?: string[];
  connected_at?: string;
}

export const CONNECTED_SERVICES_PATH = '/v1/services/connected';

export function findConnectedService(
  connections: ServiceConnection[],
  connectionId: string,
): ServiceConnection | undefined {
  return connections.find((connection) => connection.id === connectionId);
}

async function listConnections(): Promise<ServiceConnection[]> {
  const out = await api<ServiceConnection[]>('GET', CONNECTED_SERVICES_PATH);
  return Array.isArray(out) ? out : [];
}

async function cmdCatalog(json: boolean): Promise<void> {
  const list = await api<Service[]>('GET', '/v1/services');
  if (json) return printJson(list);
  const rows = list.map((s) => [s.provider, s.name, s.available === false ? fmt.dim('soon') : fmt.ok('yes')]);
  printTable(['PROVIDER', 'NAME', 'AVAILABLE'], rows);
}

async function cmdConnections(json: boolean): Promise<void> {
  const list = await listConnections();
  if (json) return printJson(list);
  if (list.length === 0) {
    stdout.write('(no service connections)\n');
    return;
  }
  const rows = list.map((c) => [c.id, c.name ?? '', c.provider, c.status, (c.scopes ?? []).join(', ')]);
  printTable(['ID', 'NAME', 'PROVIDER', 'STATUS', 'SCOPES'], rows);
}

async function cmdShow(connectionId: string, json: boolean): Promise<void> {
  const out = findConnectedService(await listConnections(), connectionId);
  if (!out) {
    stderr.write(`error: service connection "${connectionId}" was not found.\n`);
    exit(1);
  }
  if (json) return printJson(out);
  printRecord(out as unknown as Record<string, unknown>);
}

async function cmdVerify(connectionId: string, json: boolean): Promise<void> {
  const out = await api('POST', `/v1/services/${encodeURIComponent(connectionId)}/verify`);
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdDisconnect(connectionId: string, json: boolean): Promise<void> {
  const out = await api('DELETE', `/v1/services/${encodeURIComponent(connectionId)}/disconnect`);
  if (json) return printJson(out);
  stdout.write(`disconnected ${connectionId}\n`);
}

async function cmdRename(connectionId: string, name: string, json: boolean): Promise<void> {
  const out = await api('PATCH', `/v1/services/${encodeURIComponent(connectionId)}`, { body: { connection_name: name } });
  if (json) return printJson(out);
  stdout.write(`renamed ${connectionId} to ${name}\n`);
}

async function cmdCredential(provider: string, connection: string | undefined, json: boolean): Promise<void> {
  // Returns the raw credential — operator-only path. WARNING for the
  // human: shouldn't be in shell history; we don't suppress that here
  // because pipeline use cases (e.g. `cred = $(npx @getstackrun/cli
  // service credential stripe --json | jq .access_token)`) are legitimate.
  const out = await api('GET', `/v1/credentials/${encodeURIComponent(provider)}`, { query: { connection } });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

/**
 * A connect link: connect a service without the credential passing through a
 * chat or this terminal. `create` prints the one-time URL for the person to open
 * in a browser signed in to STACK (the only copy: it is never stored or
 * returned again); `get` reads whether it was used, never the URL.
 */
async function cmdConnectLink(args: string[], json: boolean): Promise<void> {
  const action = args[0];
  if (action === 'create') {
    const rest = args.slice(1);
    const scopesRaw = takeFlag(rest, '--scopes');
    // The customer's own API: a name and the hosts its key may be sent to. The key is entered on the page.
    const customName = takeFlag(rest, '--custom');
    const hostsRaw = takeFlag(rest, '--hosts');
    const description = takeFlag(rest, '--description');
    const template = takeFlag(rest, '--template');
    // Where the API's MCP endpoint is, when it speaks MCP over HTTP (https, on one of the hosts).
    const mcpUrl = takeFlag(rest, '--mcp-url');
    // A key of one of the customer's own supplier accounts: making:<gelato|prodigi|printful|lulu>, telegram:<account id> or post.
    const keyFor = takeFlag(rest, '--key');
    // What the connection is called when the service already has one.
    const connectionName = takeFlag(rest, '--connection-name');
    const named = typeof connectionName === 'string' ? { connection_name: connectionName } : {};
    if (typeof keyFor === 'string') {
      // A key link has no connection name: the API takes it only on a catalog or a custom link.
      if (typeof connectionName === 'string') {
        stderr.write(`usage: --connection-name does not apply to --key; it names a catalog or a --custom connection (${invokeHint('service connect-link create <service> --connection-name <name>')})\n`);
        exit(2);
      }
      const [kind, value] = keyFor.split(':');
      const connect = kind === 'making' && value && ['gelato', 'prodigi', 'printful', 'lulu'].includes(value)
        ? { kind: 'making_supplier', supplier: value }
        : kind === 'telegram' && value ? { kind: 'telegram_bot', account_id: value }
        : keyFor === 'post' ? { kind: 'post_address' } : null;
      if (!connect) {
        stderr.write(`usage: ${invokeHint('service connect-link create --key making:gelato|making:prodigi|making:printful|making:lulu|telegram:<account-id>|post')}\n`);
        exit(2);
      }
      const out = await api('POST', '/v1/services/connect-links', { body: { connect } });
      if (json) return printJson(out);
      printRecord(out as Record<string, unknown>);
      return;
    }
    if (typeof customName === 'string') {
      const hosts = typeof hostsRaw === 'string' ? hostsRaw.split(',').map((x) => x.trim()).filter(Boolean) : [];
      if (hosts.length === 0) {
        stderr.write(`usage: ${invokeHint('service connect-link create --custom <name> --hosts api.example.com[,more] [--description text] [--template name] [--mcp-url https://api.example.com/mcp]')}\n`);
        exit(2);
      }
      const out = await api('POST', '/v1/services/connect-links', {
        body: {
          custom: {
            name: customName,
            allowed_hosts: hosts,
            ...(typeof description === 'string' ? { description } : {}),
            ...(typeof template === 'string' ? { template } : {}),
            ...(typeof mcpUrl === 'string' ? { mcp_url: mcpUrl } : {}),
            ...named,
          },
        },
      });
      if (json) return printJson(out);
      printRecord(out as Record<string, unknown>);
      return;
    }
    const service = rest[0];
    if (!service || service.startsWith('--')) {
      stderr.write(`usage: ${invokeHint('service connect-link create <service> [--scopes a,b] [--connection-name <name>]')}\n`);
      stderr.write(`   or: ${invokeHint('service connect-link create --custom <name> --hosts api.example.com[,more]')}\n`);
      exit(2);
    }
    const scopes = typeof scopesRaw === 'string' ? scopesRaw.split(',').map((x) => x.trim()).filter(Boolean) : [];
    const out = await api('POST', '/v1/services/connect-links', {
      body: { service_id: service, ...(scopes.length > 0 ? { scopes } : {}), ...named },
    });
    if (json) return printJson(out);
    printRecord(out as Record<string, unknown>);
    return;
  }
  if (action === 'list') {
    const out = await api<{ links: Array<{ link_id: string; provider: string; connection_name?: string; method: string; expires_at: string }> }>('GET', '/v1/services/connect-links');
    if (json) return printJson(out.links);
    if (out.links.length === 0) {
      stdout.write('(no connect links waiting)\n');
      return;
    }
    printTable(['ID', 'PROVIDER', 'NAME', 'METHOD', 'EXPIRES'], out.links.map((l) => [l.link_id, l.provider, l.connection_name ?? '', l.method, l.expires_at]));
    return;
  }
  if (action === 'get') {
    const linkId = args[1];
    if (!linkId) {
      stderr.write(`usage: ${invokeHint('service connect-link get <link-id>')}\n`);
      exit(2);
    }
    const out = await api('GET', `/v1/services/connect-links/${encodeURIComponent(linkId)}`);
    if (json) return printJson(out);
    printRecord(out as Record<string, unknown>);
    return;
  }
  stderr.write(
    `usage: ${invokeHint('service connect-link create <service> [--scopes a,b]')}\n` +
      `   or: ${invokeHint('service connect-link create --custom <name> --hosts api.example.com[,more]')}\n` +
      `   or: ${invokeHint('service connect-link create --key making:gelato|making:prodigi|making:printful|making:lulu|telegram:<account-id>|post')}\n` +
      `   or: ${invokeHint('service connect-link get <link-id>')}\n` +
      `   or: ${invokeHint('service connect-link list')}\n`,
  );
  exit(2);
}

async function cmdTemplates(json: boolean): Promise<void> {
  const out = await api<{ templates?: unknown[] } | unknown[]>('GET', '/v1/services/templates');
  const list = Array.isArray(out) ? out : (out?.templates ?? []);
  if (json) return printJson(list);
  printJson(list);
}

/** Read a secret from stdin without echoing it.
 *
 * Two shapes, both normal:
 *   piped      `cat key.txt | npx @getstackrun/cli service connect-custom --stdin --name X`
 *   typed      the same command with no pipe — we prompt, turn the terminal's
 *              echo off, and read one line.
 *
 * Echo is restored in a finally, or a wrong password ends with a terminal that
 * has stopped showing what you type.
 */
async function readSecretFromStdin(promptText: string): Promise<string> {
  if (!stdin.isTTY) {
    // Piped. Read to EOF and do NOT touch the stream afterwards: pausing or
    // detaching a closing pipe trips a libuv assertion on Windows.
    const chunks: Buffer[] = [];
    return new Promise<string>((resolve, reject) => {
      stdin.on('data', (c) => chunks.push(Buffer.from(c)));
      stdin.once('end', () => resolve(Buffer.concat(chunks).toString('utf-8').trim()));
      stdin.once('error', reject);
    });
  }

  stderr.write(promptText);
  const wasRaw = stdin.isRaw === true;
  stdin.setRawMode?.(true);
  stdin.resume();
  stdin.setEncoding('utf-8');

  return new Promise<string>((resolve, reject) => {
    let buf = '';
    const done = (fn: () => void) => {
      stdin.removeListener('data', onData);
      stdin.setRawMode?.(wasRaw);
      stdin.pause();
      stderr.write('\n');
      fn();
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done(() => resolve(buf.trim()));
        // Ctrl-C / Ctrl-D: leave without writing anything anywhere.
        if (ch === '\u0003' || ch === '\u0004') {
          return done(() => reject(new Error('cancelled')));
        }
        if (ch === '\u007f' || ch === '\b') buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function cmdConnectCustom(args: string[], json: boolean): Promise<void> {
  const fromFile = takeFlag(args, '--from-file');
  const useStdin = args.includes('--stdin');
  if (useStdin) args.splice(args.indexOf('--stdin'), 1);

  // The `wrangler secret put` shape: the credential is typed or piped, never
  // an argv value. argv lands in shell history, in `ps`, and in any CI log
  // that echoes the command.
  //
  // This is also the path that keeps a secret out of a MODEL's context. An
  // agent calling stack_connect_custom_service passes the credential as a
  // tool argument, which puts it in the transcript and the provider's logs.
  // A human typing it here does not.
  if (useStdin) {
    const name = takeFlag(args, '--name');
    if (typeof name !== 'string') {
      stderr.write(
        `usage: ${invokeHint('service connect-custom --stdin --name <name> [--scopes a,b] [--connection-name <name>]')}\n` +
          `The credential is read from stdin - piped, or typed at the prompt with echo off.\n`,
      );
      exit(2);
    }
    const scopesRaw = takeFlag(args, '--scopes');
    const description = takeFlag(args, '--description');
    // Required by the API, and rightly: without it the proxy cannot tell the
    // operator's API from an attacker's host, so a stolen credential could be
    // replayed anywhere. Omitted only when the credential itself carries a
    // base_url the API can read the host from.
    const allowedHosts = takeFlag(args, '--allowed-hosts');
    // The address of the service's MCP endpoint, when it speaks MCP over HTTP: https, on one of the allowed hosts.
    const mcpUrl = takeFlag(args, '--mcp-url');
    // What the connection is called when the service already has one (not --name: that is the service's own name).
    const connectionName = takeFlag(args, '--connection-name');

    const credential = await readSecretFromStdin(`Credential for ${name}: `);
    if (!credential) {
      stderr.write('no credential given; nothing was sent.\n');
      exit(2);
    }

    const body: Record<string, unknown> = { name, credential };
    if (typeof description === 'string') body.description = description;
    if (typeof scopesRaw === 'string') {
      body.scopes = scopesRaw.split(',').map((x) => x.trim()).filter(Boolean);
    }
    if (typeof allowedHosts === 'string') {
      body.allowed_hosts = allowedHosts.split(',').map((x) => x.trim()).filter(Boolean);
    }
    if (typeof mcpUrl === 'string') body.mcp_url = mcpUrl;
    if (typeof connectionName === 'string') body.connection_name = connectionName;

    const out = await api('POST', '/v1/services/custom', { body });
    if (json) return printJson(out);
    printRecord(out as Record<string, unknown>);
    return;
  }

  if (typeof fromFile !== 'string') {
    stderr.write(
      `usage: ${invokeHint('service connect-custom --stdin --name <name>')}\n` +
        `   or: ${invokeHint('service connect-custom --from-file <config.json>')}\n` +
        `--stdin reads the credential without echoing it and without putting it in argv.\n` +
        `The JSON form should include provider, name, credentials, etc.\n`,
    );
    exit(2);
  }
  const { readFile } = await import('node:fs/promises');
  const body = JSON.parse(await readFile(fromFile, 'utf8'));
  const fileConnectionName = takeFlag(args, '--connection-name');
  if (typeof fileConnectionName === 'string') body.connection_name = fileConnectionName;
  const out = await api('POST', '/v1/services/custom', { body });
  if (json) return printJson(out);
  printRecord(out as Record<string, unknown>);
}

async function cmdGrantAgent(args: string[], json: boolean): Promise<void> {
  const fromFile = takeFlag(args, '--from-file');
  let body: Record<string, unknown> = {};
  if (typeof fromFile === 'string') {
    const { readFile } = await import('node:fs/promises');
    const parsed = JSON.parse(await readFile(fromFile, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      stderr.write('error: --from-file must contain one JSON object.\n');
      exit(2);
    }
    body = { ...(parsed as Record<string, unknown>) };
  }
  const agentNameOrId = takeFlag(args, '--agent');
  const connectionId = takeFlag(args, '--connection');
  const scopesRaw = takeFlag(args, '--scopes');
  const constraintsFile = takeFlag(args, '--constraints-file');
  const intentsFile = takeFlag(args, '--intents-file');
  const alternativesFile = takeFlag(args, '--alternatives-file');
  const allowDataFrom = takeFlag(args, '--allow-data-from');
  // GrantAgentAccessInput requires scopes (z.array(z.string()).min(1)).
  // Earlier CLI made --scopes optional which 400'd ZodError when omitted.
  const scopes = typeof scopesRaw === 'string'
    ? scopesRaw.split(',').map((s) => s.trim()).filter(Boolean)
    : Array.isArray(body['scopes']) ? body['scopes'] as string[] : [];
  const agentInput = typeof agentNameOrId === 'string' ? agentNameOrId : body['agent_id'];
  const connectionInput = typeof connectionId === 'string' ? connectionId : body['service_connection_id'];
  if (typeof agentInput !== 'string' || typeof connectionInput !== 'string' || scopes.length === 0) {
    stderr.write(
      `usage: ${invokeHint('service grant --agent <name-or-id> --connection <connection-id> --scopes scope1,scope2 [--constraints-file constraints.json] [--intents-file intents.json] [--alternatives-file rules.json] [--allow-data-from a,b]')}\n`
      + `   or: ${invokeHint('service grant --from-file grant.json')}\n`,
    );
    exit(2);
  }
  const agentId = await resolveAgentId(agentInput);
  body['agent_id'] = agentId;
  body['service_connection_id'] = connectionInput;
  body['scopes'] = scopes;
  const { readFile } = await import('node:fs/promises');
  if (typeof constraintsFile === 'string') {
    body['constraints'] = JSON.parse(await readFile(constraintsFile, 'utf8'));
  }
  if (typeof intentsFile === 'string') {
    body['intents'] = JSON.parse(await readFile(intentsFile, 'utf8'));
  }
  if (typeof alternativesFile === 'string') {
    body['alternatives'] = JSON.parse(await readFile(alternativesFile, 'utf8'));
  }
  if (typeof allowDataFrom === 'string') {
    body['allow_data_from'] = allowDataFrom.split(',').map((item) => item.trim()).filter(Boolean);
  }
  const out = await governedApi('POST', '/v1/services/grant', { body });
  if (json) return printJson(out);
  // With controls on, the agent's policy may still need to list the connection: say so beside the grant.
  const { control_policy: controlPolicy, ...grant } = out as Record<string, unknown>;
  printRecord(grant);
  const note = (controlPolicy as { message?: unknown } | null | undefined)?.message;
  if (typeof note === 'string') stderr.write(`note: ${note}
`);
}

async function cmdRevokeAgent(agentNameOrId: string, json: boolean): Promise<void> {
  const agentId = await resolveAgentId(agentNameOrId);
  const out = await api('DELETE', `/v1/services/agents/${encodeURIComponent(agentId)}/revoke`);
  if (json) return printJson(out);
  stdout.write(`revoked all service access for ${agentNameOrId}\n`);
}

async function cmdAgentPermissions(agentNameOrId: string, json: boolean): Promise<void> {
  const agentId = await resolveAgentId(agentNameOrId);
  const out = await api<unknown[]>('GET', `/v1/agents/${encodeURIComponent(agentId)}/permissions`);
  if (json) return printJson(out);
  printJson(out);
}

export async function cmdService(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const arg1 = args[1];

  if (sub === 'tools' || sub === 'call') return cmdServiceMcp(args);
  if (sub === 'catalog' || sub === 'available' || sub === 'list') return cmdCatalog(json);
  if (sub === 'connections' || sub === 'connected') return cmdConnections(json);
  if (sub === 'show') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('service show <connection-id>')}\n`);
      exit(2);
    }
    return cmdShow(arg1, json);
  }
  if (sub === 'verify') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('service verify <connection-id>')}\n`);
      exit(2);
    }
    return cmdVerify(arg1, json);
  }
  if (sub === 'disconnect') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('service disconnect <connection-id>')}\n`);
      exit(2);
    }
    return cmdDisconnect(arg1, json);
  }
  if (sub === 'rename') {
    if (!arg1 || !args[2]) {
      stderr.write(`usage: ${invokeHint('service rename <connection-id> <name>')}\n`);
      exit(2);
    }
    return cmdRename(arg1, args[2], json);
  }
  if (sub === 'credential') {
    const connection = takeFlag(args, '--connection');
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('service credential <provider> [--connection <name|id>]')}\n`);
      exit(2);
    }
    return cmdCredential(arg1, typeof connection === 'string' ? connection : undefined, json);
  }
  if (sub === 'templates') return cmdTemplates(json);
  if (sub === 'connect-link') return cmdConnectLink(args.slice(1), json);
  if (sub === 'connect-custom' || sub === 'custom') return cmdConnectCustom(args.slice(1), json);
  if (sub === 'grant') return cmdGrantAgent(args.slice(1), json);
  if (sub === 'revoke-agent') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('service revoke-agent <agent-id>')}\n`);
      exit(2);
    }
    return cmdRevokeAgent(arg1, json);
  }
  if (sub === 'permissions') {
    if (!arg1) {
      stderr.write(`usage: ${invokeHint('service permissions <agent-id>')}\n`);
      exit(2);
    }
    return cmdAgentPermissions(arg1, json);
  }
  stderr.write(
    `error: unknown service subcommand "${sub ?? ''}".\n` +
      `Use catalog | connections | show | verify | disconnect | rename | credential | templates | connect-link | connect-custom | grant | revoke-agent | permissions\n` +
      `Note: connecting an OAuth service is browser-driven via the dashboard.\n`,
  );
  exit(2);
}
