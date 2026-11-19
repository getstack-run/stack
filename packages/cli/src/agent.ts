// `stack agent enroll <name|id>` and `stack agent rotate <name|id>`.
//
// Pre-enrolls an agent from the CLI so an operator doesn't have to write
// SDK code first. Closes the arturo-shaped activation hole: register an
// agent in the dashboard, then enroll its keypair with one CLI command,
// then any subsequent SDK call (Python or TS) finds the existing
// ~/.stack/agents/<id>.json and skips re-enrollment.
//
// Silent path only — uses the operator's OAuth bearer (from
// `stack auth login`) or STACK_API_KEY. No browser bootstrap; the human
// has already authenticated to run this CLI.
//
// Same wire contract as packages/sdk/src/agent-auth.ts and
// sdk-python/src/getstack/agent_auth.py:
//   POST /v1/agents/:id/enrollment-challenge → { challenge_id, challenge }
//   sign challenge bytes with locally-generated Ed25519 privkey
//   POST /v1/agents/:id/enroll [?force=true]
//        body { public_key (JWK), challenge_id, signed_challenge }
//   persist { agent_id, publicKey, privateKey, enrolled_at } to
//   ~/.stack/agents/<id>.json (mode 0600)

import { env, stdout, stderr } from 'node:process';
// Reused below; the imports for `api`, `printTable`, `printJson`, etc.
// come further down via the agent listing/show/etc. section import block.
import { generateKeyPairSync, sign as cryptoSign, type JsonWebKey } from 'node:crypto';
import { writeFile, mkdir, chmod, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { findAgentByName } from './agent-lookup.js';
import { getAccessToken, invokeHint } from './auth.js';
import { governedApi } from './governance.js';

const API_URL = env['STACK_API_URL'] ?? 'https://api.getstack.run';

interface StoredKey {
  agent_id: string;
  publicKey: { kty: string; crv: string; x: string };
  privateKey: { kty: string; crv: string; x: string; d: string };
  enrolled_at: number;
}

interface AgentRow {
  id: string;
  name: string;
  status?: string;
  enrolled_at?: string | null;
  pubkey?: unknown;
}

function keyPath(agentId: string): string {
  return join(homedir(), '.stack', 'agents', `${agentId}.json`);
}

async function bearer(): Promise<string> {
  const token = await getAccessToken();
  if (token) return token;
  stderr.write(
    `error: not signed in.\nRun \`${invokeHint('auth login')}\` first.\n`,
  );
  process.exit(2);
}

// Resolve a name OR id to an agent row. Names without the agt_ prefix
// are looked up via /v1/agents (operator-scoped). IDs starting with
// agt_ are fetched directly via /v1/agents/:id to give a clean 404 if
// the operator doesn't own it.
async function resolveAgent(nameOrId: string, token: string): Promise<AgentRow> {
  if (nameOrId.startsWith('agt_')) {
    const res = await fetch(`${API_URL}/v1/agents/${encodeURIComponent(nameOrId)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 404) {
      stderr.write(`error: no agent with id "${nameOrId}" in your operator.\n`);
      process.exit(1);
    }
    if (!res.ok) {
      const body = await res.text();
      stderr.write(`error: failed to fetch agent (${res.status}): ${body.slice(0, 200)}\n`);
      process.exit(1);
    }
    return (await res.json()) as AgentRow;
  }
  const listRes = await fetch(`${API_URL}/v1/agents`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!listRes.ok) {
    const body = await listRes.text();
    stderr.write(`error: failed to list agents (${listRes.status}): ${body.slice(0, 200)}\n`);
    process.exit(1);
  }
  const agents = (await listRes.json()) as AgentRow[];
  const match = findAgentByName(agents, nameOrId);
  if (!match) {
    stderr.write(
      `error: no agent named "${nameOrId}" in your operator.\n` +
        `Register it first at https://getstack.run/agents.\n`,
    );
    process.exit(1);
  }
  return match;
}

// Convert a Node `crypto` Ed25519 public key to a {kty, crv, x} JWK.
// jwkExport on the public key gives the right shape directly.
function publicJwkFromKey(publicKey: ReturnType<typeof generateKeyPairSync>['publicKey']): {
  kty: string;
  crv: string;
  x: string;
} {
  const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKey & { kty?: string; crv?: string; x?: string };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) {
    throw new Error('keypair export did not yield an Ed25519 OKP JWK');
  }
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
}

function privateJwkFromKey(privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']): {
  kty: string;
  crv: string;
  x: string;
  d: string;
} {
  const jwk = privateKey.export({ format: 'jwk' }) as JsonWebKey & {
    kty?: string;
    crv?: string;
    x?: string;
    d?: string;
  };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x || !jwk.d) {
    throw new Error('keypair export did not yield a private Ed25519 OKP JWK');
  }
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d };
}

// Persist with mode 0600. Best-effort chmod on Windows.
async function persist(stored: StoredKey): Promise<void> {
  const path = keyPath(stored.agent_id);
  await mkdir(join(homedir(), '.stack', 'agents'), { recursive: true });
  await writeFile(path, JSON.stringify(stored, null, 2), { encoding: 'utf8', mode: 0o600 });
  try {
    await chmod(path, 0o600);
  } catch {
    /* Windows / unsupported FS */
  }
}

async function runEnroll(agentId: string, token: string, force: boolean): Promise<StoredKey> {
  // Step 1: challenge.
  const cRes = await fetch(`${API_URL}/v1/agents/${encodeURIComponent(agentId)}/enrollment-challenge`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
  if (!cRes.ok) {
    const errBody = (await cRes.json().catch(() => ({}))) as { error?: { message?: string } };
    throw new Error(`enrollment-challenge failed (${cRes.status}): ${errBody.error?.message ?? cRes.statusText}`);
  }
  const { challenge_id, challenge } = (await cRes.json()) as { challenge_id: string; challenge: string };

  // Step 2: generate keypair locally.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicJwk = publicJwkFromKey(publicKey);
  const privateJwk = privateJwkFromKey(privateKey);

  // Step 3: sign challenge. Node Ed25519 sign uses `sign(null, ...)`.
  const signature = cryptoSign(null, Buffer.from(challenge, 'utf8'), privateKey);
  const signed_challenge = signature.toString('base64url');

  // Step 4: POST /enroll (with ?force=true on rotation).
  const url = `${API_URL}/v1/agents/${encodeURIComponent(agentId)}/enroll${force ? '?force=true' : ''}`;
  const eRes = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: publicJwk, challenge_id, signed_challenge }),
  });
  if (!eRes.ok) {
    const errBody = (await eRes.json().catch(() => ({}))) as { error?: { message?: string } };
    const msg = errBody.error?.message ?? eRes.statusText;
    if (eRes.status === 409) {
      throw new Error(
        `agent already enrolled. Use \`${invokeHint(`agent rotate ${agentId}`)}\` (or pass --force) to rotate the keypair. ` +
          `Rotation requires operator-admin authority.`,
      );
    }
    throw new Error(`enroll failed (${eRes.status}): ${msg}`);
  }
  const enrolled = (await eRes.json()) as { enrolled_at?: string };

  const stored: StoredKey = {
    agent_id: agentId,
    publicKey: publicJwk,
    privateKey: privateJwk,
    enrolled_at: enrolled.enrolled_at
      ? Math.floor(new Date(enrolled.enrolled_at).getTime() / 1000)
      : Math.floor(Date.now() / 1000),
  };
  await persist(stored);
  return stored;
}

// Public entry: `agent enroll <name|id> [--force]`.
//
// First-time enrollment: any auth (operator key, member, OAuth, session)
// that's not member-readonly.
// Rotation (when already enrolled OR --force passed): operator-admin
// authority required by the API; the CLI surfaces the 409/403 cleanly.
export async function cmdAgentEnroll(nameOrId: string, opts: { force?: boolean }): Promise<void> {
  if (!nameOrId) {
    stderr.write('error: agent name or id required.\n');
    stderr.write(`usage: ${invokeHint('agent enroll <name|id> [--force]')}\n`);
    process.exit(2);
  }
  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);
  const force = opts.force === true;

  // Local guard before hitting the network: if we already have a
  // privkey on disk for this agent and the caller didn't pass --force,
  // refuse without consuming an enrollment-challenge slot.
  const path = keyPath(agent.id);
  if (existsSync(path) && !force) {
    const raw = await readFile(path, 'utf8').catch(() => '');
    let enrolledAt = '';
    try {
      const parsed = JSON.parse(raw) as StoredKey;
      if (parsed.enrolled_at) enrolledAt = ` (enrolled ${new Date(parsed.enrolled_at * 1000).toISOString()})`;
    } catch {
      /* corrupt local file — fall through */
    }
    stderr.write(
      `error: ${agent.id} already has a local keypair at ${path}${enrolledAt}.\n` +
        `Use \`${invokeHint(`agent rotate ${nameOrId}`)}\` (or pass --force) to replace it. ` +
        `Rotation requires operator-admin authority on the API.\n`,
    );
    process.exit(1);
  }

  try {
    const stored = await runEnroll(agent.id, token, force);
    stdout.write(
      `enrolled ${agent.name} (${agent.id})${force ? ' [rotated]' : ''}\n` +
        `  keypair saved to ${path}\n` +
        `  enrolled_at: ${new Date(stored.enrolled_at * 1000).toISOString()}\n` +
        `\nThe Python and TS SDKs will pick up this keypair automatically. ` +
        `Run any SDK call against agent_id=${agent.id} to mint the first passport.\n`,
    );
  } catch (err) {
    stderr.write(`error: ${(err as Error).message}\n`);
    process.exit(1);
  }
}

// `agent rotate <name|id>` — alias for `enroll --force`.
// Same auth requirements; the API enforces operator-admin on the
// rotation branch.
export async function cmdAgentRotate(nameOrId: string): Promise<void> {
  await cmdAgentEnroll(nameOrId, { force: true });
}

// ── Customer-managed claim signing ─────────────────
//
// `agent sign-claim <name|id> --envelope <file> [--out <file>]`
//
// Reads a JSON ClaimEnvelope, signs it locally with the agent's stored
// Ed25519 privkey (from ~/.stack/agents/<id>.json, produced by
// `agent enroll`), emits the base64url-encoded COSE_Sign1. Output goes
// to stdout by default; --out <path> writes to a file instead.
//
// The wire format is byte-identical to @stack/vault's ClaimSigner.sign,
// so the same AgentSigner.verifyPreSigned path on STACK accepts it.
//
// COSE_Sign1 logic is inlined here (not imported from @getstackrun/sdk)
// because the CLI's only function from the SDK is wire compatibility,
// not implementation reuse. ~40 lines of duplication; testable in
// isolation via a wire-compat smoke run against the API.

import { encode as cborEncode } from 'cbor-x';
import { createPrivateKey } from 'node:crypto';

// COSE constants — must match @stack/vault's ClaimSigner + the SDK's
// signClaimEnvelope. RFC 9052 / 9053 labels.
const COSE_ALG_EDDSA = -8;
const COSE_HEADER_ALG = 1;
const COSE_HEADER_KID = 4;
const COSE_HEADER_TYP = 16;
const STACK_CLAIM_TYP = 'stack/claim+cose';

function signEnvelopeWithStoredKey(
  envelopeJson: unknown,
  storedKey: StoredKey,
): string {
  const kid = `agent:${storedKey.agent_id}:v1`;
  const privateKey = createPrivateKey({
    key: storedKey.privateKey as unknown as JsonWebKey,
    format: 'jwk',
  });

  const payloadBytes = cborEncode(envelopeJson);

  const protectedHeader = new Map<number, unknown>([
    [COSE_HEADER_ALG, COSE_ALG_EDDSA],
    [COSE_HEADER_KID, Buffer.from(kid, 'utf8')],
    [COSE_HEADER_TYP, STACK_CLAIM_TYP],
  ]);
  const protectedBytes = cborEncode(protectedHeader);

  const sigStructure = [
    'Signature1',
    protectedBytes,
    Buffer.alloc(0),
    payloadBytes,
  ];
  const sigStructureBytes = cborEncode(sigStructure);

  // Ed25519: pass null as digest per RFC 8032 (alg has its own hashing).
  const signature = cryptoSign(null, sigStructureBytes, privateKey);

  const coseSign1 = [protectedBytes, new Map(), payloadBytes, signature];
  return Buffer.from(cborEncode(coseSign1)).toString('base64url');
}

export async function cmdAgentSignClaim(
  nameOrId: string,
  envelopePath: string,
  outPath: string | undefined,
): Promise<void> {
  if (!nameOrId) {
    stderr.write('error: agent name or id required.\n');
    stderr.write(`usage: ${invokeHint('agent sign-claim <name|id> --envelope <file> [--out <file>]')}\n`);
    process.exit(2);
  }
  if (!envelopePath) {
    stderr.write('error: --envelope <file> required.\n');
    stderr.write(`usage: ${invokeHint('agent sign-claim <name|id> --envelope <file> [--out <file>]')}\n`);
    process.exit(2);
  }

  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);

  const localPath = keyPath(agent.id);
  if (!existsSync(localPath)) {
    stderr.write(
      `error: no local keypair for ${agent.id} at ${localPath}.\n` +
        `Run \`${invokeHint(`agent enroll ${nameOrId}`)}\` first to generate + register a keypair.\n`,
    );
    process.exit(1);
  }
  const stored: StoredKey = JSON.parse(await readFile(localPath, 'utf8')) as StoredKey;

  let envelope: unknown;
  try {
    envelope = JSON.parse(await readFile(envelopePath, 'utf8'));
  } catch (err) {
    stderr.write(`error: failed to read envelope from ${envelopePath}: ${(err as Error).message}\n`);
    process.exit(1);
  }

  let cose: string;
  try {
    cose = signEnvelopeWithStoredKey(envelope, stored);
  } catch (err) {
    stderr.write(`error: signing failed: ${(err as Error).message}\n`);
    process.exit(1);
  }

  if (outPath) {
    await writeFile(outPath, cose, 'utf8');
    stdout.write(`signed ${agent.name} (${agent.id})\n  envelope: ${envelopePath}\n  output:   ${outPath}\n`);
  } else {
    stdout.write(cose + '\n');
  }
}

// ── List / show / register / suspend / unsuspend / delete ──────────
//
// Round out the agent surface so the CLI mirrors what MCP and the
// dashboard already offer. Auth = standard CLI bearer; all routes are
// operator-scoped on the API side.

import { api, takeFlag } from './api.js';
import { printTable, printJson, printRecord, fmt, fmtTs } from './format.js';

async function cmdAgentList(json: boolean): Promise<void> {
  const agents = await api<AgentRow[]>('GET', '/v1/agents');
  if (json) return printJson(agents);
  const rows = agents.map((a) => [
    a.id,
    a.name,
    statusBadge(a),
    a.enrolled_at ? fmt.ok('yes') : fmt.dim('no'),
    fmtTs((a as { created_at?: string }).created_at ?? null),
  ]);
  printTable(['ID', 'NAME', 'STATUS', 'ENROLLED', 'CREATED'], rows);
}

async function cmdAgentShow(nameOrId: string, json: boolean): Promise<void> {
  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);
  if (json) return printJson(agent);
  printRecord(agent as unknown as Record<string, unknown>);
}

// Parse a `--flag true|false` value (LLM gateway toggles). Bare
// `--flag` (no value) means true, matching takeFlag semantics elsewhere.
// Anything other than true/false is a hard exit 2 — these govern security
// posture (redaction OFF sends user PII to the provider), so a typo must
// never silently coerce.
function parseBoolFlag(flagName: string, value: string | boolean | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  if (value === true || value === 'true') return true;
  if (value === 'false') return false;
  stderr.write(`error: ${flagName} must be true or false (got "${String(value)}").\n`);
  process.exit(2);
}

async function agentPolicyBody(args: string[], allowRegistrationOnly: boolean): Promise<Record<string, unknown>> {
  const fromFile = takeFlag(args, '--from-file');
  let body: Record<string, unknown> = {};
  if (typeof fromFile === 'string') {
    const parsed = JSON.parse(await readFile(fromFile, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      stderr.write('error: --from-file must contain one JSON object.\n');
      process.exit(2);
    }
    body = { ...(parsed as Record<string, unknown>) };
  }

  const stringFlags: Array<[string, string]> = [
    ['--accountability-mode', 'accountability_mode'],
    ['--on-warning', 'on_warning'],
    ['--on-critical', 'on_critical'],
    ['--credential-access', 'credential_access'],
    ['--skill-access-mode', 'skill_access_mode'],
    ['--twin-policy', 'twin_policy'],
    ['--twin-llm-model', 'twin_llm_model'],
    ['--icon-url', 'icon_url'],
  ];
  if (allowRegistrationOnly) stringFlags.push(['--key-mode', 'key_mode']);
  for (const [flag, field] of stringFlags) {
    const value = takeFlag(args, flag);
    if (typeof value === 'string') body[field] = value;
  }

  const csvFlags: Array<[string, string]> = [['--allowed-skills', 'allowed_skills']];
  if (!allowRegistrationOnly) csvFlags.push(['--identity-claims', 'identity_claim_ids']);
  for (const [flag, field] of csvFlags) {
    const value = takeFlag(args, flag);
    if (typeof value === 'string') {
      body[field] = value.split(',').map((item) => item.trim()).filter(Boolean);
    }
  }

  const boolFlags: Array<[string, string]> = [
    ['--synthetic', 'is_synthetic'],
    ['--llm-inject-system-prompt', 'llm_inject_system_prompt'],
    ['--llm-redact-pii', 'llm_redact_pii'],
  ];
  boolFlags.push(['--eval-traffic', 'eval_traffic']);
  for (const [flag, field] of boolFlags) {
    const value = parseBoolFlag(flag, takeFlag(args, flag));
    if (value !== undefined) body[field] = value;
  }
  if (args.includes('--clear-twin-llm-model')) body['twin_llm_model'] = null;
  if (args.includes('--clear-icon')) body['icon_url'] = null;
  return body;
}

const PII_REDACTION_OFF_WARNING =
  '  warning: PII redaction disabled — user-message PII flows to the LLM provider unredacted\n';

async function cmdAgentRegister(
  name: string,
  description: string | undefined,
  keyMode: string | undefined,
  credentialAccess: string | undefined,
  profile: string | undefined,
  llmInjectSystemPrompt: boolean | undefined,
  llmRedactPii: boolean | undefined,
  policyBody: Record<string, unknown>,
  json: boolean,
): Promise<void> {
  const body: Record<string, unknown> = { ...policyBody, name };
  if (description) body.description = description;
  if (profile) {
    if (profile !== 'proxied-llm-bot') {
      stderr.write(
        `error: --profile must be: proxied-llm-bot (got "${profile}").\n`,
      );
      process.exit(2);
    }
    // The preset expands server-side to proxy_only + logged + stack_managed.
    body.profile = profile;
  }
  if (keyMode) {
    if (!['stack_managed', 'customer_managed', 'co_signed'].includes(keyMode)) {
      stderr.write(
        `error: --key-mode must be one of: stack_managed, customer_managed, co_signed (got "${keyMode}").\n`,
      );
      process.exit(2);
    }
    body.key_mode = keyMode;
  }
  if (credentialAccess) {
    if (!['direct', 'proxy_preferred', 'proxy_only'].includes(credentialAccess)) {
      stderr.write(
        `error: --credential-access must be one of: direct, proxy_preferred, proxy_only (got "${credentialAccess}").\n`,
      );
      process.exit(2);
    }
    body.credential_access = credentialAccess;
  }
  // LLM-gateway toggles. Both default true server-side
  // (fail-closed); only send when the operator explicitly set a value.
  if (llmInjectSystemPrompt !== undefined) body.llm_inject_system_prompt = llmInjectSystemPrompt;
  if (llmRedactPii !== undefined) body.llm_redact_pii = llmRedactPii;
  const agent = await governedApi<AgentRow>('POST', '/v1/agents/register', { body });
  if (json) return printJson(agent);
  const notes = [
    profile ? profile : null,
    keyMode && keyMode !== 'stack_managed' ? keyMode : null,
    // the default is now proxy_only, so what is worth surfacing in
    // the note is a value that LOOSENS it (direct / proxy_preferred).
    credentialAccess && credentialAccess !== 'proxy_only' ? credentialAccess : null,
    llmRedactPii === false ? 'llm_redact_pii=false' : null,
  ].filter(Boolean);
  const modeNote = notes.length ? ` [${notes.join(', ')}]` : '';
  stdout.write(`registered ${agent.name} (${agent.id})${modeNote}\n`);
  if (llmRedactPii === false) stdout.write(PII_REDACTION_OFF_WARNING);
  if (profile === 'proxied-llm-bot') {
    stdout.write(
      `  posture: proxy_only + logged + stack_managed (no key on the box, first LLM call works)\n` +
        `  next: ${invokeHint(`proxy serve --agent ${agent.name}`)}\n`,
    );
  }
}

// `agent setup --from-file setup.json`: register an agent, give it its first grants and declare the hosts its
// connections' credentials may be sent to, as one approval whose card lists all of it. The file is one JSON object:
// { "agent": { "name": ... }, "grants": [ { "service_connection_id", "scopes", "constraints"? } ],
//   "allowed_hosts": [ { "service_connection_id", "allowed_hosts": [...] } ] }.
async function cmdAgentSetup(file: string, json: boolean): Promise<void> {
  const parsed = JSON.parse(await readFile(file, 'utf8')) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    stderr.write('error: the setup file must contain one JSON object.\n');
    process.exit(2);
  }
  const body = parsed as Record<string, unknown>;
  const agentPart = body['agent'];
  if (!agentPart || typeof agentPart !== 'object' || typeof (agentPart as Record<string, unknown>)['name'] !== 'string') {
    stderr.write('error: the setup file needs an "agent" object with a "name".\n');
    process.exit(2);
  }
  const result = await governedApi<{
    agent: AgentRow;
    grants: Array<{ id: string; service_connection_id: string }>;
    allowed_hosts: Array<{ service_connection_id: string; allowed_hosts: string[] }>;
  }>('POST', '/v1/agents/setup', {
    body: { agent: agentPart, grants: body['grants'] ?? [], allowed_hosts: body['allowed_hosts'] ?? [] },
  });
  if (json) return printJson(result);
  stdout.write(`set up ${result.agent.name} (${result.agent.id})\n`);
  stdout.write(`  grants: ${result.grants.length}, host lists: ${result.allowed_hosts.length}\n`);
}

// `agent dismiss-warnings <name|id>`: resolve every open warning of the agent and keep new ones of the same kinds
// from coming back for a day. Criticals are never dismissed.
async function cmdAgentDismissWarnings(nameOrId: string, json: boolean): Promise<void> {
  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);
  const result = await api<{ dismissed: number; by_signal_type: Record<string, number>; repeats_hidden_for_seconds: number }>(
    'POST',
    `/v1/agents/${encodeURIComponent(agent.id)}/dismiss-warnings`,
    { body: {} },
  );
  if (json) return printJson(result);
  stdout.write(`dismissed ${result.dismissed} open warning${result.dismissed === 1 ? '' : 's'} for ${agent.name}\n`);
  stdout.write(`  new ones of the same kinds are hidden for ${Math.round(result.repeats_hidden_for_seconds / 3600)} hours; criticals stay open\n`);
}

async function cmdAgentSuspend(nameOrId: string, status: 'active' | 'suspended', json: boolean): Promise<void> {
  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);
  const updated = await api<AgentRow>('PATCH', `/v1/agents/${agent.id}`, { body: { status } });
  if (json) return printJson(updated);
  stdout.write(`${agent.name} → ${status}\n`);
}

// `agent update <name|id>` — mutable per-agent settings (the
// LLM-gateway toggles). Same explicit-value idiom as
// `identity update-settings --auto-revoke true|false`. Suspend/unsuspend
// stay dedicated verbs; this verb carries the settings PATCH surface.
async function cmdAgentUpdate(
  nameOrId: string,
  llmInjectSystemPrompt: boolean | undefined,
  llmRedactPii: boolean | undefined,
  policyBody: Record<string, unknown>,
  json: boolean,
): Promise<void> {
  const body: Record<string, unknown> = { ...policyBody };
  if (llmInjectSystemPrompt !== undefined) body.llm_inject_system_prompt = llmInjectSystemPrompt;
  if (llmRedactPii !== undefined) body.llm_redact_pii = llmRedactPii;
  if (Object.keys(body).length === 0) {
    stderr.write(
      `usage: ${invokeHint('agent update <name|id> [--llm-inject-system-prompt true|false] [--llm-redact-pii true|false]')}\n`,
    );
    process.exit(2);
  }
  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);
  const updated = await api<AgentRow>('PATCH', `/v1/agents/${agent.id}`, { body });
  if (json) return printJson(updated);
  const applied = Object.entries(body)
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(', ');
  stdout.write(`updated ${agent.name} (${agent.id}) [${applied}]\n`);
  if (llmRedactPii === false) stdout.write(PII_REDACTION_OFF_WARNING);
}

async function cmdAgentDelete(nameOrId: string, json: boolean): Promise<void> {
  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);
  await api('DELETE', `/v1/agents/${agent.id}`, { expectEmpty: true });
  if (json) return printJson({ deleted: true, id: agent.id });
  stdout.write(`deleted ${agent.name} (${agent.id})\n`);
}

async function cmdAgentUnblock(nameOrId: string, json: boolean): Promise<void> {
  const token = await bearer();
  const agent = await resolveAgent(nameOrId, token);
  const result = await governedApi('POST', `/v1/agents/${agent.id}/unblock`, { body: {} });
  if (json) return printJson(result);
  stdout.write(`unblocked ${agent.name} (${agent.id}) — it can issue passports again\n`);
}

function statusBadge(a: AgentRow): string {
  if ((a as { passport_blocked?: boolean }).passport_blocked) return fmt.err('blocked');
  if ((a as { status?: string }).status === 'suspended') return fmt.warn('suspended');
  if ((a as { status?: string }).status === 'revoked') return fmt.dim('revoked');
  return fmt.ok('active');
}

// Subcommand dispatcher: called from main() with args = argv.slice(3).
export async function cmdAgent(args: string[]): Promise<void> {
  const json = !!takeFlag(args, '--json');
  const sub = args[0];
  const target = args[1];
  const force = args.includes('--force');

  if (sub === 'list' || sub === 'ls') {
    await cmdAgentList(json);
    return;
  }
  if (sub === 'show' || sub === 'get') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent show <name|id>')}\n`);
      process.exit(2);
    }
    await cmdAgentShow(target, json);
    return;
  }
  if (sub === 'register') {
    if (!target) {
      stderr.write(
        `usage: ${invokeHint('agent register <name> [--from-file policy.json] [--profile proxied-llm-bot] [--description "..."]')}\n`,
      );
      process.exit(2);
    }
    const description = takeFlag(args, '--description');
    const policyBody = await agentPolicyBody(args, true);
    const keyMode = policyBody['key_mode'];
    const credentialAccess = policyBody['credential_access'];
    const profile = takeFlag(args, '--profile');
    const llmInjectSystemPrompt = policyBody['llm_inject_system_prompt'] as boolean | undefined;
    const llmRedactPii = policyBody['llm_redact_pii'] as boolean | undefined;
    await cmdAgentRegister(
      target,
      typeof description === 'string' ? description : undefined,
      typeof keyMode === 'string' ? keyMode : undefined,
      typeof credentialAccess === 'string' ? credentialAccess : undefined,
      typeof profile === 'string' ? profile : undefined,
      llmInjectSystemPrompt,
      llmRedactPii,
      policyBody,
      json,
    );
    return;
  }
  if (sub === 'setup') {
    const file = takeFlag(args, '--from-file');
    if (typeof file !== 'string') {
      stderr.write(`usage: ${invokeHint('agent setup --from-file setup.json')}\n`);
      process.exit(2);
    }
    await cmdAgentSetup(file, json);
    return;
  }
  if (sub === 'dismiss-warnings') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent dismiss-warnings <name|id>')}\n`);
      process.exit(2);
    }
    await cmdAgentDismissWarnings(target, json);
    return;
  }
  if (sub === 'update') {
    if (!target) {
      stderr.write(
        `usage: ${invokeHint('agent update <name|id> [--from-file policy.json] [policy flags...]')}\n`,
      );
      process.exit(2);
    }
    const policyBody = await agentPolicyBody(args, false);
    const llmInjectSystemPrompt = policyBody['llm_inject_system_prompt'] as boolean | undefined;
    const llmRedactPii = policyBody['llm_redact_pii'] as boolean | undefined;
    await cmdAgentUpdate(target, llmInjectSystemPrompt, llmRedactPii, policyBody, json);
    return;
  }
  if (sub === 'enroll') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent enroll <name|id> [--force]')}\n`);
      process.exit(2);
    }
    await cmdAgentEnroll(target, { force });
    return;
  }
  if (sub === 'rotate') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent rotate <name|id>')}\n`);
      process.exit(2);
    }
    await cmdAgentRotate(target);
    return;
  }
  if (sub === 'sign-claim') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent sign-claim <name|id> --envelope <file> [--out <file>]')}\n`);
      process.exit(2);
    }
    const envelope = takeFlag(args, '--envelope');
    const out = takeFlag(args, '--out');
    await cmdAgentSignClaim(
      target,
      typeof envelope === 'string' ? envelope : '',
      typeof out === 'string' ? out : undefined,
    );
    return;
  }
  if (sub === 'suspend') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent suspend <name|id>')}\n`);
      process.exit(2);
    }
    await cmdAgentSuspend(target, 'suspended', json);
    return;
  }
  if (sub === 'unsuspend' || sub === 'activate') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent unsuspend <name|id>')}\n`);
      process.exit(2);
    }
    await cmdAgentSuspend(target, 'active', json);
    return;
  }
  if (sub === 'delete' || sub === 'rm') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent delete <name|id>')}\n`);
      process.exit(2);
    }
    await cmdAgentDelete(target, json);
    return;
  }
  if (sub === 'unblock') {
    if (!target) {
      stderr.write(`usage: ${invokeHint('agent unblock <name|id>')}\n`);
      process.exit(2);
    }
    await cmdAgentUnblock(target, json);
    return;
  }
  stderr.write(
    `error: unknown agent subcommand "${sub ?? ''}".\n` +
    `Use list | show | register | setup | dismiss-warnings | update | enroll | rotate | sign-claim | suspend | unsuspend | unblock | delete\n`,
  );
  process.exit(2);
}
