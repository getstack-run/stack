#!/usr/bin/env node
// Generates the machine-readable parts of the public specifications in spec/
// from the code that implements them, so the written spec cannot drift:
//
//   spec/passport/schemas/*.json          Passport claims, issue/delegate/refresh/verify
//   spec/control-socket/schemas/*.json    decision request and answer, events
//   spec/record/schemas/**/*.json         envelope, evidence pack, claim payloads
//   spec/provider-interface/schemas/*.json  the request an account piece adapter is given
//   spec/catalogue/schemas/*.json         the catalogue document, an entry, a search result, an account's part
//   spec/rest-api/openapi.json            every route the engine serves (OpenAPI 3.1), from the routes the built API registers and the
//                                         schemas their handlers parse with; spec/rest-api/schemas/*.json the error envelope and the approval shapes
//   spec/network/schemas/*.json           the signed objects of the network and the inputs of its calls
//   spec/mcp-tools/tools.json, TOOLS.md   every MCP tool, from a live tools/list, with what answers it (`served_by`),
//                                         who it is for, its group and pieces, and whether it carries the load-on-demand hint
//   <!-- spec:generated:NAME --> blocks   constants and lists inside the SPEC.md files
//   spec/README.md                        the index of specifications and versions
//
// Usage:
//   node scripts/generate-spec.mjs          write everything
//   node scripts/generate-spec.mjs --check  fail (exit 1) if anything on disk differs
//
// It reads the BUILT packages (packages/shared/dist, packages/vault/dist,
// packages/mcp-server/dist): run `pnpm exec turbo build` first.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ERROR_ENVELOPE_SCHEMA, errorCodes, generateRestApi, operationKeys, restCoverage, scopeCounts } from './lib/rest-api-spec.mjs';
import { IDENTITY_SPECS, identityBlocks, identitySchemas } from './generate-spec-identity.mjs';
import { INTERFACE_SPECS, interfaceBlocks, interfaceCoverage, interfaceSchemas } from './generate-spec-interfaces.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
// The specification files are read and written under SPEC_BASE, the code under ROOT. They are the same
// directory except in this script's own tests, which point SPEC_BASE at a copy they have damaged.
const SPEC_BASE = process.env.STACK_SPEC_ROOT ?? ROOT;
const SPEC = join(SPEC_BASE, 'spec');
const SCHEMA_DIALECT = 'http://json-schema.org/draft-07/schema#';

// Each specification: folder, the name used in ids, the title, the schema ids
// it owns. A spec's SPEC.md carries its version; the CHANGELOG must agree.
export const SPECS = [
  { dir: 'passport', id: 'passport', title: 'STACK Passport' },
  { dir: 'control-socket', id: 'control-socket', title: 'STACK Control Socket Protocol' },
  { dir: 'provider-interface', id: 'provider-interface', title: 'STACK Provider Interface' },
  { dir: 'record', id: 'record', title: 'STACK Record Format' },
  { dir: 'mcp-tools', id: 'mcp-tools', title: 'STACK MCP Tool Definitions' },
  { dir: 'catalogue', id: 'catalogue', title: 'STACK Catalogue' },
  { dir: 'webhooks', id: 'webhooks', title: 'STACK Webhooks' },
  { dir: 'authority-receiver', id: 'authority-receiver', title: 'STACK Authority Receiver Protocol' },
  { dir: 'wallet-relay', id: 'wallet-relay', title: 'STACK Wallet Payment Relay' },
  { dir: 'agent-site-payments', id: 'agent-site-payments', title: 'STACK Agent Site Payments (x402)' },
  { dir: 'rest-api', id: 'rest-api', title: 'STACK REST API' },
  { dir: 'credentials-files', id: 'credentials-files', title: 'STACK Credentials Files' },
  { dir: 'web-bot-auth', id: 'web-bot-auth', title: 'STACK Web Bot Auth Profile' },
  { dir: 'partner', id: 'partner', title: 'STACK Partner API' },
  { dir: 'a2a', id: 'a2a', title: 'STACK A2A Profile' },
  { dir: 'service-mcp', id: 'service-mcp', title: 'STACK Service MCP Calls' },
  { dir: 'network', id: 'network', title: 'STACK Network' },
  ...IDENTITY_SPECS,
  { dir: 'agent-identity', id: 'agent-identity', title: 'STACK Agent Identity' },
  ...INTERFACE_SPECS,
];

// ─── Extension ──────────────────────────────────────────────────────

const EXTENSION = join(dirname(fileURLToPath(import.meta.url)), 'generate-spec.extension.mjs');

/**
 * A deployment may generate files of its own from what this script has derived: a sibling generate-spec.extension.mjs,
 * when there is one, is called after each stage with the stage's name and its results and writes through emitCode.
 */
async function extend(step, input) {
  if (!existsSync(EXTENSION)) return;
  const extension = await import(pathToFileURL(EXTENSION).href);
  await extension.extend(step, input);
}

// ─── Output collection ──────────────────────────────────────────────

/** Relative path (from the repository root, forward slashes) to file content. */
const outputs = new Map();
function emit(path, content) {
  outputs.set(path.replaceAll('\\', '/'), content.endsWith('\n') ? content : `${content}\n`);
}

/** Files of the code that are generated from the same definitions as the specification, relative to the repository root. */
const codeOutputs = new Map();
function emitCode(path, content) {
  codeOutputs.set(path, content.endsWith('\n') ? content : `${content}\n`);
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  const t = typeof value;
  if (t === 'number' || t === 'string' || t === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (t === 'object') {
    const parts = [];
    for (const k of Object.keys(value).sort()) {
      if (value[k] === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + canonicalize(value[k]));
    }
    return '{' + parts.join(',') + '}';
  }
  return 'null';
}

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// ─── Loading the reference implementation ───────────────────────────

async function load() {
  const need = (p) => {
    if (!existsSync(join(ROOT, p))) {
      throw new Error(`${p} is missing: run \`pnpm exec turbo build\` first`);
    }
    return pathToFileURL(join(ROOT, p)).href;
  };
  // The private build adds the hosted layer on top of the engine's exports; the engine alone has no
  // hosted entry. Either way the hosted tool schemas are found by name.
  const entry = (pkg) =>
    existsSync(join(ROOT, 'packages', pkg, 'dist/hosted/index.js'))
      ? `packages/${pkg}/dist/hosted/index.js`
      : `packages/${pkg}/dist/index.js`;
  // Without the hosted layer (the public repository) a schema only STACK's own deployment has cannot be regenerated:
  // its published file is what the specification says, and is kept as it is.
  const hostedLayer = existsSync(join(ROOT, 'packages', 'shared', 'dist/hosted/index.js'));
  const shared = await import(need(entry('shared')));
  const vault = await import(need(entry('vault')));
  const mcp = await import(need(entry('mcp-server')));
  const sharedRequire = createRequire(join(ROOT, 'packages', 'shared', 'package.json'));
  const zodToJsonSchema = sharedRequire('zod-to-json-schema').zodToJsonSchema;
  const zod = sharedRequire('zod');
  const mcpRequire = createRequire(join(ROOT, 'packages', 'mcp-server', 'package.json'));
  const { Client } = await import(pathToFileURL(mcpRequire.resolve('@modelcontextprotocol/sdk/client/index.js')).href);
  const { InMemoryTransport } = await import(pathToFileURL(mcpRequire.resolve('@modelcontextprotocol/sdk/inMemory.js')).href);
  return { shared, vault, mcp, zodToJsonSchema, zod, Client, InMemoryTransport, hostedLayer };
}

// ─── JSON Schemas from Zod ──────────────────────────────────────────

function schemaBody(ctx, zodSchema, name) {
  const converted = ctx.zodToJsonSchema(zodSchema, { name, $refStrategy: 'none' });
  const inner = converted?.definitions?.[name] ?? converted;
  const { $schema: _dropped, ...rest } = inner;
  return rest;
}

function emitSchema(ctx, spec, name, zodSchema, subdir = '') {
  if (!zodSchema) {
    const file = `spec/${spec}/schemas/${subdir ? `${subdir}/` : ''}${name}.json`;
    if (ctx.hostedLayer || !existsSync(join(SPEC, file.slice('spec/'.length)))) throw new Error(`schema ${name} is missing from @stack/shared`);
    const kept = readFileSync(join(SPEC, file.slice('spec/'.length)), 'utf8');
    emit(file, kept);
    return JSON.parse(kept);
  }
  const body = schemaBody(ctx, zodSchema, name);
  const idPath = subdir ? `${subdir}/${name}` : name;
  const schema = {
    $schema: SCHEMA_DIALECT,
    $id: `urn:stack:spec:${spec}:1:${idPath.replaceAll('/', ':')}`,
    title: name,
    ...body,
  };
  emit(`spec/${spec}/schemas/${subdir ? `${subdir}/` : ''}${name}.json`, pretty(schema));
  return schema;
}

function generateSchemas(ctx) {
  const s = ctx.shared;
  for (const name of [
    'PassportClaims', 'ServiceScope', 'Constraint', 'DeclaredOperation', 'ScopePolicy',
    'IssuePassportInputObject', 'DelegatePassportInput', 'RefreshPassportInput',
    'VerifyPassportInput', 'VerifyPassportResult', 'RevocationEvent',
  ]) {
    const published = name === 'IssuePassportInputObject' ? 'IssuePassportInput' : name;
    emitSchema(ctx, 'passport', published, s[name]);
  }

  for (const name of ['ControlDecisionRequest', 'ControlDecisionAnswer', 'ControlEvent', 'ControlEventsBatch']) {
    emitSchema(ctx, 'control-socket', name, s[name]);
  }

  emitSchema(ctx, 'provider-interface', 'OpenAgentAccountInput', s.OpenAgentAccountInput);

  identitySchemas(ctx, emitSchema);
  interfaceSchemas(ctx, emitSchema);

  for (const name of ['CatalogueDocument', 'CatalogueEntry', 'CatalogueSearchResult', 'CatalogueAccountView']) {
    emitSchema(ctx, 'catalogue', name, s[name]);
  }

  for (const name of [
    'AuthorityPresentationRequestInput', 'AuthorityStatusCheckInput', 'ReceiverReceiptInput', 'AuthorityPresentationView',
    'AuthorityReceiverPresentationPayload', 'AuthorityReference', 'NativeReceiverProfileV1', 'AuthorityProofCallbackInput',
    'CreateEnterpriseOidcAuthoritySetupInput',
  ]) {
    emitSchema(ctx, 'authority-receiver', name, s[name]);
  }
  emitSchema(ctx, 'wallet-relay', 'WalletPaymentInput', s.WalletPaymentInput);

  // Who an agent is, answered on request: only STACK's own deployment serves it, so without the hosted layer the published files stay.
  for (const name of ['AgentIdentityLookupQuery', 'AgentIdentityView', 'AgentIdentityClaims', 'SetAgentIdentityInput', 'AgentIdentitySettingsView']) {
    emitSchema(ctx, 'agent-identity', name, s[name]);
  }

  for (const name of [
    'PartnerAccountCreateInput', 'PartnerAccountCreateResult', 'PartnerAccountView', 'PartnerAccountRevokeResult',
    'PartnerAccountRotateKeyResult', 'PartnerAccountInviteInput', 'PartnerAccountInviteResult',
    'PartnerReleaseInput', 'PartnerReleaseRecord',
    'CreateInboundWebhookInput', 'CreateInboundWebhookResult', 'InboundWebhookView',
  ]) {
    emitSchema(ctx, 'partner', name, s[name]);
  }

  for (const name of [
    'NetworkInstallProofClaims', 'NetworkInstallPopClaims', 'CountersignatureClaims', 'RevocationListClaims',
    'VerifiedStatementClaims', 'DetectionRuleSetClaims', 'InstallPublicJwk', 'RegisterInstallInput', 'AddInstallKeyInput',
    'RevokeNetworkInput', 'PublishRevocationInput', 'CreateNetworkSubscriptionInput', 'ListRevocationsQuery',
    'VerifyCountersignatureInput', 'VerifiedStatusQuery', 'NetworkClassifyInput', 'RevokeLicenceInput',
  ]) {
    emitSchema(ctx, 'network', name, s[name]);
  }

  for (const name of ['ClaimEnvelope', 'CoSignature', 'Receipt', 'EvidencePackManifest', 'EvidencePackClaim']) {
    emitSchema(ctx, 'record', name, s[name]);
  }

  // The REST API: the one error body every answer has, and the shapes of a governance approval.
  emit('spec/rest-api/schemas/ErrorEnvelope.json', pretty({
    $schema: SCHEMA_DIALECT,
    $id: 'urn:stack:spec:rest-api:1:ErrorEnvelope',
    title: 'ErrorEnvelope',
    ...ERROR_ENVELOPE_SCHEMA,
  }));
  for (const name of ['GovernanceApprovalView', 'GovernanceApprovalDetail', 'GovernanceChatDecisionInput', 'PolicyRefusalEvidence']) {
    emitSchema(ctx, 'rest-api', name, s[name]);
  }

  // The files the command line and the SDKs keep under ~/.stack.
  for (const name of ['StoredOperatorCredentials', 'StoredAgentKey']) emitSchema(ctx, 'credentials-files', name, s[name]);

  // Claim payload schemas are published once, forever, under a content hash
  // (published once). The spec carries the same bytes; a
  // difference means the published set and the code have drifted.
  const bundle = JSON.parse(readFileSync(join(ROOT, 'packages/shared/src/generated/schemas-bundle.json'), 'utf8'));
  const claimTypes = [];
  for (const [type, zodSchema] of Object.entries(s.PASSPORT_CLAIM_SCHEMAS)) {
    const body = schemaBody(ctx, zodSchema, type);
    const contentHash = `sha256:${sha256(canonicalize(body))}`;
    const pinned = bundle[type]?.content_hash;
    if (pinned && pinned !== contentHash) {
      throw new Error(`claim schema ${type} no longer matches its published content hash (${pinned}); run \`pnpm run schemas:publish\` or revert the change: published claim schemas are additive-only`);
    }
    if (!pinned) {
      throw new Error(`claim schema ${type} has no published entry; run \`pnpm run schemas:publish\``);
    }
    const wrapped = { $schema: SCHEMA_DIALECT, content_hash: contentHash, json_schema: body };
    emit(`spec/record/schemas/claims/${type}.json`, pretty(wrapped));
    claimTypes.push({ type, content_hash: contentHash });
  }
  claimTypes.sort((a, b) => a.type.localeCompare(b.type));
  return { claimTypes };
}

// ─── MCP tool definitions ───────────────────────────────────────────

async function listTools(ctx, opts) {
  // The private build lists every tool group; the engine alone lists the engine's.
  const createServer = ctx.mcp.createHostedMcpServer ?? ctx.mcp.createStackMcpServer;
  const server = createServer('http://localhost:0', 'sk_unused', opts);
  const [clientTransport, serverTransport] = ctx.InMemoryTransport.createLinkedPair();
  const client = new ctx.Client({ name: 'spec-generator', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const tools = [];
  let cursor;
  do {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    tools.push(...page.tools);
    cursor = page.nextCursor;
  } while (cursor);
  await client.close();
  return tools;
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortObject(value[k])]));
  }
  return value;
}

/**
 * What answers each tool's REST calls, from the module that registers it: the engine, STACK's network, or
 * (a staff-only group, never in this catalog) STACK's own. The private build reads every module; the engine
 * alone, its own.
 */
function servedByTool(ctx) {
  const modules = ctx.mcp.ALL_TOOL_MODULES ?? ctx.mcp.ENGINE_TOOL_MODULES;
  const servedBy = new Map();
  for (const module of modules) {
    for (const name of Object.keys(module.annotations)) servedBy.set(name, module.servedBy);
  }
  return servedBy;
}

async function generateMcpTools(ctx) {
  const servedBy = servedByTool(ctx);
  const exposure = ctx.mcp.exposureOf(ctx.mcp.ALL_TOOL_MODULES ?? ctx.mcp.ENGINE_TOOL_MODULES);
  const standard = await listTools(ctx, { profile: 'standard' });
  const directoryTools = new Map((await listTools(ctx, { profile: 'directory' })).map((t) => [t.name, t]));
  const directory = new Set(directoryTools.keys());
  // What the directory lists in place of the standard text: a deployment can give it its own (a tool's `forDirectory`
  // text or a module's `directoryDescriptions`), and the specification is the contract for that profile too.
  const directoryDescriptionOf = (tool) => {
    const text = directoryTools.get(tool.name)?.description ?? tool.description ?? '';
    return text !== (tool.description ?? '') ? text : undefined;
  };
  let tools = standard
    .map((tool) => ({
      name: tool.name,
      title: tool.title ?? tool.name,
      description: tool.description ?? '',
      directory_description: directoryDescriptionOf(tool),
      inputSchema: sortObject(tool.inputSchema),
      annotations: {
        readOnlyHint: tool.annotations?.readOnlyHint ?? false,
        destructiveHint: tool.annotations?.destructiveHint ?? false,
        openWorldHint: tool.annotations?.openWorldHint ?? false,
      },
      profiles: directory.has(tool.name) ? ['standard', 'directory'] : ['standard'],
      served_by: servedBy.get(tool.name),
      group: exposure[tool.name]?.group,
      audience: exposure[tool.name]?.audience,
      pieces: exposure[tool.name]?.pieces,
      on_demand: exposure[tool.name]?.deferred,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  if (!ctx.hostedLayer) {
    // Without the hosted layer the tools STACK's network answers cannot be listed live: their committed entries stay as they are.
    const committed = JSON.parse(readFileSync(join(SPEC, 'mcp-tools/tools.json'), 'utf8'));
    const live = new Set(tools.map((tool) => tool.name));
    tools = [...tools, ...committed.tools.filter((tool) => tool.served_by !== 'engine' && !live.has(tool.name))]
      .sort((a, b) => a.name.localeCompare(b.name));
  }
  const unplaced = tools.filter((tool) => !tool.served_by).map((tool) => tool.name);
  if (unplaced.length > 0) throw new Error(`no module says what answers: ${unplaced.join(', ')}`);
  const unexposed = tools.filter((tool) => !tool.group).map((tool) => tool.name);
  if (unexposed.length > 0) throw new Error(`no module says who these tools are for: ${unexposed.join(', ')}`);

  const catalog = { spec: 'stack-mcp-tools', tool_count: tools.length, directory_tool_count: tools.filter((t) => t.profiles.includes('directory')).length, tools };
  emit('spec/mcp-tools/tools.json', pretty(catalog));

  const lines = [
    '<!-- Generated by scripts/generate-spec.mjs from a live tools/list. Do not edit. -->',
    '',
    '# MCP tool reference',
    '',
    `${tools.length} tools in the standard profile; ${catalog.directory_tool_count} of them are also served in the directory profile.`,
    'Hints: `R` read-only, `D` destructive, `W` open-world (reaches a party outside the caller\'s account).',
    'Audience: `agent`, `owner` or `both`; pieces: the account pieces that list the tool to an agent (none is the core); on demand marks a rarely used tool that carries the load-on-demand hint.',
    '',
    '| Tool | Title | Hints | Profiles | Group | Audience | Pieces | On demand |',
    '|---|---|---|---|---|---|---|---|',
  ];
  const hints = (a) => `${a.readOnlyHint ? 'R' : ''}${a.destructiveHint ? 'D' : ''}${a.openWorldHint ? 'W' : ''}` || '-';
  for (const tool of tools) {
    const pieces = tool.pieces.length > 0 ? tool.pieces.map((piece) => `\`${piece}\``).join(', ') : 'core';
    lines.push(`| [\`${tool.name}\`](#${tool.name}) | ${tool.title} | ${hints(tool.annotations)} | ${tool.profiles.join(', ')} | ${tool.group} | ${tool.audience} | ${pieces} | ${tool.on_demand ? 'yes' : '-'} |`);
  }
  for (const tool of tools) {
    lines.push('', `## ${tool.name}`, '', `**${tool.title}**`, '', tool.description, '');
    if (tool.directory_description) lines.push(`**Directory profile description:** ${tool.directory_description}`, '');
    const props = tool.inputSchema?.properties ?? {};
    const required = new Set(tool.inputSchema?.required ?? []);
    const names = Object.keys(props);
    if (names.length === 0) {
      lines.push('No parameters.');
    } else {
      lines.push('| Parameter | Type | Required | Description |', '|---|---|---|---|');
      for (const name of names) {
        const prop = props[name];
        const type = describeType(prop, tool.inputSchema);
        const description = (prop.description ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
        lines.push(`| \`${name}\` | ${type} | ${required.has(name) ? 'yes' : 'no'} | ${description} |`);
      }
    }
  }
  emit('spec/mcp-tools/TOOLS.md', lines.join('\n'));
  await extend('mcp-tools', { ctx, tools, emit, emitCode, pretty });
  return { tools, directoryCount: catalog.directory_tool_count };
}

/**
 * The node a local `$ref` ("#/properties/uuid") points at in the tool's input schema, or undefined. A schema object
 * used in several places is written once and referred to after that, so a type column that ignores the reference
 * reads "any" for every use but the first.
 */
function resolveLocalRef(ref, root) {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) return undefined;
  let node = root;
  for (const part of ref.slice(2).split('/')) {
    if (!node || typeof node !== 'object') return undefined;
    node = node[part.replaceAll('~1', '/').replaceAll('~0', '~')];
  }
  return node;
}

function describeType(prop, root, followed = new Set()) {
  if (!prop || typeof prop !== 'object') return 'any';
  if (prop.$ref !== undefined) {
    // A reference that points back at itself, or at nothing, stays "any".
    if (followed.has(prop.$ref)) return 'any';
    return describeType(resolveLocalRef(prop.$ref, root), root, new Set([...followed, prop.$ref]));
  }
  if (prop.enum) return prop.enum.map((v) => `\`${JSON.stringify(v)}\``).join(' or ');
  if (prop.anyOf) return prop.anyOf.map((option) => describeType(option, root, followed)).join(' or ');
  if (prop.type === 'array') return `array of ${describeType(prop.items, root, followed)}`;
  if (Array.isArray(prop.type)) return prop.type.join(' or ');
  return prop.type ?? 'any';
}

// ─── Generated blocks inside the SPEC.md files ──────────────────────

const table = (header, rows) => [
  `| ${header.join(' | ')} |`,
  `|${header.map(() => '---').join('|')}|`,
  ...rows.map((row) => `| ${row.join(' | ')} |`),
].join('\n');

function seconds(n) {
  if (n % 3600 === 0) return `${n} s (${n / 3600} h)`;
  if (n % 60 === 0) return `${n} s (${n / 60} min)`;
  return `${n} s`;
}

function blocks(ctx, derived) {
  const s = ctx.shared;
  const errors = [
    new s.PassportExpiredError(),
    new s.PassportRevokedError(),
    new s.PassportInvalidError(),
    new s.DelegationDepthExceededError(),
    new s.ScopeEscalationError(),
    new s.DelegationAccountabilityError('enforced', 'standard'),
    new s.PassportBlockedError('agt_example'),
  ];
  const result = {};

  result['passport-constants'] = table(['Constant', 'Value'], [
    ['Default lifetime', seconds(s.PASSPORT_DEFAULT_TTL_SECONDS)],
    ['Maximum lifetime', seconds(s.PASSPORT_MAX_TTL_SECONDS)],
    ['Refresh grace after expiry', seconds(s.PASSPORT_REFRESH_GRACE_SECONDS)],
    ['Maximum delegation depth', String(s.PASSPORT_MAX_DELEGATION_DEPTH)],
    ['Issuer (`iss`)', `\`${s.PASSPORT_ISSUER}\``],
    ['Audience (`aud`)', `\`${s.PASSPORT_JWT_AUDIENCE}\``],
    ['Signature algorithm', '`EdDSA` (Ed25519)'],
    ['Revocation channel', `\`${ctx.vault.REVOCATION_CHANNEL}\``],
  ]);

  result['passport-errors'] = table(
    ['Code', 'HTTP status', 'Message'],
    errors.map((e) => [`\`${e.code}\``, String(e.statusCode), e.message]),
  );

  result['control-constants'] = table(['Constant', 'Value'], [
    ['Decision timeout, default', `${s.CONTROL_DECISION_TIMEOUT_DEFAULT_MS} ms`],
    ['Decision timeout, configurable range', `${s.CONTROL_DECISION_TIMEOUT_MIN_MS} to ${s.CONTROL_DECISION_TIMEOUT_MAX_MS} ms`],
    ['Largest decision answer', `${s.CONTROL_DECISION_RESPONSE_MAX_BYTES} bytes`],
    ['Largest decision request or events batch', `${s.CONTROL_DECISION_REQUEST_MAX_BYTES} bytes`],
    ['Signature timestamp tolerance', seconds(s.CONTROL_SIGNATURE_TOLERANCE_SECONDS)],
    ['Rotated secret stays valid', seconds(s.CONTROL_SECRET_ROTATION_GRACE_MS / 1000)],
    ['Events batch limit', `${s.CONTROL_EVENTS_BATCH_MAX_EVENTS} events or ${s.CONTROL_EVENTS_BATCH_MAX_BYTES} bytes`],
    ['Events delivery timeout', `${s.CONTROL_EVENTS_TIMEOUT_MS} ms`],
    ['Events retry back-off', `${s.CONTROL_EVENTS_BACKOFF_BASE_MS / 1000} s doubling to ${s.CONTROL_EVENTS_BACKOFF_MAX_MS / 1000} s`],
    ['Events delivery gives up after', seconds(s.CONTROL_EVENTS_GIVE_UP_MS / 1000)],
    ['Client errors before a batch is dead-lettered', String(s.CONTROL_EVENTS_CLIENT_ERROR_LIMIT)],
    ['Undelivered events kept for', `${s.CONTROL_EVENTS_RETENTION_DAYS} days`],
    ['Decisions in flight per customer per machine', String(s.CONTROL_DECISION_MAX_IN_FLIGHT)],
    ['Breaker opens after', `${s.CONTROL_BREAKER_CONSECUTIVE_FAILURES} consecutive failures, or more than half of the last ${s.CONTROL_BREAKER_WINDOW_CALLS} calls within ${s.CONTROL_BREAKER_WINDOW_MS / 1000} s`],
    ['Breaker stays open', `${s.CONTROL_BREAKER_OPEN_MS / 1000} s, then one probe`],
    ['Agent-stated purpose, longest', `${s.CONTROL_PURPOSE_MAX_CHARS} characters`],
    ['Reason code pattern', `\`${s.CONTROL_REASON_CODE_PATTERN.source}\``],
    ['Reason message, longest', `${s.CONTROL_REASON_MESSAGE_MAX_CHARS} characters`],
    ['Retry reference header', `\`${s.CONTROL_REF_HEADER}\``],
    ['Agent purpose header', `\`${s.CONTROL_PURPOSE_HEADER}\``],
  ]);

  result['authority-receiver-constants'] = table(['Constant', 'Value'], [
    ['Protocol', `\`${ctx.vault.STACK_DIRECT_POST_PROTOCOL_KEY}\`, version \`${ctx.vault.STACK_DIRECT_POST_PROTOCOL_VERSION}\``],
    ['Request authentication method', `\`${ctx.vault.STACK_DIRECT_POST_REQUEST_AUTH_METHOD}\``],
    ['Delivery mode', `\`${ctx.vault.STACK_DIRECT_POST_DELIVERY_MODE}\``],
    ['Call assertion, longest life', seconds(ctx.vault.AUTHORITY_ASSERTION_MAX_SECONDS)],
    ['Signed presentation request, agent proof and presentation, longest life', seconds(ctx.vault.AUTHORITY_PRESENTATION_MAX_SECONDS)],
    ['Receipt, longest life', seconds(ctx.vault.AUTHORITY_RECEIPT_MAX_SECONDS)],
    ['Clock tolerance', seconds(ctx.vault.AUTHORITY_CLOCK_TOLERANCE_SECONDS)],
    ['Origin verification challenge valid for', seconds(ctx.vault.AUTHORITY_VERIFICATION_CHALLENGE_SECONDS)],
  ]);

  result['partner-constants'] = table(['Constant', 'Value'], [
    ['Release statuses', s.PARTNER_RELEASE_STATUSES.map((status) => `\`${status}\``).join(', ')],
    ['Who can ask for a release', s.PARTNER_RELEASE_REQUESTERS.map((who) => `\`${who}\``).join(', ')],
    ['A claim link works for', seconds(s.PARTNER_CLAIM_TTL_SECONDS)],
    ['A claim link is not mailed again for the same account within', seconds(s.PARTNER_CLAIM_RESEND_SECONDS)],
    ['A release stays readable to the partner after it ended for', seconds(s.PARTNER_RELEASE_RECORD_SECONDS)],
    ['Releases and invitations per partner', `${s.PARTNER_MAIL_RATE_PER_HOUR} per hour`],
    ['Role of an invited customer', `\`${s.PARTNER_INVITE_ROLE}\``],
    ['Reserved placeholder domain of the address an account holds until it is claimed', `\`*${s.TENANT_PLACEHOLDER_EMAIL_DOMAIN}\``],
    ['Inbound webhook request body, largest', `${s.INBOUND_WEBHOOK_BODY_LIMIT_BYTES} bytes`],
    ['Content scanned of an inbound request, at most', `${s.INBOUND_WEBHOOK_SCAN_CONTENT_MAX_BYTES} bytes`],
    ['A repeated provider event is recognised for', seconds(s.INBOUND_WEBHOOK_DEDUPE_TTL_SECONDS)],
    ['Forward timeout', `${s.INBOUND_WEBHOOK_FORWARD_TIMEOUT_MS / 1000} s`],
  ]);

  result['control-action-types'] = s.CONTROL_ACTION_TYPES.map((t) => `- \`${t}\``).join('\n');
  result['control-unavailable-causes'] = s.CONTROL_UNAVAILABLE_CAUSES.map((t) => `- \`${t}\``).join('\n');

  if (ctx.hostedLayer) {
    result['provider-piece-kinds'] = table(
      ['Kind', 'Close order'],
      s.ACCOUNT_OPEN_PIECE_KINDS.map((kind) => [
        `\`${kind}\``,
        String(ctx.vault.ACCOUNT_PIECE_CLOSE_ORDER.indexOf(kind) + 1),
      ]),
    );
    result['provider-constants'] = table(['Constant', 'Value'], [
      ['Open attempts before a piece fails', String(ctx.vault.PIECE_MAX_OPEN_ATTEMPTS)],
      ['Recheck of a piece waiting on the customer', `${ctx.vault.AWAITING_CUSTOMER_RECHECK_MS / 1000} s`],
    ]);
  } else {
    // The provider specification is written from STACK's own deployment; the public repository keeps what it says.
    result['provider-piece-kinds'] = KEEP;
    result['provider-constants'] = KEEP;
  }

  Object.assign(result, identityBlocks(ctx));
  Object.assign(result, interfaceBlocks(ctx));


  // The wire constants of the agent identity specification are in @stack/shared's own constants (not the hosted layer),
  // so the public repository writes the same table the private build does.
  result['agent-identity-constants'] = table(['Constant', 'Value'], [
    ['Protected header `typ` of a statement', `\`${s.AGENT_IDENTITY_TYP}\``],
    ['Audience (`aud`)', `\`${s.AGENT_IDENTITY_AUDIENCE}\``],
    ['Issuer (`iss`)', `\`${s.PASSPORT_ISSUER}\``],
    ['Signature algorithm', '`EdDSA` (Ed25519)'],
    ['Version of the claim (`identity.v`)', String(s.AGENT_IDENTITY_CLAIM_VERSION)],
    ['A statement is good for', seconds(s.AGENT_IDENTITY_TTL_SECONDS)],
    ['A statement may be good for, at most', seconds(s.AGENT_IDENTITY_MAX_TTL_SECONDS)],
    ['Ways to ask', s.AGENT_IDENTITY_SELECTORS.map((selector) => `\`${selector}\``).join(', ')],
    ['Statuses', s.AGENT_IDENTITY_STATUSES.map((status) => `\`${status}\``).join(', ')],
    ['Agent name, longest', `${s.AGENT_IDENTITY_NAME_MAX} characters`],
    ['The owner\'s switches and their defaults', `\`enabled\` ${s.AGENT_IDENTITY_SETTING_DEFAULTS.enabled}, \`show_name\` ${s.AGENT_IDENTITY_SETTING_DEFAULTS.show_name}`],
    ['Description in a card when the name is not shown', `\`${s.AGENT_IDENTITY_ANONYMOUS_DESCRIPTION}\``],
    ['Files of an agent', Object.values(s.AGENT_IDENTITY_FILES).map((file) => `\`${file}\``).join(', ')],
  ]);

  result['record-claim-types'] = table(
    ['Claim type', 'Payload schema', 'Content hash'],
    derived.claimTypes.map(({ type, content_hash: hash }) => [`\`${type}\``, `[\`schemas/claims/${type}.json\`](schemas/claims/${type}.json)`, `\`${hash}\``]),
  );

  const bytes = (n) => (n % (1024 * 1024) === 0 ? `${n / (1024 * 1024)} MiB` : n % 1024 === 0 ? `${n / 1024} KiB` : `${n} bytes`);
  const kindInfo = {
    model: ['`model:<model id>`', 'models', 'the model list of a model provider, every model with the modalities it lists'],
    tool: ['`tool:<provider><endpoint>`', 'tools', 'every endpoint of the paid-tools provider'],
    service: ['`service:<provider>`', 'services', 'the services a customer can connect'],
    skill: ['`skill:<skill id>`', 'skills', 'published skills'],
    account: ['`account:<piece>`', 'stack', 'the pieces of the account itself'],
    mcp_tool: ['`mcp_tool:<tool name>`', 'stack', 'the tools of STACK\'s own MCP server'],
  };
  result['catalogue-kinds'] = table(
    ['Kind', 'Id', 'Section', 'Comes from'],
    s.CATALOGUE_KINDS.map((kind) => {
      const info = kindInfo[kind];
      if (!info) throw new Error(`the catalogue kind ${kind} has no row in the specification table: add it to scripts/generate-spec.mjs`);
      if (!s.CATALOGUE_SOURCES.includes(info[1])) throw new Error(`the catalogue section ${info[1]} is not a source`);
      return [`\`${kind}\``, info[0], `\`${info[1]}\``, info[2]];
    }),
  );
  result['catalogue-constants'] = table(['Constant', 'Value'], [
    ['Kinds', s.CATALOGUE_KINDS.map((k) => `\`${k}\``).join(', ')],
    ['Sections (`source`)', s.CATALOGUE_SOURCES.map((k) => `\`${k}\``).join(', ')],
    ['Section statuses', s.CATALOGUE_SECTION_STATUSES.map((k) => `\`${k}\``).join(', ')],
    ['Price units', s.CATALOGUE_PRICE_UNITS.map((k) => `\`${k}\``).join(', ')],
    ['Result trust', s.CATALOGUE_RESULT_TRUSTS.map((k) => `\`${k}\``).join(', ')],
    ['Origins', s.CATALOGUE_ORIGINS.map((k) => `\`${k}\``).join(', ')],
    ['Tool audiences (`tool.audience`)', s.CATALOGUE_TOOL_AUDIENCES.map((k) => `\`${k}\``).join(', ')],
    ['Entry id, longest', `${s.CATALOGUE_ENTRY_ID_MAX_CHARS} characters`],
    ['Name, longest', `${s.CATALOGUE_NAME_MAX_CHARS} characters`],
    ['Input schema, largest', bytes(s.CATALOGUE_SCHEMA_MAX_BYTES)],
    ['Input schema, deepest', `${s.CATALOGUE_SCHEMA_MAX_DEPTH} levels`],
    ['Properties in one input schema object, most', String(s.CATALOGUE_SCHEMA_MAX_PROPERTIES)],
    ['Entries in a document, most', String(s.CATALOGUE_MAX_ENTRIES)],
    ['Document, largest', bytes(s.CATALOGUE_MAX_DOCUMENT_BYTES)],
    ['Entries in a search answer, most', String(s.CATALOGUE_SEARCH_MAX_RESULTS)],
    ['Path of the file on the API', `\`${s.CATALOGUE_PATH}\``],
    ['MCP resource', `\`${s.CATALOGUE_RESOURCE_URI}\``],
    ['Cost cap header of a model call', `\`${s.CATALOGUE_COST_CAP_HEADER}\``],
    ['A shared cache may keep the file for', seconds(s.CATALOGUE_CACHE_MAX_AGE_SECONDS)],
    ['The reference publisher refreshes the provider parts every', seconds(s.CATALOGUE_REFRESH_INTERVAL_SECONDS)],
  ]);

  if (derived.rest) {
    const doc = derived.rest.document;
    const operations = operationKeys(doc);
    const tagged = new Set(Object.values(doc.paths).flatMap((item) => Object.values(item).flatMap((operation) => operation.tags)));
    const open = Object.values(doc.paths).flatMap((item) => Object.values(item)).filter((operation) => operation.security.length === 0).length;
    result['rest-counts'] = `The engine's document lists ${operations.length} operations on ${Object.keys(doc.paths).length} paths, in ${tagged.size} groups (OpenAPI tags). ${open} of them take no bearer credential: they are public, or carry a credential of their own kind (a signed request, a token in the path).`;
    const counts = scopeCounts(doc);
    result['rest-oauth-scopes'] = table(
      ['Scope', 'Operations'],
      [...s.OAUTH_SCOPES].map((scope) => [`\`${scope}\``, String(counts.get(scope) ?? 0)]),
    );
    result['rest-governance-actions'] = table(
      ['Action', 'Decided'],
      s.GOVERNANCE_ACTIONS.map((action) => [`\`${action}\``, s.GOVERNANCE_BROWSER_ONLY_ACTIONS.has(action) ? 'on the approval page in a signed-in browser only' : 'on the approval page, or in a chat client that attests the person confirmed']),
    );
    result['rest-approval-constants'] = table(['Constant', 'Value'], [
      ['Header that names the approval', '`X-Governance-Approval`'],
      ['An approval stays open for', seconds(s.GOVERNANCE_APPROVAL_TTL_SECONDS)],
      ['Approval states', s.GOVERNANCE_APPROVAL_STATUSES.map((status) => `\`${status}\``).join(', ')],
      ['Approval id', '`gvr_` followed by letters, digits, `_` and `-`'],
    ]);
    result['rest-licence-features'] = table(['Feature', 'What it covers'], s.LICENCE_FEATURES.map((feature) => [`\`${feature}\``, s.LICENCE_FEATURE_LABELS[feature]]));
    result['rest-policy-reason-codes'] = table(['`rule.code`'], s.POLICY_REASON_CODES.map((code) => [`\`${code}\``]));
    result['rest-policy-sections'] = s.POLICY_SECTIONS.map((section) => `\`${section}\``).join(', ');
    result['rest-error-codes'] = table(
      ['Code', 'HTTP status'],
      derived.rest.codes.map((entry) => [`\`${entry.code}\``, entry.statuses.length > 0 ? entry.statuses.join(', ') : 'set where it is raised']),
    );
  }

  result['credentials-agent-jwt'] = table(['Constant', 'Value'], [
    ['Issuer (`iss`)', `\`${s.AGENT_JWT_ISSUER}\``],
    ['Audience (`aud`)', `\`${s.AGENT_JWT_AUDIENCE}\``],
    ['Lifetime the clients mint', seconds(s.AGENT_JWT_TTL_SECONDS)],
    ['Longest lifetime a server accepts', seconds(s.AGENT_JWT_MAX_TTL_SECONDS)],
  ]);

  result['network-kinds'] = table(['Object', '`typ` (header)', '`aud` (claim)', 'Signed by'], [
    ['Countersignature', `\`${s.COUNTERSIGNATURE_TYP}\``, `\`${s.COUNTERSIGNATURE_AUDIENCE}\``, 'STACK'],
    ['Revocation list', `\`${s.REVOCATION_LIST_TYP}\``, `\`${s.REVOCATION_LIST_AUDIENCE}\``, 'STACK'],
    ['STACK-verified statement', `\`${s.VERIFIED_STATEMENT_TYP}\``, `\`${s.VERIFIED_STATEMENT_AUDIENCE}\``, 'STACK'],
    ['Detection rule set', `\`${s.DETECTION_RULES_TYP}\``, `\`${s.DETECTION_RULES_AUDIENCE}\``, 'STACK'],
    ['Install proof (a request)', `\`${s.NETWORK_INSTALL_PROOF_TYP}\``, `\`${s.NETWORK_AUDIENCE}\``, "the install's key"],
    ['Key proof of possession', `\`${s.NETWORK_INSTALL_POP_TYP}\``, `\`${s.NETWORK_AUDIENCE}\``, 'the key being registered'],
  ]);
  result['network-constants'] = table(['Constant', 'Value'], [
    ['Install proof, longest life (`exp` minus `iat`)', seconds(s.NETWORK_PROOF_MAX_LIFETIME_SECONDS)],
    ['Clock difference accepted on a proof, either way', seconds(s.NETWORK_PROOF_CLOCK_SKEW_SECONDS)],
    ['Key registration challenge lives', seconds(s.NETWORK_KEY_CHALLENGE_TTL_SECONDS)],
    ['Countersignature life, default', seconds(s.COUNTERSIGNATURE_DEFAULT_TTL_SECONDS)],
    ['Countersignature life, shortest and longest a proof may ask for', `${seconds(s.COUNTERSIGNATURE_MIN_TTL_SECONDS)} and ${seconds(s.COUNTERSIGNATURE_MAX_TTL_SECONDS)}`],
    ['Countersignature record kept after it expires', `${s.COUNTERSIGNATURE_RETENTION_DAYS} days`],
    ['STACK-verified statement life', seconds(s.VERIFIED_STATEMENT_TTL_SECONDS)],
    ['Revocation list life', seconds(s.REVOCATION_LIST_TTL_SECONDS)],
    ['Detection rule set life', seconds(s.DETECTION_RULES_TTL_SECONDS)],
    ['Usable keys of one install, most', String(s.NETWORK_MAX_LIVE_KEYS_PER_INSTALL)],
    ['Key rollover, default and longest', `${seconds(s.NETWORK_KEY_ROLLOVER_DEFAULT_SECONDS)} and ${seconds(s.NETWORK_KEY_ROLLOVER_MAX_SECONDS)}`],
    ['Active installs of one account, most', String(s.NETWORK_MAX_INSTALLS_PER_OPERATOR)],
    ['Subscriptions of one account, most', String(s.NETWORK_MAX_SUBSCRIPTIONS_PER_OPERATOR)],
    ['Revocation list page, default and largest', `${s.REVOCATION_LIST_PAGE_DEFAULT} and ${s.REVOCATION_LIST_PAGE_MAX} entries`],
    ['Revocation push timeout', `${s.NETWORK_WEBHOOK_TIMEOUT_MS / 1000} s`],
    ['Revocation push retry back-off', `${s.NETWORK_WEBHOOK_BACKOFF_BASE_MS / 1000} s doubling to ${s.NETWORK_WEBHOOK_BACKOFF_MAX_MS / 1000} s`],
    ['A failing subscription pauses after', seconds(s.NETWORK_WEBHOOK_GIVE_UP_MS / 1000)],
    ['A revoked licence key is refused everywhere within', seconds(s.LICENCE_REVOCATION_CACHE_SECONDS)],
    ['A revoked licence key is listed after it would have expired for', `${s.LICENCE_REVOCATION_RETENTION_DAYS} days`],
    ['Mark', `\`${s.STACK_VERIFIED_MARK}\``],
  ]);
  result['network-revocation-lists'] = table(['List', 'Values'], [
    ['`kind`', s.NETWORK_REVOCATION_KINDS.map((k) => `\`${k}\``).join(', ')],
    ['`reason`', s.NETWORK_REVOCATION_REASONS.map((k) => `\`${k}\``).join(', ')],
    ['`by`', s.NETWORK_REVOCATION_PUBLISHERS.map((k) => `\`${k}\``).join(', ')],
    ['Install and key `status`', s.NETWORK_INSTALL_STATUSES.map((k) => `\`${k}\``).join(', ')],
    ['Subscription `status`', s.NETWORK_SUBSCRIPTION_STATUSES.map((k) => `\`${k}\``).join(', ')],
    ['Statement `status`', s.NETWORK_VERIFIED_STATUSES.map((k) => `\`${k}\``).join(', ')],
    ['Rule packs (`id`, direction)', s.NETWORK_RULE_PACKS.map((p) => `\`${p.id}\` (${p.direction})`).join(', ')],
  ]);

  const servedCount = (value) => derived.tools.filter((tool) => tool.served_by === value).length;
  result['mcp-counts'] = `The standard profile has ${derived.tools.length} tools; the directory profile serves ${derived.directoryCount} of them. ${servedCount('engine')} are answered by the engine and ${servedCount('network')} by STACK's network (\`served_by\`). The full reference is [TOOLS.md](TOOLS.md) and the machine-readable catalog is [tools.json](tools.json).`;

  const exposureRows = [];
  for (const group of [...new Set(derived.tools.map((tool) => tool.group))]) {
    const own = derived.tools.filter((tool) => tool.group === group);
    const count = (audience) => own.filter((tool) => tool.audience === audience).length;
    exposureRows.push([`\`${group}\``, String(own.length), String(count('agent')), String(count('owner')), String(count('both')), String(own.filter((tool) => tool.on_demand).length)]);
  }
  exposureRows.sort((a, b) => a[0].localeCompare(b[0]));
  result['mcp-exposure'] = table(['Group', 'Tools', 'Agent', 'Owner', 'Both', 'On demand'], exposureRows);

  return result;
}

/** A block that cannot be regenerated here (it reads the hosted layer): the committed text stays. */
const KEEP = Symbol('kept');

const BLOCK = /(<!-- spec:generated:([a-z0-9-]+) -->\n)([\s\S]*?)(<!-- \/spec:generated -->)/g;

function applyBlocks(path, text, generated, used) {
  return text.replace(BLOCK, (_all, open, name, _body, close) => {
    if (!(name in generated)) throw new Error(`${path}: unknown generated block "${name}"`);
    used.add(name);
    if (generated[name] === KEEP) return _all;
    return `${open}\n${generated[name]}\n\n${close}`;
  });
}

// ─── Index and version coherence ────────────────────────────────────

function readVersion(path) {
  const text = readFileSync(join(SPEC_BASE, path), 'utf8');
  const match = text.match(/^\*\*Version:\*\* (\d+\.\d+\.\d+)\s*$/m);
  if (!match) throw new Error(`${path}: no "**Version:** x.y.z" line`);
  return match[1];
}

function readChangelogVersion(path) {
  const text = readFileSync(join(SPEC_BASE, path), 'utf8');
  const match = text.match(/^## \[?(\d+\.\d+\.\d+)\]?/m);
  if (!match) throw new Error(`${path}: no "## x.y.z" release heading`);
  return match[1];
}

function specIndex() {
  const rows = [];
  for (const spec of SPECS) {
    const specPath = `spec/${spec.dir}/SPEC.md`;
    const logPath = `spec/${spec.dir}/CHANGELOG.md`;
    if (!existsSync(join(SPEC_BASE, specPath))) throw new Error(`${specPath} is missing`);
    if (!existsSync(join(SPEC_BASE, logPath))) throw new Error(`${logPath} is missing`);
    const version = readVersion(specPath);
    const logVersion = readChangelogVersion(logPath);
    if (version !== logVersion) {
      throw new Error(`${specPath} is version ${version} but the first release in ${logPath} is ${logVersion}`);
    }
    rows.push([`[${spec.title}](${spec.dir}/SPEC.md)`, version, `[changelog](${spec.dir}/CHANGELOG.md)`]);
  }
  return table(['Specification', 'Version', 'History'], rows);
}

// ─── Hand-written prose must cover what the code defines ───────────

/** The text of a SPEC.md without its generated blocks. */
function prose(path) {
  return readFileSync(join(SPEC_BASE, path), 'utf8').replaceAll('\r\n', '\n').replace(BLOCK, '');
}

function coverage(ctx) {
  const missing = [];
  // Every action kind has a row in the control socket target table.
  const control = prose('spec/control-socket/SPEC.md');
  for (const kind of ctx.shared.CONTROL_ACTION_TYPES) {
    if (!control.includes(`| \`${kind}\` |`)) missing.push(`spec/control-socket/SPEC.md has no target row for the action kind ${kind}`);
  }
  // Every revocation event type is described in the passport specification.
  const passport = prose('spec/passport/SPEC.md');
  for (const option of ctx.shared.RevocationEvent.options) {
    const type = option.shape.type.value;
    if (!passport.includes(`| \`${type}\` |`)) missing.push(`spec/passport/SPEC.md has no row for the revocation event ${type}`);
  }
  // Every section status, price unit and trust marking of the catalogue is explained in its specification.
  const catalogue = prose('spec/catalogue/SPEC.md');
  for (const [what, values] of [
    ['section status', ctx.shared.CATALOGUE_SECTION_STATUSES],
    ['price unit', ctx.shared.CATALOGUE_PRICE_UNITS],
    ['result trust', ctx.shared.CATALOGUE_RESULT_TRUSTS],
    ['origin', ctx.shared.CATALOGUE_ORIGINS],
  ]) {
    for (const value of values) {
      if (!catalogue.includes(`| \`${value}\` |`)) missing.push(`spec/catalogue/SPEC.md has no row for the ${what} ${value}`);
    }
  }
  for (const audience of ctx.shared.CATALOGUE_TOOL_AUDIENCES) {
    if (!catalogue.includes(`| \`${audience}\` |`)) missing.push(`spec/catalogue/SPEC.md has no row for the tool audience ${audience}`);
  }
  // Every status of a release and who may ask for one is explained in the partner specification.
  const partnerSpec = prose('spec/partner/SPEC.md');
  for (const status of ctx.shared.PARTNER_RELEASE_STATUSES) {
    if (!partnerSpec.includes(`| \`${status}\` |`)) missing.push(`spec/partner/SPEC.md has no row for the release status ${status}`);
  }
  for (const who of ctx.shared.PARTNER_RELEASE_REQUESTERS) {
    if (!partnerSpec.includes(`| \`${who}\` |`)) missing.push(`spec/partner/SPEC.md has no row for who can ask for a release: ${who}`);
  }
  // Every status of an agent and every switch of its owner is explained in the agent identity specification.
  const identity = prose('spec/agent-identity/SPEC.md');
  for (const status of ctx.shared.AGENT_IDENTITY_STATUSES) {
    if (!identity.includes(`| \`${status}\` |`)) missing.push(`spec/agent-identity/SPEC.md has no row for the agent status ${status}`);
  }
  for (const selector of ctx.shared.AGENT_IDENTITY_SELECTORS) {
    if (!identity.includes(`| \`${selector}\` |`)) missing.push(`spec/agent-identity/SPEC.md has no row for the way to ask ${selector}`);
  }
  for (const switchName of Object.keys(ctx.shared.AGENT_IDENTITY_SETTING_DEFAULTS)) {
    if (!identity.includes(`| \`${switchName}\` |`)) missing.push(`spec/agent-identity/SPEC.md has no row for the switch ${switchName}`);
  }
  const mcp = prose('spec/mcp-tools/SPEC.md');
  for (const audience of ctx.shared.CATALOGUE_TOOL_AUDIENCES) {
    if (!mcp.includes(`| \`${audience}\` |`)) missing.push(`spec/mcp-tools/SPEC.md has no row for the audience ${audience}`);
  }
  // Every install proof action has a row in the network specification, and every refusal reason of a proof is named.
  const network = prose('spec/network/SPEC.md');
  for (const act of ctx.shared.NETWORK_PROOF_ACTIONS) {
    if (!network.includes(`| \`${act}\` |`)) missing.push(`spec/network/SPEC.md has no row for the install proof action ${act}`);
  }
  for (const reason of ctx.shared.INSTALL_PROOF_REASONS ?? []) {
    if (!network.includes(`| \`${reason}\` |`)) missing.push(`spec/network/SPEC.md has no row for the install proof refusal ${reason}`);
  }
  missing.push(...interfaceCoverage(ctx, prose));
  if (missing.length > 0) throw new Error(`the specification text has fallen behind the code:\n  ${missing.join('\n  ')}`);
}

// ─── Run ────────────────────────────────────────────────────────────

export async function generate() {
  outputs.clear();
  codeOutputs.clear();
  const ctx = await load();
  const { claimTypes } = generateSchemas(ctx);
  const { tools, directoryCount } = await generateMcpTools(ctx);
  const rest = await generateRestApi({
    root: ROOT,
    hostedLayer: ctx.hostedLayer,
    specVersion: readVersion('spec/rest-api/SPEC.md'),
    shared: ctx.shared,
    zod: ctx.zod,
  });
  emit('spec/rest-api/openapi.json', pretty(rest.engine));
  await extend('rest-api', { ctx, rest, emit, emitCode, pretty });
  const derived = { claimTypes, tools, directoryCount, rest: { document: rest.engine, codes: errorCodes(ROOT) } };
  const generated = blocks(ctx, derived);

  // Fill the blocks of every SPEC.md and README.md that has them.
  const used = new Set();
  for (const spec of SPECS) {
    const path = `spec/${spec.dir}/SPEC.md`;
    const text = readFileSync(join(SPEC_BASE, path), 'utf8').replaceAll('\r\n', '\n');
    emit(path, applyBlocks(path, text, generated, used));
  }
  const readmePath = 'spec/README.md';
  const readme = readFileSync(join(SPEC_BASE, readmePath), 'utf8').replaceAll('\r\n', '\n');
  emit(readmePath, applyBlocks(readmePath, readme, { 'spec-index': specIndex() }, new Set()));

  coverage(ctx);
  const restProblems = restCoverage({
    prose: prose('spec/rest-api/SPEC.md'),
    engineCodes: derived.rest.codes,
    hostedCodes: ctx.hostedLayer ? errorCodes(ROOT, { includeHosted: true }) : null,
    document: rest.engine,
  });
  if (restProblems.length > 0) throw new Error(`the REST specification text has fallen behind the code:\n  ${restProblems.join('\n  ')}`);

  const declared = new Set(Object.keys(generated));
  for (const name of declared) {
    if (!used.has(name)) throw new Error(`generated block "${name}" is not used by any SPEC.md`);
  }
  return new Map(outputs);
}

/** The generated code files, by path from the repository root. */
export function generatedCode() {
  return new Map(codeOutputs);
}

function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, acc);
    else acc.push(full);
  }
  return acc;
}

async function main() {
  const check = process.argv.includes('--check');
  const files = await generate();
  const code = generatedCode();
  const stale = [];
  for (const [path, content] of code) {
    const full = join(ROOT, path);
    const current = existsSync(full) ? readFileSync(full, 'utf8').replaceAll('\r\n', '\n') : null;
    if (current !== content) stale.push(path);
    if (!check && current !== content) writeFileSync(full, content, 'utf8');
  }
  for (const [path, content] of files) {
    const full = join(SPEC_BASE, path);
    const current = existsSync(full) ? readFileSync(full, 'utf8').replaceAll('\r\n', '\n') : null;
    if (current !== content) stale.push(path);
    if (!check && current !== content) {
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, content, 'utf8');
    }
  }
  // A generated file no longer produced (a removed schema) is stale too.
  const generatedRoots = SPECS.map((s) => join(SPEC, s.dir, 'schemas'));
  for (const root of generatedRoots) {
    if (!existsSync(root)) continue;
    for (const full of walk(root)) {
      const rel = relative(SPEC_BASE, full).replaceAll('\\', '/');
      if (!files.has(rel)) stale.push(`${rel} (no longer generated)`);
    }
  }
  if (check) {
    if (stale.length > 0) {
      console.error(`spec is out of date with the code (${stale.length} file(s)):\n  ${stale.join('\n  ')}\nRun \`node scripts/generate-spec.mjs\` and commit the result.`);
      process.exit(1);
    }
    console.log(`spec is current (${files.size + code.size} generated files)`);
  } else {
    console.log(`wrote ${stale.length} changed file(s) of ${files.size + code.size} generated`);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
