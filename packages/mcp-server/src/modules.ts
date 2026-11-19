import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { StackToolAnnotation } from './tool-annotations.js';
import type { ModuleExposure } from './exposure.js';
import { ENGINE_EXPOSURE } from './engine-exposure.js';
import type { ToolContext, ToolRegistrar } from './tools/context.js';
import { FLEETS_ANNOTATIONS, FLEETS_DIRECTORY_EXCLUDED, registerFleetsTools } from './tools/fleets.js';
import { AGENTS_ANNOTATIONS, AGENTS_DIRECTORY_EXCLUDED, registerAgentsTools } from './tools/agents.js';
import { SERVICES_ANNOTATIONS, SERVICES_DIRECTORY_EXCLUDED, registerServicesTools } from './tools/services.js';
import { PASSPORTS_ANNOTATIONS, PASSPORTS_DIRECTORY_EXCLUDED, registerPassportsTools } from './tools/passports.js';
import { CREDENTIALS_ANNOTATIONS, CREDENTIALS_DIRECTORY_EXCLUDED, registerCredentialsTools } from './tools/credentials.js';
import { TEAM_ANNOTATIONS, TEAM_DIRECTORY_EXCLUDED, registerTeamTools } from './tools/team.js';
import { IDENTITY_ANNOTATIONS, IDENTITY_DIRECTORY_EXCLUDED, registerIdentityTools } from './tools/identity.js';
import { DROPOFFS_ANNOTATIONS, registerDropoffsTools } from './tools/dropoffs.js';
import { ACCOUNTABILITY_ANNOTATIONS, registerAccountabilityTools } from './tools/accountability.js';
import { PROXY_ANNOTATIONS, PROXY_DIRECTORY_EXCLUDED, registerProxyTools } from './tools/proxy.js';
import { AUTHORITY_ANNOTATIONS, AUTHORITY_DIRECTORY_EXCLUDED, registerAuthorityTools } from './tools/authority.js';
import { MISSIONS_ANNOTATIONS, MISSIONS_DIRECTORY_EXCLUDED, registerMissionsTools } from './tools/missions.js';
import { SIGNED_RECORDS_ANNOTATIONS, SIGNED_RECORDS_DIRECTORY_EXCLUDED, registerSignedRecordsTools } from './tools/signed-records.js';
import { SECURITY_ANNOTATIONS, SECURITY_DIRECTORY_EXCLUDED, registerSecurityTools } from './tools/security.js';
import { CONTROL_SOCKET_ANNOTATIONS, CONTROL_SOCKET_DIRECTORY_EXCLUDED, registerControlSocketTools } from './tools/control-socket.js';
import { CONTROL_POLICIES_ANNOTATIONS, CONTROL_POLICIES_DIRECTORY_EXCLUDED, registerControlPolicyTools } from './tools/control-policies.js';
import { NETWORK_ANNOTATIONS, NETWORK_DIRECTORY_EXCLUDED, registerNetworkTools } from './tools/network.js';
import { AUDIT_ANNOTATIONS, AUDIT_DIRECTORY_EXCLUDED, registerAuditTools } from './tools/audit.js';
import { LLM_ANNOTATIONS, registerLlmTools } from './tools/llm.js';
import { NOTIFICATIONS_ANNOTATIONS, NOTIFICATIONS_DIRECTORY_EXCLUDED, registerNotificationsTools } from './tools/notifications.js';
import { WEBHOOKS_ANNOTATIONS, registerWebhooksTools } from './tools/webhooks.js';
import { PARTNERS_ANNOTATIONS, PARTNERS_DIRECTORY_EXCLUDED, registerPartnersTools } from './tools/partners.js';
import { APPROVALS_ANNOTATIONS, registerApprovalsTools } from './tools/approvals.js';

/**
 * Who answers a tool's REST calls. The definitions of every tool are public
 * (any MCP client can list them); what differs is the server behind the call.
 *
 * - `engine`: the engine an install runs.
 * - `network`: STACK's hosted service, which an install reaches only through
 *   the network or not at all.
 * - `private`: STACK's own staff tools; never served to anyone else.
 */
export type McpServedBy = 'engine' | 'network' | 'private';

/** One group of tools, registered together. */
export interface McpToolModule {
  id: string;
  servedBy: McpServedBy;
  /**
   * Where the group sits in `tools/list`. The order of registration is the
   * order a client reads, so it is fixed by this number across every module a
   * server is built from, whichever package the module comes from.
   */
  order: number;
  /**
   * The title and the three hints of each tool the group registers. A tool
   * with no entry here cannot be registered (the server throws), and an entry
   * for a tool the group does not register is a test failure.
   */
  annotations: Readonly<Record<string, StackToolAnnotation>>;
  /**
   * Who the group's tools are for, which account pieces they belong to and which are rarely used: what a
   * session lists (`exposure.ts`). Required, so a group cannot ship without saying.
   */
  exposure: ModuleExposure;
  /** The tools of the group the directory profile never registers, each with its reason. */
  directoryExcluded?: Readonly<Record<string, string>>;
  /**
   * The text the directory profile lists for a tool of the group in place of its description, for a deployment
   * that must say more about a tool than the engine can. A tool's own
   * `forDirectory.description` at its registration wins; the standard profile never reads this.
   */
  directoryDescriptions?: Readonly<Record<string, string>>;
  /** Registered only for a platform-staff session: a session without it never lists these. */
  staffOnly?: boolean;
  register(server: ToolRegistrar, ctx: ToolContext): void;
  /** MCP resources the group adds beside its tools. */
  registerResources?(mcp: McpServer, ctx: ToolContext): void;
}

const engine = (
  id: string,
  order: number,
  register: McpToolModule['register'],
  annotations: McpToolModule['annotations'],
  directoryExcluded?: McpToolModule['directoryExcluded'],
): McpToolModule => ({
  id,
  servedBy: 'engine',
  order,
  annotations,
  exposure: ENGINE_EXPOSURE[id] ?? missingExposure(id),
  ...(directoryExcluded ? { directoryExcluded } : {}),
  register,
});

function missingExposure(id: string): never {
  throw new Error(`MCP tool module ${id} has no exposure: say who its tools are for in engine-exposure.ts`);
}

/**
 * The tools the engine serves, in the positions they have in the full list. A
 * server built with no modules gets exactly these, so the engine can never
 * register a hosted tool by accident.
 */
export const ENGINE_TOOL_MODULES: readonly McpToolModule[] = [
  engine('fleets', 10, registerFleetsTools, FLEETS_ANNOTATIONS, FLEETS_DIRECTORY_EXCLUDED),
  engine('agents', 20, registerAgentsTools, AGENTS_ANNOTATIONS, AGENTS_DIRECTORY_EXCLUDED),
  engine('services', 90, registerServicesTools, SERVICES_ANNOTATIONS, SERVICES_DIRECTORY_EXCLUDED),
  engine('passports', 100, registerPassportsTools, PASSPORTS_ANNOTATIONS, PASSPORTS_DIRECTORY_EXCLUDED),
  engine('credentials', 110, registerCredentialsTools, CREDENTIALS_ANNOTATIONS, CREDENTIALS_DIRECTORY_EXCLUDED),
  engine('team', 120, registerTeamTools, TEAM_ANNOTATIONS, TEAM_DIRECTORY_EXCLUDED),
  engine('identity', 130, registerIdentityTools, IDENTITY_ANNOTATIONS, IDENTITY_DIRECTORY_EXCLUDED),
  engine('dropoffs', 140, registerDropoffsTools, DROPOFFS_ANNOTATIONS),
  engine('accountability', 150, registerAccountabilityTools, ACCOUNTABILITY_ANNOTATIONS),
  engine('proxy', 170, registerProxyTools, PROXY_ANNOTATIONS, PROXY_DIRECTORY_EXCLUDED),
  engine('authority', 180, registerAuthorityTools, AUTHORITY_ANNOTATIONS, AUTHORITY_DIRECTORY_EXCLUDED),
  engine('missions', 190, registerMissionsTools, MISSIONS_ANNOTATIONS, MISSIONS_DIRECTORY_EXCLUDED),
  engine('signed-records', 200, registerSignedRecordsTools, SIGNED_RECORDS_ANNOTATIONS, SIGNED_RECORDS_DIRECTORY_EXCLUDED),
  engine('security', 220, registerSecurityTools, SECURITY_ANNOTATIONS, SECURITY_DIRECTORY_EXCLUDED),
  engine('control-socket', 230, registerControlSocketTools, CONTROL_SOCKET_ANNOTATIONS, CONTROL_SOCKET_DIRECTORY_EXCLUDED),
  engine('control-policies', 240, registerControlPolicyTools, CONTROL_POLICIES_ANNOTATIONS, CONTROL_POLICIES_DIRECTORY_EXCLUDED),
  engine('network', 250, registerNetworkTools, NETWORK_ANNOTATIONS, NETWORK_DIRECTORY_EXCLUDED),
  engine('audit', 280, registerAuditTools, AUDIT_ANNOTATIONS, AUDIT_DIRECTORY_EXCLUDED),
  engine('llm', 290, registerLlmTools, LLM_ANNOTATIONS),
  engine('notifications', 300, registerNotificationsTools, NOTIFICATIONS_ANNOTATIONS, NOTIFICATIONS_DIRECTORY_EXCLUDED),
  engine('webhooks', 320, registerWebhooksTools, WEBHOOKS_ANNOTATIONS),
  engine('partners', 330, registerPartnersTools, PARTNERS_ANNOTATIONS, PARTNERS_DIRECTORY_EXCLUDED),
  engine('approvals', 340, registerApprovalsTools, APPROVALS_ANNOTATIONS),
];

/** The modules a server registers, in `tools/list` order. */
export function orderedToolModules(modules: readonly McpToolModule[]): McpToolModule[] {
  const seen = new Set<string>();
  for (const module of modules) {
    if (seen.has(module.id)) throw new Error(`MCP tool module ${module.id} is listed twice`);
    seen.add(module.id);
  }
  return [...modules].sort((a, b) => a.order - b.order);
}

/** Every tool's annotation across the modules; a tool annotated by two modules is a wiring mistake. */
export function annotationsOf(modules: readonly McpToolModule[]): Readonly<Record<string, StackToolAnnotation>> {
  const merged: Record<string, StackToolAnnotation> = {};
  for (const module of modules) {
    for (const [name, annotation] of Object.entries(module.annotations)) {
      if (Object.hasOwn(merged, name)) throw new Error(`MCP tool ${name} is annotated twice`);
      merged[name] = annotation;
    }
  }
  return merged;
}

/** Every tool the directory profile leaves out across the modules, with its reason. */
export function directoryExclusionsOf(modules: readonly McpToolModule[]): Readonly<Record<string, string>> {
  const merged: Record<string, string> = {};
  for (const module of modules) {
    for (const [name, reason] of Object.entries(module.directoryExcluded ?? {})) {
      if (Object.hasOwn(merged, name)) throw new Error(`MCP tool ${name} is excluded from the directory twice`);
      merged[name] = reason;
    }
  }
  return merged;
}

/** Every directory-profile description a module sets for one of its tools; two modules cannot set the same tool's. */
export function directoryDescriptionsOf(modules: readonly McpToolModule[]): Readonly<Record<string, string>> {
  const merged: Record<string, string> = {};
  for (const module of modules) {
    for (const [name, text] of Object.entries(module.directoryDescriptions ?? {})) {
      if (Object.hasOwn(merged, name)) throw new Error(`MCP tool ${name} has two directory descriptions`);
      merged[name] = text;
    }
  }
  return merged;
}

/** The engine's annotations. A deployment that serves more reads its own modules' (`annotationsOf`). */
export const TOOL_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = annotationsOf(ENGINE_TOOL_MODULES);

/** The tools the engine's directory profile never registers, with the reason. */
export const DIRECTORY_EXCLUDED_TOOLS: Readonly<Record<string, string>> = directoryExclusionsOf(ENGINE_TOOL_MODULES);
