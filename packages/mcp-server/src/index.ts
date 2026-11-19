import { McpServer, type ToolCallback } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createApiClient } from './api-client.js';
import { CHAT_CONFIRMATION_TIMEOUT_MS, Elicitor, type ChatConfirmationOptions, type ToolCallExtra } from './elicitation.js';
import { createToolCallRunner, type ResultHandoff, type ToolProgressExtra } from './tool-call.js';
import { confirmGovernance, ElicitationConfirmer, type ConfirmerFactory } from './governance-confirm.js';
import {
  DIRECTORY_OMITTED_PARAMS,
  type McpProfile,
  type StackToolAnnotation,
} from './tool-annotations.js';
import type { ToolRegistrar, ToolRegistrationOptions } from './tools/context.js';
import { exposureOf, LOAD_ON_DEMAND_META, ToolSetController } from './exposure.js';
import {
  annotationsOf,
  directoryDescriptionsOf,
  directoryExclusionsOf,
  ENGINE_TOOL_MODULES,
  orderedToolModules,
  type McpToolModule,
} from './modules.js';

/**
 * Create the STACK MCP server instance with all tools registered.
 * The server is transport-agnostic — callers connect it to Streamable HTTP or stdio.
 *
 * @param apiBaseUrl - Base URL of the STACK API (e.g. http://localhost:3000)
 * @param apiKey - Operator API key for authentication
 * @param opts - Session context.
 *   `modules` is the set of tool groups to register; it defaults to the engine's
 *   (`ENGINE_TOOL_MODULES`), so a server built with no options can never
 *   register a hosted tool. A deployment that serves more passes its own list;
 *   the order of `tools/list` is the order of the modules' `order`.
 *   `isPlatformStaff` gates the platform-staff-only `stack_repo_*`
 *   introspection tools (a module marked `staffOnly`): they are registered ONLY
 *   when true, so a non-staff session's `tools/list` never advertises them (and
 *   `tools/call` returns tool-not-found). Fail-closed: omit / false → tools not
 *   registered.
 *   `profile` selects the tool set. 'standard' (default) is the full
 *   catalog served at /mcp. 'directory' is the subset served at /directory
 *   for the Claude and ChatGPT connector directories: it never registers the
 *   tools in DIRECTORY_EXCLUDED_TOOLS (staff, money, generic executor,
 *   credential handling) and drops optional `passport_token` parameters.
 *   Every tool in both profiles carries a title and explicit readOnlyHint,
 *   destructiveHint and openWorldHint annotations, from the module that
 *   registers it (`annotations`), and a module names the tools the directory
 *   profile leaves out (`directoryExcluded`).
 *   `chat` is what the transport knows about the session, for the person's
 *   confirmation of a governance approval: asked of the person, never the
 *   model. The engine opens the approval page in the person's browser when the
 *   client can show one, and every other approval falls back to its approval
 *   link. `confirmer` builds a deployment's own confirmation for the session
 *   instead (STACK's hosted deployment asks in the chat and relays the answer
 *   with an attestation only this server can sign).
 *   `toolSet` decides which of the registered tools the session lists (who is connected and
 *   which account pieces are on: exposure.ts). Every tool is registered either way; one that is
 *   not listed is disabled, so `tools/list` leaves it out and `tools/call` refuses it. Absent:
 *   every tool is listed, as for the SDK, the CLI and a server built with no options. It applies
 *   to the standard profile only: the directory profile is a reviewed list and is never narrowed.
 *   `resultHandoff` saves a tool result that is too large for one call (`TOOL_RESULT_MAX_BYTES`) and answers with the words
 *   that replace it; without one such a result is refused in words. Either way the session carries on. Every call is also
 *   given the deadline of its tool (`toolDeadlineMs`): past it that call alone is answered with an error.
 *   `wakeNotifications` declares the `logging` capability, which is how a wake-up
 *   reaches an agent's open session (a `notifications/message` from logger
 *   `stack.wake`). Only the transport asks for it, and only for an agent's own session.
 *   `instructions` is the text the server gives a client at initialize. Absent: none, as for the engine.
 */
export function createStackMcpServer(
  apiBaseUrl: string,
  apiKey: string,
  opts: {
    isPlatformStaff?: boolean;
    profile?: McpProfile;
    chat?: ChatConfirmationOptions;
    wakeNotifications?: boolean;
    modules?: readonly McpToolModule[];
    confirmer?: ConfirmerFactory;
    toolSet?: ToolSetController;
    resultHandoff?: ResultHandoff;
    instructions?: string;
  } = {},
) {
  const profile: McpProfile = opts.profile ?? 'standard';
  if (profile !== 'standard' && profile !== 'directory') {
    throw new Error('Unknown MCP profile');
  }
  const modules = orderedToolModules(opts.modules ?? ENGINE_TOOL_MODULES);
  const moduleAnnotations: Readonly<Record<string, StackToolAnnotation>> = annotationsOf(modules);
  const directoryExcluded = directoryExclusionsOf(modules);
  const directoryDescriptions = directoryDescriptionsOf(modules);
  const exposure = exposureOf(modules);
  const toolSet = profile === 'standard' ? opts.toolSet : undefined;
  const mcp = new McpServer(
    {
      name: 'stack',
      version: '0.1.0',
    },
    opts.wakeNotifications || opts.instructions
      ? {
        ...(opts.wakeNotifications ? { capabilities: { logging: {} } } : {}),
        ...(opts.instructions ? { instructions: opts.instructions } : {}),
      }
      : undefined,
  );
  toolSet?.bind(mcp);
  // How many confirmations asked of the person are open on this session: a call waiting on the person is not timed.
  let pendingConfirmations = 0;
  let lastConfirmationEndedAt = 0;
  const chatOptions: ChatConfirmationOptions = {
    ...(opts.chat ?? {}),
    onElicitationPending: (delta) => {
      pendingConfirmations = Math.max(0, pendingConfirmations + delta);
      if (pendingConfirmations === 0) lastConfirmationEndedAt = Date.now();
      opts.chat?.onElicitationPending?.(delta);
    },
  };
  const elicitor = new Elicitor(mcp, chatOptions);

  // Every registration goes through this wrapper. It attaches the title and
  // annotations, applies the directory profile, and fails closed on a tool
  // with no annotation entry. The `server.tool(` call form is kept because
  // a repository check counts registrations by that text.
  const server: ToolRegistrar = {
    tool<Args extends z.ZodRawShape>(
      name: string,
      description: string,
      shape: Args,
      cb: ToolCallback<Args>,
      options?: ToolRegistrationOptions,
    ): void {
      const annotation = moduleAnnotations[name];
      if (!annotation) throw new Error(`MCP tool ${name} has no annotation entry`);
      if (profile === 'directory' && Object.hasOwn(directoryExcluded, name)) return;
      const forDirectory = profile === 'directory' ? options?.forDirectory : undefined;
      const registeredDescription = forDirectory?.description
        ?? (profile === 'directory' ? directoryDescriptions[name] : undefined)
        ?? description;
      let inputSchema: z.ZodRawShape = forDirectory?.shape ?? shape;
      if (profile === 'directory') {
        const narrowed: Record<string, z.ZodTypeAny> = { ...inputSchema };
        for (const param of DIRECTORY_OMITTED_PARAMS) {
          const field = narrowed[param];
          if (!field) continue;
          if (!field.isOptional()) {
            throw new Error(`MCP tool ${name} requires ${param}; exclude it from the directory profile`);
          }
          delete narrowed[param];
        }
        inputSchema = narrowed;
      }
      const toolExposure = exposure[name];
      if (!toolExposure) throw new Error(`MCP tool ${name} has no exposure entry`);
      const registered = mcp.registerTool(
        name,
        {
          title: annotation.title,
          description: registeredDescription,
          // A strict object names the refusal instead of stripping an
          // undeclared key, so a secret passed to a tool that takes none is
          // refused before the handler runs and is never echoed. The SDK takes
          // a Zod object here; the cast only satisfies the shape-typed callback.
          inputSchema: options?.refuseUnknownArguments
            ? (z.object(inputSchema).strict(options.refuseUnknownArguments) as unknown as z.ZodRawShape)
            : inputSchema,
          annotations: {
            title: annotation.title,
            readOnlyHint: annotation.readOnlyHint,
            destructiveHint: annotation.destructiveHint,
            openWorldHint: annotation.openWorldHint,
          },
          // The load-on-demand hint for a rarely used tool, in the standard profile only (a client with tool search reads it).
          ...(profile === 'standard' && toolExposure.deferred ? { _meta: { ...LOAD_ON_DEMAND_META } } : {}),
        },
        // The handler runs with its request context available, so a nested
        // API call can ask the person to confirm (MCP elicitation) on the
        // stream of this exact tool call.
        ((args: unknown, extra: ToolCallExtra & ToolProgressExtra) =>
          runToolCall(name, args, extra, cb as unknown as (a: unknown, e: unknown) => unknown)
        ) as unknown as ToolCallback<z.ZodRawShape>,
      );
      toolSet?.attach(name, registered, toolExposure);
    },
  };

  const ctx = createApiClient(apiBaseUrl, apiKey, {
    confirmApproval: (approvalId, approvalUrl, plainApi) => {
      const engine = new ElicitationConfirmer(elicitor, plainApi);
      const confirmer = opts.confirmer
        ? opts.confirmer({ mcp, elicitor, api: plainApi, options: chatOptions, engine })
        : engine;
      return confirmGovernance(confirmer, plainApi, approvalId, approvalUrl);
    },
  });

  // Every call is timed by its tool's own deadline and its result kept to what one call can carry.
  const runToolCall = createToolCallRunner({
    pendingConfirmations: () => pendingConfirmations,
    lastConfirmationEndedAt: () => lastConfirmationEndedAt,
    confirmationTimeoutMs: chatOptions.timeoutMs ?? CHAT_CONFIRMATION_TIMEOUT_MS,
    api: ctx.api,
    ...(opts.resultHandoff ? { handoff: opts.resultHandoff } : {}),
  });

  // The modules' `order` is the order `tools/list` returns, so keep it stable.
  for (const module of modules) {
    // Platform-staff-only: a non-staff session never registers these, so its
    // `tools/list` does not advertise them and `tools/call` returns tool-not-found.
    if (module.staffOnly && opts.isPlatformStaff !== true) continue;
    module.register(server, ctx);
  }
  // Resources are added after every tool: a resource is read with the caller's
  // own bearer, in both profiles, so it needs only what its route needs.
  for (const module of modules) module.registerResources?.(mcp, ctx);

  return mcp;
}

export {
  DIRECTORY_OMITTED_PARAMS,
  FORBIDDEN_DESCRIPTION_PATTERN,
  PRICE_IN_DESCRIPTION_PATTERN,
  hint,
  type McpProfile,
  type StackToolAnnotation,
} from './tool-annotations.js';
export {
  annotationsOf,
  directoryDescriptionsOf,
  directoryExclusionsOf,
  DIRECTORY_EXCLUDED_TOOLS,
  ENGINE_TOOL_MODULES,
  orderedToolModules,
  TOOL_ANNOTATIONS,
  type McpServedBy,
  type McpToolModule,
} from './modules.js';
export {
  exposureOf,
  LOAD_ON_DEMAND_META,
  ToolSetController,
  type ModuleExposure,
  type ToolExposure,
  type ToolExposureRule,
} from './exposure.js';
export { retryAfterSeconds, temporarilyUnavailableMessage } from './api-client.js';
export {
  LONGEST_TOOL_DEADLINE_SECONDS,
  TOOL_DEADLINE_MARGIN_SECONDS,
  TOOL_DEADLINE_SECONDS,
  TOOL_DEFAULT_DEADLINE_SECONDS,
  TOOL_PROGRESS_INTERVAL_MS,
  TOOL_RESULT_MAX_BYTES,
  toolDeadlineMs,
} from './tool-deadlines.js';
export type { ResultHandoff } from './tool-call.js';
export { CHAT_CONFIRMATION_TIMEOUT_MS, Elicitor, type ChatConfirmationOptions } from './elicitation.js';
export type { ApprovalDetail, ChatDecision } from './elicitation.js';
export {
  ElicitationConfirmer,
  type ConfirmationSession,
  type ConfirmerFactory,
  type ToolCallConfirmer,
} from './governance-confirm.js';
