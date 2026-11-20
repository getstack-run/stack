import type { IncomingMessage } from 'node:http';
import type { ConfirmerFactory, McpToolModule, ResultHandoff } from '@stack/mcp-server';
import type { SessionEntry } from './serve/types.js';

/** What a deployment says about the tools a session lists. */
export interface ToolSetSource {
  /**
   * Which pieces are on for the session behind a bearer, and whose it is. Null when it cannot be read: the
   * session then lists the core only, and reads again on its next `tools/list`.
   */
  read(request: { apiUrl: string; bearer: string; fetchImpl: typeof fetch; timeoutMs: number; logger?: Pick<Console, 'error'>; forwardedClient?: string }): Promise<{
    audience: 'agent' | 'owner';
    operatorId: string;
    pieces: readonly string[];
  } | null>;
}

/** What a deployment's own start-up work is given: the open sessions, where logs go, and Redis. */
export interface McpServeContext {
  /** The sessions open right now, read when something is to be sent to one. */
  sessions: () => Iterable<SessionEntry>;
  logger: Pick<Console, 'error'>;
  /** Where the API publishes what a deployment pushes to open sessions. Unset: nothing arrives. */
  redisUrl: string | undefined;
}

/**
 * What a deployment adds to the engine's MCP server. The engine serves the
 * engine's tools and opens an approval's page in the person's browser; a
 * deployment that sells more passes its tool groups, its own in-chat
 * confirmation, and any background work that reaches open sessions.
 */
export interface McpServeExtension {
  /** The tool groups served, in addition to none: the engine's own are never implied. */
  modules: readonly McpToolModule[];
  /** Builds, per MCP session, what decides a pending governance approval in the chat. Absent: the engine's, which opens the approval page. */
  confirmer?: ConfirmerFactory;
  /** Saves a tool result too large for one call and says where it went. Absent: such a result is refused in words, and the session carries on. */
  resultHandoff?: ResultHandoff;
  /** Lists a session only the tools that apply to who is connected and which pieces are on. Absent: every tool, as the engine lists them. */
  toolSets?: ToolSetSource;
  /** Declare the `logging` capability on an agent's own session, so something can be pushed to it. */
  wakeNotifications?: boolean;
  /** What the server tells a client at initialize, on the standard profile only (the directory profile's text is reviewed). Absent: nothing. */
  instructions?: string;
  /**
   * Derives, from the attestation key the server shares with the API, the key that signs the `x-stack-forwarded-client` header
   * on a session's API calls; null for no header. Absent: no call carries one.
   */
  forwardedClientKey?: (attestationKey: string) => string | null;
  /**
   * The address of the end client a request came from, as the deployment's own infrastructure states it, or null when the
   * request has none or it is not an IP address. The engine has no default reader: without this, no request has an address
   * and no call carries the forwarded-client header.
   */
  clientAddress?: (request: IncomingMessage) => string | null;
  /** Start work that needs the open sessions; resolves to the function that stops it. */
  onStart?(context: McpServeContext): Promise<() => Promise<void>>;
}
