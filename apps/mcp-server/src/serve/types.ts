import type { Server } from 'node:http';
import type { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { McpProfile, ToolSetController, createStackMcpServer } from '@stack/mcp-server';

export interface EndpointConfig {
  profile: McpProfile;
  /** RFC 9728 metadata URL named in this endpoint's 401 challenge. */
  metadataUrl: string;
  /** Scopes named in this endpoint's 401 challenge (the client's default request). */
  scopes: readonly string[];
  /** Whether a credential with this signed OAuth resource may use the endpoint. */
  acceptsResource: (resource: string | undefined) => boolean;
}

export interface SessionState {
  /** In-chat confirmations (MCP elicitation) waiting on the person. */
  pendingElicitations: number;
  /** When the last of them was answered (ms, the server's clock), 0 when none was: a call approved then has a full deadline from here. */
  lastElicitationEndedAt: number;
  /** Notification streams (GET) open on the session right now: where a wake-up can be sent. */
  notificationStreams: number;
}

export interface SessionEntry {
  transport: StreamableHTTPServerTransport;
  /** The session's tool server, which a wake-up notification is sent through. */
  server: ReturnType<typeof createStackMcpServer>;
  apiKeyHash: Buffer;
  bearerFingerprint: string;
  principalFingerprint: string;
  isPlatformStaff: boolean;
  /** The endpoint that created the session. A session never crosses paths. */
  profile: McpProfile;
  lastSeenAt: number;
  /** POST responses stream as SSE, so the server can ask the client mid-call. */
  sse: boolean;
  state: SessionState;
  /** What decides which tools the session lists; absent when the deployment lists every tool. */
  toolSet?: SessionToolSet;
}

export interface SessionToolSet {
  controller: ToolSetController;
  /** The operator the list was made for, once the pieces have been read (a Redis message names an operator). */
  operatorId: string | undefined;
  /** When the pieces were last read, in the server's clock; zero when never. */
  readAt: number;
  /** Reads which pieces are on again and updates the list (one notice when it changed). Never throws, and one read at a time. */
  refresh(): Promise<void>;
}

export interface ValidAuthContext {
  status: 'valid';
  principalFingerprint: string;
  isPlatformStaff: boolean;
  /** Exact resource signed into an OAuth MCP token; undefined otherwise. */
  oauthResource?: string;
}

export interface InvalidAuthContext {
  status: 'invalid';
}

/** STACK could not prove the credential valid or invalid; the caller retries after the wait. */
export interface UnavailableAuthContext {
  status: 'unavailable';
  /** Whole seconds, 1 through 300, from the API's Retry-After or a default. */
  retryAfterSeconds: number;
}

/**
 * The credential is good but its account has no platform subscription: the API answered 402
 * `PLATFORM_SUBSCRIPTION_REQUIRED`, and the session is refused with that same answer.
 */
export interface SubscriptionRequiredAuthContext {
  status: 'subscription_required';
  /** The API's own error body, passed on as it is (the message and `details.subscribe` say how to start one). */
  body: unknown;
}

export type AuthContext =
  | ValidAuthContext
  | InvalidAuthContext
  | UnavailableAuthContext
  | SubscriptionRequiredAuthContext;

export interface StackMcpHttpServerOptions {
  apiUrl?: string;
  mcpResource?: string;
  /** Resource URL of the connector-directory endpoint. Default: <mcp origin>/directory. */
  directoryResource?: string;
  /** OpenAI apps domain-verification token served at /.well-known/openai-apps-challenge. */
  openaiAppsChallengeToken?: string;
  oauthEnabled?: boolean;
  fetchImpl?: typeof fetch;
  now?: () => number;
  sessionIdleTtlMs?: number;
  sessionSweepIntervalMs?: number;
  authValidationTimeoutMs?: number;
  maxSessionsPerBearer?: number;
  maxSessionsPerProcess?: number;
  maxRequestBodyBytes?: number;
  /** What a request may carry before its bearer is known to be a session's own. Default 1 MiB, never above `maxRequestBodyBytes`. */
  maxNewSessionBodyBytes?: number;
  /** How long a body larger than `maxNewSessionBodyBytes` may take to arrive. */
  bodyReceiveTimeoutMs?: number;
  /** How often a buffered response that is still being made gets a space to keep its connection open. */
  jsonKeepaliveMs?: number;
  /** How many raw bytes of the bodies larger than `maxNewSessionBodyBytes` one process holds at once, counted as they arrive. Default 150 MiB. */
  maxLargeBodyBytesInFlight?: number;
  /** How long a tool call may run, from the tool's name. Default: the tool's own deadline (`toolDeadlineMs` of `@stack/mcp-server`). */
  toolDeadlineMs?: (tool: string) => number;
  /** How long after a tool's deadline the transport ends the request itself. Default 15 seconds. */
  toolBackstopMs?: number;
  maxResponseBytes?: number;
  requestTimeoutMs?: number;
  maxInFlightRequests?: number;
  maxInFlightPerBearer?: number;
  maxInFlightPerSession?: number;
  /**
   * Shared with the API; enables in-chat approval. Default
   * MCP_ELICITATION_ATTESTATION_KEY. Unset or shorter than 32 characters:
   * approvals fall back to the approval link and nothing is ever unsigned.
   */
  elicitationAttestationKey?: string;
  /** How long a tool call may wait for the person's answer. */
  elicitationTimeoutMs?: number;
  /** This process's machine id, for session affinity. Default: the machine id its host platform sets. */
  machineId?: string;
  /** Mark every answer `X-Robots-Tag: noindex, nofollow`. Default: on for a staging deployment (`STACK_STAGING=true`). */
  noindex?: boolean;
  sseKeepaliveMs?: number;
  /**
   * Where wake-ups for an agent's open sessions arrive (the API publishes them): a Redis URL.
   * Default REDIS_URL. Unset: the server runs without them, and the API's other channels carry the wake.
   */
  redisUrl?: string;
  logger?: Pick<Console, 'error'>;
}

export interface StackMcpHttpServer {
  httpServer: Server;
  listen(port: number, host: string): Promise<void>;
  close(): Promise<void>;
  pruneIdleSessions(): Promise<void>;
  sessionCount(): number;
}
