import {
  DEFAULT_AUTH_VALIDATION_TIMEOUT_MS,
  DEFAULT_BODY_RECEIVE_TIMEOUT_MS,
  DEFAULT_JSON_KEEPALIVE_MS,
  DEFAULT_MAX_IN_FLIGHT_PER_BEARER,
  DEFAULT_MAX_IN_FLIGHT_PER_SESSION,
  DEFAULT_MAX_IN_FLIGHT_REQUESTS,
  DEFAULT_MAX_LARGE_BODY_BYTES_IN_FLIGHT,
  DEFAULT_MAX_NEW_SESSION_BODY_BYTES,
  DEFAULT_MAX_REQUEST_BODY_BYTES,
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_MAX_SESSIONS_PER_BEARER,
  DEFAULT_MAX_SESSIONS_PER_PROCESS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_SESSION_IDLE_TTL_MS,
  DEFAULT_SESSION_SWEEP_INTERVAL_MS,
  DEFAULT_SSE_KEEPALIVE_MS,
  DIRECTORY_PATH,
  MACHINE_ID,
  TOOL_REQUEST_BACKSTOP_MS,
} from './config.js';
import { deployment, staging } from '@stack/shared';
import { CHAT_CONFIRMATION_TIMEOUT_MS, toolDeadlineMs as defaultToolDeadlineMs } from '@stack/mcp-server';
import { createEndpointTable } from './resource-metadata.js';
import type { EndpointConfig, StackMcpHttpServerOptions } from './types.js';

export interface ServerSettings {
  apiUrl: string;
  mcpResource: string;
  directoryResource: string;
  openaiAppsChallengeToken: string;
  oauthEnabled: boolean;
  fetchImpl: typeof fetch;
  now: () => number;
  sessionIdleTtlMs: number;
  sessionSweepIntervalMs: number;
  authValidationTimeoutMs: number;
  maxSessionsPerBearer: number;
  maxSessionsPerProcess: number;
  maxRequestBodyBytes: number;
  /** The body a request may carry before its bearer is known to be a session's own: never above `maxRequestBodyBytes`. */
  maxNewSessionBodyBytes: number;
  /** How long a body larger than `maxNewSessionBodyBytes` may take to arrive. */
  bodyReceiveTimeoutMs: number;
  jsonKeepaliveMs: number;
  /** How many raw bytes of the bodies larger than `maxNewSessionBodyBytes` one process holds at once. */
  maxLargeBodyBytesInFlight: number;
  /** How long a tool call may run, from the tool's name. */
  toolDeadlineMs: (tool: string) => number;
  /** How long after a tool's deadline the transport ends the request itself. */
  toolBackstopMs: number;
  maxResponseBytes: number;
  requestTimeoutMs: number;
  maxInFlightRequests: number;
  maxInFlightPerBearer: number;
  maxInFlightPerSession: number;
  elicitationAttestationKey: string;
  elicitationTimeoutMs: number;
  sseKeepaliveMs: number;
  /** Session affinity across machines; undefined when no machine id is set, where session ids stay plain. */
  machineId: string | undefined;
  /** A staging deployment (`STACK_STAGING=true`): every answer carries `X-Robots-Tag: noindex, nofollow`. */
  noindex: boolean;
  logger: Pick<Console, 'error'> & Partial<Pick<Console, 'warn'>>;
  endpoints: Record<string, EndpointConfig>;
}

/**
 * Resolve the server options against the environment and defaults, and refuse
 * any limit that is not a positive number.
 */
export function resolveServerSettings(options: StackMcpHttpServerOptions): ServerSettings {
  const apiUrl = options.apiUrl ?? process.env['API_URL'] ?? deployment().apiBaseUrl;
  const mcpResource = options.mcpResource ?? process.env['MCP_RESOURCE'] ?? deployment().mcpResource;
  const directoryResource = options.directoryResource
    ?? process.env['MCP_DIRECTORY_RESOURCE']
    ?? `${new URL(mcpResource).origin}${DIRECTORY_PATH}`;
  if (new URL(directoryResource).pathname !== DIRECTORY_PATH) {
    throw new Error(`directoryResource must end in ${DIRECTORY_PATH}`);
  }
  const openaiAppsChallengeToken = (
    options.openaiAppsChallengeToken ?? process.env['OPENAI_APPS_CHALLENGE_TOKEN'] ?? ''
  ).trim();
  const oauthEnabled = options.oauthEnabled
    ?? (process.env['OAUTH_ENABLED'] === 'true' || process.env['OAUTH_ENABLED'] === '1');
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const sessionIdleTtlMs = options.sessionIdleTtlMs ?? DEFAULT_SESSION_IDLE_TTL_MS;
  const sessionSweepIntervalMs = options.sessionSweepIntervalMs ?? DEFAULT_SESSION_SWEEP_INTERVAL_MS;
  const authValidationTimeoutMs = options.authValidationTimeoutMs ?? DEFAULT_AUTH_VALIDATION_TIMEOUT_MS;
  const maxSessionsPerBearer = options.maxSessionsPerBearer ?? DEFAULT_MAX_SESSIONS_PER_BEARER;
  const maxSessionsPerProcess = options.maxSessionsPerProcess ?? DEFAULT_MAX_SESSIONS_PER_PROCESS;
  const maxRequestBodyBytes = options.maxRequestBodyBytes ?? DEFAULT_MAX_REQUEST_BODY_BYTES;
  const maxNewSessionBodyBytes = Math.min(maxRequestBodyBytes, options.maxNewSessionBodyBytes ?? DEFAULT_MAX_NEW_SESSION_BODY_BYTES);
  const bodyReceiveTimeoutMs = options.bodyReceiveTimeoutMs ?? DEFAULT_BODY_RECEIVE_TIMEOUT_MS;
  const maxLargeBodyBytesInFlight = options.maxLargeBodyBytesInFlight ?? DEFAULT_MAX_LARGE_BODY_BYTES_IN_FLIGHT;
  const jsonKeepaliveMs = options.jsonKeepaliveMs ?? DEFAULT_JSON_KEEPALIVE_MS;
  const toolDeadlineMs = options.toolDeadlineMs ?? defaultToolDeadlineMs;
  const toolBackstopMs = options.toolBackstopMs ?? TOOL_REQUEST_BACKSTOP_MS;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const maxInFlightRequests = options.maxInFlightRequests ?? DEFAULT_MAX_IN_FLIGHT_REQUESTS;
  const maxInFlightPerBearer = options.maxInFlightPerBearer ?? DEFAULT_MAX_IN_FLIGHT_PER_BEARER;
  const maxInFlightPerSession = options.maxInFlightPerSession ?? DEFAULT_MAX_IN_FLIGHT_PER_SESSION;
  const elicitationAttestationKey = (options.elicitationAttestationKey ?? process.env['MCP_ELICITATION_ATTESTATION_KEY'] ?? '').trim();
  const elicitationTimeoutMs = options.elicitationTimeoutMs ?? CHAT_CONFIRMATION_TIMEOUT_MS;
  const sseKeepaliveMs = options.sseKeepaliveMs ?? DEFAULT_SSE_KEEPALIVE_MS;
  const rawMachineId = (options.machineId ?? process.env['FLY_MACHINE_ID'] ?? '').trim().toLowerCase();
  // Session affinity across machines: a session id names the machine that
  // holds it, and a request that lands elsewhere is replayed there with
  // `fly-replay`. Without a valid machine id (local runs) ids stay plain.
  const machineId = MACHINE_ID.test(rawMachineId) ? rawMachineId : undefined;
  const logger = options.logger ?? console;
  // Read at boot: a staging deployment with no allow-list, or an unreadable STACK_STAGING, refuses to start here.
  const noindex = options.noindex ?? staging().enabled;
  const endpoints = createEndpointTable(mcpResource, directoryResource);

  if (!Number.isFinite(sessionIdleTtlMs) || sessionIdleTtlMs <= 0) {
    throw new Error('sessionIdleTtlMs must be a positive number');
  }
  if (!Number.isFinite(sessionSweepIntervalMs) || sessionSweepIntervalMs <= 0) {
    throw new Error('sessionSweepIntervalMs must be a positive number');
  }
  if (!Number.isFinite(authValidationTimeoutMs) || authValidationTimeoutMs <= 0) {
    throw new Error('authValidationTimeoutMs must be a positive number');
  }
  if (!Number.isInteger(maxSessionsPerBearer) || maxSessionsPerBearer <= 0) {
    throw new Error('maxSessionsPerBearer must be a positive integer');
  }
  if (!Number.isInteger(maxSessionsPerProcess) || maxSessionsPerProcess <= 0) {
    throw new Error('maxSessionsPerProcess must be a positive integer');
  }
  for (const [name, value] of [
    ['elicitationTimeoutMs', elicitationTimeoutMs],
    ['sseKeepaliveMs', sseKeepaliveMs],
    ['maxRequestBodyBytes', maxRequestBodyBytes],
    ['maxNewSessionBodyBytes', maxNewSessionBodyBytes],
    ['bodyReceiveTimeoutMs', bodyReceiveTimeoutMs],
    ['maxLargeBodyBytesInFlight', maxLargeBodyBytesInFlight],
    ['jsonKeepaliveMs', jsonKeepaliveMs],
    ['toolBackstopMs', toolBackstopMs],
    ['maxResponseBytes', maxResponseBytes],
    ['requestTimeoutMs', requestTimeoutMs],
    ['maxInFlightRequests', maxInFlightRequests],
    ['maxInFlightPerBearer', maxInFlightPerBearer],
    ['maxInFlightPerSession', maxInFlightPerSession],
  ] as const) {
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`${name} must be a positive integer`);
    }
  }

  return {
    apiUrl,
    mcpResource,
    directoryResource,
    openaiAppsChallengeToken,
    oauthEnabled,
    fetchImpl,
    now,
    sessionIdleTtlMs,
    sessionSweepIntervalMs,
    authValidationTimeoutMs,
    maxSessionsPerBearer,
    maxSessionsPerProcess,
    maxRequestBodyBytes,
    maxNewSessionBodyBytes,
    bodyReceiveTimeoutMs,
    jsonKeepaliveMs,
    maxLargeBodyBytesInFlight,
    toolDeadlineMs,
    toolBackstopMs,
    maxResponseBytes,
    requestTimeoutMs,
    maxInFlightRequests,
    maxInFlightPerBearer,
    maxInFlightPerSession,
    elicitationAttestationKey,
    elicitationTimeoutMs,
    sseKeepaliveMs,
    machineId,
    noindex,
    logger,
    endpoints,
  };
}
