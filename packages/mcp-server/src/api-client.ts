/**
 * The HTTP client every tool handler uses to reach the STACK API. It sends the
 * caller's Bearer token and turns the response into either a parsed value or a
 * thrown Error. It never lets a body that is empty or not JSON surface as a
 * parse exception.
 */

import { FETCH_WAIT_CEILING_MS, longRequest } from './long-request.js';
import { currentCallScope } from './tool-deadlines.js';

const nativeFetch = globalThis.fetch;

/** How the response body decoded: valid JSON, no body at all, or something else. */
export type ApiBodyFormat = 'json' | 'empty' | 'text';

export interface ApiResponse {
  status: number;
  ok: boolean;
  format: ApiBodyFormat;
  /** The parsed JSON value when format is 'json', otherwise undefined. */
  body: unknown;
  /** The body as UTF-8 text, exactly as sent, when there is one. Set for a JSON body too, for a handler that needs the exact bytes. */
  text?: string;
  /** The body's bytes when it is not JSON (a CSV, NDJSON or COSE download), otherwise undefined. */
  bytes?: Uint8Array;
  contentType: string | null;
  /** The raw `Retry-After` header, when the response carried one. */
  retryAfter: string | null;
}

/** The wait, in seconds, a 503 names when neither the header nor the body gives one. */
export const UNAVAILABLE_RETRY_DEFAULT_SECONDS = 5;
const UNAVAILABLE_RETRY_MIN_SECONDS = 1;
const UNAVAILABLE_RETRY_MAX_SECONDS = 300;

const clampWait = (seconds: number): number =>
  Math.min(UNAVAILABLE_RETRY_MAX_SECONDS, Math.max(UNAVAILABLE_RETRY_MIN_SECONDS, seconds));

/**
 * How long to wait after a 503, in whole seconds from 1 to 300: the
 * `Retry-After` header (a number of seconds or an HTTP date), else the body's
 * `error.details.retry_after_seconds`, else 5. A value that is neither is
 * ignored rather than trusted.
 */
export function retryAfterSeconds(header: string | null | undefined, body?: unknown, now: number = Date.now()): number {
  const raw = header?.trim() ?? '';
  if (/^\d+$/.test(raw)) return clampWait(Number(raw));
  if (raw !== '' && !/^-?\d/.test(raw)) {
    const date = Date.parse(raw);
    if (Number.isFinite(date)) return clampWait(Math.ceil((date - now) / 1000));
  }
  const details = body !== null && typeof body === 'object'
    ? ((body as { error?: { details?: { retry_after_seconds?: unknown } } }).error?.details)
    : undefined;
  const wait = details?.retry_after_seconds;
  if (typeof wait === 'number' && Number.isSafeInteger(wait)) return clampWait(wait);
  return UNAVAILABLE_RETRY_DEFAULT_SECONDS;
}

/**
 * What a model reads for an upstream 503. It names the cause and the wait and
 * nothing else: a 503 never says anything about the caller's credential, so
 * the text must not suggest it is invalid or needs rotating or re-authorizing.
 */
export function temporarilyUnavailableMessage(seconds: number): string {
  return `STACK is temporarily unavailable, retry in ${seconds} ${seconds === 1 ? 'second' : 'seconds'}. It is a temporary condition on the STACK side.`;
}

export type ApiFn = (
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
) => Promise<unknown>;

export type ApiRawFn = (
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
) => Promise<ApiResponse>;

/** The `error` object of the API's error envelope, `{ error: { code, message, details } }`. */
export interface ApiErrorObject {
  message?: string;
  code?: string;
  details?: { approval_id?: string; approval_url?: string } & Record<string, unknown>;
}

interface ApiErrorBody {
  error?: ApiErrorObject;
}

/** The envelope's `error` object, or undefined when the body is not JSON or carries none. */
export function errorBodyOf(response: ApiResponse): ApiErrorObject | undefined {
  if (response.format !== 'json' || response.body === null || typeof response.body !== 'object') return undefined;
  const error = (response.body as ApiErrorBody).error;
  return error !== null && typeof error === 'object' ? error : undefined;
}

/**
 * The 503 codes that mean STACK, or something it depends on, is briefly
 * unavailable. Any other code on a 503 (a revoked customer key) is not cured by
 * waiting, so its own message is kept.
 */
const RETRIABLE_503_CODES: ReadonlySet<string> = new Set([
  'SERVICE_UNAVAILABLE',
  'CONTROL_UNAVAILABLE',
  'PROVIDER_CAPACITY_UNAVAILABLE',
  'TOOLS_UNAVAILABLE',
]);

/**
 * The message for a non-2xx response: for a 503 that names no code or a
 * temporary-unavailability code (a bare proxy 503 included), the
 * temporary-outage text, otherwise the API's own error message when the body
 * carries one, otherwise the status code.
 */
export function apiErrorMessage(response: ApiResponse): string {
  if (response.status === 503) {
    const code = errorBodyOf(response)?.code;
    if (code === undefined || RETRIABLE_503_CODES.has(code)) {
      return temporarilyUnavailableMessage(retryAfterSeconds(response.retryAfter, response.body));
    }
  }
  return errorBodyOf(response)?.message ?? `API error: ${response.status}`;
}

/** Throws the Error a handler surfaces for a response that is not 2xx. */
export function throwApiError(response: ApiResponse): never {
  const err = errorBodyOf(response);
  if (err?.code === 'GOVERNANCE_APPROVAL_REQUIRED') {
    throw new Error(JSON.stringify({
      code: err.code,
      message: err.message,
      approval_id: err.details?.approval_id,
      approval_url: err.details?.approval_url,
    }));
  }
  // An approval a retry named that cannot be used: pending (wait for the person), rejected or expired (ask again).
  if (err?.code === 'GOVERNANCE_APPROVAL_PENDING' || err?.code === 'GOVERNANCE_APPROVAL_REJECTED' || err?.code === 'GOVERNANCE_APPROVAL_EXPIRED') {
    throw new Error(JSON.stringify({
      code: err.code,
      message: err.message,
      approval_id: err.details?.approval_id,
    }));
  }
  // A service with several connections and a call that named none: the names the caller may pass as `connection`.
  if (err?.code === 'CONNECTION_AMBIGUOUS') {
    throw new Error(JSON.stringify({
      code: err.code,
      message: err.message,
      connections: Array.isArray(err.details?.['connections']) ? err.details['connections'] : [],
    }));
  }
  throw new Error(apiErrorMessage(response));
}

/**
 * The value a handler returns for a 2xx response. An empty body (204, or a
 * 200 with nothing in it) is a success with nothing to say, so it becomes
 * `{ ok: true, status }`. A body that is present but is not JSON is an error
 * the caller can act on, never a SyntaxError from JSON.parse.
 */
export function apiSuccessValue(response: ApiResponse): unknown {
  if (response.format === 'json') return response.body;
  if (response.format === 'empty') return { ok: true, status: response.status };
  throw new Error(JSON.stringify({
    code: 'API_RESPONSE_NOT_JSON',
    message: `The STACK API answered HTTP ${response.status} with a body that is not JSON${response.contentType ? ` (${response.contentType})` : ''}.`,
    status: response.status,
  }));
}

async function readResponse(res: Response): Promise<ApiResponse> {
  const contentType = res.headers.get('content-type');
  const retryAfter = res.headers.get('retry-after');
  const bytes = new Uint8Array(await res.arrayBuffer());
  const text = new TextDecoder().decode(bytes);
  if (text.trim() === '') return { status: res.status, ok: res.ok, format: 'empty', body: undefined, contentType, retryAfter };
  try {
    return { status: res.status, ok: res.ok, format: 'json', body: JSON.parse(text) as unknown, text, contentType, retryAfter };
  } catch {
    return { status: res.status, ok: res.ok, format: 'text', body: undefined, text, bytes, contentType, retryAfter };
  }
}

/**
 * Asks the person, in the chat, to decide a pending approval. It receives a
 * client without this hook, so a confirmation never asks for a confirmation.
 * 'approved' means the person approved this exact change and the call is
 * retried with the approval; 'rejected' stops the call; 'unavailable' returns
 * the approval link to the caller. The approval itself is never decided here
 * by the model: only the person's answer, relayed with the MCP server's
 * attestation, can approve.
 */
export type ConfirmApproval = (
  approvalId: string,
  approvalUrl: string | undefined,
  api: ApiFn,
) => Promise<'approved' | 'rejected' | 'unavailable'>;

export function createApiClient(
  apiBaseUrl: string,
  apiKey: string,
  hooks: { confirmApproval?: ConfirmApproval } = {},
): { api: ApiFn; apiRaw: ApiRawFn } {
  const apiRaw: ApiRawFn = async (method, path, body, extraHeaders) => {
    // Inside a tool call the request stops when the call's deadline passes, and one that may run past what `fetch` waits
    // for a response (a long workspace command) goes by a request that has no wait of its own.
    const scope = currentCallScope();
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
      ...extraHeaders,
    };
    const payload = body ? JSON.stringify(body) : undefined;
    // A `fetch` that was replaced (a test, an instrumented host) is always the one used.
    const res = scope && scope.deadlineMs > FETCH_WAIT_CEILING_MS && globalThis.fetch === nativeFetch
      ? await longRequest(`${apiBaseUrl}${path}`, { method, headers, ...(payload !== undefined ? { body: payload } : {}), signal: scope.signal })
      : await fetch(`${apiBaseUrl}${path}`, { method, headers, body: payload, ...(scope ? { signal: scope.signal } : {}) });
    return readResponse(res);
  };

  // The client confirmations use: no confirmation hook.
  const apiPlain: ApiFn = async (method, path, body, extraHeaders) => {
    const response = await apiRaw(method, path, body, extraHeaders);
    if (!response.ok) throwApiError(response);
    return apiSuccessValue(response);
  };

  const api: ApiFn = async (method, path, body, extraHeaders) => {
    const response = await apiRaw(method, path, body, extraHeaders);
    if (!response.ok) {
      const err = errorBodyOf(response);
      const approvalId = err?.details?.approval_id;
      if (hooks.confirmApproval && err?.code === 'GOVERNANCE_APPROVAL_REQUIRED' && approvalId) {
        const outcome = await hooks.confirmApproval(approvalId, err.details?.approval_url, apiPlain);
        if (outcome === 'approved') {
          // The person approved this exact payload. Apply it with the
          // approval, and never ask a second time.
          const retried = await apiRaw(method, path, body, { ...extraHeaders, 'X-Governance-Approval': approvalId });
          if (!retried.ok) throwApiError(retried);
          return apiSuccessValue(retried);
        }
        if (outcome === 'rejected') {
          throw new Error('The change was rejected in the chat, so STACK did not apply it.');
        }
      }
      throwApiError(response);
    }
    return apiSuccessValue(response);
  };

  return { api, apiRaw };
}
