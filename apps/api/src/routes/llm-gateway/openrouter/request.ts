// The request the OpenRouter passthrough reads: which OpenRouter endpoint the caller is asking for, and the bytes to
// send it. The path and the query are the caller's own, below the one base STACK sends them to; the body is forwarded as
// it came (never re-serialised), and read only to know what the call names (its model, whether it streams) for the gates.

import type { FastifyRequest } from 'fastify';
import {
  OPENROUTER_API_BASE,
  OPENROUTER_GATEWAY_PREFIX,
  StackError,
  matchOpenRouterEndpoint,
  openRouterPathProblem,
  type OpenRouterEndpointMatch,
} from '@stack/shared';

export interface OpenRouterCall {
  method: string;
  /** The path below the API base, with a leading slash and no trailing one: `/chat/completions`. */
  path: string;
  /** The query string with its `?`, or an empty string. */
  search: string;
  /** What the gateway knows of this endpoint, or null for one OpenRouter has that the table does not list. */
  match: OpenRouterEndpointMatch | null;
  contentType: string | null;
  /** The body exactly as the caller sent it; null when there is none. */
  rawBody: Buffer | null;
  /** The body as an object when it is JSON (what the gates read); an empty object otherwise. */
  body: Record<string, unknown>;
  /** Where the call goes: the one host, the one base, the caller's path. */
  upstream: URL;
}

const JSON_TYPE = /^(?:application|text)\/(?:[a-z0-9.+-]*\+)?json(?:\s*;|$)/i;
const QUERY = /^\?[\x21-\x7e]{1,8192}$/;

function invalid(message: string): never {
  throw new StackError(message, 'INVALID_REQUEST', 400);
}

/** Whether a body of this content type is JSON the gates can read. */
export function isJsonType(contentType: string | null | undefined): boolean {
  return contentType !== null && contentType !== undefined && JSON_TYPE.test(contentType.trim());
}

export function readOpenRouterCall(request: FastifyRequest): OpenRouterCall {
  const url = request.raw.url ?? '';
  const queryAt = url.indexOf('?');
  const pathname = queryAt === -1 ? url : url.slice(0, queryAt);
  let search = queryAt === -1 ? '' : url.slice(queryAt);
  if (search === '?') search = '';
  if (search !== '' && !QUERY.test(search)) invalid('The query string must be printable ASCII with no spaces, at most 8192 characters.');

  // The route is /v1/llm/openrouter/*, so the pathname starts with the prefix; what follows is OpenRouter's own path.
  const rest = pathname.startsWith(OPENROUTER_GATEWAY_PREFIX) ? pathname.slice(OPENROUTER_GATEWAY_PREFIX.length) : '';
  const trimmed = rest.replace(/^\/+/, '').replace(/\/+$/, '');
  if (trimmed === '') invalid('Name an OpenRouter endpoint after /v1/llm/openrouter, for example /v1/llm/openrouter/chat/completions.');
  const problem = openRouterPathProblem(trimmed);
  if (problem) invalid(problem);
  const path = `/${trimmed}`;

  const method = request.method.toUpperCase();
  const contentType = typeof request.headers['content-type'] === 'string' ? request.headers['content-type'] : null;
  const raw = request.body;
  const rawBody = Buffer.isBuffer(raw) ? (raw.length > 0 ? raw : null) : null;

  let body: Record<string, unknown> = {};
  if (rawBody && isJsonType(contentType)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody.toString('utf8'));
    } catch {
      invalid('The body is not valid JSON.');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) invalid('The body must be a JSON object.');
    body = parsed as Record<string, unknown>;
  }

  const upstream = new URL(`${OPENROUTER_API_BASE}${path}${search}`);
  // The host and the base are fixed: nothing in the path or the query can change where STACK's key goes.
  if (upstream.protocol !== 'https:' || upstream.host !== new URL(OPENROUTER_API_BASE).host || !upstream.pathname.startsWith(`${new URL(OPENROUTER_API_BASE).pathname}/`)) {
    invalid('The path does not stay below the OpenRouter API.');
  }
  return { method, path, search, match: matchOpenRouterEndpoint(method, path), contentType, rawBody, body, upstream };
}
