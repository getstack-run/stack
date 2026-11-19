// Shared API helper for every CLI subcommand. Consolidates:
//   - Bearer-token resolution (OAuth from `auth login` or STACK_API_KEY).
//   - JSON parsing with a consistent error envelope (`{error: {code,
//     message}}`).
//   - Friendly error printing — never silent, always shows the API's
//     reason on stderr so the operator can diagnose without re-running
//     with a sniffer.
//
// Used by: agent.ts, passports.ts, services.ts, dropoffs.ts, skills.ts,
// identity.ts, audit.ts, events.ts, team.ts. Anything that hits the
// REST API should go through here, not bare fetch().

import { env, stderr, exit } from 'node:process';
import { findAgentByName } from './agent-lookup.js';
import { getAccessToken, invokeHint, stringifyOAuthError } from './auth.js';

export const API_URL = env['STACK_API_URL'] ?? 'https://api.getstack.run';

export type ApiMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export interface ApiOptions {
  body?: unknown;
  query?: Record<string, string | number | undefined>;
  expectEmpty?: boolean;
  headers?: Record<string, string>;
}

/** The header an approved action's retry carries the ref of its approval in. */
export const CONTROL_REF_HEADER = 'X-Control-Ref';

let controlRef: string | undefined;

/** The ref the `--control-ref` flag gave this run, if any. */
export function currentControlRef(): string | undefined {
  return controlRef;
}

/** Make every write of this run carry the ref (or, with `undefined`, none). */
export function setControlRef(ref: string | undefined): void {
  controlRef = ref;
}

/**
 * Take the global `--control-ref <ref>` flag out of an argv slice and remember it for the run. It is the retry of an
 * action the owner approved: the ref is the one a CONTROL_DENIED refusal (reason review_required) named. A flag with no
 * value is an error, not a flag left in place for a command to misread.
 */
export function takeControlRefFlag(args: string[]): void {
  const value = takeFlag(args, '--control-ref');
  if (value === undefined) return;
  if (typeof value !== 'string' || value.trim() === '') {
    stderr.write('error: --control-ref needs the ref the refusal named (--control-ref <ref>).\n');
    exit(2);
  }
  controlRef = value;
}

export class ApiRequestError extends Error {
  constructor(
    public readonly status: number,
    public readonly method: ApiMethod,
    public readonly path: string,
    public readonly response: unknown,
  ) {
    super(stringifyOAuthError(response));
    this.name = 'ApiRequestError';
  }

  get code(): string | undefined {
    const error = (this.response as { error?: { code?: unknown } } | undefined)?.error;
    return typeof error?.code === 'string' ? error.code : undefined;
  }

  get details(): Record<string, unknown> | undefined {
    const error = (this.response as { error?: { details?: unknown } } | undefined)?.error;
    return error?.details && typeof error.details === 'object' && !Array.isArray(error.details)
      ? error.details as Record<string, unknown>
      : undefined;
  }
}

/**
 * Require an auth token or exit with a clear "not signed in" message.
 * Most CLI commands gate on this; the few that don't (--demo style)
 * skip this helper.
 */
export async function requireToken(): Promise<string> {
  const token = await getAccessToken();
  if (token) return token;
  stderr.write(
    `error: not signed in.\nRun \`${invokeHint('auth login')}\` first.\n`,
  );
  exit(2);
}

/**
 * Authenticated REST call. Method-aware. Body auto-JSON-stringified
 * unless explicitly disabled (e.g. for x-www-form-urlencoded paths).
 * Returns parsed JSON on success. On error: prints to stderr (with the
 * actual API reason) and exits 1.
 */
export async function requestApi<T = unknown>(
  method: ApiMethod,
  path: string,
  opts?: ApiOptions,
): Promise<T> {
  const token = await requireToken();
  const url = new URL(`${API_URL}${path}`);
  if (opts?.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
    }
  }
  const headers: Record<string, string> = {
    // Only a write can be held for the owner, so only a write carries the ref.
    ...(controlRef !== undefined && method !== 'GET' ? { [CONTROL_REF_HEADER]: controlRef } : {}),
    ...(opts?.headers ?? {}),
    Authorization: `Bearer ${token}`,
  };
  let body: string | undefined;
  if (opts?.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }

  const res = await fetch(url.toString(), { method, headers, body });
  if (res.status === 204) {
    return undefined as T;
  }

  const text = await res.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    // Non-JSON body — probably an HTML error page from an intermediary.
    if (!res.ok) {
      throw new ApiRequestError(res.status, method, path, text.slice(0, 200));
    }
    return text as unknown as T;
  }

  if (!res.ok) {
    throw new ApiRequestError(res.status, method, path, data);
  }
  if (opts?.expectEmpty) {
    return undefined as T;
  }
  return data as T;
}

/** The API's member-role refusal ("This action requires standard access or higher", and the admin one). */
function isRoleRefusal(message: string): boolean {
  return /\brequires (standard|admin) access\b/.test(message);
}

export async function api<T = unknown>(
  method: ApiMethod,
  path: string,
  opts?: ApiOptions,
): Promise<T> {
  try {
    return await requestApi<T>(method, path, opts);
  } catch (error) {
    if (error instanceof ApiRequestError) {
      stderr.write(`error: API ${error.status} ${method} ${path}: ${error.message}\n`);
      if (error.code === 'CONNECTION_AMBIGUOUS') {
        // The service has several connections and the call named none: list what it could have named.
        const rows = Array.isArray(error.details?.['connections']) ? (error.details['connections'] as Array<{ id?: unknown; name?: unknown }>) : [];
        for (const row of rows) stderr.write(`  ${String(row.name ?? '')} (${String(row.id ?? '')})\n`);
        stderr.write('hint: pass --connection <name|id> to choose one.\n');
      }
      if (error.status === 403 && isRoleRefusal(error.message)) {
        // The API refused the signed-in team member's role. No new sign-in or scope changes that.
        stderr.write('hint: your team role cannot make this change. Ask the account owner or an admin to change your role.\n');
      } else if (error.status === 403) {
      // Guardrail: a 403 on a write verb is easy to misread as "the CLI is
      // broken." An intentionally narrow OAuth family may need a fresh login
      // with an explicit scope set. Refresh never widens a family. This stays
      // generic because other 403s can be governance denials.
      stderr.write(
        `hint: if this is a write command, your CLI token may be read-only.\n` +
          `      Set STACK_OAUTH_SCOPE to the exact scopes you intend, then re-run\n` +
          `      \`${invokeHint('auth login')}\`; refresh tokens cannot widen scope.\n`,
      );
      }
      exit(1);
    }
    throw error;
  }
}

/**
 * Pull a global flag value (e.g. --json, --limit 20) from an argv slice.
 * Returns the value as a string (for `--key val` form) or true for
 * standalone (`--flag`). Argv is mutated to remove the consumed tokens
 * so the caller's positional parsing isn't polluted.
 */
export function takeFlag(args: string[], name: string): string | boolean | undefined {
  const idx = args.indexOf(name);
  if (idx === -1) return undefined;
  const next = args[idx + 1];
  if (!next || next.startsWith('--')) {
    args.splice(idx, 1);
    return true;
  }
  args.splice(idx, 2);
  return next;
}

/**
 * Resolve an agent name OR id to the agent_id (agt_*). Most CLI commands
 * accept either form because operators routinely type the human-readable
 * name they registered — but the API only accepts agt_* IDs on
 * /v1/agents/:id/* paths. Without this resolver, passing the name
 * silently 404s ("Agent not found: my-agent-name").
 *
 * Returns the agt_* id. Exits 1 with a clear error if the name doesn't
 * match anything in the operator's agent list.
 */
export async function resolveAgentId(nameOrId: string): Promise<string> {
  if (nameOrId.startsWith('agt_')) return nameOrId;
  const agents = await api<Array<{ id: string; name: string; status?: string }>>('GET', '/v1/agents');
  const match = findAgentByName(Array.isArray(agents) ? agents : [], nameOrId);
  if (!match) {
    stderr.write(
      `error: no agent named "${nameOrId}" in your operator.\n` +
        `Pass either the human name (from \`agent list\`) or the agt_* id.\n`,
    );
    exit(1);
  }
  return match.id;
}
