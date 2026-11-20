import { StackError, apiError } from './errors.js';
import { createAgentTokenProvider } from './agent-auth.js';
import { readCredentialsFile, withCredentialsLock, writeCredentialsFile, type StoredCredentials } from './credentials-file.js';
import { browserBootstrap, shouldRunBrowserBootstrap } from './browser-bootstrap.js';

/** The header an approved action's retry carries the ref of its approval in (the SDK does not import the API's constants). */
const CONTROL_REF_HEADER = 'X-Control-Ref';

export interface ClientOptions {
  /**
   * Long-lived `sk_live_*` operator key. When omitted, the SDK
   * falls back to (a) the `STACK_API_KEY` env var, (b) a refresh token
   * stored at `~/.stack/credentials.json` (written by `stack-cli auth
   * login`), exchanged on demand for a 5-minute access token.
   */
  apiKey?: string;
  baseUrl?: string;
  /**
   * Exact OAuth scope requested only when the SDK performs its interactive
   * first-run browser login. The default covers core agent runtime calls.
   * Supply broader management scopes deliberately; an existing refresh-token
   * family cannot be widened, so changing this requires a fresh login.
   */
  oauthScope?: string;
  /**
   * agent-runtime mode. When set, every request is signed with
   * a fresh 60-second EdDSA JWT minted from the agent's local privkey
   * (~/.stack/agents/<agent_id>.json, mode 0600). On first run, the SDK
   * generates the keypair locally and enrolls the public half via
   * /v1/agents/:id/enroll using the developer's OAuth credentials —
   * the privkey never crosses the network or terminal.
   */
  agent_id?: string;
}

export class HttpClient {
  private readonly explicitApiKey: string | undefined;
  private readonly baseUrl: string;
  private readonly interactiveOAuthScope: string | undefined;
  private cachedAccessToken: { token: string; expiresAt: number } | null = null;
  private readonly agentTokenProvider: (() => Promise<string>) | null;
  /** The client this one was made from by `withControlRef`: it resolves the credential, so a refresh happens once. */
  private parent: HttpClient | null = null;
  /** The ref of an approved action, sent as `X-Control-Ref` on every request of this client. */
  private controlRef: string | undefined;

  constructor(options: ClientOptions = {}) {
    this.explicitApiKey = options.apiKey ?? process.env['STACK_API_KEY'] ?? undefined;
    this.baseUrl = (options.baseUrl ?? process.env['STACK_API_URL'] ?? 'https://api.getstack.run').replace(/\/$/, '');
    this.interactiveOAuthScope = options.oauthScope;
    this.agentTokenProvider = options.agent_id
      ? createAgentTokenProvider({
          agentId: options.agent_id,
          baseUrl: this.baseUrl,
          // Bearer for the enrollment dance only — once enrolled the
          // agent JWTs sign requests directly. Reuse the OAuth refresh
          // path so the developer doesn't need to ship a separate key
          // to their agent runtime; if neither STACK_API_KEY nor
          // ~/.stack/credentials.json is present, enrollment will fail
          // with a clear error.
          bearerProvider: () => this.resolveStaticBearer(),
        })
      : null;
  }

  /**
   * A client that sends `X-Control-Ref: <ref>` on every request it makes and is otherwise this one (same server, same
   * credential, same refresh). When a policy holds a call for the owner, the refusal names a ref; once the owner has
   * approved, the same call is made again through a client made with that ref. Use it for that one call.
   */
  withControlRef(ref: string): HttpClient {
    if (ref.trim() === '') throw new TypeError('controlRef must be the non-empty ref the refusal named');
    const child = new HttpClient({ baseUrl: this.baseUrl });
    child.parent = this;
    child.controlRef = ref;
    return child;
  }

  private controlRefHeaders(): Record<string, string> {
    return this.controlRef === undefined ? {} : { [CONTROL_REF_HEADER]: this.controlRef };
  }

  async get<T>(
    path: string,
    query?: Record<string, string | undefined>,
    options?: { headers?: Record<string, string>; bearer?: string },
  ): Promise<T> {
    const url = this.buildUrl(path, query);
    return this.request<T>('GET', url, undefined, options?.headers, true, undefined, options?.bearer);
  }

  /**
   * A conditional GET of a JSON document. A `304` answers `{ status: 304, etag,
   * body: null }`; a `200` answers the parsed body and the response's `ETag`.
   * Any other status throws the API's error, as every other call does.
   */
  async getConditional<T>(
    path: string,
    options: { query?: Record<string, string | undefined>; ifNoneMatch?: string } = {},
  ): Promise<{ status: 200 | 304; etag: string | null; body: T | null }> {
    const bearer = await this.resolveBearer();
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${bearer}`,
      'Accept': 'application/json',
    };
    if (options.ifNoneMatch) headers['If-None-Match'] = options.ifNoneMatch;
    const res = await fetch(this.buildUrl(path, options.query), { method: 'GET', headers });
    if (res.status === 304) {
      return { status: 304, etag: res.headers.get('etag') ?? options.ifNoneMatch ?? null, body: null };
    }
    if (!res.ok) {
      let errorBody: { error?: { message?: string; code?: string }; message?: string } = {};
      try {
        errorBody = await res.json() as typeof errorBody;
      } catch {
        // ignore parse errors
      }
      throw apiError(
        errorBody.error?.message ?? errorBody.message ?? res.statusText,
        errorBody.error?.code ?? `HTTP_${res.status}`,
        res.status,
        errorBody,
      );
    }
    return { status: 200, etag: res.headers.get('etag'), body: await res.json() as T };
  }

  /** The API base URL this client talks to, without a trailing slash. */
  get apiBaseUrl(): string {
    return this.baseUrl;
  }

  /** The `Authorization` header a request of this client carries, for a connection the client does not make itself (a WebSocket). */
  async authorizationHeader(): Promise<string> {
    return `Bearer ${await this.resolveBearer()}`;
  }

  /**
   * A call to a public endpoint: no credential is resolved or sent, so it works
   * with none configured. For the checks anyone may run (STACK's public keys, the
   * signed revocation list, a countersignature check).
   */
  async publicRequest<T>(
    method: 'GET' | 'POST',
    path: string,
    options: { query?: Record<string, string | undefined>; body?: unknown } = {},
  ): Promise<T> {
    return sendUnauthenticated<T>(this.buildUrl(path, options.query), method, options.body);
  }

  /** Fetch an authenticated response as exact bytes. */
  async getBytes(path: string): Promise<Uint8Array> {
    const bearer = await this.resolveBearer();
    const response = await fetch(this.buildUrl(path), {
      headers: {
        'Authorization': `Bearer ${bearer}`,
        'Accept': 'application/json',
      },
    });
    if (!response.ok) {
      let errorBody: { error?: { message?: string; code?: string }; message?: string } = {};
      try {
        errorBody = await response.json() as typeof errorBody;
      } catch {
        // Keep the status text when the error body is not JSON.
      }
      throw apiError(
        errorBody.error?.message ?? errorBody.message ?? response.statusText,
        errorBody.error?.code ?? `HTTP_${response.status}`,
        response.status,
        errorBody,
      );
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  /**
   * Any method, with the answer as exact bytes and the type it came with: for an answer that is not JSON (an audio file, a
   * video, a picture). A non-2xx answer throws the API's error, as every other call does.
   */
  async requestBytes(
    method: string,
    path: string,
    options?: { body?: unknown; headers?: Record<string, string> },
  ): Promise<{ status: number; contentType: string | null; bytes: Uint8Array }> {
    const bearer = await this.resolveBearer();
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${bearer}`,
      'Accept': '*/*',
      ...this.controlRefHeaders(),
      ...(options?.headers ?? {}),
    };
    if (options?.body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(this.buildUrl(path), {
      method,
      headers,
      body: options?.body !== undefined ? JSON.stringify(options.body) : undefined,
    });
    if (!res.ok) {
      let errorBody: { error?: { message?: string; code?: string }; message?: string } = {};
      try {
        errorBody = await res.json() as typeof errorBody;
      } catch {
        // Keep the status text when the error body is not JSON.
      }
      throw apiError(
        errorBody.error?.message ?? errorBody.message ?? res.statusText,
        errorBody.error?.code ?? `HTTP_${res.status}`,
        res.status,
        errorBody,
      );
    }
    return { status: res.status, contentType: res.headers.get('content-type'), bytes: new Uint8Array(await res.arrayBuffer()) };
  }

  /**
   * `timeoutMs` aborts the call after that long; without it the call has no client-side limit. `bearer` is the credential
   * of this one call, used instead of the client's own (and with no client credential configured): a call that must be
   * made as an agent passes the agent's Passport.
   */
  async post<T>(path: string, body?: unknown, options?: { headers?: Record<string, string>; timeoutMs?: number; bearer?: string }): Promise<T> {
    const url = this.buildUrl(path);
    return this.request<T>('POST', url, body, options?.headers, true, options?.timeoutMs, options?.bearer);
  }

  /**
   * POST to a route that takes no credential (a public form). It sends no
   * Authorization header, so it works with no key configured and never puts an
   * operator key on a public route.
   */
  async postPublic<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', this.buildUrl(path), body, undefined, false);
  }

  /**
   * PUT the bytes of a file as the whole request body (`application/octet-stream`), with the caller's credential. The body is sent
   * as it is and never held whole: a `Blob` or a stream is streamed. `contentLength` is sent as `Content-Length` when known, which
   * lets the server refuse a file that is too large before it reads it. `signal` aborts the request; there is no other time limit.
   */
  async putRaw<T>(
    path: string,
    body: RawBody,
    options?: { query?: Record<string, string | undefined>; headers?: Record<string, string>; contentLength?: number; signal?: AbortSignal },
  ): Promise<T> {
    const headers = { 'Authorization': `Bearer ${await this.resolveBearer()}`, ...this.controlRefHeaders(), ...(options?.headers ?? {}) };
    return sendRaw<T>(this.buildUrl(path, options?.query), 'PUT', body, { headers, contentLength: options?.contentLength, signal: options?.signal });
  }

  async patch<T>(path: string, body?: unknown, options?: { headers?: Record<string, string> }): Promise<T> {
    const url = this.buildUrl(path);
    return this.request<T>('PATCH', url, body, options?.headers);
  }

  async put<T>(path: string, body?: unknown, options?: { headers?: Record<string, string> }): Promise<T> {
    const url = this.buildUrl(path);
    return this.request<T>('PUT', url, body, options?.headers);
  }

  async delete<T>(path: string, options?: { headers?: Record<string, string> }): Promise<T> {
    const url = this.buildUrl(path);
    return this.request<T>('DELETE', url, undefined, options?.headers);
  }

  /**
   * streaming POST for the LLM gateway. Returns the raw
   * `ReadableStream<Uint8Array>` for the caller to pipe / iterate.
   * Caller owns the stream lifecycle (must drain or cancel). Throws
   * `StackError` on non-2xx responses (parsed as JSON error envelope
   * before opening the stream — error bodies are short).
   *
   * `accept: text/event-stream` is set automatically so providers know
   * to emit SSE. Bearer auth + extra headers handled the same way as
   * `post()`.
   */
  async postStream(
    path: string,
    body?: unknown,
    options?: { headers?: Record<string, string> },
  ): Promise<ReadableStream<Uint8Array>> {
    const bearer = await this.resolveBearer();
    const url = this.buildUrl(path);
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${bearer}`,
      'Accept': 'text/event-stream',
      ...this.controlRefHeaders(),
      ...(options?.headers ?? {}),
    };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let errorBody: { error?: { message?: string; code?: string }; message?: string } = {};
      try {
        errorBody = await res.json() as typeof errorBody;
      } catch {
        // ignore parse errors
      }
      const message = errorBody.error?.message ?? errorBody.message ?? res.statusText;
      const code = errorBody.error?.code ?? `HTTP_${res.status}`;
      throw apiError(message, code, res.status, errorBody);
    }
    if (!res.body) {
      throw new StackError(
        'upstream returned no body for streaming request',
        'EMPTY_STREAM',
        502,
        {},
      );
    }
    return res.body;
  }

  private buildUrl(path: string, query?: Record<string, string | undefined>): string {
    const url = new URL(path, this.baseUrl);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined) url.searchParams.set(key, value);
      }
    }
    return url.toString();
  }

  /**
   * Resolve the bearer token to attach to a request. Three sources, in
   * priority order:
   *   1. Explicit `apiKey` on the constructor or STACK_API_KEY env var
   *      (legacy `sk_live_*`, preserved for CI).
   *   2. Cached OAuth access token (5-minute TTL; refresh-rotates).
   *   3. Refresh token in `~/.stack/credentials.json` (written by the
   *      CLI's `auth login`) — exchanged for a fresh access token.
   *
   * Throws `StackError('NOT_AUTHENTICATED', ...)` when none of the
   * three resolve.
   */
  private async resolveBearer(): Promise<string> {
    if (this.parent) return this.parent.resolveBearer();
    // agent-runtime mode short-circuits everything. Mint a
    // fresh agent JWT per request; enrollment happens inside the
    // provider on first call.
    if (this.agentTokenProvider) {
      return this.agentTokenProvider();
    }
    return this.resolveStaticBearer();
  }

  /**
   * Static-bearer resolution: explicit apiKey → STACK_API_KEY env →
   * ~/.stack/credentials.json refresh-token exchange → first-run
   * browser-spawn bootstrap (interactive only). Does NOT mint agent
   * JWTs — that's `resolveBearer()`'s job. Exposed separately so the
   * agent-token provider can use this same path for the one-time
   * enrollment dance (which itself needs a static bearer to authenticate).
   */
  private async resolveStaticBearer(): Promise<string> {
    if (this.explicitApiKey) return this.explicitApiKey;

    // Browser / non-Node runtimes: refresh-from-file is not possible.
    // Fall through to the same NOT_AUTHENTICATED error.
    const isNode = typeof process !== 'undefined' && process.versions?.node;
    if (!isNode) throw notAuthenticated();

    const now = Math.floor(Date.now() / 1000);
    if (this.cachedAccessToken && this.cachedAccessToken.expiresAt - 30 > now) {
      // Re-use the cached access token unless within 30s of expiry.
      return this.cachedAccessToken.token;
    }

    const fresh = await refreshAccessTokenFromFile(this.baseUrl);
    if (fresh) {
      this.cachedAccessToken = { token: fresh.access_token, expiresAt: now + (fresh.expires_in ?? 300) };
      return fresh.access_token;
    }

    // Last resort: spawn the browser. Gated by TTY + opt-out env so
    // production agent runtimes (no TTY) don't accidentally try to open
    // a browser.
    if (shouldRunBrowserBootstrap()) {
      const result = await browserBootstrap(this.baseUrl, this.interactiveOAuthScope);
      this.cachedAccessToken = { token: result.access_token, expiresAt: now + result.expires_in };
      return result.access_token;
    }

    throw notAuthenticated();
  }

  private async request<T>(
    method: string,
    url: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
    authenticated = true,
    timeoutMs?: number,
    bearer?: string,
  ): Promise<T> {
    const headers: Record<string, string> = {
      ...(authenticated ? { 'Authorization': `Bearer ${bearer ?? await this.resolveBearer()}` } : {}),
      'Accept': 'application/json',
      ...(authenticated ? this.controlRefHeaders() : {}),
      ...(extraHeaders ?? {}),
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      ...(timeoutMs !== undefined ? { signal: AbortSignal.timeout(timeoutMs) } : {}),
    });

    if (!res.ok) {
      let errorBody: { error?: { message?: string; code?: string }; message?: string } = {};
      try {
        errorBody = await res.json() as typeof errorBody;
      } catch {
        // ignore parse errors
      }

      const message = errorBody.error?.message ?? errorBody.message ?? res.statusText;
      const code = errorBody.error?.code ?? `HTTP_${res.status}`;
      throw apiError(message, code, res.status, errorBody);
    }

    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
  }
}

/** One unauthenticated JSON call, with the API's error envelope turned into a `StackError`. */
export async function sendUnauthenticated<T>(url: string, method: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: {
      'Accept': 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let errorBody: { error?: { message?: string; code?: string }; message?: string } = {};
    try {
      errorBody = await res.json() as typeof errorBody;
    } catch {
      // ignore parse errors
    }
    throw apiError(
      errorBody.error?.message ?? errorBody.message ?? res.statusText,
      errorBody.error?.code ?? `HTTP_${res.status}`,
      res.status,
      errorBody,
    );
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** The bytes of a file sent as a request body: held in memory, a `Blob`, or a stream read as it goes. */
export type RawBody = Uint8Array | Blob | ReadableStream<Uint8Array>;

/**
 * One request whose body is raw bytes, with the API's error envelope turned into a `StackError`. It adds no credential: the caller's
 * `headers` carry one when the route needs it. A stream goes out as it is read (no length is known to the sender, so `contentLength`
 * names it when the caller does). A network failure is a `DRIVE_UPLOAD_FAILED` `StackError` that does not name the URL, which can be a
 * bearer URL; an abort by the caller's `signal` is passed on as it is.
 */
export async function sendRaw<T>(
  url: string,
  method: 'PUT',
  body: RawBody,
  options: { headers?: Record<string, string>; contentLength?: number; signal?: AbortSignal } = {},
): Promise<T> {
  const headers: Record<string, string> = {
    'Accept': 'application/json',
    'Content-Type': 'application/octet-stream',
    ...(options.headers ?? {}),
  };
  if (options.contentLength !== undefined) headers['Content-Length'] = String(options.contentLength);
  const init: RequestInit & { duplex?: 'half' } = {
    method,
    headers,
    body: body as NonNullable<RequestInit['body']>,
    ...(options.signal ? { signal: options.signal } : {}),
    ...(body instanceof Uint8Array || body instanceof Blob ? {} : { duplex: 'half' as const }),
  };
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new StackError('The upload did not reach STACK or the connection dropped before it was answered', 'DRIVE_UPLOAD_FAILED', 0);
  }
  if (!res.ok) {
    let errorBody: { error?: { message?: string; code?: string }; message?: string } = {};
    try {
      errorBody = await res.json() as typeof errorBody;
    } catch {
      // ignore parse errors
    }
    throw apiError(
      errorBody.error?.message ?? errorBody.message ?? res.statusText,
      errorBody.error?.code ?? `HTTP_${res.status}`,
      res.status,
      errorBody,
    );
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

function notAuthenticated(): StackError {
  return new StackError(
    'No STACK credentials found. Run `npx @getstackrun/cli auth login`.',
    'NOT_AUTHENTICATED',
    401,
    {},
  );
}

/**
 * Read `~/.stack/credentials.json` (written by the CLI or by the SDK's
 * own browser-bootstrap), exchange the stored refresh token for a fresh
 * access token, write the rotated refresh back to the file. Returns
 * null when the file is missing or the refresh has been revoked.
 *
 * Lazy-loaded Node-only path. The browser bundle skips this entirely
 * via the isNode check in resolveBearer.
 */
async function refreshAccessTokenFromFile(
  baseUrl: string,
): Promise<{ access_token: string; expires_in: number } | null> {
  // No sign-in, no lock: there is nothing to renew.
  if (!(await readCredentialsFile())) return null;
  // Renewing rotates the refresh token, so it is done one process at a time, reading the file again once the lock is held.
  return withCredentialsLock(async () => {
    const creds = await readCredentialsFile();
    if (!creds) return null;

    const res = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: creds.refresh_token,
        client_id: creds.client_id,
      }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { access_token: string; refresh_token: string; expires_in: number };

    // Persist the rotated refresh — failure to write means next run pays
    // the round-trip again, but the in-memory access token is still good.
    const next: StoredCredentials = {
      ...creds,
      refresh_token: data.refresh_token,
      issued_at: Math.floor(Date.now() / 1000),
      refresh_expires_at: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
    };
    try {
      await writeCredentialsFile(next);
    } catch {
      /* non-fatal */
    }

    return { access_token: data.access_token, expires_in: data.expires_in };
  });
}
