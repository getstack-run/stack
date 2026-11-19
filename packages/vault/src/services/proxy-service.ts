import {
  CREDENTIAL_TEMPLATES,
  PROXY_REQUEST_TIMEOUT_MS,
  PROXY_RESPONSE_MAX_BYTES,
  assertPublicUrl,
  resolvePublicUrl,
  publicFetch,
  PublicFetchLimitError,
  stripHopByHopHeaders,
  UnsafeUrlError,
  isHostAllowed,
  ConnectionNoAccessTokenError,
  SERVICE_MCP_ACCEPT,
  SERVICE_MCP_INITIALIZED_BODY,
  SERVICE_MCP_PROTOCOL_VERSION,
  isServiceMcpSessionId,
  readServiceMcpAnswer,
  serviceMcpInitializeBody,
} from '@stack/shared';
import type { ProxyRequestInput } from '@stack/shared';
import {
  interpolate,
  parseCredentialObject,
  proxyFieldsFromCredential,
  templateApplies,
} from './credential-fields.js';

/** Known OAuth providers → default Bearer auth */
const OAUTH_BEARER_PROVIDERS = new Set([
  'slack', 'github', 'google_drive', 'gmail', 'notion', 'linear',
  'discord', 'figma', 'dropbox', 'microsoft', 'spotify', 'asana',
  'google_calendar', 'google_sheets', 'google_docs',
]);

export interface ProxyResult {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface PreparedProxyDispatch {
  service: string;
  method: ProxyRequestInput['method'];
  finalUrl: string;
  headers: Record<string, string>;
  bodyBytes: string | null;
}

export type ProxyTransportOutcome =
  | { kind: 'response'; response: ProxyResult }
  | { kind: 'outcome_unknown'; reason: 'timeout' | 'connection_lost' | 'response_too_large' | 'transport_error' };

const SAFE_RESPONSE_HEADERS = new Set([
  'cache-control',
  'content-language',
  'content-type',
  'date',
  'etag',
  'idempotent-replayed',
  'last-modified',
  // The session an MCP service opens: read by `forwardMcpPrepared`, ended after its one call.
  'mcp-session-id',
  'request-id',
  'retry-after',
  'stripe-request-id',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'x-request-id',
]);

export function pickSafeProxyResponseHeaders(headers: Headers): Record<string, string> {
  const permitted: Record<string, string> = {};
  stripHopByHopHeaders(headers).forEach((value, key) => {
    const name = key.toLowerCase();
    if (SAFE_RESPONSE_HEADERS.has(name)) permitted[name] = value;
  });
  return permitted;
}

/**
 * Adds the signature that tells a site which agent a request is from (Web Bot
 * Auth), for an agent that has an account. Returns no headers for any other
 * agent. It never throws: a request that cannot be signed goes unsigned.
 */
export interface EgressSigner {
  forAgent(subject: EgressSubject, request: { method: string; url: string }): Promise<Record<string, string>>;
}

/** The agent a proxied request is made for. */
export interface EgressSubject {
  operatorId: string;
  agentId: string;
}

export class ProxyService {
  constructor(private readonly egressSigner: EgressSigner | null = null) {}

  /** The signature headers for the request about to leave, added after everything the operation ledger hashes. */
  private async egressHeaders(
    egress: EgressSubject | undefined,
    method: string,
    url: string,
  ): Promise<Record<string, string>> {
    if (!egress || !this.egressSigner) return {};
    return this.egressSigner.forAgent(egress, { method, url });
  }

  /**
   * Resolve auth headers for a provider given its credential.
   * Reuses template verification_headers patterns from CREDENTIAL_TEMPLATES.
   */
  resolveAuthHeaders(provider: string, credential: string): Record<string, string> {
    // Multi-field credentials arrive as a JSON object; a bare token is offered
    // as both `api_key` and `token`.
    const { fields, structured } = proxyFieldsFromCredential(credential);

    // Try template-based auth headers first
    const templateKey = provider.replace(/^custom_/, '');
    const template = CREDENTIAL_TEMPLATES[templateKey];
    if (template?.verification_headers && templateApplies(template, { fields, structured })) {
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(template.verification_headers)) {
        // Handle Basic auth pattern
        const basicMatch = value.match(/^Basic \{\{__basic:(\w+):(\w+)\}\}$/);
        if (basicMatch && basicMatch[1] && basicMatch[2]) {
          const user = fields[basicMatch[1]] ?? '';
          const pass = fields[basicMatch[2]] ?? '';
          headers[key] = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
        } else {
          headers[key] = interpolate(value, fields);
        }
      }
      return headers;
    }

    // OAuth providers → Bearer token
    if (OAUTH_BEARER_PROVIDERS.has(provider)) {
      if (structured) {
        // An OAuth token response holds `access_token`; a key or token the person
        // pasted for the same service holds `api_key` or `token`.
        const token = [fields.access_token, fields.api_key, fields.token]
          .find((value) => typeof value === 'string' && value !== '');
        if (token === undefined) throw new ConnectionNoAccessTokenError();
        return { Authorization: `Bearer ${token}` };
      }
      return { Authorization: `Bearer ${credential}` };
    }

    // Fallback: if it looks like a single token, use Bearer
    if (!structured) {
      return { Authorization: `Bearer ${credential}` };
    }

    // Multi-field credential without a template — try common patterns
    if (fields.api_key) {
      return { Authorization: `Bearer ${fields.api_key}` };
    }
    if (fields.access_token) {
      return { Authorization: `Bearer ${fields.access_token}` };
    }
    if (fields.token) {
      return { Authorization: `Bearer ${fields.token}` };
    }

    return {};
  }

  /**
   * Interpolate credential fields into the target URL.
   * Supports {{instance_url}}, {{host}}, {{app_id}} etc.
   */
  resolveTargetUrl(url: string, credential: string): string {
    // A bare token carries no host or instance fields, so the URL stays as given.
    const fields = parseCredentialObject<Record<string, string>>(credential);
    return fields ? interpolate(url, fields) : url;
  }

  /**
   * Complete every failure-prone check that can be proven before the durable
   * dispatch decision. The caller runs this before claiming the operation.
   */
  async validatePrepared(
    prepared: PreparedProxyDispatch,
    allowedHosts: readonly string[],
  ): Promise<ProxyResult | null> {
    if (prepared.bodyBytes !== null && Buffer.byteLength(prepared.bodyBytes, 'utf8') > PROXY_RESPONSE_MAX_BYTES) {
      return {
        status: 413,
        headers: {},
        body: { error: 'Request too large', max_bytes: PROXY_RESPONSE_MAX_BYTES },
      };
    }

    try {
      await assertPublicUrl(prepared.finalUrl, { allowedProtocols: ['https:'] });
    } catch (err) {
      const message = err instanceof UnsafeUrlError ? err.message : 'Invalid URL';
      return {
        status: 400,
        headers: {},
        body: { error: `Refusing to proxy: ${message}` },
      };
    }

    const destinationHost = (() => {
      try { return new URL(prepared.finalUrl).hostname; } catch { return ''; }
    })();
    if (!isHostAllowed(destinationHost, allowedHosts)) {
      return {
        status: 403,
        headers: {},
        body: {
          error:
            `Refusing to proxy: host ${destinationHost || '(unparseable)'} is not a declared ` +
            `destination for the ${prepared.service} connection. A credential may only be sent to ` +
            `the hosts that connection declares. ` +
            (allowedHosts.length === 0
              ? 'This connection has no declared hosts — set allowed_hosts on it before proxying.'
              : `Declared: ${allowedHosts.join(', ')}.`),
          code: 'DESTINATION_NOT_ALLOWED',
        },
      };
    }
    return null;
  }

  /**
   * Perform one transport attempt using the exact bytes admitted by the
   * operation ledger. Any failure after the durable dispatch claim is unknown,
   * never a safe invitation to repeat a generic write.
   */
  async forwardPrepared(
    prepared: PreparedProxyDispatch,
    authHeaders: Record<string, string>,
    allowedHosts: readonly string[],
    egress?: EgressSubject,
  ): Promise<ProxyTransportOutcome> {
    // Re-check the structural host binding at the last possible point. DNS is
    // pinned again by publicFetch, closing rebinding between validation/send.
    const destinationHost = (() => {
      try { return new URL(prepared.finalUrl).hostname; } catch { return ''; }
    })();
    if (!isHostAllowed(destinationHost, allowedHosts)) {
      return { kind: 'outcome_unknown', reason: 'transport_error' };
    }

    try {
      const signature = await this.egressHeaders(egress, prepared.method, prepared.finalUrl);
      const res = await publicFetch(prepared.finalUrl, {
        method: prepared.method,
        headers: { ...prepared.headers, ...authHeaders, ...signature },
        body: prepared.bodyBytes ?? undefined,
        redirect: 'manual',
      }, {
        timeoutMs: PROXY_REQUEST_TIMEOUT_MS,
        maxRequestBytes: PROXY_RESPONSE_MAX_BYTES,
        maxResponseBytes: PROXY_RESPONSE_MAX_BYTES,
        // reuse the TLS connection to this provider. Bound to the
        // address set publicFetch resolves and checks for THIS call.
        keepAlive: true,
      });

      if (res.status >= 300 && res.status < 400) {
        return {
          kind: 'response',
          response: {
            status: 502,
            headers: {},
            body: { error: 'Upstream returned a redirect; redirects are not followed by the proxy' },
          },
        };
      }

      const responseHeaders = pickSafeProxyResponseHeaders(res.headers);
      const text = await res.text();
      let body: unknown;
      try { body = JSON.parse(text); } catch { body = text; }
      return {
        kind: 'response',
        response: { status: res.status, headers: responseHeaders, body },
      };
    } catch (err) {
      if (err instanceof PublicFetchLimitError && err.direction === 'response') {
        return { kind: 'outcome_unknown', reason: 'response_too_large' };
      }
      const message = err instanceof Error ? err.message : '';
      if ((err instanceof Error && err.name === 'AbortError') || message.toLowerCase().includes('timeout')) {
        return { kind: 'outcome_unknown', reason: 'timeout' };
      }
      if (message.toLowerCase().includes('socket') || message.toLowerCase().includes('connection')) {
        return { kind: 'outcome_unknown', reason: 'connection_lost' };
      }
      return { kind: 'outcome_unknown', reason: 'transport_error' };
    }
  }

  /**
   * One call to a connected service's MCP endpoint, sent the way an MCP client sends it over Streamable HTTP: `initialize`,
   * then `notifications/initialized`, then the admitted call with the session the service gave (if any) and the version it
   * answered, then the session ended. Every request goes through `forwardPrepared`, so each carries the credential, the
   * host binding and the signature exactly as the call does; only the call itself is the operation the ledger admitted.
   * When the opening fails the call was never sent, so the outcome is known: the service's refusal, answered 502
   * `SERVICE_MCP_SESSION_FAILED`, never `outcome_unknown`.
   */
  async forwardMcpPrepared(
    prepared: PreparedProxyDispatch,
    authHeaders: Record<string, string>,
    allowedHosts: readonly string[],
    egress?: EgressSubject,
  ): Promise<ProxyTransportOutcome> {
    const base = { 'content-type': 'application/json', accept: SERVICE_MCP_ACCEPT };
    const send = (method: PreparedProxyDispatch['method'], body: string | null, headers: Record<string, string>) =>
      this.forwardPrepared({ ...prepared, method, headers: { ...base, ...headers }, bodyBytes: body }, authHeaders, allowedHosts, egress);
    const failed = (reason: string): ProxyTransportOutcome => ({
      kind: 'response',
      response: {
        status: 502,
        headers: {},
        body: { error: `${prepared.service} did not open an MCP session, so the call was not sent: ${reason}`, code: 'SERVICE_MCP_SESSION_FAILED' },
      },
    });

    const opened = await send('POST', JSON.stringify(serviceMcpInitializeBody()), {});
    if (opened.kind !== 'response') return failed(`no answer to initialize (${opened.reason})`);
    const answer = readServiceMcpAnswer(prepared.service, opened.response);
    if (!answer.ok) return failed(answer.message);
    const sessionId = opened.response.headers['mcp-session-id'];
    if (sessionId !== undefined && !isServiceMcpSessionId(sessionId)) return failed('it gave a session id that is not visible ASCII');
    const version = typeof answer.result['protocolVersion'] === 'string' && /^[\x21-\x7E]{1,64}$/.test(answer.result['protocolVersion'])
      ? answer.result['protocolVersion']
      : SERVICE_MCP_PROTOCOL_VERSION;
    const session: Record<string, string> = { 'mcp-protocol-version': version, ...(sessionId ? { 'mcp-session-id': sessionId } : {}) };

    const ready = await send('POST', JSON.stringify(SERVICE_MCP_INITIALIZED_BODY), session);
    if (ready.kind !== 'response') return failed(`no answer to notifications/initialized (${ready.reason})`);
    if (ready.response.status < 200 || ready.response.status >= 300) return failed(`it answered notifications/initialized with ${ready.response.status}`);

    const outcome = await this.forwardPrepared(
      { ...prepared, headers: { ...prepared.headers, accept: SERVICE_MCP_ACCEPT, ...session } },
      authHeaders,
      allowedHosts,
      egress,
    );
    // Ending the session is a courtesy the call's outcome never waits on; a service that keeps none answers 405 and is left alone.
    if (sessionId) void send('DELETE', null, session).catch(() => undefined);
    return outcome;
  }

  /**
   * Forward the request to the external service.
   *
   * `allowedHosts` binds the injected credential to its connection: the
   * request is only sent if the final host is one the operator declared for
   * that connection. This is a REQUIRED argument rather than an optional one
   * on purpose — a future caller must not be able to reach `fetch` with a
   * decrypted credential by forgetting a parameter. Pass an explicitly empty
   * array only if you intend every destination to be refused.
   *
   * The check runs on `finalUrl`, after query merging and after
   * `resolveTargetUrl` has interpolated any `{{instance_url}}` placeholder,
   * because that is the string actually handed to `fetch`.
   */
  async forward(
    input: ProxyRequestInput,
    authHeaders: Record<string, string>,
    resolvedUrl: string,
    allowedHosts: readonly string[],
    egress?: EgressSubject,
  ): Promise<ProxyResult> {
    // Build final URL with query params
    let finalUrl = resolvedUrl;
    if (input.query && Object.keys(input.query).length > 0) {
      const url = new URL(finalUrl);
      for (const [key, value] of Object.entries(input.query)) {
        url.searchParams.set(key, value);
      }
      finalUrl = url.toString();
    }

    // Merge headers: auth headers take precedence, strip agent-provided auth
    const headers: Record<string, string> = {
      ...stripAuthHeaders(input.headers ?? {}),
      ...authHeaders,
    };

    // Set content-type for request bodies
    if (input.body !== undefined && !headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json';
    }

    // Resolve and check the destination ONCE; the same checked addresses are
    // the ones the socket is pinned to below (publicFetch re-validates them
    // without a second DNS query). This used to resolve twice per call.
    let resolvedAddresses: string[];
    try {
      resolvedAddresses = (await resolvePublicUrl(finalUrl, { allowedProtocols: ['https:'] }))
        .addresses.map(({ address }) => address);
    } catch (err) {
      const message = err instanceof UnsafeUrlError ? err.message : 'Invalid URL';
      return {
        status: 400,
        headers: {},
        body: { error: `Refusing to proxy: ${message}` },
      };
    }

    // Credential-to-destination binding. `resolvePublicUrl` above is an SSRF
    // guard — it blocks private ranges and metadata IPs, and an attacker's
    // server is a perfectly public address. This is the check that stops the
    // injected credential going somewhere it does not belong.
    //
    // Runs AFTER the SSRF guard so an unparseable URL is already handled, and
    // BEFORE `fetch` so no credential leaves on a refusal.
    const destinationHost = (() => {
      try {
        return new URL(finalUrl).hostname;
      } catch {
        return '';
      }
    })();
    if (!isHostAllowed(destinationHost, allowedHosts)) {
      return {
        status: 403,
        headers: {},
        body: {
          error:
            `Refusing to proxy: host ${destinationHost || '(unparseable)'} is not a declared ` +
            `destination for the ${input.service} connection. A credential may only be sent to ` +
            `the hosts that connection declares. ` +
            (allowedHosts.length === 0
              ? `This connection has no declared hosts — set allowed_hosts on it before proxying.`
              : `Declared: ${allowedHosts.join(', ')}.`),
          code: 'DESTINATION_NOT_ALLOWED',
        },
      };
    }

    // Signed last, from the URL as it will be requested, so what the site checks is what it receives.
    Object.assign(headers, await this.egressHeaders(egress, input.method, finalUrl));

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROXY_REQUEST_TIMEOUT_MS);

    try {
      const res = await publicFetch(finalUrl, {
        method: input.method,
        headers,
        // 244 Finding 5: `body` may arrive as a native object OR as
        // an already-serialized JSON string (some MCP arg-encoding paths
        // pre-stringify nested JSON). Stringify an object once; pass a
        // string through untouched. Mirrors the guard the audit path already
        // uses at apps/api/src/routes/proxy.ts:662-667. Without this, a
        // string body gets double-encoded ("{\"model\":...}") and the
        // upstream rejects it with "JSON parsing failed".
        body:
          input.body === undefined
            ? undefined
            : typeof input.body === 'string'
              ? input.body
              : JSON.stringify(input.body),
        signal: controller.signal,
        redirect: 'manual',
      }, {
        timeoutMs: PROXY_REQUEST_TIMEOUT_MS,
        maxResponseBytes: PROXY_RESPONSE_MAX_BYTES,
        resolvedAddresses,
        // reuse the TLS connection to this provider, pinned to the
        // address set checked above.
        keepAlive: true,
      });

      if (res.status >= 300 && res.status < 400) {
        return {
          status: 502,
          headers: {},
          body: { error: 'Upstream returned a redirect; redirects are not followed by the proxy' },
        };
      }

      // Read response with size limit
      const contentLength = res.headers.get('content-length');
      if (contentLength && parseInt(contentLength, 10) > PROXY_RESPONSE_MAX_BYTES) {
        return {
          status: 502,
          headers: {},
          body: { error: 'Response too large', max_bytes: PROXY_RESPONSE_MAX_BYTES },
        };
      }

      const responseHeaders: Record<string, string> = {};
      stripHopByHopHeaders(res.headers).forEach((value, key) => {
        // Forward safe response headers
        if (!key.startsWith('set-cookie') && key !== 'transfer-encoding') {
          responseHeaders[key] = value;
        }
      });

      // Try to parse as JSON, fall back to text
      const text = await res.text();
      if (Buffer.byteLength(text, 'utf8') > PROXY_RESPONSE_MAX_BYTES) {
        return {
          status: 502,
          headers: {},
          body: { error: 'Response too large', max_bytes: PROXY_RESPONSE_MAX_BYTES },
        };
      }

      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }

      return { status: res.status, headers: responseHeaders, body };
    } catch (err) {
      if (err instanceof PublicFetchLimitError) {
        if (err.direction === 'request') {
          return { status: 413, headers: {}, body: { error: 'Request too large', max_bytes: err.limitBytes } };
        }
        return { status: 502, headers: {}, body: { error: 'Response too large', max_bytes: PROXY_RESPONSE_MAX_BYTES } };
      }
      const message = err instanceof Error ? err.message : 'Unknown error';
      if (controller.signal.aborted || (err instanceof Error && err.name === 'AbortError') || message.includes('abort')) {
        return {
          status: 504,
          headers: {},
          body: { error: 'Request timed out', timeout_ms: PROXY_REQUEST_TIMEOUT_MS },
        };
      }
      return {
        status: 502,
        headers: {},
        // Header/URL validation errors can contain injected credential values.
        body: { error: 'Upstream request failed' },
      };
    } finally { clearTimeout(timeout); }
  }
}

/** Strip auth-related headers from agent-provided headers to prevent override */
function stripAuthHeaders(headers: Record<string, string>): Record<string, string> {
  const stripped: Record<string, string> = {};
  for (const [key, value] of stripHopByHopHeaders(headers)) {
    const lower = key.toLowerCase();
    if (lower === 'authorization' || lower === 'x-api-key' || lower === 'api-key') {
      continue; // Strip auth headers — proxy injects the real ones
    }
    stripped[key] = value;
  }
  return stripped;
}
