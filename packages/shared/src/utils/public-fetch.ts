import { Agent as HttpAgent, request as httpRequest, type ClientRequest, type IncomingMessage } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest, type RequestOptions } from 'node:https';
import { isIP, type Socket } from 'node:net';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';
import { isBlockedIp, parsePublicUrl, resolvePublicUrl, UnsafeUrlError } from './url-guard.js';

export interface PublicFetchOptions {
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRequestBytes?: number;
  allowedProtocols?: string[];
  /** Trusted internal callers may reuse an already validated DNS result. */
  resolvedAddresses?: readonly string[];
  /**
   * Reuse the connection for later calls to the same destination.
   * Off by default. A connection is reused only by a call to the same
   * protocol, host, port and TLS server name whose (re)checked address set is
   * exactly the set that connection was opened for, so DNS rebinding can never
   * hand an old socket to a newly blocked or different address. Any failure,
   * cap, timeout, abort, redirect refusal or upgrade destroys the socket
   * instead of returning it to the pool.
   */
  keepAlive?: boolean;
}

/** Idle pooled connections close after this long. */
const POOL_IDLE_MS = 15_000;
/** Bounds on the pool itself, so it cannot grow without limit. */
const POOL_MAX_DESTINATIONS = 256;
const POOL_MAX_SOCKETS_PER_DESTINATION = 32;
const POOL_MAX_FREE_SOCKETS_PER_DESTINATION = 8;

const connectionPools = new Map<string, HttpAgent>();

/**
 * The keep-alive agent for one destination. The key carries everything a
 * reused socket is bound to: protocol, host, port, TLS server name and the
 * sorted pinned address set. Least recently used destinations are evicted
 * (and their sockets destroyed) beyond POOL_MAX_DESTINATIONS.
 */
function pooledAgent(url: URL, servername: string | undefined, addresses: readonly { address: string }[]): HttpAgent {
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  const pinned = [...new Set(addresses.map(({ address }) => address))].sort().join(',');
  const key = `${url.protocol}//${url.hostname}:${port}|sni=${servername ?? ''}|${pinned}`;
  const existing = connectionPools.get(key);
  if (existing) {
    connectionPools.delete(key);
    connectionPools.set(key, existing);
    return existing;
  }
  const options = {
    keepAlive: true,
    maxSockets: POOL_MAX_SOCKETS_PER_DESTINATION,
    maxFreeSockets: POOL_MAX_FREE_SOCKETS_PER_DESTINATION,
    // Applies to idle pooled sockets: the agent destroys one that times out.
    // In-flight requests are bounded by the call's own deadline.
    timeout: POOL_IDLE_MS,
    scheduling: 'lifo' as const,
  };
  const agent = url.protocol === 'https:' ? new HttpsAgent(options) : new HttpAgent(options);
  connectionPools.set(key, agent);
  if (connectionPools.size > POOL_MAX_DESTINATIONS) {
    const [oldestKey, oldest] = connectionPools.entries().next().value as [string, HttpAgent];
    connectionPools.delete(oldestKey);
    oldest.destroy();
  }
  return agent;
}

/**
 * A failed exchange never leaves its connection for reuse. While the socket is
 * still bound to the exchange, destroying the request above already destroyed
 * it; this covers the one case where the agent took it back first (a complete
 * response whose decoded body then failed a check): destroyed while it is
 * idle in the pool. If another call already picked it up it is left alone; the
 * agent only reuses a socket after a fully received response, so it is in a
 * clean protocol state, bound to the same checked address set.
 */
function discardPooledSocket(pool: HttpAgent | undefined, socket: Socket | undefined, freed: boolean): void {
  if (!pool || !socket || socket.destroyed) return;
  if (!freed) { socket.destroy(); return; }
  const idle = Object.values(pool.freeSockets).some((sockets) => sockets?.includes(socket));
  if (idle) socket.destroy();
}

/** Close every pooled connection. For shutdown and tests. */
export function closePublicFetchPools(): void {
  for (const agent of connectionPools.values()) agent.destroy();
  connectionPools.clear();
}

export class PublicFetchLimitError extends Error {
  constructor(
    message: string,
    readonly direction: 'request' | 'response' = 'response',
    readonly limitBytes?: number,
  ) { super(message); this.name = 'PublicFetchLimitError'; }
}

/** Sent when the caller sets none. fetch() always sends one, and some APIs
 * (GitHub among them) answer 403 to a request without it. */
export const PUBLIC_FETCH_USER_AGENT = 'STACK (+https://getstack.run)';

const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade'];

/** Remove connection-specific headers, including names nominated by Connection. */
export function stripHopByHopHeaders(input: ConstructorParameters<typeof Headers>[0]): Headers {
  const headers = new Headers(input);
  const nominated = (headers.get('connection') ?? '').split(',').map((name) => name.trim().toLowerCase());
  for (const name of [...HOP_BY_HOP, ...nominated]) if (name) headers.delete(name);
  return headers;
}

function aborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    const stop = () => reject(signal.reason);
    signal.addEventListener('abort', stop, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener('abort', stop));
  });
}

/**
 * One bounded HTTP(S) exchange. DNS is checked once and supplied to the socket's
 * lookup callback; TLS still verifies the URL hostname. No redirects, proxy
 * environment, or cookies are used, and no connection is shared unless the
 * caller opts in with `keepAlive` (see that option for how reuse is bound). The
 * promise resolves only after the body has passed byte and total-duration
 * limits.
 */
export async function publicFetch(
  input: string | URL | Request,
  init: RequestInit = {},
  options: PublicFetchOptions = {},
): Promise<Response> {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024;
  const maxRequestBytes = options.maxRequestBytes ?? 10 * 1024 * 1024;
  for (const value of [timeoutMs, maxResponseBytes, maxRequestBytes]) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error('Invalid outbound request limit');
  }
  const original = new Request(input, init);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new DOMException('Outbound request timed out', 'AbortError')), timeoutMs);
  const signal = AbortSignal.any([original.signal, controller.signal]);
  let request: ClientRequest | undefined;
  let incoming: IncomingMessage | undefined;
  // Pooled connections only: the socket this exchange used, and whether the
  // agent already took it back (it does so as soon as the response is fully
  // received, which can be before a decoded-size check fails).
  let pool: HttpAgent | undefined;
  let pooledSocket: Socket | undefined;
  let socketFreed = false;
  try {
    signal.throwIfAborted();
    const allowedProtocols = options.allowedProtocols ?? ['https:'];
    const url = parsePublicUrl(original.url, { allowedProtocols });
    const addresses = options.resolvedAddresses
      ? options.resolvedAddresses.map((address) => ({ address, family: isIP(address) }))
      : (await aborted(resolvePublicUrl(url.href, { allowedProtocols }), signal)).addresses;
    if (!addresses.length || addresses.some(({ address }) => isBlockedIp(address))) {
      throw new UnsafeUrlError('Destination resolves to a non-public address');
    }
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (isIP(hostname) && addresses.some(({ address }) => address !== hostname)) {
      throw new UnsafeUrlError('Pinned address does not match the URL');
    }
    const headers = stripHopByHopHeaders(original.headers);
    headers.delete('host');
    headers.delete('content-length');
    // Decode these ourselves under the decoded-byte limit as well as a wire cap.
    headers.set('accept-encoding', 'gzip, deflate, br');
    if (!headers.has('user-agent')) headers.set('user-agent', PUBLIC_FETCH_USER_AGENT);
    const chunks: Uint8Array[] = [];
    let sent = 0;
    if (original.body) {
      const reader = original.body.getReader();
      try {
        while (true) {
          const { value, done } = await aborted(reader.read(), signal);
          if (done) break;
          sent += value.byteLength;
          if (sent > maxRequestBytes) throw new PublicFetchLimitError('Request body exceeds the size limit', 'request', maxRequestBytes);
          chunks.push(value);
        }
      } finally { void reader.cancel().catch(() => {}); reader.releaseLock(); }
      headers.set('content-length', String(sent));
    }
    signal.throwIfAborted();
    const servername = url.protocol === 'https:' && !isIP(hostname) ? hostname : undefined;
    return await new Promise<Response>((resolve, reject) => {
      const requestOptions: RequestOptions = {
        method: original.method,
        headers: Object.fromEntries(headers),
        agent: options.keepAlive ? (pool = pooledAgent(url, servername, addresses)) : false,
        signal,
        ...(servername ? { servername } : {}),
        lookup: (_hostname, lookupOptions, callback) => {
          if (lookupOptions.all) callback(null, addresses);
          else callback(null, addresses[0]!.address, addresses[0]!.family);
        },
      };
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, requestOptions, (response) => {
        incoming = response;
        void (async () => {
          const status = response.statusCode ?? 0;
          if (status >= 300 && status < 400 && original.redirect !== 'manual') {
            throw new UnsafeUrlError('Outbound redirects are not allowed');
          }
          const noBody = original.method === 'HEAD' || status === 204 || status === 205 || status === 304;
          const declared = Number(response.headers['content-length']);
          // HEAD and 304 may describe the selected representation, not a body
          // on this exchange. Actual received bytes remain bounded below.
          if (!noBody && declared > maxResponseBytes) throw new PublicFetchLimitError('Response body exceeds the size limit', 'response', maxResponseBytes);
          let wireBytes = 0;
          response.on('data', (chunk: Buffer) => {
            wireBytes += chunk.length;
            if (wireBytes > maxResponseBytes) response.destroy(new PublicFetchLimitError('Response body exceeds the size limit', 'response', maxResponseBytes));
          });
          const encoding = noBody ? undefined : response.headers['content-encoding']?.toLowerCase();
          const decoder = encoding === 'gzip' ? createGunzip() : encoding === 'deflate' ? createInflate()
            : encoding === 'br' ? createBrotliDecompress() : undefined;
          if (encoding && encoding !== 'identity' && !decoder) throw new Error('Unsupported response encoding');
          if (decoder) response.on('error', (error) => decoder.destroy(error));
          const stream = decoder ? response.pipe(decoder) : response;
          const body: Buffer[] = [];
          let received = 0;
          try {
            for await (const chunk of stream) {
              const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              received += buffer.length;
              if (received > maxResponseBytes) throw new PublicFetchLimitError('Response body exceeds the size limit', 'response', maxResponseBytes);
              body.push(buffer);
            }
          } finally { if (decoder) decoder.destroy(); }
          if (!response.complete) throw new Error('Incomplete outbound response');
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) for (const item of value) responseHeaders.append(key, item);
            else if (value !== undefined) responseHeaders.set(key, value);
          }
          const safeHeaders = stripHopByHopHeaders(responseHeaders);
          safeHeaders.delete('content-encoding');
          safeHeaders.delete('content-length');
          resolve(new Response(noBody ? null : Buffer.concat(body), { status, headers: safeHeaders }));
        })().catch((error: unknown) => {
          response.destroy();
          request?.destroy();
          reject(error);
        });
      });
      if (pool) {
        request.on('socket', (socket) => {
          pooledSocket = socket;
          socket.once('free', () => { socketFreed = true; });
        });
      }
      request.on('error', reject);
      request.on('upgrade', (_response, socket) => { socket.destroy(); reject(new Error('Outbound protocol upgrades are not allowed')); });
      request.end(chunks.length ? Buffer.concat(chunks) : undefined);
    });
  } catch (error) {
    incoming?.destroy();
    request?.destroy();
    discardPooledSocket(pool, pooledSocket, socketFreed);
    if (signal.aborted) throw signal.reason;
    throw error;
  } finally { clearTimeout(timeout); }
}
