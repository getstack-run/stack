import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';

/**
 * A request is sent with `fetch` unless its tool may run longer than this: `fetch` gives up on a response whose headers
 * have not come after 5 minutes, whatever the caller's own deadline says.
 */
export const FETCH_WAIT_CEILING_MS = 240_000;

const NO_BODY_STATUSES = new Set([101, 204, 205, 304]);

/**
 * One request over `node:http` or `node:https` with no wait of its own, for a tool whose call may run longer than
 * `fetch` waits. It ends when the response is read or when `signal` fires, and answers as a `Response`, like `fetch`.
 */
export function longRequest(
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal },
): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    const target = new URL(url);
    const send = target.protocol === 'https:' ? httpsRequest : httpRequest;
    const headers: Record<string, string> = { ...init.headers };
    if (init.body !== undefined) headers['Content-Length'] = String(Buffer.byteLength(init.body));
    const req = send(
      target,
      { method: init.method, headers, ...(init.signal ? { signal: init.signal } : {}) },
      (res) => {
        const responseHeaders = new Headers();
        for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) responseHeaders.append(res.rawHeaders[i]!, res.rawHeaders[i + 1]!);
        const status = res.statusCode ?? 502;
        if (NO_BODY_STATUSES.has(status)) {
          res.resume();
          resolve(new Response(null, { status, headers: responseHeaders }));
          return;
        }
        resolve(new Response(Readable.toWeb(res) as ReadableStream<Uint8Array>, {
          status,
          ...(res.statusMessage ? { statusText: res.statusMessage } : {}),
          headers: responseHeaders,
        }));
      },
    );
    req.on('error', reject);
    req.end(init.body);
  });
}
