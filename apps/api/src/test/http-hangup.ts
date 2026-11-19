import http from 'node:http';
import type { FastifyInstance } from 'fastify';

/**
 * A real listening Fastify server and real clients, for proving what happens
 * when a client hangs up: `app.inject` has no socket to destroy, so it can
 * never show an aborted request.
 *
 * Most of what a client hangs up on is a POST with a JSON body (every model
 * call is), and Fastify tells a request whose body was read from one that was
 * not: pass `method` and `body` to make the request the way a real client does.
 */
export const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface HangupRequestOptions {
  method?: 'GET' | 'POST';
  /** Sent as JSON; the whole body is written before the client waits. */
  body?: unknown;
  headers?: Record<string, string>;
}

export async function listen(app: FastifyInstance) {
  await app.listen({ port: 0, host: '127.0.0.1' });
  const port = (app.server.address() as { port: number }).port;

  const open = (path: string, options: HangupRequestOptions) => {
    const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
    const request = http.request({
      host: '127.0.0.1',
      port,
      path,
      method: options.method ?? 'GET',
      headers: {
        ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }),
        ...options.headers,
      },
    });
    request.end(payload);
    return request;
  };

  /** A client that waits for the whole answer and returns its status. */
  const call = (path: string, options: HangupRequestOptions = {}) => new Promise<number>((resolve, reject) => {
    const request = open(path, options);
    request.on('response', (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    });
    request.on('error', reject);
  });

  /** A client that opens a request and destroys its socket after `afterMs`, with the answer unfinished. */
  const hangUp = async (path: string, afterMs = 100, options: HangupRequestOptions = {}) => {
    const request = open(path, options);
    request.on('error', () => undefined);
    request.on('response', (res) => { res.on('data', () => undefined); res.on('error', () => undefined); });
    await pause(afterMs);
    request.destroy();
    await pause(100);
  };

  return { call, hangUp };
}
