// Helpers for the reference tests.

import { existsSync, mkdirSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** Listen on an ephemeral port on the loopback address and return the server and its base URL. */
export async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { server, url: `http://127.0.0.1:${port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

/**
 * The example control server imports `@getstackrun/sdk` as any user's copy of it
 * would after `npm install`. In a checkout that install has not happened, so
 * link the package from this workspace the way an install would, then import
 * the example. The link is under a node_modules directory, which is ignored.
 */
export async function importExampleServer() {
  const dir = join(REPO, 'examples', 'control-socket');
  const link = join(dir, 'node_modules', '@getstackrun', 'sdk');
  if (!existsSync(link)) {
    mkdirSync(dirname(link), { recursive: true });
    symlinkSync(join(REPO, 'packages', 'sdk'), link, 'junction');
  }
  return import(pathToFileURL(join(dir, 'server.mjs')).href);
}

/** A JWKS served over HTTP, for verifiers that fetch their keys. */
export async function serveJson(body) {
  const path = `/jwks/${Math.random().toString(36).slice(2)}.json`;
  const server = createServer((req, res) => {
    if (req.url === path) return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    return res.writeHead(404).end();
  });
  const { url, close } = await listen(server);
  return { url: `${url}${path}`, close };
}
