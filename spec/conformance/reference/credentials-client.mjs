// The reference client of the credentials files: the TypeScript SDK. It writes and reads `~/.stack` with the code every
// SDK user runs. The sign-in is written and read with the SDK's own file helpers; an agent key is generated and stored
// by the SDK's own enrolment (`createAgentTokenProvider`), against a small stand-in for the two enrolment routes of the
// API, so what the suite judges is what a real enrolment leaves.
//
// Run from a checkout of this repository after `pnpm --filter @getstackrun/sdk build`.

import { createServer } from 'node:http';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { REPO } from './support.mjs';

const dist = (file) => pathToFileURL(join(REPO, 'packages', 'sdk', 'dist', file)).href;

/** Run `work` with the home directory of this process pointing at `home`. */
let queue = Promise.resolve();
function inHome(home, work) {
  const run = async () => {
    const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    try {
      return await work();
    } finally {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  };
  const result = queue.then(run, run);
  queue = result.catch(() => undefined);
  return result;
}

/** The two routes an enrolment calls, in the shape the API answers them. */
async function enrolmentApi() {
  const server = createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      response.setHeader('content-type', 'application/json');
      if (/\/enrollment-challenge$/.test(request.url)) return response.end(JSON.stringify({ challenge_id: 'chal_1', challenge: 'a challenge to sign' }));
      if (/\/enroll$/.test(request.url)) return response.end(JSON.stringify({ enrolled_at: new Date().toISOString() }));
      response.statusCode = 404;
      return response.end('{}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

/** A client of the files: `{ write, writeAgentKey, read, close }`, for `runCredentialsFilesSuite`. */
export async function createReferenceClient() {
  const { readCredentialsFile, writeCredentialsFile } = await import(dist('credentials-file.js'));
  const { createAgentTokenProvider } = await import(dist('agent-auth.js'));
  const api = await enrolmentApi();
  return {
    write: ({ home, credentials }) => inHome(home, () => writeCredentialsFile(credentials)),
    writeAgentKey: ({ home, agentId }) =>
      inHome(home, async () => {
        const token = await createAgentTokenProvider({ agentId, baseUrl: api.url, bearerProvider: async () => 'an-operator-credential' })();
        if (typeof token !== 'string') throw new Error('no token was minted');
      }),
    read: ({ home }) => inHome(home, () => readCredentialsFile()),
    close: () => api.close(),
  };
}
