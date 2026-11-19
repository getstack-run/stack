// SDK first-run bootstrap (Authorization Code + PKCE with
// localhost callback).
//
// When `new Stack()` is instantiated and there's no apiKey, no
// STACK_API_KEY env, AND no ~/.stack/credentials.json — instead of
// throwing NOT_AUTHENTICATED, the SDK can spawn the user's browser
// and run the full OAuth dance itself. End state: credentials.json
// is written, the access token is returned, the SDK is usable.
//
// Triggered ONLY when:
//   1. The current process has a TTY (developer at a terminal); AND
//   2. STACK_AUTH_INTERACTIVE is not 'false' (explicit opt-out for
//      headless dev environments that look like a TTY).
//
// In production agent runtimes (Lambda, Vercel, K8s, etc.) there's
// no TTY — the SDK falls through to the existing NOT_AUTHENTICATED
// error and the operator must set STACK_API_KEY (or use agent_id
// mode with credentials seeded another way). The browser-spawn path
// is strictly a developer convenience.

import type { StoredCredentials } from './credentials-file.js';
import { writeCredentialsFile, credentialsFilePath } from './credentials-file.js';

const DEFAULT_AUTH_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes — matches the auth-code TTL

// The interactive bootstrap defaults to the SDK's core agent-runtime surface,
// not the SDK's entire method inventory. Account administration, raw
// credentials, billing, team/security policy and marketplace publishing stay
// explicit opt-ins through ClientOptions.oauthScope. Kept local because the
// published SDK deliberately has no @stack/shared runtime dependency.
export const SDK_DEFAULT_OAUTH_SCOPES = [
  'account:read',
  'passports:read', 'passports:write',
  'agents:read', 'agents:write',
  'services:read',
  'proxy:read', 'proxy:write',
  'audit:read',
] as const;
export const SDK_DEFAULT_OAUTH_SCOPE = SDK_DEFAULT_OAUTH_SCOPES.join(' ');

export function normalizeInteractiveOAuthScope(scope: string): string {
  const tokens = [...new Set(scope.split(/\s+/).filter(Boolean))];
  if (tokens.length === 0) {
    throw new Error('STACK SDK: oauthScope must contain at least one OAuth scope.');
  }
  return tokens.join(' ');
}

export interface BootstrapResult {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  client_id: string;
}

/**
 * Decide whether to spawn the browser. Conservative — opt-in by
 * environment, not opt-out.
 */
export function shouldRunBrowserBootstrap(): boolean {
  if (typeof process === 'undefined') return false;
  if (!process.stdout?.isTTY) return false;
  if (process.env['STACK_AUTH_INTERACTIVE'] === 'false') return false;
  if (process.env['CI']) return false; // belt-and-braces — no spawn in CI
  return true;
}

/**
 * Run the full OAuth Authorization-Code + PKCE flow: DCR a client,
 * mint a PKCE pair, spawn a localhost server, open the browser, wait
 * for the callback, exchange the code for tokens, persist + return.
 */
export async function browserBootstrap(
  baseUrl: string,
  scope = SDK_DEFAULT_OAUTH_SCOPE,
): Promise<BootstrapResult> {
  const { createHash, randomBytes } = await import('node:crypto');
  const url = baseUrl.replace(/\/$/, '');
  const requestedScope = normalizeInteractiveOAuthScope(scope);

  // 1. DCR a public PKCE client. One per machine — keeps the per-client
  //    audit trail clean and avoids a shared client_id across the SDK
  //    user base.
  const dcr = await fetch(`${url}/oauth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: hostFingerprint(),
      redirect_uris: [`http://127.0.0.1`], // placeholder; the real one is added per-flow with the chosen port
      grant_types: ['authorization_code', 'refresh_token'],
      software_id: 'getstackrun.sdk-ts.bootstrap',
      scope: requestedScope,
    }),
  });
  if (!dcr.ok) {
    throw new Error(`STACK SDK: client registration failed (${dcr.status}). Try running \`npx @getstackrun/cli auth login\`.`);
  }
  const { client_id } = (await dcr.json()) as { client_id: string };

  // 2. PKCE pair.
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(16).toString('base64url');

  // 3. Spawn the localhost callback server FIRST (so we can claim the port
  //    before the browser opens), then open the browser to /oauth/authorize.
  const { server, port, codePromise } = await spawnCallbackServer(state);

  // 4. Re-register the client with the actual loopback URI now that we
  //    know the port. (DCR is open, the second register supersedes the
  //    first for redirect_uri matching.)
  const reRegister = await fetch(`${url}/oauth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: hostFingerprint(),
      redirect_uris: [`http://127.0.0.1:${port}/callback`],
      grant_types: ['authorization_code', 'refresh_token'],
      software_id: 'getstackrun.sdk-ts.bootstrap',
      scope: requestedScope,
    }),
  });
  if (!reRegister.ok) {
    server.close();
    throw new Error(`STACK SDK: client re-registration with loopback URI failed (${reRegister.status}).`);
  }
  const { client_id: scopedClientId } = (await reRegister.json()) as { client_id: string };

  const authorizeUrl = `${url}/oauth/authorize?` + new URLSearchParams({
    response_type: 'code',
    client_id: scopedClientId,
    redirect_uri: `http://127.0.0.1:${port}/callback`,
    scope: requestedScope,
    resource: 'https://api.getstack.run',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  }).toString();

  process.stderr.write(`\n  STACK SDK first-run sign-in\n`);
  process.stderr.write(`  ──────────────────────────\n\n`);
  process.stderr.write(`  Opening your browser to approve.\n`);
  process.stderr.write(`  If it doesn't open, paste this URL:\n\n  ${authorizeUrl}\n\n`);

  await openBrowser(authorizeUrl);

  // 5. Wait for the callback to deliver the code.
  let code: string;
  try {
    code = await codePromise;
  } catch (err) {
    server.close();
    throw err;
  }
  server.close();

  // 6. Exchange the code for tokens.
  const tok = await fetch(`${url}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: `http://127.0.0.1:${port}/callback`,
      client_id: scopedClientId,
      code_verifier: verifier,
    }),
  });
  if (!tok.ok) {
    const data = await tok.json().catch(() => ({}));
    throw new Error(`STACK SDK: token exchange failed (${tok.status}) ${JSON.stringify(data)}`);
  }
  const { access_token, refresh_token, expires_in, scope: grantedScope } = (await tok.json()) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    scope?: string;
  };

  // 7. Persist for subsequent runs. Same file the CLI writes.
  const stored: StoredCredentials = {
    client_id: scopedClientId,
    refresh_token,
    issued_at: Math.floor(Date.now() / 1000),
    refresh_expires_at: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
    scope: grantedScope ?? requestedScope,
  };
  await writeCredentialsFile(stored);
  process.stderr.write(`  Signed in. Credentials saved to ${await credentialsFilePath()}\n\n`);

  void client_id; // keep linter happy — initial DCR is superseded
  return { access_token, refresh_token, expires_in, client_id: scopedClientId };
}

// ─── Helpers ──────────────────────────────────────────────────────────

function hostFingerprint(): string {
  // Best-effort label so the operator can recognize the client in their
  // dashboard (when we ship the per-client list view). Falls through to
  // a generic name in environments where os.hostname is locked down.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const os = require('node:os');
    const host = (os.hostname?.() as string | undefined) ?? 'sdk-host';
    return `STACK SDK on ${host.slice(0, 40)}`;
  } catch {
    return 'STACK SDK';
  }
}

async function openBrowser(url: string): Promise<void> {
  const { spawn } = await import('node:child_process');
  try {
    if (process.platform === 'darwin') {
      spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    } else if (process.platform === 'win32') {
      spawn('cmd', ['/c', 'start', '', url], { stdio: 'ignore', detached: true }).unref();
    } else {
      spawn('xdg-open', [url], { stdio: 'ignore', detached: true }).unref();
    }
  } catch {
    /* best-effort — the URL is also printed */
  }
}

interface CallbackHarness {
  server: import('node:http').Server;
  port: number;
  codePromise: Promise<string>;
}

async function spawnCallbackServer(expectedState: string): Promise<CallbackHarness> {
  const { createServer } = await import('node:http');
  return new Promise<CallbackHarness>((resolve, reject) => {
    const server = createServer((req, res) => {
      try {
        const parsed = new URL(req.url ?? '/', 'http://127.0.0.1');
        if (parsed.pathname !== '/callback') {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not found');
          return;
        }
        const code = parsed.searchParams.get('code');
        const state = parsed.searchParams.get('state');
        const error = parsed.searchParams.get('error');
        if (error) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`<html><body style="font-family:system-ui;padding:40px"><h1>Sign-in failed</h1><p>${escape(error)}</p><p>You can close this tab.</p></body></html>`);
          rejectCb(new Error(`OAuth authorize returned error: ${error}`));
          return;
        }
        if (!code || state !== expectedState) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`<html><body style="font-family:system-ui;padding:40px"><h1>Invalid callback</h1><p>State mismatch or missing code.</p></body></html>`);
          rejectCb(new Error('Invalid callback: state mismatch or missing code'));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body style="font-family:system-ui;padding:40px;text-align:center"><h1>Signed in</h1><p>You can close this tab and return to your terminal.</p></body></html>`);
        resolveCb(code);
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal error');
        rejectCb(err as Error);
      }
    });

    let resolveCb: (code: string) => void;
    let rejectCb: (err: Error) => void;
    const codePromise = new Promise<string>((res, rej) => {
      resolveCb = res;
      rejectCb = rej;
    });

    // Bind to a random free port.
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (typeof addr === 'object' && addr && typeof addr.port === 'number') {
        // Auth-code + browser flow gets DEFAULT_AUTH_TIMEOUT_MS to complete.
        const timer = setTimeout(() => {
          rejectCb(new Error('Sign-in timed out (5 min). Re-run to try again.'));
        }, DEFAULT_AUTH_TIMEOUT_MS);
        codePromise.finally(() => clearTimeout(timer));
        resolve({ server, port: addr.port, codePromise });
      } else {
        reject(new Error('Failed to bind localhost callback server'));
      }
    });
    server.on('error', reject);
  });
}

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);
}
