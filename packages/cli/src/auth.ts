// CLI auth — Device Authorization Grant (RFC 8628).
//
// auth login → DCR-register a client (first run only), kick off
//   the device flow, print user_code + URL, open the browser, poll the
//   token endpoint, persist refresh_token to ~/.stack/credentials.json.
// auth status → read credentials, exchange refresh → access,
//   call /v1/operators/me, print operator + scope.
// auth logout → revoke refresh, delete credentials file.
//
// No native deps. Refresh tokens live in a file with mode 0600. macOS
// Keychain / Windows Credential Manager / libsecret integration is a
// follow-up — an earlier change closes the file-on-disk threat with passkey-rooted
// retrieval. Until then this matches the storage model of `aws cli`,
// `gcloud`, etc.

import { stdout, stderr, env, exit, platform } from 'node:process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { mkdir, writeFile, readFile, chmod, unlink, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';

const API_URL = env['STACK_API_URL'] ?? 'https://api.getstack.run';
const RESOURCE = env['STACK_OAUTH_RESOURCE'] ?? `${API_URL}`;

// Default login scope covers the CLI's routine runtime and inspection flows.
// High-impact management surfaces stay opt-in even when the CLI has a command
// for them: account/team mutations, raw credential retrieval, billing and
// payout writes, OAuth-app/CMEK administration, authority and identity
// mutation, notification/security-policy changes, partner administration,
// and platform admin. An operator can request an exact broader set for a
// deliberate session with STACK_OAUTH_SCOPE. Kept as a literal because the
// published CLI intentionally has no @stack/shared runtime dependency.
export const CLI_DEFAULT_OAUTH_SCOPES = [
  'account:read',
  'team:read',
  'passports:read', 'passports:write',
  'agents:read', 'agents:write',
  'accounts:read', 'accounts:write', 'accounts:act',
  'services:read', 'services:write', 'services:connect',
  'inbound-webhooks:read',
  'proxy:read', 'proxy:write',
  'audit:read',
  'billing:read',
  'identity:read',
  'authority:read',
  'governance:read',
  'intents:read', 'intents:write',
  'missions:read', 'missions:write',
  'reviews:read',
  'evidence:read', 'evidence:write',
  'dropoffs:read', 'dropoffs:write',
  'skills:read', 'skills:write', 'skills:invoke',
  'notifications:read',
  'security-events:read',
  'llm:read', 'llm:invoke',
  'scan:read', 'scan:write',
  'detectors:read',
  'pii:read',
  'partner:read',
] as const;
export const DEFAULT_SCOPE = CLI_DEFAULT_OAUTH_SCOPES.join(' ');

// The scope the CLI requests at login. STACK_OAUTH_SCOPE overrides the
// least-privilege default (used to sign in read-only for monitoring). Read at
// call time, not frozen at import, so a programmatically-set env var still
// takes effect (and so auth.test.ts can exercise the override).
export function requestedScope(): string {
  return env['STACK_OAUTH_SCOPE'] ?? DEFAULT_SCOPE;
}

// The one command name the CLI prints. Every usage line, error, hint and
// help string must go through `invokeHint` (or `CLI_COMMAND` for the bare
// name); a test fails on any other spelling in the sources.
//
// It is a constant, not derived from how the process was started: the
// `npx @getstackrun/cli` form is copy-pasteable everywhere (npx finds a
// global install's bin as well as fetching from npm). An earlier "detect
// npx vs global" heuristic misjudged enough Windows path layouts that the
// hint told operators to run `stack-cli ...`, which their shell rejected
// with "the term 'stack-cli' is not recognized". The published bin is still
// named `stack-cli`; only the printed form is fixed.
export const CLI_COMMAND = 'npx @getstackrun/cli';

export function invokeHint(subcommand: string): string {
  return `${CLI_COMMAND} ${subcommand}`;
}

// Stringify whatever shape the API returns for an error so the CLI
// never prints "[object Object]". The OAuth spec wants {error,
// error_description} strings, but our wider API uses {error: {code,
// message}}; both can slip through this endpoint.
export function stringifyOAuthError(data: unknown): string {
  if (!data || typeof data !== 'object') return String(data ?? 'unknown');
  const d = data as { error?: unknown; error_description?: string; code?: string; message?: string };
  if (typeof d.error === 'string') {
    return d.error_description ? `${d.error}: ${d.error_description}` : d.error;
  }
  if (d.error && typeof d.error === 'object') {
    const e = d.error as { code?: string; message?: string };
    if (e.code || e.message) return e.message ? `${e.code ?? 'error'}: ${e.message}` : (e.code ?? 'error');
  }
  if (d.message) return d.message;
  try { return JSON.stringify(d).slice(0, 200); } catch { return 'unknown error'; }
}

const useColor = stdout.isTTY === true && !env['NO_COLOR'];
const color = (n: string) => (useColor ? `\x1b[${n}m` : '');
const C = {
  reset: color('0'), bold: color('1'), dim: color('2'),
  red: color('31'), green: color('32'), yellow: color('33'), cyan: color('36'), gray: color('90'), white: color('37'),
};

interface Credentials {
  client_id: string;
  refresh_token: string;
  issued_at: number;
  refresh_expires_at: number;
  operator_email?: string;
  scope: string;
}

const CREDS_DIR = join(homedir(), '.stack');
const CREDS_PATH = join(CREDS_DIR, 'credentials.json');
const LOCK_PATH = join(CREDS_DIR, 'credentials.lock');

// Single-flight lock around refresh-token rotation. Two concurrent
// `npx @getstackrun/cli ...` invocations would otherwise both POST the
// same refresh_token A; the server rotates A→B for the first caller,
// then sees A again from the second caller, detects family reuse, and
// revokes the whole family. This happened twice in practice.
//
// Mechanism: atomic exclusive-create writeFile(..., flag: 'wx'). Whoever
// wins the create holds the lock; losers wait + retry. After acquiring
// the lock the caller MUST re-read creds from disk, because the
// previous holder may have just rotated A→B (the disk now holds B —
// posting A would still fire reuse detection on the server). Stale
// locks (process crashed without releasing) self-clear after 30s by
// mtime check.
const LOCK_ACQUIRE_TIMEOUT_MS = 5_000;
const LOCK_RETRY_INTERVAL_MS = 50;
const LOCK_STALE_MS = 30_000;

async function acquireRefreshLock(): Promise<() => Promise<void>> {
  await mkdir(CREDS_DIR, { recursive: true });
  const deadline = Date.now() + LOCK_ACQUIRE_TIMEOUT_MS;

  while (Date.now() < deadline) {
    try {
      // 'wx' = O_CREAT | O_EXCL — fails with EEXIST if the file exists.
      // Atomic on every platform Node supports. Write our PID so a
      // future cross-process diagnostic can identify the holder.
      await writeFile(LOCK_PATH, String(process.pid), { flag: 'wx' });
      return async () => {
        try { await unlink(LOCK_PATH); } catch { /* already gone */ }
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
        // Permission error / disk full / etc. Degrade to lock-free —
        // equivalent to pre-fix behavior, not worse.
        return async () => {};
      }
      // Stale-lock detection: the holder may have crashed without
      // releasing. mtime older than LOCK_STALE_MS → safe to clear.
      try {
        const st = await stat(LOCK_PATH);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          try { await unlink(LOCK_PATH); } catch { /* race with another waiter; retry */ }
          continue;
        }
      } catch { /* lock vanished between EEXIST and stat — loop and retry create */ }
      await new Promise((r) => setTimeout(r, LOCK_RETRY_INTERVAL_MS));
    }
  }
  // Timed out. Proceed lock-free — same race window as today, no worse.
  return async () => {};
}

async function readCreds(): Promise<Credentials | null> {
  try {
    const raw = await readFile(CREDS_PATH, 'utf8');
    const parsed: unknown = JSON.parse(raw);
    // A file that cannot sign anyone in is no sign-in at all (spec/credentials-files).
    if (parsed === null || typeof parsed !== 'object') return null;
    const { client_id: clientId, refresh_token: refreshToken } = parsed as Record<string, unknown>;
    if (typeof clientId !== 'string' || clientId === '' || typeof refreshToken !== 'string' || refreshToken === '') return null;
    return parsed as Credentials;
  } catch {
    return null;
  }
}

async function writeCreds(creds: Credentials): Promise<void> {
  await mkdir(CREDS_DIR, { recursive: true });
  // Created readable by the owner only; the chmod below also covers a file that already existed.
  await writeFile(CREDS_PATH, JSON.stringify(creds, null, 2), { encoding: 'utf8', mode: 0o600 });
  // Restrict to owner — best-effort on Windows where chmod is a no-op,
  // but the default ACL on %USERPROFILE%\.stack is already user-scoped.
  try {
    await chmod(CREDS_PATH, 0o600);
  } catch {
    /* Windows / unsupported FS — ignore */
  }
}

async function deleteCreds(): Promise<void> {
  try {
    await unlink(CREDS_PATH);
  } catch {
    /* already gone */
  }
}

export function openBrowser(url: string): void {
  // Best-effort. Failure is silent — the URL is also printed.
  try {
    const child = platform === 'darwin'
      ? spawn('open', [url], { stdio: 'ignore', detached: true })
      : platform === 'win32'
        ? spawn('cmd', ['/c', 'start', '', url], { stdio: 'ignore', detached: true })
        : spawn('xdg-open', [url], { stdio: 'ignore', detached: true });
    child.on('error', () => undefined);
    child.unref();
  } catch {
    /* user opens manually */
  }
}

async function ensureClientId(creds: Credentials | null): Promise<string> {
  if (creds?.client_id) return creds.client_id;
  // Dynamic Client Registration (RFC 7591). Public PKCE client; one
  // client_id per CLI install — better blast radius than a single
  // shared client_id.
  const res = await fetch(`${API_URL}/oauth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'STACK CLI',
      redirect_uris: ['http://127.0.0.1/callback'], // unused for device flow but required by spec
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      software_id: 'getstack.cli',
      scope: requestedScope(),
    }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({})) as { error_description?: string; error?: string };
    throw new Error(`client registration failed: ${data.error_description ?? data.error ?? res.statusText}`);
  }
  const data = (await res.json()) as { client_id: string };
  return data.client_id;
}

async function pollToken(deviceCode: string, clientId: string, intervalSeconds: number): Promise<{ refresh_token: string; access_token: string; scope: string }> {
  let interval = intervalSeconds * 1000;
  // Cap total wait at the device code TTL (15 min) — the API will return
  // expired_token once it lapses, but bail explicitly so the CLI doesn't
  // loop indefinitely if the API is unreachable.
  const deadline = Date.now() + 15 * 60 * 1000;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, interval));
    const res = await fetch(`${API_URL}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
        client_id: clientId,
      }),
    });
    const data = (await res.json().catch(() => ({}))) as { access_token?: string; refresh_token?: string; scope?: string; error?: string | { code?: string; message?: string } };
    if (res.ok && data.access_token && data.refresh_token) {
      return { access_token: data.access_token, refresh_token: data.refresh_token, scope: data.scope ?? requestedScope() };
    }
    if (data.error === 'authorization_pending') continue;
    if (data.error === 'slow_down') {
      interval = Math.min(interval * 2, 60_000);
      continue;
    }
    if (data.error === 'access_denied') throw new Error('user denied the request');
    if (data.error === 'expired_token') throw new Error(`device code expired — run \`${invokeHint('auth login')}\` again`);
    // Any other error shape — pass through stringifyOAuthError so we never
    // emit "[object Object]" (the 2026-05-11 bug where {error: {code,
    // message}} envelope leaked through the typed `data.error: string`).
    if (data.error || !res.ok) throw new Error(`token endpoint: ${stringifyOAuthError(data)}`);
  }
  throw new Error('device code expired (CLI timeout)');
}

export async function cmdLogin(): Promise<void> {
  const existing = await readCreds();
  const clientId = await ensureClientId(existing);

  // Kick off the device flow.
  const deviceRes = await fetch(`${API_URL}/oauth/device/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, scope: requestedScope(), resource: RESOURCE }),
  });
  if (!deviceRes.ok) {
    const data = (await deviceRes.json().catch(() => ({}))) as { error_description?: string; error?: string };
    stderr.write(`${C.red}error:${C.reset} ${data.error_description ?? data.error ?? `HTTP ${deviceRes.status}`}\n`);
    exit(1);
  }
  const device = (await deviceRes.json()) as {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    interval: number;
  };

  stdout.write(`
  ${C.bold}STACK CLI sign-in${C.reset}
  ${C.gray}─────────────────${C.reset}

  ${C.dim}1.${C.reset} Open this URL in your browser:
       ${C.cyan}${device.verification_uri_complete}${C.reset}

  ${C.dim}2.${C.reset} Confirm this code matches what your browser shows:
       ${C.bold}${C.green}${device.user_code}${C.reset}

  ${C.gray}Waiting for approval...${C.reset}

`);

  openBrowser(device.verification_uri_complete);

  let tokens: { access_token: string; refresh_token: string; scope: string };
  try {
    tokens = await pollToken(device.device_code, clientId, device.interval);
  } catch (err) {
    stderr.write(`${C.red}error:${C.reset} ${(err as Error).message}\n`);
    exit(1);
  }

  // Fetch operator email for friendly status display. Best-effort.
  let operatorEmail: string | undefined;
  try {
    const meRes = await fetch(`${API_URL}/v1/operators/me`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (meRes.ok) {
      const me = (await meRes.json()) as { email?: string };
      operatorEmail = me.email;
    }
  } catch {
    /* non-fatal */
  }

  await writeCreds({
    client_id: clientId,
    refresh_token: tokens.refresh_token,
    issued_at: Math.floor(Date.now() / 1000),
    refresh_expires_at: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
    operator_email: operatorEmail,
    scope: tokens.scope,
  });

  stdout.write(`  ${C.green}✓${C.reset} Signed in${operatorEmail ? ` as ${C.bold}${operatorEmail}${C.reset}` : ''}
  ${C.gray}Credentials saved to ${CREDS_PATH}${C.reset}

`);
}

export async function cmdStatus(): Promise<void> {
  const creds = await readCreds();
  if (!creds) {
    stdout.write(`${C.gray}Not signed in.${C.reset} Run ${C.cyan}${invokeHint('auth login')}${C.reset}.\n`);
    exit(1);
  }
  const refreshExpiresIn = creds.refresh_expires_at - Math.floor(Date.now() / 1000);
  if (refreshExpiresIn <= 0) {
    stdout.write(`${C.yellow}Session expired.${C.reset} Run ${C.cyan}${invokeHint('auth login')}${C.reset} again.\n`);
    exit(1);
  }
  const days = Math.floor(refreshExpiresIn / 86400);
  stdout.write(`  ${C.green}✓${C.reset} Signed in${creds.operator_email ? ` as ${C.bold}${creds.operator_email}${C.reset}` : ''}
  ${C.gray}Scope:${C.reset}     ${creds.scope}
  ${C.gray}Client:${C.reset}    ${creds.client_id}
  ${C.gray}Expires:${C.reset}   in ${days} day${days === 1 ? '' : 's'}
  ${C.gray}File:${C.reset}      ${CREDS_PATH}
`);
}

export async function cmdLogout(): Promise<void> {
  const creds = await readCreds();
  if (!creds) {
    stdout.write(`${C.gray}Not signed in.${C.reset}\n`);
    return;
  }
  // Best-effort revoke. Failure on the network doesn't stop us deleting
  // the local file — that's the user's intent here.
  try {
    await fetch(`${API_URL}/oauth/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: creds.refresh_token, client_id: creds.client_id }),
    });
  } catch {
    /* network error — local file removal still succeeds */
  }
  await deleteCreds();
  stdout.write(`  ${C.green}✓${C.reset} Signed out\n`);
}

/**
 * Used by `monitor --follow` and any future authenticated command.
 * Returns a fresh access token by exchanging the stored refresh token.
 * Falls back to STACK_API_KEY env var for back-compat with existing
 * users who haven't migrated. Returns null when no auth source exists.
 *
 * Refresh rotation is single-flight per machine via a file lock at
 * ~/.stack/credentials.lock. See acquireRefreshLock above for the
 * race this prevents.
 */
export async function getAccessToken(): Promise<string | null> {
  const agentId = env['STACK_AGENT_ID'];
  if (agentId) {
    const { createAgentTokenProvider } = await import('@getstackrun/sdk');
    return createAgentTokenProvider({ agentId, baseUrl: API_URL,
      bearerProvider: async () => (await getOperatorAccessToken()) ?? '' })();
  }
  return getOperatorAccessToken();
}

async function getOperatorAccessToken(): Promise<string | null> {
  const apiKey = env['STACK_API_KEY'];
  if (apiKey) return apiKey; // legacy path — no rotation, no lock needed

  // Early-exit when not signed in. Avoids acquiring a lock just to
  // discover there are no creds.
  const probe = await readCreds();
  if (!probe) return null;

  const releaseLock = await acquireRefreshLock();
  try {
    // CRITICAL: re-read AFTER acquiring the lock. A peer process may
    // have rotated A→B while we waited; the disk now holds B and
    // posting the stale A would fire the server's family-reuse detector
    // and revoke everyone's refresh.
    const creds = await readCreds();
    if (!creds) return null;

    const res = await fetch(`${API_URL}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: creds.refresh_token,
        client_id: creds.client_id,
      }),
    });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as { error?: string | { code?: string; message?: string } };
      // Surface the actual reason on stderr instead of silently returning
      // null. Previously a refresh failure produced just "not signed in"
      // downstream — impossible to diagnose. Now: print the OAuth error
      // code (invalid_grant, expired, reuse_detected, etc.) before falling
      // through. Caller still gets null so existing branches don't change.
      const reason = stringifyOAuthError(data);
      stderr.write(`${C.yellow}warning:${C.reset} refresh failed (${reason}). Re-authenticate with ${C.cyan}${invokeHint('auth login')}${C.reset}.\n`);
      const errorCode = typeof data.error === 'string'
        ? data.error
        : (typeof data.error === 'object' && data.error?.code) || '';
      if (errorCode === 'invalid_grant') {
        // Refresh revoked or family broken — wipe and force re-login.
        await deleteCreds();
      }
      return null;
    }
    const data = (await res.json()) as { access_token: string; refresh_token: string };
    // Rotate stored refresh.
    await writeCreds({
      ...creds,
      refresh_token: data.refresh_token,
      issued_at: Math.floor(Date.now() / 1000),
      refresh_expires_at: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
    });
    return data.access_token;
  } finally {
    await releaseLock();
  }
}

// Suppress unused-import warnings for crypto helpers we may need in
// future SDK-keypair-style additions; safe no-op today.
void createHash; void randomBytes;
