// agent-keypair runtime auth.
//
// When `new Stack({ agent_id })` is constructed, the SDK enters
// agent-runtime mode: every API call is signed with a fresh 60-second
// EdDSA JWT minted on demand from the agent's local privkey.
//
// First run flow:
//   1. Try to read ~/.stack/agents/<agent_id>.json (privkey JWK).
//   2. If missing, kick off the enrollment dance using the developer's
//      OAuth credentials (the ones written by `stack-cli auth login`):
//         a. POST /v1/agents/<id>/enrollment-challenge
//         b. Generate Ed25519 keypair locally
//         c. Sign the challenge bytes with the new privkey
//         d. POST /v1/agents/<id>/enroll with the public_key JWK +
//            signed_challenge
//      Persist the privkey to disk (mode 0600) and proceed.
//
// Subsequent runs hit step 1 only — no enrollment, no browser, no
// developer interaction.
//
// Threat model: the privkey lives on disk just like an OAuth refresh
// token. (passkey-rooted) closes the laptop-decryption gap.
// Until then, file-on-disk + chmod 600 is the same posture as `aws cli`.

import { generateKeyPair, exportJWK, importJWK, SignJWT, type JWK } from 'jose';
import { sign as cryptoSign, randomBytes } from 'node:crypto';
import { shouldRunBrowserBootstrap } from './browser-bootstrap.js';

const AGENT_KEY_DIR = '.stack/agents';
const AGENT_JWT_TTL = 60;
const AGENT_JWT_AUDIENCE = 'stack:agent';
const AGENT_JWT_ISSUER = 'stack-sdk';

/**
 * Dashboard origin to which the SDK opens the browser for the
 * approval screen. Mirrors the operator-visible website. Override via
 * STACK_DASHBOARD_URL for self-hosted or test environments.
 */
function dashboardUrl(apiBaseUrl: string): string {
  if (process.env['STACK_DASHBOARD_URL']) return process.env['STACK_DASHBOARD_URL'];
  // Dev shortcut: api on localhost ⇒ dashboard on :3100.
  if (/^https?:\/\/(127\.0\.0\.1|localhost)/.test(apiBaseUrl)) {
    return 'http://localhost:3100';
  }
  return 'https://getstack.run';
}

const ENROLLMENT_AUTH_TIMEOUT_MS = 5 * 60 * 1000; // matches ticket TTL

interface StoredKey {
  agent_id: string;
  publicKey: JWK;
  privateKey: JWK;
  enrolled_at: number;
}

async function keyPath(agentId: string): Promise<string> {
  const { homedir } = await import('node:os');
  const { join } = await import('node:path');
  return join(homedir(), AGENT_KEY_DIR, `${agentId}.json`);
}

async function readStoredKey(agentId: string): Promise<StoredKey | null> {
  try {
    const { readFile } = await import('node:fs/promises');
    const path = await keyPath(agentId);
    const raw = await readFile(path, 'utf8');
    return JSON.parse(raw) as StoredKey;
  } catch {
    return null;
  }
}

async function writeStoredKey(key: StoredKey): Promise<void> {
  const { writeFile, mkdir, chmod, rename, unlink } = await import('node:fs/promises');
  const { randomUUID } = await import('node:crypto');
  const { join, dirname } = await import('node:path');
  const { homedir } = await import('node:os');
  const path = join(homedir(), AGENT_KEY_DIR, `${key.agent_id}.json`);
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporaryPath, JSON.stringify(key, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await rename(temporaryPath, path);
  } finally { await unlink(temporaryPath).catch(() => undefined); }
  try {
    await chmod(path, 0o600);
  } catch {
    /* Windows / unsupported FS */
  }
}

export async function prepareFleetEnrollmentKey(policyId: string, idempotencyKey: string) {
  const { createHash, createPrivateKey } = await import('node:crypto');
  const { mkdir, writeFile } = await import('node:fs/promises');
  const { dirname } = await import('node:path');
  const keyId = `fleet_${createHash('sha256').update(JSON.stringify([policyId, idempotencyKey])).digest('hex')}`;
  let stored = await readStoredKey(keyId);
  if (!stored) {
    const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    const candidate: StoredKey = { agent_id: keyId, publicKey: await exportJWK(pair.publicKey),
      privateKey: await exportJWK(pair.privateKey), enrolled_at: Math.floor(Date.now() / 1000) };
    const path = await keyPath(keyId);
    await mkdir(dirname(path), { recursive: true });
    try { await writeFile(path, JSON.stringify(candidate), { encoding: 'utf8', mode: 0o600, flag: 'wx' }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    stored = await readStoredKey(keyId);
    // Another process may have created the pending file but not flushed it yet.
    for (let attempt = 0; !stored && attempt < 20; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 25));
      stored = await readStoredKey(keyId);
    }
  }
  if (!stored) throw new Error('Invalid input');
  const privateKey = createPrivateKey({ key: stored.privateKey as { kty: string; crv: string; x: string; d: string }, format: 'jwk' });
  const key = stored;
  return {
    publicKey: { kty: 'OKP' as const, crv: 'Ed25519' as const, x: stored.publicKey.x! },
    sign: (challenge: string) => cryptoSign(null, Buffer.from(challenge), privateKey).toString('base64url'),
    persist: async (agentId: string) => {
      if (!/^agt_[\w-]+$/.test(agentId)) throw new Error('Invalid input');
      await writeStoredKey({ ...key, agent_id: agentId });
    },
  };
}

/**
 * Spawn a one-shot loopback HTTP server on a random free port, open
 * the dashboard /sdk-bootstrap page in the user's browser, and resolve
 * with the enrollment ticket once the user approves (or reject on
 * deny / timeout). Used as the interactive-mode bearer provider in
 * place of the silent OAuth path.
 *
 * The ticket itself is a JWT bound to (operator, member, agent_id,
 * machine_label). Single-use: burned by the API on /enroll success.
 */
async function ticketViaBrowserApproval(args: {
  agentId: string;
  apiBaseUrl: string;
}): Promise<string> {
  const { createServer } = await import('node:http');
  const { hostname } = await import('node:os');
  const open = (await import('node:child_process')).spawn;

  const state = randomBytes(16).toString('base64url');
  const machine = hostname().slice(0, 80);
  const proc = `${process.argv0 ?? 'node'} ${process.argv[1]?.split(/[/\\]/).pop() ?? ''}`.slice(0, 80);

  return new Promise<string>((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      try { server.close(); } catch { /* */ }
      clearTimeout(timeout);
      fn();
    };

    const server = createServer((req, res) => {
      try {
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');
        if (url.pathname !== '/cb') {
          res.writeHead(404);
          res.end();
          return;
        }
        const error = url.searchParams.get('error');
        const ticket = url.searchParams.get('ticket');
        const callbackState = url.searchParams.get('state');
        if (callbackState !== state) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end('<html><body style="font-family:system-ui;padding:40px"><h1>State mismatch</h1></body></html>');
          settle(() => reject(new Error('enrollment callback state mismatch')));
          return;
        }
        if (error) {
          res.writeHead(403, { 'Content-Type': 'text/html' });
          res.end('<html><body style="font-family:system-ui;padding:40px"><h1>Enrollment denied</h1><p>You can close this tab.</p></body></html>');
          settle(() => reject(new Error(`enrollment ${error}`)));
          return;
        }
        if (!ticket) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end('<html><body style="font-family:system-ui;padding:40px"><h1>Missing ticket</h1></body></html>');
          settle(() => reject(new Error('enrollment callback missing ticket')));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body style="font-family:system-ui;padding:40px;text-align:center"><h1>Approved</h1><p>You can close this tab and return to your terminal.</p></body></html>');
        settle(() => resolve(ticket));
      } catch (e) {
        settle(() => reject(e instanceof Error ? e : new Error(String(e))));
      }
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      if (!port) {
        settle(() => reject(new Error('failed to bind loopback port for enrollment callback')));
        return;
      }
      const callback = `http://127.0.0.1:${port}/cb`;
      const dash = dashboardUrl(args.apiBaseUrl);
      const url = `${dash}/sdk-bootstrap?` + new URLSearchParams({
        agent_id: args.agentId,
        callback,
        state,
        machine,
        process: proc,
      }).toString();

      process.stderr.write('\n  STACK SDK agent enrollment\n');
      process.stderr.write('  ──────────────────────────\n\n');
      process.stderr.write(`  Approve in your browser: ${url}\n\n`);

      try {
        const opener = process.platform === 'win32'
          ? open('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' })
          : process.platform === 'darwin'
            ? open('open', [url], { detached: true, stdio: 'ignore' })
            : open('xdg-open', [url], { detached: true, stdio: 'ignore' });
        opener.unref?.();
      } catch {
        /* best-effort */
      }
    });

    const timeout = setTimeout(() => {
      settle(() => reject(new Error('enrollment approval timed out (5 min). Re-run to try again.')));
    }, ENROLLMENT_AUTH_TIMEOUT_MS);
  });
}

/**
 * Run the enrollment dance for `agentId`.
 *
 * Two paths converge on the same /enrollment-challenge + /enroll calls:
 *
 *   - **Interactive (TTY + not CI):** open the dashboard /sdk-bootstrap
 *     page so the operator explicitly approves enrollment of THIS agent
 *     on THIS machine. The dashboard mints a single-use enrollment
 *     ticket which the SDK uses as the Bearer.
 *
 *   - **Headless / CI:** fall through to the developer's OAuth bearer
 *     (or sk_live_* via STACK_API_KEY). No browser, no human-in-the-
 *     loop — convenience for CI runners. Same enrollment endpoints.
 *
 * Either way, the privkey is generated locally and never crosses the
 * network. The ticket only authenticates the enrollment dance itself.
 */
async function enroll(args: {
  agentId: string;
  baseUrl: string;
  bearerProvider: () => Promise<string>;
}): Promise<StoredKey> {
  let bearer: string;
  if (shouldRunBrowserBootstrap()) {
    try {
      bearer = await ticketViaBrowserApproval({ agentId: args.agentId, apiBaseUrl: args.baseUrl });
    } catch (e) {
      // Fall back to OAuth-bearer-silent mode — useful when the user
      // explicitly approved but the localhost bind failed (firewall),
      // or when the dashboard rejected because, say, the cookie
      // session expired and they bailed out. Surface the original
      // error so the user knows what happened.
      throw new Error(
        `Browser approval for SDK agent enrollment failed (${(e as Error).message}). ` +
          `Fix the issue and re-run.`,
        { cause: e },
      );
    }
  } else {
    bearer = await args.bearerProvider();
  }

  // Step 1: request challenge.
  const challengeRes = await fetch(`${args.baseUrl}/v1/agents/${args.agentId}/enrollment-challenge`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Content-Type': 'application/json',
    },
  });
  if (!challengeRes.ok) {
    const errBody = await challengeRes.json().catch(() => ({})) as { error?: { message?: string } };
    throw new Error(`enrollment-challenge failed: ${errBody.error?.message ?? challengeRes.statusText}`);
  }
  const { challenge_id, challenge } = (await challengeRes.json()) as { challenge_id: string; challenge: string };

  // Step 2: generate keypair locally.
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);

  // Step 3: sign the challenge bytes with the privkey.
  // Node's `sign(null, ...)` is the Ed25519 entry-point; matches what
  // the API's `crypto.verify(null, ...)` consumes.
  const { createPrivateKey } = await import('node:crypto');
  const privateKeyObject = createPrivateKey({ key: privateJwk as { kty: string; crv: string; x: string; d: string }, format: 'jwk' });
  const signatureBytes = cryptoSign(null, Buffer.from(challenge, 'utf8'), privateKeyObject);
  const signed_challenge = signatureBytes.toString('base64url');

  // Step 4: POST /enroll.
  const enrollRes = await fetch(`${args.baseUrl}/v1/agents/${args.agentId}/enroll`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      public_key: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x },
      challenge_id,
      signed_challenge,
    }),
  });
  if (!enrollRes.ok) {
    const errBody = await enrollRes.json().catch(() => ({})) as { error?: { message?: string } };
    throw new Error(`enroll failed: ${errBody.error?.message ?? enrollRes.statusText}`);
  }
  const { enrolled_at } = (await enrollRes.json()) as { enrolled_at: string };

  const stored: StoredKey = {
    agent_id: args.agentId,
    publicKey: publicJwk,
    privateKey: privateJwk,
    enrolled_at: Math.floor(new Date(enrolled_at).getTime() / 1000),
  };
  await writeStoredKey(stored);
  return stored;
}

/**
 * Mint a fresh agent JWT (60s TTL) signed with the agent's privkey.
 * One JWT per request — no caching. Cheap (≈1ms EdDSA sign) and the
 * jti uniqueness ensures the API's replay-cache stays effective.
 */
async function signAgentJwt(stored: StoredKey, agentId: string): Promise<string> {
  const key = await importJWK(stored.privateKey, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuer(AGENT_JWT_ISSUER)
    .setSubject(agentId)
    .setAudience(AGENT_JWT_AUDIENCE)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + AGENT_JWT_TTL)
    // A JTI is a replay-protection nonce, so it must not come from
    // Math.random(). 128 bits of CSPRNG entropy keeps independently running
    // SDK processes collision-safe without leaking time or process state.
    .setJti(`aj_${randomBytes(16).toString('base64url')}`)
    .sign(key);
}

/**
 * Token provider for the HttpClient. Returns a fresh agent JWT per call.
 * On first run (no stored key), runs the enrollment flow using the
 * supplied bearerProvider for OAuth fallback authentication.
 */
export function createAgentTokenProvider(args: {
  agentId: string;
  baseUrl: string;
  bearerProvider: () => Promise<string>;
}): () => Promise<string> {
  let cached: StoredKey | null = null;
  return async () => {
    if (!cached) {
      cached = await readStoredKey(args.agentId);
    }
    if (!cached) {
      cached = await enroll({ agentId: args.agentId, baseUrl: args.baseUrl, bearerProvider: args.bearerProvider });
    }
    return signAgentJwt(cached, args.agentId);
  };
}
