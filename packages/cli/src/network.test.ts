import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { stderr } from 'node:process';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { governedApi } from './governance.js';
import { printJson } from './format.js';
import { cmdNetwork } from './network.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({ nonce: 'n'.repeat(32) })) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'STACKLIC1.from.stdin') }));

/** The claims of a compact JWS, unchecked: these tests look at what the CLI signed. */
const decodeJwt = (token: string) => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;

let dir: string;
beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(stderr, 'write').mockImplementation(() => true);
  dir = mkdtempSync(join(tmpdir(), 'stack-network-cli-'));
});
afterEach(() => {
  vi.unstubAllGlobals();
  rmSync(dir, { recursive: true, force: true });
});

describe('network owner commands', () => {
  it('register, list, show and revoke call the install routes', async () => {
    await cmdNetwork(['install', 'register', 'office']);
    await cmdNetwork(['install', 'list']);
    await cmdNetwork(['install', 'show', 'ins_a']);
    await cmdNetwork(['install', 'revoke', 'ins_a', '--reason', 'key_compromise']);
    await cmdNetwork(['install', 'key', 'revoke', 'ins_a', 'ink_b']);
    expect(vi.mocked(api).mock.calls).toEqual([
      ['POST', '/v1/network/installs', { body: { name: 'office' } }],
      ['GET', '/v1/network/installs'],
      ['GET', '/v1/network/installs/ins_a'],
      ['POST', '/v1/network/installs/ins_a/revoke', { body: { reason: 'key_compromise' } }],
      ['POST', '/v1/network/installs/ins_a/keys/ink_b/revoke', { body: {} }],
    ]);
    expect(governedApi).not.toHaveBeenCalled();
  });

  it('adds a key through the approval flow, writing a private key only the owner can read, and never printing it', async () => {
    const file = join(dir, 'install.pem');
    await cmdNetwork(['install', 'key', 'add', 'ins_a', '--key-file', file, '--rollover-seconds', '600']);
    expect(governedApi).toHaveBeenCalledWith('POST', '/v1/network/installs/ins_a/key-challenges', { body: {} });
    const [, path, options] = vi.mocked(api).mock.calls[0]!;
    expect(path).toBe('/v1/network/installs/ins_a/keys');
    const body = (options as { body: { public_jwk: Record<string, string>; proof: string; rollover_seconds: number } }).body;
    expect(Object.keys(body.public_jwk).sort()).toEqual(['crv', 'kty', 'x']);
    expect(body.rollover_seconds).toBe(600);
    expect(decodeJwt(body.proof)).toMatchObject({ install: 'ins_a', nonce: 'n'.repeat(32), aud: 'stack:network' });
    const pem = readFileSync(file, 'utf8');
    expect(pem).toContain('PRIVATE KEY');
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
    const printed = JSON.stringify(vi.mocked(printJson).mock.calls) + JSON.stringify(vi.mocked(stderr.write).mock.calls);
    expect(printed).not.toContain(pem.split('\n')[1]!);
  });

  it('reuses a key file that is already there instead of replacing it', async () => {
    const file = join(dir, 'install.pem');
    await cmdNetwork(['install', 'key', 'add', 'ins_a', '--key-file', file]);
    const first = readFileSync(file, 'utf8');
    await cmdNetwork(['install', 'key', 'add', 'ins_b', '--key-file', file]);
    expect(readFileSync(file, 'utf8')).toBe(first);
    const jwks = vi.mocked(api).mock.calls.map((call) => (call[2] as { body: { public_jwk: { x: string } } }).body.public_jwk.x);
    expect(jwks[0]).toBe(jwks[1]);
  });

  it('refuses a key file it cannot parse and writes nothing over it', async () => {
    const file = join(dir, 'broken.pem');
    writeFileSync(file, 'not a key');
    await expect(cmdNetwork(['install', 'key', 'add', 'ins_a', '--key-file', file])).rejects.toThrow();
    expect(readFileSync(file, 'utf8')).toBe('not a key');
    expect(api).not.toHaveBeenCalled();
  });

  it('needs a key file, and takes only known kinds and reasons', async () => {
    await expect(cmdNetwork(['install', 'key', 'add', 'ins_a'])).rejects.toThrow('--key-file');
    await expect(cmdNetwork(['revoke', 'planet', 'x'])).rejects.toThrow('the kind');
    // Every revocation names its install: the owner's form needs --for-install, the install's own form signs with its key.
    await expect(cmdNetwork(['revoke', 'agent', 'x'])).rejects.toThrow('--for-install');
    await expect(cmdNetwork(['revoke', 'agent', 'x', '--reason', 'because'])).rejects.toThrow('--reason');
    expect(existsSync(join(dir, 'install.pem'))).toBe(false);
  });

  it('publishes the owner revocation, subscriptions and their lifecycle', async () => {
    await cmdNetwork(['revoke', 'agent', 'support-bot', '--for-install', 'ins_a', '--reason', 'agent_decommissioned']);
    await cmdNetwork(['subscription', 'create', 'https://c.example/hook', '--install', 'ins_a', '--install', 'ins_b']);
    await cmdNetwork(['subscription', 'list']);
    await cmdNetwork(['subscription', 'resume', 'nsub_1']);
    await cmdNetwork(['subscription', 'delete', 'nsub_1']);
    expect(vi.mocked(api).mock.calls).toEqual([
      ['POST', '/v1/network/revocations', { body: { kind: 'agent', subject: 'support-bot', install: 'ins_a', reason: 'agent_decommissioned' } }],
      ['POST', '/v1/network/subscriptions', { body: { url: 'https://c.example/hook', installs: ['ins_a', 'ins_b'] } }],
      ['GET', '/v1/network/subscriptions'],
      ['POST', '/v1/network/subscriptions/nsub_1/resume', { body: {} }],
      ['DELETE', '/v1/network/subscriptions/nsub_1'],
    ]);
  });

  it('revokes a licence key read from a file or standard input, never from an argument', async () => {
    const file = join(dir, 'licence.txt');
    writeFileSync(file, 'STACKLIC1.from.file\n');
    await cmdNetwork(['licence', 'revoke', '--licence-file', file, '--reason', 'key_compromise']);
    await cmdNetwork(['licence', 'revoke']);
    await cmdNetwork(['licence', 'list']);
    expect(vi.mocked(api).mock.calls).toEqual([
      ['POST', '/v1/network/licences/revoke', { body: { licence_key: 'STACKLIC1.from.file', reason: 'key_compromise' } }],
      ['POST', '/v1/network/licences/revoke', { body: { licence_key: 'STACKLIC1.from.stdin' } }],
      ['GET', '/v1/network/licences/revoked'],
    ]);
    expect(governedApi).not.toHaveBeenCalled();
    // A key given as an argument is refused before any request, so it never lands in a shell history.
    await expect(cmdNetwork(['licence', 'revoke', 'STACKLIC1.on.argv'])).rejects.toThrow();
    await expect(cmdNetwork(['licence', 'revoke', '--reason', 'because'])).rejects.toThrow(/reason/);
    expect(vi.mocked(api)).toHaveBeenCalledTimes(3);
  });
});

describe('network install commands', () => {
  async function installFile(): Promise<string> {
    const file = join(dir, 'install.pem');
    await cmdNetwork(['install', 'key', 'add', 'ins_a', '--key-file', file]);
    vi.clearAllMocks();
    return file;
  }

  it('sign each request with the install key and send no account credential', async () => {
    const file = await installFile();
    const calls: Array<{ url: string; auth: string | undefined; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: { headers: Record<string, string>; body?: string }) => {
      calls.push({ url, auth: init.headers['Authorization'], body: init.body ? JSON.parse(init.body) : undefined });
      return new Response(JSON.stringify({ id: 'csg_1', countersignature: 'a.b.c' }), { status: 201, headers: { 'content-type': 'application/json' } });
    }));
    const passport = 'aaaa.bbbb.cccc';
    await cmdNetwork(['countersign', passport, '--install', 'ins_a', '--key-file', file, '--agent', 'support-bot', '--ttl-seconds', '600']);
    await cmdNetwork(['revoke', 'agent', 'support-bot', '--install', 'ins_a', '--key-file', file]);
    expect(api).not.toHaveBeenCalled();
    expect(calls[0]!.url).toMatch(/\/v1\/network\/countersignatures$/);
    const proof = calls[0]!.auth!.replace('Bearer ', '');
    expect(decodeJwt(proof)).toMatchObject({ iss: 'ins_a', act: 'countersign', agent: 'support-bot', ttl: 600 });
    expect(decodeJwt(calls[1]!.auth!.replace('Bearer ', ''))).toMatchObject({ act: 'revoke', kind: 'agent', subject: 'support-bot' });
    expect(calls[0]!.body).toEqual({});
  });

  it('need both the install and its key file', async () => {
    await expect(cmdNetwork(['rules', '--install', 'ins_a'])).rejects.toThrow('--key-file');
    await expect(cmdNetwork(['rules', '--key-file', join(dir, 'x.pem')])).rejects.toThrow('--install');
  });
});

describe('network public checks', () => {
  it('verify sends the countersignature and the passport and needs no sign-in', async () => {
    const seen: Array<{ url: string; headers: Record<string, string>; body?: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: { headers: Record<string, string>; body?: string }) => {
      seen.push({ url, headers: init.headers, body: init.body ? JSON.parse(init.body) : undefined });
      return new Response(JSON.stringify({ valid: true, reasons: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
    }));
    await cmdNetwork(['verify', 'aaaaaaaaaa.bbbbbbbbbb.cccccccccc', '--passport', 'dddddddddd.eeeeeeeeee.ffffffffff']);
    expect(seen[0]!.url).toMatch(/\/v1\/network\/verify$/);
    expect(seen[0]!.body).toEqual({ countersignature: 'aaaaaaaaaa.bbbbbbbbbb.cccccccccc', passport: 'dddddddddd.eeeeeeeeee.ffffffffff' });
    expect(seen[0]!.headers['Authorization']).toBeUndefined();
    expect(api).not.toHaveBeenCalled();
  });

  it('verified needs a subject', async () => {
    await expect(cmdNetwork(['verified'])).rejects.toThrow('--passport-digest');
  });

  it('refuses an unknown subcommand', async () => {
    await expect(cmdNetwork(['nope'])).rejects.toThrow('network takes');
  });
});
