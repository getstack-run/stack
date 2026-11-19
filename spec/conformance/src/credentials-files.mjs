// Conformance suite for the local files a client keeps under `~/.stack/` (spec/credentials-files/SPEC.md): the operator's
// sign-in and an agent's key. The kit looks at the files and at what a client does with them.
//
//   { dir }                 a `.stack` directory a client wrote: every file in it is judged (the schemas, the names, the
//                           key pair, the mode)
//   { write }               a function that makes your client write: `write({ home, dir, credentials })` writes a sign-in
//                           (home is a fresh directory your client must treat as the home directory), and `writeAgentKey({ home, dir, agentId })`
//                           makes it generate and store the key of an agent. What it wrote is judged
//   { read }                `read({ home, dir })` returns the sign-in your client would use from the files the kit put in
//                           `dir`, or null when it would use none. The kit gives it good files and bad ones
//
// No STACK package judges your client: the kit reads the files and checks the keys with `node:crypto`.

import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assert, assertEqual, runChecks, skip } from './harness.mjs';

const THIRTY_DAYS = 30 * 24 * 60 * 60;
const AGENT_ID = /^(agt_[A-Za-z0-9_-]+|fleet_[0-9a-f]{64})$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const POSIX = process.platform !== 'win32';

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isWholeSeconds = (value) => Number.isInteger(value) && value >= 0;
const nonEmpty = (value) => typeof value === 'string' && value.length > 0;

/** What is wrong with a sign-in file's content as section 3 describes it, or null. */
export function credentialsProblem(value) {
  if (!isObject(value)) return 'it is not a JSON object';
  if (!nonEmpty(value.client_id)) return '"client_id" is not a non-empty string';
  if (!nonEmpty(value.refresh_token)) return '"refresh_token" is not a non-empty string';
  if (!isWholeSeconds(value.issued_at)) return '"issued_at" is not a whole number of seconds';
  if (!isWholeSeconds(value.refresh_expires_at)) return '"refresh_expires_at" is not a whole number of seconds';
  if ('operator_email' in value && typeof value.operator_email !== 'string') return '"operator_email" is not a string';
  if (typeof value.scope !== 'string') return '"scope" is not a string';
  return null;
}

/** What is wrong with an agent key file's content as section 6 describes it, or null. `name` is the file's name without `.json`. */
export function agentKeyProblem(value, name) {
  if (!isObject(value)) return 'it is not a JSON object';
  if (typeof value.agent_id !== 'string' || !AGENT_ID.test(value.agent_id)) return `"agent_id" is ${JSON.stringify(value.agent_id)}, not agt_... or fleet_ and 64 hexadecimal characters`;
  if (value.agent_id !== name) return `"agent_id" is ${value.agent_id} but the file is named ${name}.json`;
  for (const field of ['publicKey', 'privateKey']) {
    const jwk = value[field];
    if (!isObject(jwk)) return `"${field}" is not an object`;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return `"${field}" is not an Ed25519 key of type OKP`;
    if (typeof jwk.x !== 'string' || !BASE64URL_32.test(jwk.x)) return `"${field}.x" is not the base64url of 32 bytes`;
  }
  if (typeof value.privateKey.d !== 'string' || !BASE64URL_32.test(value.privateKey.d)) return '"privateKey.d" is not the base64url of 32 bytes';
  if (value.publicKey.x !== value.privateKey.x) return '"publicKey.x" and "privateKey.x" differ';
  try {
    const derived = createPublicKey(createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x: value.privateKey.x, d: value.privateKey.d }, format: 'jwk' })).export({ format: 'jwk' });
    if (derived.x !== value.privateKey.x) return '"privateKey.x" is not the public key of "privateKey.d"';
  } catch {
    return '"privateKey" is not a usable Ed25519 key';
  }
  if (!isWholeSeconds(value.enrolled_at)) return '"enrolled_at" is not a whole number of seconds';
  return null;
}

function readJson(path) {
  try {
    return { value: JSON.parse(readFileSync(path, 'utf8')) };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

/** A fresh Ed25519 agent key in the form of section 6. */
export function makeAgentKey(agentId = `agt_${randomBytes(12).toString('base64url')}`) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' });
  const priv = privateKey.export({ format: 'jwk' });
  return {
    agent_id: agentId,
    publicKey: { kty: pub.kty, crv: pub.crv, x: pub.x },
    privateKey: { kty: priv.kty, crv: priv.crv, x: priv.x, d: priv.d },
    enrolled_at: Math.floor(Date.now() / 1000),
  };
}

export function makeCredentials() {
  const now = Math.floor(Date.now() / 1000);
  return {
    client_id: `oclient_${randomBytes(9).toString('base64url')}`,
    refresh_token: `refresh_${randomBytes(18).toString('base64url')}`,
    issued_at: now,
    refresh_expires_at: now + THIRTY_DAYS,
    operator_email: 'owner@example.test',
    scope: 'agents:read passports:read',
  };
}

/** Every file of a `.stack` directory, judged. Returns the problems found as `{ id, file, problem }`. */
function judgeDirectory(dir) {
  const problems = [];
  const credentialsPath = join(dir, 'credentials.json');
  let exists = true;
  try { statSync(credentialsPath); } catch { exists = false; }
  const files = [];
  if (exists) {
    files.push(credentialsPath);
    const { value, error } = readJson(credentialsPath);
    const problem = error ? `it is not JSON: ${error}` : credentialsProblem(value);
    if (problem) problems.push({ id: 'F01', file: 'credentials.json', problem });
    else if (value.refresh_expires_at <= value.issued_at) problems.push({ id: 'F02', file: 'credentials.json', problem: '"refresh_expires_at" is not after "issued_at"' });
  }
  const agentsDir = join(dir, 'agents');
  let names = [];
  try { names = readdirSync(agentsDir); } catch { /* none */ }
  for (const name of names) {
    const path = join(agentsDir, name);
    if (!name.endsWith('.json')) {
      problems.push({ id: 'F06', file: `agents/${name}`, problem: 'a file that is not an agent key is left in the directory of the keys' });
      continue;
    }
    files.push(path);
    const { value, error } = readJson(path);
    const problem = error ? `it is not JSON: ${error}` : agentKeyProblem(value, name.slice(0, -'.json'.length));
    if (problem) problems.push({ id: 'F03', file: `agents/${name}`, problem });
  }
  try { statSync(join(dir, 'credentials.lock')); files.push(join(dir, 'credentials.lock')); } catch { /* none */ }
  if (POSIX) {
    for (const path of files) {
      const mode = statSync(path).mode & 0o777;
      if ((mode & 0o077) !== 0) problems.push({ id: 'F05', file: path.slice(dir.length + 1).replaceAll('\\', '/'), problem: `the mode is ${mode.toString(8).padStart(3, '0')}: it is readable by others` });
    }
  }
  return { problems, count: files.length };
}

/**
 * @param {{
 *   dir?: string,
 *   write?: (input: { home: string, dir: string, credentials: object }) => Promise<void> | void,
 *   writeAgentKey?: (input: { home: string, dir: string, agentId: string }) => Promise<void> | void,
 *   read?: (input: { home: string, dir: string }) => Promise<object | null> | object | null,
 * }} options
 */
export async function runCredentialsFilesSuite(options) {
  const { dir, write, writeAgentKey, read } = options;
  const temporary = [];
  const fresh = () => {
    const home = mkdtempSync(join(tmpdir(), 'stack-conformance-home-'));
    temporary.push(home);
    return { home, dir: join(home, '.stack') };
  };
  const judged = (id, label) => ({
    id, level: 'MUST', title: label,
    async run() {
      if (!dir) return skip('needs dir: a .stack directory your client wrote');
      const { problems, count } = judgeDirectory(dir);
      if (count === 0) return skip('the directory holds none of the files');
      const mine = problems.filter((p) => p.id === id);
      assert(mine.length === 0, mine.map((p) => `${p.file}: ${p.problem}`).join('; '));
    },
  });

  const checks = [
    judged('F01', 'credentials.json is a JSON object with the fields of the sign-in'),
    judged('F02', 'the sign-in expires after it was issued'),
    judged('F03', 'every file of agents/ is an agent key whose agent_id is its name and whose key pair is consistent'),
    judged('F05', 'no file is readable by others (mode 0600)'),
    {
      id: 'F06', level: 'SHOULD', title: 'nothing but agent keys is left in agents/',
      async run() {
        if (!dir) return skip('needs dir: a .stack directory your client wrote');
        const mine = judgeDirectory(dir).problems.filter((p) => p.id === 'F06');
        assert(mine.length === 0, mine.map((p) => `${p.file}: ${p.problem}`).join('; '));
      },
    },

    // ─── A writer ───
    {
      id: 'W01', level: 'MUST', title: 'a client writes the sign-in it is given to .stack/credentials.json, whole, for its owner only',
      async run() {
        if (!write) return skip('needs write: a function that makes your client write a sign-in');
        const target = fresh();
        const credentials = makeCredentials();
        await write({ ...target, credentials });
        const { value, error } = readJson(join(target.dir, 'credentials.json'));
        assert(!error, `credentials.json is not JSON: ${error}`);
        assertEqual(credentialsProblem(value), null, 'credentials.json');
        for (const [field, expected] of Object.entries(credentials)) assertEqual(value[field], expected, `credentials.json "${field}"`);
        if (POSIX) assertEqual(statSync(join(target.dir, 'credentials.json')).mode & 0o777, 0o600, 'the mode of credentials.json');
      },
    },
    {
      id: 'W02', level: 'MUST', title: 'a client stores the key it generates for an agent at agents/<agent_id>.json: a consistent Ed25519 pair, for its owner only',
      async run() {
        if (!writeAgentKey) return skip('needs writeAgentKey: a function that makes your client generate and store an agent key');
        const target = fresh();
        const agentId = `agt_${randomBytes(12).toString('base64url')}`;
        await writeAgentKey({ ...target, agentId });
        const path = join(target.dir, 'agents', `${agentId}.json`);
        const { value, error } = readJson(path);
        assert(!error, `agents/${agentId}.json is not JSON: ${error}`);
        assertEqual(agentKeyProblem(value, agentId), null, `agents/${agentId}.json`);
        if (POSIX) assertEqual(statSync(path).mode & 0o777, 0o600, 'the mode of the key file');
        const second = fresh();
        await writeAgentKey({ ...second, agentId });
        const other = readJson(join(second.dir, 'agents', `${agentId}.json`)).value;
        assert(other?.privateKey?.d !== value.privateKey.d, 'two clients generated the same private key');
      },
    },

    // ─── A reader ───
    {
      id: 'R01', level: 'MUST', title: 'a client uses the sign-in in a good file, and ignores fields it does not know',
      async run() {
        if (!read) return skip('needs read: a function that returns the sign-in your client would use');
        const target = fresh();
        mkdirSync(target.dir, { recursive: true });
        const credentials = { ...makeCredentials(), field_of_a_later_version: { kept: true } };
        writeFileSync(join(target.dir, 'credentials.json'), JSON.stringify(credentials, null, 2), { mode: 0o600 });
        const used = await read(target);
        assert(isObject(used), 'the client found no sign-in in a good file');
        assertEqual(used.client_id, credentials.client_id, 'client_id');
        assertEqual(used.refresh_token, credentials.refresh_token, 'refresh_token');
      },
    },
    {
      id: 'R02', level: 'MUST', title: 'a client uses no sign-in from a file that is missing, not JSON, or without a client id and a refresh token',
      async run() {
        if (!read) return skip('needs read: a function that returns the sign-in your client would use');
        const good = makeCredentials();
        const bodies = [
          undefined,
          '',
          'not json',
          '[]',
          'null',
          '"text"',
          '{}',
          JSON.stringify({ ...good, client_id: undefined }),
          JSON.stringify({ ...good, refresh_token: undefined }),
          JSON.stringify({ ...good, client_id: '' }),
          JSON.stringify({ ...good, refresh_token: '' }),
          JSON.stringify({ ...good, refresh_token: 12345 }),
        ];
        for (const body of bodies) {
          const target = fresh();
          mkdirSync(target.dir, { recursive: true });
          if (body !== undefined) writeFileSync(join(target.dir, 'credentials.json'), body);
          let used;
          try { used = await read(target); } catch { used = null; }
          assert(used === null || used === undefined, `the client used a sign-in from ${body === undefined ? 'no file' : JSON.stringify(body).slice(0, 60)}`);
        }
      },
    },
  ];

  try {
    return await runChecks('credentials files', checks);
  } finally {
    for (const home of temporary) rmSync(home, { recursive: true, force: true });
  }
}

