// The TypeScript SDK is the reference client of the files under ~/.stack: it must pass the `credentials` suite, writing and
// reading them as the specification says, and the suite must fail files and clients that each have one deliberate defect.

import { spawn } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { agentKeyProblem, credentialsProblem, formatReport, makeAgentKey, makeCredentials, runCredentialsFilesSuite } from '../src/index.mjs';
import { createReferenceClient } from './credentials-client.mjs';
import { REPO } from './support.mjs';

const POSIX = process.platform !== 'win32';
const failedIds = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);
const temporary = [];
afterAll(() => temporary.forEach((dir) => rmSync(dir, { recursive: true, force: true })));

/** A `.stack` directory laid out by hand. */
function stackDir({ credentials, agents = [], mode = 0o600 } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'stack-files-'));
  temporary.push(home);
  const dir = join(home, '.stack');
  mkdirSync(join(dir, 'agents'), { recursive: true });
  const put = (path, body) => {
    writeFileSync(path, typeof body === 'string' ? body : JSON.stringify(body, null, 2), { mode });
    if (POSIX) chmodSync(path, mode);
  };
  if (credentials !== undefined) put(join(dir, 'credentials.json'), credentials);
  for (const [name, key] of agents) put(join(dir, 'agents', `${name}.json`), key);
  return dir;
}

describe('credentials suite', () => {
  it('passes the TypeScript SDK as a writer and a reader of the files, and judges what it left', async () => {
    const client = await createReferenceClient();
    try {
      const report = await runCredentialsFilesSuite({ write: client.write, writeAgentKey: client.writeAgentKey, read: client.read });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.warnings, formatReport(report)).toBe(0);
      // Without a directory the F checks have nothing to look at: skipped, never passed.
      expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['F01', 'F02', 'F03', 'F05', 'F06']);
      expect(report.passed).toBe(4);
    } finally {
      await client.close();
    }
  });

  it('passes a directory the SDK wrote, with every file judged', async () => {
    const client = await createReferenceClient();
    try {
      const home = mkdtempSync(join(tmpdir(), 'stack-files-'));
      temporary.push(home);
      await client.write({ home, credentials: makeCredentials() });
      await client.writeAgentKey({ home, agentId: 'agt_written_by_the_sdk' });
      const report = await runCredentialsFilesSuite({ dir: join(home, '.stack') });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.results.filter((r) => ['F01', 'F02', 'F03', 'F05', 'F06'].includes(r.id)).map((r) => r.status)).toEqual(['pass', 'pass', 'pass', 'pass', 'pass']);
    } finally {
      await client.close();
    }
  });

  describe('fails files with one defect', () => {
    const credentials = makeCredentials();
    const key = makeAgentKey('agt_example');
    const run = (dir) => runCredentialsFilesSuite({ dir });

    it('a good directory', async () => {
      expect(failedIds(await run(stackDir({ credentials, agents: [['agt_example', key]] })))).toEqual([]);
    });
    it('a sign-in without a refresh token', async () => {
      expect(failedIds(await run(stackDir({ credentials: { ...credentials, refresh_token: undefined } })))).toEqual(['F01']);
    });
    it('a sign-in that is not JSON', async () => {
      expect(failedIds(await run(stackDir({ credentials: '{ not json' })))).toEqual(['F01']);
    });
    it('a sign-in that expires before it was issued', async () => {
      expect(failedIds(await run(stackDir({ credentials: { ...credentials, refresh_expires_at: credentials.issued_at - 1 } })))).toEqual(['F02']);
    });
    it('a sign-in whose times are not whole seconds', async () => {
      expect(failedIds(await run(stackDir({ credentials: { ...credentials, issued_at: credentials.issued_at + 0.5 } })))).toEqual(['F01']);
    });
    it('an agent key under another name', async () => {
      expect(failedIds(await run(stackDir({ agents: [['agt_other', key]] })))).toEqual(['F03']);
    });
    it('an agent key whose private key is not the public key', async () => {
      const other = makeAgentKey('agt_example');
      expect(failedIds(await run(stackDir({ agents: [['agt_example', { ...key, privateKey: other.privateKey }]] })))).toEqual(['F03']);
    });
    it('an agent key whose enrolment time is text', async () => {
      expect(failedIds(await run(stackDir({ agents: [['agt_example', { ...key, enrolled_at: '2026-10-24T09:30:00.000Z' }]] })))).toEqual(['F03']);
    });
    it('an agent key that is not Ed25519', async () => {
      expect(failedIds(await run(stackDir({ agents: [['agt_example', { ...key, publicKey: { ...key.publicKey, crv: 'P-256' } }]] })))).toEqual(['F03']);
    });
    it.runIf(POSIX)('a file readable by others', async () => {
      expect(failedIds(await run(stackDir({ credentials, agents: [['agt_example', key]], mode: 0o644 })))).toEqual(['F05']);
    });
    it('a temporary file left among the keys', async () => {
      const dir = stackDir({ credentials, agents: [['agt_example', key]] });
      writeFileSync(join(dir, 'agents', 'agt_example.json.1234.tmp'), '{}', { mode: 0o600 });
      expect(failedIds(await run(dir))).toEqual(['F06']);
    });
  });

  describe('fails clients with one defect', () => {
    it('a reader that uses a file with no refresh token', async () => {
      const careless = ({ dir }) => JSON.parse(readFileSync(join(dir, 'credentials.json'), 'utf8'));
      const report = await runCredentialsFilesSuite({ read: careless });
      expect(failedIds(report)).toEqual(['R02']);
    });
    it('a reader that finds nothing in a good file', async () => {
      const blind = () => null;
      expect(failedIds(await runCredentialsFilesSuite({ read: blind }))).toEqual(['R01']);
    });
    it.runIf(POSIX)('a writer that creates the sign-in readable by others', async () => {
      const loose = ({ dir, credentials }) => {
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, 'credentials.json'), JSON.stringify(credentials), { mode: 0o644 });
        chmodSync(join(dir, 'credentials.json'), 0o644);
      };
      expect(failedIds(await runCredentialsFilesSuite({ write: loose }))).toEqual(['W01']);
    });
    it('a writer that drops a field of the sign-in', async () => {
      const lossy = ({ dir, credentials }) => {
        mkdirSync(dir, { recursive: true });
        const { scope: _scope, ...rest } = credentials;
        writeFileSync(join(dir, 'credentials.json'), JSON.stringify(rest), { mode: 0o600 });
      };
      expect(failedIds(await runCredentialsFilesSuite({ write: lossy }))).toEqual(['W01']);
    });
    it('a writer that gives every agent the same key', async () => {
      const key = makeAgentKey('agt_x');
      const fixed = ({ dir, agentId }) => {
        mkdirSync(join(dir, 'agents'), { recursive: true });
        writeFileSync(join(dir, 'agents', `${agentId}.json`), JSON.stringify({ ...key, agent_id: agentId }), { mode: 0o600 });
      };
      expect(failedIds(await runCredentialsFilesSuite({ writeAgentKey: fixed }))).toEqual(['W02']);
    });
  });

  it('reads the files the way the specification describes them', () => {
    const key = makeAgentKey('fleet_' + 'a'.repeat(64));
    expect(agentKeyProblem(key, 'fleet_' + 'a'.repeat(64))).toBeNull();
    expect(agentKeyProblem(key, 'agt_name')).toMatch(/named/);
    expect(credentialsProblem(makeCredentials())).toBeNull();
    expect(credentialsProblem({ ...makeCredentials(), operator_email: 5 })).toMatch(/operator_email/);
    expect(credentialsProblem([])).toMatch(/JSON object/);
  });

  it('runs from the command line against a directory, and exits 1 for one that does not conform', async () => {
    const cli = (args) => new Promise((done) => {
      const child = spawn(process.execPath, [join(REPO, 'spec', 'conformance', 'bin', 'stack-conformance.mjs'), ...args]);
      let stdout = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.on('exit', (status) => done({ status, stdout }));
    });
    const good = await cli(['credentials', '--dir', stackDir({ credentials: makeCredentials(), agents: [['agt_example', makeAgentKey('agt_example')]] }), '--json']);
    expect(good.status).toBe(0);
    expect(JSON.parse(good.stdout).conforms).toBe(true);
    const bad = await cli(['credentials', '--dir', stackDir({ credentials: '{}' })]);
    expect(bad.status).toBe(1);
    expect(bad.stdout).toContain('DOES NOT CONFORM');
  });
});
