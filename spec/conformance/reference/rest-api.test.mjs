// The reference server of the REST API wire contract must pass the `rest-api` suite, and the suite must fail a server that
// has one deliberate defect, naming the checks that defect should break.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { envelopeProblem, formatReport, runRestApiSuite } from '../src/index.mjs';
import { QUIRKS, startRestApiServer } from './rest-api-server.mjs';
import { REPO } from './support.mjs';

const servers = [];
afterAll(() => Promise.all(servers.map((s) => s.close())));
const start = async (quirk, options = {}) => {
  const server = await startRestApiServer({ quirk, ...options });
  servers.push(server);
  return server;
};
const run = (server, extra = {}) =>
  runRestApiSuite({
    url: server.url,
    apiKey: server.apiKey,
    approve: server.approve,
    probes: { payment: server.probes.payment, controls: server.probes.controls, costCap: server.probes.costCap, perJob: server.probes.perJob },
    timeoutMs: 5000,
    ...extra,
  });
/** The CLI as a child process, asynchronously: the server under test runs in this process and has to keep answering. */
const cli = (args, env = {}) =>
  new Promise((done) => {
    const child = spawn(process.execPath, [join(REPO, 'spec', 'conformance', 'bin', 'stack-conformance.mjs'), ...args], { env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('exit', (status) => done({ status, stdout, stderr }));
  });
const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe('rest-api suite', () => {
  it('passes the reference server with every check run, by a gated change that is not registering an agent, and leaves no agent behind', async () => {
    const server = await start('none');
    const report = await run(server);
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(27);
    expect(server.agents.size, 'agents the suite made and did not remove').toBe(0);
    expect([...server.approvals.values()].some((approval) => approval.action === 'agent_unblock')).toBe(true);
    expect([...server.approvals.values()].some((approval) => approval.action === 'agent_register')).toBe(false);
  });

  it('asks for registering an agent when that is what the server gates, and leaves no agent behind', async () => {
    const server = await start('none', { gate: 'register' });
    const report = await run(server);
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(27);
    expect([...server.approvals.values()].some((approval) => approval.action === 'agent_register')).toBe(true);
    expect(server.agents.size, 'agents the suite made and did not remove').toBe(0);
  });

  it('asks for the gated change a server names in its probes', async () => {
    const server = await start('none', { gate: 'register' });
    const stepUp = { asked: { method: 'POST', path: '/v1/agents/register', body: { name: 'named-by-probes' } }, other: { method: 'POST', path: '/v1/agents/register', body: { name: 'named-by-probes-other' } } };
    const report = await run(server, { probes: { payment: server.probes.payment, controls: server.probes.controls, costCap: server.probes.costCap, perJob: server.probes.perJob, stepUp } });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.passed).toBe(27);
  });

  it('judges a cost cap on a key of the deployment\'s own by the worst case, not by the key', async () => {
    const server = await start('none');
    const report = await run(server, { probes: { costCap: server.probes.costCapDeploymentKey } });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.results.filter((r) => r.id.startsWith('M')).map((r) => r.status)).toEqual(['pass', 'pass']);
  });

  it('runs what needs no credential, and skips the rest with the reason, never passes it', async () => {
    const server = await start('none');
    const report = await runRestApiSuite({ url: server.url, timeoutMs: 5000 });
    expect(report.failed, formatReport(report)).toBe(0);
    const skipped = report.results.filter((r) => r.status === 'skip');
    expect(skipped.map((r) => r.id)).toEqual(['A03', 'A04', 'S01', 'S02', 'S03', 'S04', 'S05', 'S06', 'S07', 'S10', 'P01', 'C01', 'C02', 'M01', 'M02']);
    expect(skipped.every((r) => r.detail)).toBe(true);
  });

  it('skips the retry of an approved change when nobody can decide the approval', async () => {
    const server = await start('none');
    const report = await run(server, { approve: undefined });
    expect(report.failed).toBe(0);
    expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['S10']);
  });

  describe('fails a server with one defect', () => {
    const expectations = {
      'plain-404': ['R01', 'R02', 'R03'],
      'echo-404': ['R03'],
      'status-405': ['R02'],
      'no-head': ['R04'],
      'parser-500': ['R10'],
      'verbose-401': ['A02'],
      'wrong-415': ['R12'],
      'passport-500': ['R14'],
      'pending-accepted': ['S05', 'S07'],
      reusable: ['S10'],
      unbound: ['S10'],
      'bearer-decides': ['S07'],
      'no-details': ['S01', 'S03', 'S04', 'S05', 'S07', 'S10'],
      'cap-lenient': ['M01'],
      'cap-ignored': ['M02'],
      'payment-text': ['P01'],
      'socket-5xx': ['C01'],
      'per-job-open': ['C02'],
      'stranger-allowed': ['C02'],
      'names-recipient': ['C02'],
    };
    for (const [quirk, ids] of Object.entries(expectations)) {
      it(quirk, async () => {
        const report = await run(await start(quirk));
        expect(mustFailedIds(report), formatReport(report)).toEqual(ids);
      });
    }

    it('echo-validation: a validation message that carries the values sent is a warning, not a failure', async () => {
      const report = await run(await start('echo-validation'));
      expect(mustFailedIds(report), formatReport(report)).toEqual([]);
      expect(report.results.filter((r) => r.status === 'fail').map((r) => r.id)).toEqual(['R15']);
    });

    it('extra-property: a body that is not only "error" fails every check that reads an error', async () => {
      const report = await run(await start('extra-property'));
      expect(mustFailedIds(report)).toEqual(expect.arrayContaining(['R01', 'A01', 'S01', 'P01', 'C01', 'M02']));
    });

    it('has a negative control for every quirk the reference server has', () => {
      const covered = new Set([...Object.keys(expectations), 'none', 'extra-property', 'echo-validation']);
      expect(QUIRKS.filter((quirk) => !covered.has(quirk))).toEqual([]);
    });
  });

  it('reads an error answer the way the specification describes it', () => {
    const answer = (status, body, type = 'application/json; charset=utf-8') => ({ status, headers: new Headers({ 'content-type': type }), json: body });
    const good = { error: { code: 'NOT_FOUND', message: 'x' } };
    expect(envelopeProblem(answer(404, good))).toBeNull();
    expect(envelopeProblem(answer(404, { error: { ...good.error, details: { a: 1 } } }))).toBeNull();
    expect(envelopeProblem(answer(200, good))).toMatch(/not an error/);
    expect(envelopeProblem(answer(404, good, 'text/html'))).toMatch(/content type/);
    expect(envelopeProblem(answer(404, { error: 'Not Found' }))).toMatch(/not an object/);
    expect(envelopeProblem(answer(404, { ...good, statusCode: 404 }))).toMatch(/properties/);
    expect(envelopeProblem(answer(404, { error: { code: 'not_upper', message: 'x' } }))).toMatch(/code/);
    expect(envelopeProblem(answer(404, { error: { code: 'NOT_FOUND', message: '' } }))).toMatch(/message/);
    expect(envelopeProblem(answer(404, { error: { ...good.error, details: [] } }))).toMatch(/details/);
    expect(envelopeProblem(answer(404, { error: { ...good.error, hint: 'x' } }))).toMatch(/extra/);
  });

  it('runs from the command line, with the probes in a file, and exits 0 for a server that conforms', async () => {
    const server = await start('none');
    const dir = mkdtempSync(join(tmpdir(), 'stack-rest-api-'));
    try {
      const probes = join(dir, 'probes.json');
      writeFileSync(probes, JSON.stringify({ payment: server.probes.payment, controls: server.probes.controls, costCap: server.probes.costCap, perJob: server.probes.perJob }));
      const ok = await cli(['rest-api', '--url', server.url, '--probes', probes, '--json'], { STACK_CONFORMANCE_API_KEY: server.apiKey });
      expect(ok.status, ok.stderr).toBe(0);
      const report = JSON.parse(ok.stdout);
      expect(report.conforms).toBe(true);
      expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['S10']);

      const broken = await start('parser-500');
      const bad = await cli(['rest-api', '--url', broken.url]);
      expect(bad.status).toBe(1);
      expect(bad.stdout).toContain('DOES NOT CONFORM');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
