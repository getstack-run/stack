// node --test scripts/generate-spec.test.mjs
//
// The generator is what stops the written specifications drifting from the
// code, so it must be shown to notice drift: each case damages a copy of spec/
// in one way and requires `--check` to fail and to say why. It needs the
// packages built (`pnpm exec turbo build`), as the generator does.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = join(ROOT, 'scripts', 'generate-spec.mjs');

function check(specRoot) {
  const run = spawnSync(process.execPath, [SCRIPT, '--check'], {
    encoding: 'utf8',
    env: { ...process.env, ...(specRoot ? { STACK_SPEC_ROOT: specRoot } : {}) },
    timeout: 120_000,
  });
  return { status: run.status, output: `${run.stdout}${run.stderr}` };
}

/** A copy of spec/ (without installed or built folders) that a case may damage. */
function copyOfSpec(t) {
  const dir = mkdtempSync(join(tmpdir(), 'stack-spec-'));
  cpSync(join(ROOT, 'spec'), join(dir, 'spec'), {
    recursive: true,
    filter: (source) => !/[\\/](node_modules|dist|\.turbo)$/.test(source),
  });
  // Assert the path comes straight from mkdtemp in the system temporary directory before removing it.
  t.after(() => {
    assert.equal(dirname(dir), join(tmpdir()));
    rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

function edit(dir, path, fn) {
  const full = join(dir, path);
  const before = readFileSync(full, 'utf8').replaceAll('\r\n', '\n');
  const after = fn(before);
  assert.notEqual(after, before, `the case did not change ${path}`);
  writeFileSync(full, after);
}

test('the specification in the repository is current with the code', () => {
  const result = check();
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /spec is current/);
});

test('a hand-edited generated schema is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/passport/schemas/PassportClaims.json', (text) => text.replace('"agent_id"', '"agent_identifier"'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /spec\/passport\/schemas\/PassportClaims\.json/);
});

test('a tool missing from the catalog is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/mcp-tools/tools.json', (text) => {
    const catalog = JSON.parse(text);
    catalog.tools = catalog.tools.filter((tool) => tool.name !== 'stack_issue_passport');
    return `${JSON.stringify(catalog, null, 2)}\n`;
  });
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /spec\/mcp-tools\/tools\.json/);
});

test('a generated constants table that was edited by hand is rewritten, not trusted', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/passport/SPEC.md', (text) => text.replace('| Maximum delegation depth | 4 |', '| Maximum delegation depth | 40 |'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /spec\/passport\/SPEC\.md/);
});

test('an action kind with no row in the control socket specification is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/control-socket/SPEC.md', (text) => text.split('\n').filter((line) => !line.startsWith('| `wallet.payment` |')).join('\n'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /wallet\.payment/);
});

test('a revocation event type with no row in the Passport specification is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/passport/SPEC.md', (text) => text.split('\n').filter((line) => !line.startsWith('| `bulk_mission` |')).join('\n'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /bulk_mission/);
});

test('a catalogue section status or price unit with no row in the catalogue specification is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/catalogue/SPEC.md', (text) => text.split('\n').filter((line) => !line.startsWith('| `stale` |') && !line.startsWith('| `varies` |')).join('\n'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /section status stale/);
  assert.match(result.output, /price unit varies/);
});

test('a hand-edited catalogue schema is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/catalogue/schemas/CatalogueEntry.json', (text) => text.replace('"result_trust"', '"result_trustworthiness"'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /spec\/catalogue\/schemas\/CatalogueEntry\.json/);
});

test('a specification version without a matching changelog entry is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/record/SPEC.md', (text) => text.replace('**Version:** 1.0.0', '**Version:** 1.1.0'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /1\.1\.0.*1\.0\.0|first release/s);
});

test('a generated block that the code no longer fills is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/provider-interface/SPEC.md', (text) => text.replace('spec:generated:provider-piece-kinds', 'spec:generated:no-such-block'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /no-such-block/);
});

test('an operation removed from the REST API document is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/rest-api/openapi.json', (text) => {
    const document = JSON.parse(text);
    delete document.paths['/v1/dropoffs'];
    return `${JSON.stringify(document, null, 2)}\n`;
  });
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /spec\/rest-api\/openapi\.json/);
});

test('an operation added to the REST API document by hand is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/rest-api/openapi.json', (text) => {
    const document = JSON.parse(text);
    document.paths['/v1/not-a-route'] = { get: { operationId: 'getV1NotARoute', responses: { default: { description: 'x' } } } };
    return `${JSON.stringify(document, null, 2)}\n`;
  });
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /spec\/rest-api\/openapi\.json/);
});

test('an error code in the REST API text that the engine does not raise is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/rest-api/SPEC.md', (text) => text.replace('| `RATE_LIMITED` | 429 |', '| `NO_SUCH_CODE` | 418 | A code nothing raises. |\n| `RATE_LIMITED` | 429 |'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /NO_SUCH_CODE/);
});

test('an error code given another status in the REST API text is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/rest-api/SPEC.md', (text) => text.replace('| `INVALID_API_KEY` | 401 |', '| `INVALID_API_KEY` | 403 |'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /INVALID_API_KEY.*403/s);
});

test('an operation named in the REST API text that the engine does not serve is caught', (t) => {
  const dir = copyOfSpec(t);
  edit(dir, 'spec/rest-api/SPEC.md', (text) => text.replace('`GET /v1/governance/approvals`', '`GET /v1/governance/approvals-list`'));
  const result = check(dir);
  assert.equal(result.status, 1);
  assert.match(result.output, /approvals-list/);
});

test('the agent identity constants the specification prints are STACK\'s public constants, not hosted ones, so the public repository can write the table', () => {
  // The generator names these; every one must come from the main entry of @stack/shared, which the export carries.
  const names = [
    'AGENT_IDENTITY_TYP', 'AGENT_IDENTITY_AUDIENCE', 'AGENT_IDENTITY_CLAIM_VERSION', 'AGENT_IDENTITY_TTL_SECONDS', 'AGENT_IDENTITY_MAX_TTL_SECONDS',
    'AGENT_IDENTITY_SELECTORS', 'AGENT_IDENTITY_STATUSES', 'AGENT_IDENTITY_NAME_MAX', 'AGENT_IDENTITY_SETTING_DEFAULTS',
    'AGENT_IDENTITY_ANONYMOUS_DESCRIPTION', 'AGENT_IDENTITY_FILES',
  ];
  // Read from the built main entry in a child process: the module is named by a path computed here, which the export's closure check could not follow.
  const entry = pathToFileURL(join(ROOT, 'packages', 'shared', 'dist', 'index.js')).href;
  const probe = spawnSync(process.execPath, ['--input-type=module', '-e', `const m = await import(${JSON.stringify(entry)}); console.log(JSON.stringify(${JSON.stringify(names)}.filter((name) => m[name] === undefined)));`], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(probe.status, 0, probe.stderr);
  assert.deepEqual(JSON.parse(probe.stdout), [], 'a constant of the agent identity specification is not exported by the main entry of @stack/shared');
  const generator = readFileSync(SCRIPT, 'utf8');
  for (const name of names) assert.ok(generator.includes(name), `the generator no longer names ${name}`);
  // The constants are not read from the hosted entry, and the export is not excused for naming them.
  assert.ok(!/shared\/hosted|src\/hosted/.test(generator.split('\n').filter((line) => /AGENT_IDENTITY_/.test(line)).join('\n')));
  // The export manifest is private (the public repository has no exporter): where it is, it excuses none of these names.
  const manifestPath = join(ROOT, 'scripts', 'public-repo', 'manifest.json');
  if (existsSync(manifestPath)) {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const excused = manifest.scan_allow.filter((entry) => /AGENT_IDENTITY_|identity/.test(entry.pattern));
    assert.deepEqual(excused, [], 'a hosted identifier of the agent identity specification is excused in the export manifest');
  }
});
