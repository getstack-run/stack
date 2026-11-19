// The reference provider adapter (reference-adapter.mjs) is a fake that implements the provider interface. It must
// pass the provider suite, as a library and as the command line a user runs on their own adapter.

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatReport, runProviderAdapterSuite } from '../src/index.mjs';
import createHarness from './reference-adapter.mjs';
import { REPO } from './support.mjs';

describe('the reference provider adapter', () => {
  it('conforms as a library, with nothing failed and no warning', async () => {
    const report = await runProviderAdapterSuite(createHarness());
    expect(report.conforms, formatReport(report)).toBe(true);
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBeGreaterThan(15);
  });

  it('conforms through the command line, which is how the kit is run on an adapter of your own', () => {
    const kit = join(REPO, 'spec', 'conformance');
    const run = spawnSync(process.execPath, [join(kit, 'bin', 'stack-conformance.mjs'), 'provider', '--module', join(kit, 'reference', 'reference-adapter.mjs'), '--json'], { encoding: 'utf8' });
    expect(run.status, run.stderr).toBe(0);
    const report = JSON.parse(run.stdout);
    expect(report.conforms).toBe(true);
    expect(report.failed).toBe(0);
  });
});
