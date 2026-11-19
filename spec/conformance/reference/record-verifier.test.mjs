// @getstackrun/verify is the reference record verifier (spec/record section 8),
// as a library and as the command line a user runs. Both must pass the kit.

import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyPack } from '@getstackrun/verify';
import { commandRecordVerifier, formatReport, runRecordVerifierSuite } from '../src/index.mjs';
import { REPO } from './support.mjs';

describe('@getstackrun/verify', () => {
  it('conforms as a library, at level 2', async () => {
    const verify = (manifest, o) => verifyPack(manifest, { strict: o.strict, ignoreUnknown: o.ignoreUnknown, airGap: o.airGap });
    const report = await runRecordVerifierSuite({ verify, level: 2 });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.passed).toBe(19);
  });

  it('conforms as a command line, at level 2', async () => {
    const verify = commandRecordVerifier(process.execPath, [join(REPO, 'packages', 'verifier', 'dist', 'cli.js')]);
    const report = await runRecordVerifierSuite({ verify, level: 2 });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.passed).toBe(19);
  });
});
