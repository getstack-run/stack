// Conformance suite for a RECORD VERIFIER (spec/record/SPEC.md section 10).
// The kit feeds each fixture pack in fixtures/record/ to your verifier and
// compares three things with the outcome the specification demands: `valid`,
// `complete`, and the set of error codes (as a set, ignoring order and
// repetition).
//
// A verifier is either
//   - a function  verify(manifest, options) -> VerifyResult  (async or not), or
//   - a program, wrapped with `commandRecordVerifier`: it is run as
//       <program> [...args] <path to pack.json> [--strict] [--ignore-unknown] [--air-gap] --json
//     and must print the VerifyResult as JSON on stdout (exit code 0 or 1).
//
// `options` is { strict?, ignoreUnknown?, airGap? }.

import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assert, fail, runChecks } from './harness.mjs';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'record');

export function loadRecordFixtures(dir = FIXTURES) {
  const expected = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8'));
  return expected.fixtures.map((entry) => ({ ...entry, manifest: JSON.parse(readFileSync(join(dir, entry.file), 'utf8')) }));
}

/**
 * @param {{ verify: (manifest: object, options: { strict?: boolean, ignoreUnknown?: boolean, airGap?: boolean }) => Promise<any> | any, level?: 1 | 2 | 3, fixturesDir?: string }} options
 */
export async function runRecordVerifierSuite(options) {
  const { verify, level = 1, fixturesDir } = options;
  const fixtures = loadRecordFixtures(fixturesDir).filter((f) => f.level <= level);
  const checks = fixtures.map((fixture, index) => ({
    id: `R${String(index + 1).padStart(2, '0')}`,
    level: 'MUST',
    title: `${fixture.file.replace('.json', '')}: ${fixture.description}`,
    async run() {
      let result;
      try {
        result = await verify(structuredClone(fixture.manifest), fixture.options);
      } catch (error) {
        fail(`the verifier threw: ${error instanceof Error ? error.message : String(error)}`);
      }
      assert(result && typeof result === 'object', 'the verifier returned no result');
      const codes = [...new Set((result.errors ?? []).map((e) => e.code))].sort();
      const problems = [];
      if (result.valid !== fixture.valid) problems.push(`valid is ${result.valid}, expected ${fixture.valid}`);
      if (result.complete !== fixture.complete) problems.push(`complete is ${result.complete}, expected ${fixture.complete}`);
      if (JSON.stringify(codes) !== JSON.stringify(fixture.errors)) {
        problems.push(`error codes are [${codes.join(', ')}], expected [${fixture.errors.join(', ')}]`);
      }
      if (problems.length > 0) fail(problems.join('; '));
    },
  }));
  checks.push({
    id: 'R90',
    level: 'MUST',
    title: 'refuses strict together with ignore-unknown',
    async run() {
      const manifest = fixtures[0]?.manifest;
      assert(manifest, 'no fixtures loaded');
      let outcome = 'returned';
      try {
        const result = await verify(structuredClone(manifest), { strict: true, ignoreUnknown: true });
        if (result && result.valid === false) outcome = 'invalid';
      } catch {
        outcome = 'threw';
      }
      assert(outcome !== 'returned', 'strict and ignore-unknown together were accepted and gave a valid result');
    },
  });
  return runChecks(`record verifier (level ${level})`, checks);
}

/** Wrap a program as a record verifier (see the header of this file). */
export function commandRecordVerifier(command, args = []) {
  return (manifest, options = {}) =>
    new Promise((resolve, reject) => {
      const dir = mkdtempSync(join(tmpdir(), 'stack-conformance-'));
      const path = join(dir, 'pack.json');
      writeFileSync(path, JSON.stringify(manifest));
      const flags = [options.strict && '--strict', options.ignoreUnknown && '--ignore-unknown', options.airGap && '--air-gap', '--json'].filter(Boolean);
      const child = spawn(command, [...args, path, ...flags], { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
      let out = '';
      let err = '';
      child.stdout.on('data', (chunk) => { out += chunk; });
      child.stderr.on('data', (chunk) => { err += chunk; });
      child.on('error', (error) => { rmSync(dir, { recursive: true, force: true }); reject(error); });
      child.on('close', () => {
        rmSync(dir, { recursive: true, force: true });
        try {
          resolve(JSON.parse(out));
        } catch {
          reject(new Error(`the program printed no JSON result${err ? `: ${err.trim().slice(0, 200)}` : ''}`));
        }
      });
    });
}
