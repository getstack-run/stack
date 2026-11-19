// A tiny check runner shared by every suite. A suite is a list of checks; each
// check is a MUST (a failure means the implementation does not conform) or a
// SHOULD (a failure is reported as a warning and does not fail the run).

/**
 * @typedef {'MUST' | 'SHOULD'} Level
 * @typedef {{ id: string, level: Level, title: string, run: () => Promise<void | 'skip' | { skip: string }> }} Check
 * @typedef {{ id: string, level: Level, title: string, status: 'pass' | 'fail' | 'skip', detail?: string }} CheckResult
 * @typedef {{ suite: string, results: CheckResult[], failed: number, warnings: number, passed: number, skipped: number, conforms: boolean }} Report
 */

export class CheckFailure extends Error {}

/** Throw a failure with a message a person can act on. */
export function fail(message) {
  throw new CheckFailure(message);
}

export function assert(condition, message) {
  if (!condition) fail(message);
}

export function assertEqual(actual, expected, message) {
  if (actual !== expected) fail(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

/** Skip a check from inside it, with the reason. */
export function skip(reason) {
  return { skip: reason };
}

/**
 * Run the checks in order. A check that throws fails (an unexpected exception
 * is reported with its message). Checks are independent: one failing does not
 * stop the others.
 * @param {string} suite
 * @param {Check[]} checks
 * @returns {Promise<Report>}
 */
export async function runChecks(suite, checks) {
  /** @type {CheckResult[]} */
  const results = [];
  for (const check of checks) {
    try {
      const outcome = await check.run();
      if (outcome && typeof outcome === 'object' && 'skip' in outcome) {
        results.push({ id: check.id, level: check.level, title: check.title, status: 'skip', detail: outcome.skip });
      } else {
        results.push({ id: check.id, level: check.level, title: check.title, status: 'pass' });
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      results.push({
        id: check.id,
        level: check.level,
        title: check.title,
        status: 'fail',
        detail: error instanceof CheckFailure ? detail : `unexpected error: ${detail}`,
      });
    }
  }
  const failed = results.filter((r) => r.status === 'fail' && r.level === 'MUST').length;
  const warnings = results.filter((r) => r.status === 'fail' && r.level === 'SHOULD').length;
  const passed = results.filter((r) => r.status === 'pass').length;
  const skipped = results.filter((r) => r.status === 'skip').length;
  return { suite, results, failed, warnings, passed, skipped, conforms: failed === 0 };
}

/** A plain-text report. */
export function formatReport(report) {
  const lines = [`${report.suite}`];
  for (const r of report.results) {
    const mark = r.status === 'pass' ? 'ok  ' : r.status === 'skip' ? 'skip' : r.level === 'MUST' ? 'FAIL' : 'warn';
    lines.push(`  ${mark} ${r.id} [${r.level}] ${r.title}${r.detail ? `\n         ${r.detail}` : ''}`);
  }
  lines.push(
    `  ${report.passed} passed, ${report.failed} failed, ${report.warnings} warnings, ${report.skipped} skipped: ` +
      (report.conforms ? 'CONFORMS' : 'DOES NOT CONFORM'),
  );
  return lines.join('\n');
}

/** A fetch with a hard timeout that never throws on a non-2xx status. */
export async function post(url, { headers, body, timeoutMs = 10_000, fetchImpl = fetch }) {
  const started = performance.now();
  const response = await fetchImpl(url, {
    method: 'POST',
    headers,
    body,
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await response.text();
  return { status: response.status, headers: response.headers, text, ms: Math.round(performance.now() - started) };
}
