// The reference exporter and collector of the security-monitoring export (siem-reference.mjs) pass the suites that judge
// them, and each defective variant fails the checks that name its defect. A kit that cannot fail a broken implementation
// would certify anything.

import { describe, expect, it } from 'vitest';
import { formatSyslogMessage, makeSiemRecords, octetFrames, parseSyslogMessage, readOctetFrames, recordProblem, runSiemCollectorSuite, runSiemExporterSuite } from '../src/index.mjs';
import { COLLECTOR_QUIRKS, EXPORTER_QUIRKS, createReferenceExporter, startReferenceCollector } from './siem-reference.mjs';

// The exporter reads its settling delay against this clock, so that a record emitted after its first pass is old enough at the next.
const later = () => Date.now() + 3_600_000;
const exporterSuite = (quirk, transports) => runSiemExporterSuite({ transports, exporter: async (config) => createReferenceExporter(config, { quirk, now: later }) });
const collectorSuite = (quirk) => runSiemCollectorSuite({ collector: async ({ token }) => startReferenceCollector({ token, quirk }) });
const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const failed = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);

describe('the wire format helpers', () => {
  it('builds a message the parser reads back, with the escaping of RFC 5424', () => {
    const [record] = makeSiemRecords('security', 1, { over: () => ({ id: 'a"b]c\\d', event: 'x y/z' }) });
    const parsed = parseSyslogMessage(formatSyslogMessage(record));
    expect(parsed.pri).toBe(38);
    expect(Object.fromEntries(parsed.params)).toMatchObject({ id: 'a"b]c\\d', event: 'x_y_z', stream: 'security' });
    expect(JSON.parse(parsed.msg)).toEqual(record);
    expect(recordProblem(record)).toBeUndefined();
    expect(recordProblem({ ...record, extra: 1 })).toMatch(/members/);
  });

  it('counts octets in bytes and reads a frame that arrives in pieces', () => {
    const whole = octetFrames(['héllo', 'second']);
    expect(whole.toString('utf8')).toBe('6 héllo6 second');
    const first = readOctetFrames(whole.subarray(0, 4));
    expect(first.frames).toEqual([]);
    const all = readOctetFrames(whole);
    expect(all.frames.map((f) => f.toString('utf8'))).toEqual(['héllo', 'second']);
    expect(all.rest.length).toBe(0);
  });
});

describe.concurrent('the reference exporter', { timeout: 240_000 }, () => {
  it('passes the siem-exporter suite with every check run', async () => {
    const report = await exporterSuite('none');
    expect(report.results.filter((r) => r.status !== 'pass'), JSON.stringify(report.results.filter((r) => r.status !== 'pass'))).toEqual([]);
    expect(report.results.length).toBe(15);
    expect(report.conforms).toBe(true);
  });

  it('skips what the harness does not offer, never passes it', async () => {
    const report = await exporterSuite('none', ['https']);
    expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(expect.arrayContaining(['X10', 'X13', 'X14', 'X20', 'X41']));
    expect(report.results.filter((r) => r.status === 'fail')).toEqual([]);
  });

  // [quirk, the checks that must fail]
  const defects = [
    ['wrong-pri', ['X10']],
    ['sd-unescaped', ['X11']],
    ['newline-framing', ['X10', 'X13']],
    ['char-count', ['X13']],
    ['no-truncate', ['X12']],
    ['udp-batch', ['X14']],
    ['replays-history', ['X01']],
    ['no-bearer', ['X30']],
    ['no-final-newline', ['X30']],
    ['one-request', ['X30']],
    ['tls-insecure', ['X21']],
    ['follows-redirects', ['X40']],
    ['drops-on-failure', ['X40', 'X41']],
    ['leaks-canary', ['X50']],
    ['reorders', ['X32']],
    ['duplicates', ['X32']],
    ['ignores-streams', ['X32']],
    ['extra-fields', ['X30', 'X50']],
  ];

  it('has a defective variant for every quirk it lists', () => {
    expect(defects.map(([quirk]) => quirk).sort()).toEqual(EXPORTER_QUIRKS.filter((q) => q !== 'none').sort());
  });

  for (const [quirk, ids] of defects) {
    it(`fails an exporter with the defect "${quirk}" at ${ids.join(' and ')}`, async () => {
      const report = await exporterSuite(quirk);
      expect(report.conforms).toBe(false);
      expect(mustFailed(report)).toEqual(expect.arrayContaining(ids));
    });
  }
});

describe.concurrent('the reference collector', { timeout: 240_000 }, () => {
  it('passes the siem-collector suite with every check run', async () => {
    const report = await collectorSuite('none');
    expect(report.results.filter((r) => r.status !== 'pass'), JSON.stringify(report.results.filter((r) => r.status !== 'pass'))).toEqual([]);
    expect(report.results.length).toBe(10);
    expect(report.conforms).toBe(true);
  });

  const defects = [
    ['no-dedupe', ['C06'], true],
    ['dedupe-by-id', ['C06'], true],
    ['newline-split', ['C02', 'C03'], true],
    ['char-count', ['C02'], true],
    ['no-auth', ['C05'], true],
    ['sd-parse', ['C07'], true],
    ['ack-before-store', ['C04'], true],
    ['rejects-unknown', ['C08'], true],
    ['rejects-truncated', ['C08'], true],
    ['redirect', ['C09'], true],
    ['body-limit', ['C04'], true],
    ['accepts-bad-body', ['C10'], false],
  ];

  it('has a defective variant for every quirk it lists', () => {
    expect(defects.map(([quirk]) => quirk).sort()).toEqual(COLLECTOR_QUIRKS.filter((q) => q !== 'none').sort());
  });

  for (const [quirk, ids, isMust] of defects) {
    it(`fails a collector with the defect "${quirk}" at ${ids.join(' and ')}${isMust ? '' : ' (a warning)'}`, async () => {
      const report = await collectorSuite(quirk);
      expect(failed(report)).toEqual(expect.arrayContaining(ids));
      expect(report.conforms).toBe(!isMust);
    });
  }
});
