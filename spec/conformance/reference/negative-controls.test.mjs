// A conformance kit that passes everything proves nothing. These tests run
// every suite against implementations with ONE deliberate defect each and
// require the suite to name exactly the checks that defect should break, and
// against a correct implementation of the same kind and require a clean pass.

import { afterAll, describe, expect, it } from 'vitest';
import {
  runDecisionServerSuite,
  runEventsReceiverSuite,
  runPassportVerifierSuite,
  runProviderAdapterSuite,
  runRecordVerifierSuite,
  formatReport,
} from '../src/index.mjs';
import { carelessVerifier, makeInboxDouble, startControlServer } from './doubles.mjs';

const DECISION_SECRET = `whsec_${Buffer.alloc(32, 0x41).toString('base64')}`;
const EVENTS_SECRET = `whsec_${Buffer.alloc(32, 0x42).toString('base64')}`;

const failedIds = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);
const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe('control socket suites', () => {
  const servers = [];
  afterAll(() => Promise.all(servers.map((s) => s.close())));
  const start = async (quirk) => {
    const s = await startControlServer({ quirk, decisionSecret: DECISION_SECRET, eventsSecret: EVENTS_SECRET });
    servers.push(s);
    return s;
  };
  const decide = async (quirk) => runDecisionServerSuite({ url: `${(await start(quirk)).url}/decide`, secret: DECISION_SECRET, timeoutMs: 3000 });
  const events = async (quirk) => runEventsReceiverSuite({ url: `${(await start(quirk)).url}/events`, secret: EVENTS_SECRET, timeoutMs: 3000 });

  it('passes a correct decision server and events receiver', async () => {
    const report = await decide('none');
    // The correct double allows everything and does not check digests or the message id (two SHOULDs).
    expect(mustFailedIds(report), formatReport(report)).toEqual([]);
    expect(failedIds(report)).toEqual(['D45', 'D47']);
    const eventsReport = await events('none');
    expect(eventsReport.conforms, formatReport(eventsReport)).toBe(true);
  });

  it('fails a decision server that does not verify signatures', async () => {
    const ids = mustFailedIds(await decide('no-verify'));
    expect(ids).toEqual(expect.arrayContaining(['D40', 'D41', 'D42', 'D43', 'D44']));
  });

  it('fails a decision server that accepts a stale timestamp', async () => {
    const ids = mustFailedIds(await decide('allow-stale'));
    expect(ids).toEqual(['D42', 'D43']);
  });

  it('fails a decision server that signs its answer with the wrong message id', async () => {
    const report = await decide('wrong-id');
    expect(mustFailedIds(report)).toContain('D01');
  });

  it('fails a decision server that does not echo the request digest', async () => {
    const report = await decide('no-echo');
    expect(mustFailedIds(report)).toContain('D01');
  });

  it('fails a decision server that answers a verdict other than allow or deny', async () => {
    const report = await decide('bad-verdict');
    expect(mustFailedIds(report)).toContain('D01');
  });

  it('fails a decision server that errors on an action kind it does not know', async () => {
    expect(mustFailedIds(await decide('crash-on-unknown'))).toEqual(['D30']);
  });

  it('fails a decision server that cannot read a rotation overlap', async () => {
    expect(mustFailedIds(await decide('no-rotation'))).toEqual(['D31']);
  });

  it('fails an events receiver that does not verify signatures', async () => {
    const ids = mustFailedIds(await events('no-verify'));
    expect(ids).toEqual(['E10', 'E11', 'E12', 'E13']);
  });
});

describe('passport verifier suite', () => {
  it('passes a verifier that checks signature, issuer, audience and expiry', async () => {
    const report = await runPassportVerifierSuite({ verify: carelessVerifier('complete') });
    // This verifier is not careless about claims, but it does not check every structural rule:
    // the kit must still find the shape checks it skips.
    expect(mustFailedIds(report)).toEqual(expect.arrayContaining(['P20', 'P21', 'P22', 'P23', 'P24']));
    expect(mustFailedIds(report)).not.toEqual(expect.arrayContaining(['P01', 'P10', 'P11', 'P12', 'P13', 'P14', 'P15', 'P16', 'P17', 'P18']));
  });

  it('fails a verifier that checks only the signature', async () => {
    const ids = mustFailedIds(await runPassportVerifierSuite({ verify: carelessVerifier('signature-only') }));
    expect(ids).toEqual(expect.arrayContaining(['P10', 'P11', 'P12']));
  });

  it('fails a verifier that accepts alg none', async () => {
    expect(mustFailedIds(await runPassportVerifierSuite({ verify: carelessVerifier('accepts-none') }))).toContain('P13');
  });

  it('fails a verifier that ignores expiry', async () => {
    expect(mustFailedIds(await runPassportVerifierSuite({ verify: carelessVerifier('no-expiry') }))).toContain('P10');
  });

  it('fails a verifier that accepts everything, and one that accepts nothing', async () => {
    const all = await runPassportVerifierSuite({ verify: async () => ({ jti: 'pas_conformance', stk: { agent_id: 'agt_conformance' } }) });
    expect(all.conforms).toBe(false);
    expect(mustFailedIds(all).length).toBeGreaterThan(10);
    const none = await runPassportVerifierSuite({ verify: async () => { throw new Error('no'); } });
    expect(none.conforms).toBe(false);
    expect(mustFailedIds(none)).toEqual(expect.arrayContaining(['P01', 'P02', 'P03', 'P04', 'P05']));
  });
});

describe('record verifier suite', () => {
  it('fails a verifier that calls every pack valid', async () => {
    const report = await runRecordVerifierSuite({ verify: async () => ({ valid: true, complete: false, errors: [] }), level: 2 });
    expect(report.conforms).toBe(false);
    expect(mustFailedIds(report).length).toBeGreaterThan(10);
  });

  it('fails a verifier that calls every pack invalid, or that throws', async () => {
    const invalid = await runRecordVerifierSuite({ verify: async () => ({ valid: false, complete: false, errors: [{ code: 'INVALID_MANIFEST' }] }), level: 2 });
    expect(mustFailedIds(invalid)).toEqual(expect.arrayContaining(['R01', 'R02', 'R03']));
    const throws = await runRecordVerifierSuite({ verify: async () => { throw new Error('boom'); }, level: 2 });
    expect(throws.conforms).toBe(false);
  });

  it('fails a verifier that reports the right verdict with the wrong code', async () => {
    const relabel = (result) => ({ ...result, errors: result.errors.map(() => ({ code: 'SOMETHING_ELSE' })) });
    const { verifyPack } = await import('@getstackrun/verify');
    const report = await runRecordVerifierSuite({ verify: async (m, o) => relabel(await verifyPack(m, o)), level: 2 });
    expect(report.conforms).toBe(false);
  });

  it('fails a verifier that claims a pack is complete', async () => {
    const { verifyPack } = await import('@getstackrun/verify');
    const report = await runRecordVerifierSuite({ verify: async (m, o) => ({ ...(await verifyPack(m, o)), complete: true }), level: 2 });
    expect(report.conforms).toBe(false);
  });
});

describe('provider adapter suite', () => {
  const run = (quirk) => runProviderAdapterSuite({ ...makeInboxDouble(quirk) });

  it('passes a correct adapter, with no check skipped', async () => {
    const report = await run('none');
    expect(report.conforms, formatReport(report)).toBe(true);
    expect(report.skipped).toBe(1); // the double has no afterClose
    expect(report.warnings).toBe(0);
  });

  it('fails an adapter that creates a second resource when asked to open again', async () => {
    expect(mustFailedIds(await run('duplicates'))).toEqual(expect.arrayContaining(['A06']));
  });

  it('fails an adapter that leaks a credential into details', async () => {
    expect(mustFailedIds(await run('leaks-secret'))).toContain('A04');
  });

  it('fails an adapter that throws unclassified errors', async () => {
    expect(mustFailedIds(await run('raw-errors'))).toEqual(['F-retryable', 'F-permanent', 'F-awaiting_customer', 'F-not_configured']);
  });

  it('fails an adapter that puts a credential into an error message', async () => {
    expect(mustFailedIds(await run('leaks-in-error'))).toEqual(['F-retryable']);
  });

  it('fails an adapter whose close throws when the resource is already gone', async () => {
    expect(mustFailedIds(await run('close-throws-when-gone'))).toEqual(expect.arrayContaining(['A09', 'A10']));
  });

  it('fails an adapter whose find creates a resource', async () => {
    expect(mustFailedIds(await run('find-creates'))).toContain('A02');
  });

  it('fails an adapter that names resources at random, so a crashed open cannot be found again', async () => {
    expect(mustFailedIds(await run('random-name'))).toEqual(expect.arrayContaining(['A05']));
  });
});
