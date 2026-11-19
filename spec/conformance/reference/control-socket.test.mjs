// The example control server (examples/control-socket) is the reference
// implementation of a decision server and an events receiver. It must pass the
// kit.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { formatReport, runDecisionServerSuite, runEventsReceiverSuite } from '../src/index.mjs';
import { importExampleServer, listen } from './support.mjs';

const DECISION_SECRET = `whsec_${Buffer.alloc(32, 0x31).toString('base64')}`;
const EVENTS_SECRET = `whsec_${Buffer.alloc(32, 0x32).toString('base64')}`;

describe('example control server', () => {
  let instance;

  beforeAll(async () => {
    const example = await importExampleServer();
    const server = example.createControlServer({ decisionSecret: DECISION_SECRET, eventsSecret: EVENTS_SECRET });
    instance = await listen(server);
  });
  afterAll(() => instance?.close());

  it('conforms as a decision server', async () => {
    const report = await runDecisionServerSuite({ url: `${instance.url}/stack/decide`, secret: DECISION_SECRET });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBeGreaterThan(25);
  });

  it('conforms as an events receiver', async () => {
    const report = await runEventsReceiverSuite({ url: `${instance.url}/stack/events`, secret: EVENTS_SECRET });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBe(11);
  });

  it('keeps the two secrets apart: the events secret cannot sign an allow', async () => {
    const report = await runDecisionServerSuite({ url: `${instance.url}/stack/decide`, secret: EVENTS_SECRET });
    expect(report.conforms).toBe(false);
  });
});
