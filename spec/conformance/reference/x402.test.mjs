// The reference x402 site and buyer must pass the x402 suite, and the suite
// must fail sites and buyers that each have one deliberate defect.

import { createServer } from 'node:http';
import { afterAll, describe, expect, it } from 'vitest';
import { formatReport, runX402Suite } from '../src/index.mjs';
import { pay } from './x402-client.mjs';
import { createX402Site, serveX402Site } from './x402-site-server.mjs';
import { listen } from './support.mjs';

const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const failedIds = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);

describe('x402 suite', () => {
  const closers = [];
  afterAll(() => Promise.all(closers.map((close) => close())));

  it('passes the reference buyer', async () => {
    const report = await runX402Suite({ pay });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBe(7);
  });

  it('passes the reference site, with the whole exchange when it takes test payments', async () => {
    const site = await serveX402Site({});
    closers.push(site.close);
    const full = await runX402Suite({ url: site.url, acceptsTestPayments: true, timeoutMs: 3000 });
    expect(full.failed, formatReport(full)).toBe(0);
    expect(full.warnings, formatReport(full)).toBe(0);
    expect(full.results.filter((r) => r.status === 'skip').every((r) => r.id.startsWith('XC'))).toBe(true);
    const without = await runX402Suite({ url: (await serveX402Site({})).url, timeoutMs: 3000 });
    expect(without.failed, formatReport(without)).toBe(0);
    expect(without.results.filter((r) => r.status === 'skip' && !r.id.startsWith('XC')).map((r) => r.id)).toEqual(['X20', 'X21']);
  });

  describe('fails a buyer with one defect', () => {
    const run = (client) => runX402Suite({ pay: client });
    const decode = (header) => JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
    const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');

    it('one that reuses its nonce', async () => {
      let first;
      const ids = mustFailedIds(await run(async (input) => {
        const decoded = decode(await pay(input));
        first ??= decoded.payload.authorization.nonce;
        decoded.payload.authorization.nonce = first;
        return encode(decoded);
      }));
      expect(ids).toEqual(expect.arrayContaining(['XC04']));
    });

    it('one that pays the amount it chooses and not the one asked', async () => {
      const ids = mustFailedIds(await run(async (input) => {
        const decoded = decode(await pay(input));
        decoded.payload.authorization.value = '1';
        return encode(decoded);
      }));
      expect(ids).toEqual(['XC02', 'XC05']);
    });

    it('one that signs another domain than the asset\'s', async () => {
      const ids = mustFailedIds(await run((input) => pay({ ...input, sign: (typedData) => input.sign({ ...typedData, domain: { ...typedData.domain, name: 'Dollar' } }) })));
      expect(ids).toEqual(['XC05']);
    });

    it('one that cannot tell an exact entry from another and takes the first', async () => {
      const ids = mustFailedIds(await run(async (input) => pay({ ...input, paymentRequired: { ...input.paymentRequired, accepts: input.paymentRequired.accepts.map((entry) => ({ ...entry, scheme: 'exact' })) } })));
      expect(ids).toContain('XC06');
    });

    it('one that pays any price (a SHOULD)', async () => {
      const report = await run((input) => pay({ ...input, maxAmount: undefined }));
      expect(report.conforms, formatReport(report)).toBe(true);
      expect(failedIds(report)).toEqual(['XC07']);
    });
  });

  describe('fails a site with one defect', () => {
    const serve = async (handler) => {
      const server = createServer((req, res) => {
        const url = new URL(req.url, 'http://site.invalid');
        const answer = handler({ host: req.headers.host, pathname: url.pathname, payment: req.headers['payment-signature'] });
        res.writeHead(answer.status, answer.headers).end(answer.body);
      });
      const instance = await listen(server);
      closers.push(instance.close);
      return `${instance.url}/reports/42`;
    };
    const run = async (handler, options = {}) => runX402Suite({ url: await serve(handler), timeoutMs: 3000, ...options });

    it('one that serves the page to anyone who sends any header', async () => {
      const site = createX402Site({});
      const ids = mustFailedIds(await run((req) => (req.payment === undefined ? site.handle(req) : { status: 200, headers: {}, body: 'The report.' })));
      expect(ids).toEqual(expect.arrayContaining(['X10', 'X11', 'X12', 'X13', 'X14']));
    });

    it('one that does not compare the payee of the authorisation', async () => {
      const site = createX402Site({});
      const ids = mustFailedIds(await run((req) => {
        if (req.payment === undefined) return site.handle(req);
        try {
          const payment = JSON.parse(Buffer.from(req.payment, 'base64').toString('utf8'));
          payment.payload.authorization.to = payment.accepted.payTo;
          return site.handle({ ...req, payment: Buffer.from(JSON.stringify(payment), 'utf8').toString('base64') });
        } catch {
          return site.handle(req);
        }
      }));
      expect(ids).toEqual(['X13']);
    });

    it('one that lets the 402 be cached', async () => {
      const site = createX402Site({});
      const ids = mustFailedIds(await run((req) => {
        const answer = site.handle(req);
        const { 'cache-control': _dropped, ...headers } = answer.headers;
        return { ...answer, headers };
      }));
      expect(ids).toEqual(expect.arrayContaining(['X01', 'X15']));
    });

    it('one that puts the requirements in the body and not in the header', async () => {
      const site = createX402Site({});
      const ids = mustFailedIds(await run((req) => {
        const answer = site.handle(req);
        const { 'payment-required': header, ...headers } = answer.headers;
        return header ? { ...answer, headers, body: Buffer.from(header, 'base64').toString('utf8') } : answer;
      }));
      expect(ids).toContain('X01');
    });
  });
});
