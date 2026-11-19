// The SDK's `verifyWebhook` is the reference receiver of STACK webhooks. It must
// pass the kit, as a function and behind a URL, and the kit must fail receivers
// that each have one deliberate defect.

import { createServer } from 'node:http';
import { createHmac } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as sdk from '@getstackrun/sdk';
import { formatReport, runWebhooksSuite } from '../src/index.mjs';
import { listen } from './support.mjs';

const SECRET = `whsec_${Buffer.alloc(32, 0x61).toString('base64')}`;

const failedIds = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);
const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe('webhooks suite', () => {
  /** The reference receiver as a function, with its own memory of ids. */
  const reference = () => {
    const replayGuard = sdk.createReplayGuard();
    return ({ headers, body, secrets, now }) => sdk.verifyWebhook({ headers, body, secret: secrets, now, replayGuard }).ok;
  };

  it('passes the SDK verifier as a function', async () => {
    const report = await runWebhooksSuite({ verify: reference(), secret: SECRET });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(15);
  });

  describe('behind a URL', () => {
    let instance;
    beforeAll(async () => {
      const replayGuard = sdk.createReplayGuard();
      const server = createServer((req, res) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          const check = sdk.verifyWebhook({ headers: req.headers, body: Buffer.concat(chunks), secret: SECRET, replayGuard });
          res.writeHead(check.ok ? 204 : 401).end();
        });
      });
      instance = await listen(server);
    });
    afterAll(() => instance?.close());

    it('passes the SDK verifier served over HTTP', async () => {
      const report = await runWebhooksSuite({ url: `${instance.url}/hook`, secret: SECRET, timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.warnings, formatReport(report)).toBe(0);
      // The two checks that need a function are skipped, never passed.
      expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['W06', 'W20']);
    });
  });

  describe('fails a receiver with one defect', () => {
    const run = (verify) => runWebhooksSuite({ verify, secret: SECRET });
    const decodeKey = (secret) => Buffer.from(secret.slice('whsec_'.length), 'base64');
    const hmac = (secret, id, timestamp, body) => createHmac('sha256', decodeKey(secret)).update(`${id}.${timestamp}.${body}`).digest('base64');

    it('one that checks nothing', async () => {
      const ids = mustFailedIds(await run(() => true));
      expect(ids).toEqual(expect.arrayContaining(['W10', 'W11', 'W12', 'W13', 'W14', 'W15', 'W16', 'W17']));
    });

    it('one that never looks at the timestamp', async () => {
      const verify = ({ headers, body, secrets }) => {
        const offered = (headers['webhook-signature'] ?? '').split(' ');
        return secrets.some((s) => offered.includes(`v1,${hmac(s, headers['webhook-id'], headers['webhook-timestamp'], body)}`));
      };
      const ids = mustFailedIds(await run(verify));
      expect(ids).toEqual(['W15', 'W16']);
    });

    it('one that verifies a re-serialised body and not the raw one', async () => {
      const verify = ({ headers, body, secrets, now }) => {
        let again;
        try {
          again = JSON.stringify(JSON.parse(body));
        } catch {
          return false;
        }
        return sdk.verifyWebhook({ headers, body: again, secret: secrets, now }).ok;
      };
      expect(mustFailedIds(await run(verify))).toContain('W02');
    });

    it('one that reads only the first signature', async () => {
      const verify = ({ headers, body, secrets, now }) => {
        const first = (headers['webhook-signature'] ?? '').split(' ')[0];
        return sdk.verifyWebhook({ headers: { ...headers, 'webhook-signature': first }, body, secret: secrets, now }).ok;
      };
      expect(mustFailedIds(await run(verify))).toContain('W03');
    });

    it('one that refuses any signature list that holds an unknown version', async () => {
      const verify = ({ headers, body, secrets, now }) =>
        !(headers['webhook-signature'] ?? '').includes('v2,') && sdk.verifyWebhook({ headers, body, secret: secrets, now }).ok;
      expect(mustFailedIds(await run(verify))).toContain('W04');
    });

    it('one that has no memory of the ids it has handled (a warning, not a failure)', async () => {
      const report = await run(({ headers, body, secrets, now }) => sdk.verifyWebhook({ headers, body, secret: secrets, now }).ok);
      expect(report.conforms, formatReport(report)).toBe(true);
      expect(failedIds(report)).toEqual(['W20']);
    });
  });
});
