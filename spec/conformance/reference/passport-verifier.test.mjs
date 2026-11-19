// The SDK's offline verifier is the reference implementation of Passport
// verification (spec/passport section 9.1). It must pass the kit.

import { afterAll, describe, expect, it } from 'vitest';
import { verifyPassportOffline } from '@getstackrun/sdk';
import { formatReport, runPassportVerifierSuite } from '../src/index.mjs';
import { serveJson } from './support.mjs';

const served = [];
afterAll(() => Promise.all(served.map((s) => s.close())));

describe('@getstackrun/sdk verifyPassportOffline', () => {
  it('conforms, fetching the keys from a JWKS URL', async () => {
    const jwksHost = new Map();
    const verify = async (token, { jwks, issuer, audience }) => {
      // One JWKS per run: the SDK caches key sets per URL for the life of the process.
      const key = JSON.stringify(jwks);
      if (!jwksHost.has(key)) {
        const host = await serveJson(jwks);
        served.push(host);
        jwksHost.set(key, host.url);
      }
      return verifyPassportOffline(token, { jwksUrl: jwksHost.get(key), issuer, audience });
    };
    const report = await runPassportVerifierSuite({ verify });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.passed).toBeGreaterThan(15);
  });
});
