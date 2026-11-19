// The reference relying party of single sign-on (sso-login-reference.mjs) passes the `sso-login` suite, and each defective
// variant of it fails the checks that name its defect. A kit that cannot fail a broken relying party would certify anything.

import { describe, expect, it } from 'vitest';
import { runSsoLoginSuite } from '../src/index.mjs';
import { SSO_QUIRKS, startSsoReference } from './sso-login-reference.mjs';

async function run(quirk) {
  const server = await startSsoReference({ quirk });
  try {
    return { report: await runSsoLoginSuite({ baseUrl: server.baseUrl, configure: server.configure, domains: server.domains }), server };
  } finally {
    await server.close();
  }
}

const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe.concurrent('the reference single sign-on relying party', { timeout: 120_000 }, () => {
  it('passes the sso-login suite with every check run', async () => {
    const { report, server } = await run('none');
    expect(report.results.filter((r) => r.status !== 'pass'), JSON.stringify(report.results.filter((r) => r.status !== 'pass'))).toEqual([]);
    expect(report.results.length).toBe(24);
    expect(report.conforms).toBe(true);
    // Everyone who signed in is a person of the account, at an address in lower case.
    expect([...server.people.keys()].every((email) => email === email.trim().toLowerCase())).toBe(true);
  });

  it('skips the checks of verified domains, without failing, when the deployment gives the kit no way to verify one', async () => {
    const server = await startSsoReference({ quirk: 'none' });
    try {
      const report = await runSsoLoginSuite({ baseUrl: server.baseUrl, configure: server.configure });
      expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['S25', 'S26', 'S27', 'S28']);
      expect(report.conforms).toBe(true);
    } finally {
      await server.close();
    }
  });

  // [quirk, the checks that must fail]
  const defects = [
    ['binding-optional', ['S01']],
    ['slug-400', ['S02']],
    ['secret-in-url', ['S03']],
    ['no-pkce', ['S03', 'S10']],
    ['cookie-js', ['S03']],
    ['cookie-not-cleared', ['S10']],
    ['alg-none', ['S21']],
    ['hmac-confusion', ['S21']],
    ['any-kid', ['S21']],
    ['no-refetch', ['S14']],
    ['no-nonce-check', ['S20']],
    ['no-iss-check', ['S20']],
    ['no-aud-check', ['S20']],
    ['no-exp-check', ['S20']],
    ['no-skew', ['S13']],
    ['no-sub-check', ['S20']],
    ['empty-email', ['S20']],
    ['no-binding', ['S31']],
    ['state-reusable', ['S30']],
    ['refusal-redirects', ['S20', 'S21', 'S22']],
    ['ref-short', ['S10']],
    ['handoff-open', ['S40']],
    ['no-email-verified-check', ['S23']],
    ['email-only-match', ['S24']],
    ['domain-any-account', ['S27']],
    ['domain-subdomains', ['S26']],
    ['domain-overrides-claim', ['S26']],
    ['domain-never-expires', ['S28']],
  ];

  it('has a defective variant for every quirk it lists', () => {
    expect(defects.map(([quirk]) => quirk).sort()).toEqual(SSO_QUIRKS.filter((q) => q !== 'none').sort());
  });

  for (const [quirk, ids] of defects) {
    it(`fails a relying party with the defect "${quirk}" at ${ids.join(' and ')}`, async () => {
      const { report } = await run(quirk);
      expect(report.conforms).toBe(false);
      expect(mustFailed(report)).toEqual(expect.arrayContaining(ids));
    });
  }
});
