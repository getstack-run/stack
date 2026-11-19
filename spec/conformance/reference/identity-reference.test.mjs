// The public reference server of agent key enrollment, fleet enrollment and the online half of a Passport
// (identity-server-reference.mjs) passes the three suites that judge a server of them, and each defective variant of it
// fails the checks that name its defect. A kit that cannot fail a broken server would certify anything.

import { afterAll, describe, expect, it } from 'vitest';
import { runAgentEnrollmentSuite, runFleetEnrollmentSuite, runPassportOnlineSuite } from '../src/index.mjs';
import { IDENTITY_QUIRKS, startIdentityReference } from './identity-server-reference.mjs';

const servers = [];
afterAll(() => Promise.all(servers.map((s) => s.close())));

async function run(suite, quirk) {
  const server = await startIdentityReference({ quirk });
  servers.push(server);
  const base = { baseUrl: server.baseUrl, headers: server.headers, approve: server.approve };
  if (suite === 'agent-enrollment') return runAgentEnrollmentSuite(base);
  if (suite === 'fleet-enrollment') return runFleetEnrollmentSuite(base);
  return runPassportOnlineSuite({ ...base, revocations: server.revocations, connection: server.connection });
}

const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe('the identity reference server', { timeout: 120_000 }, () => {
  for (const [suite, passes] of [['agent-enrollment', 14], ['fleet-enrollment', 10], ['passport-online', 16]]) {
    it(`passes the ${suite} suite with every check run`, async () => {
      const report = await run(suite, 'none');
      expect(report.results.filter((r) => r.status !== 'pass'), JSON.stringify(report.results.filter((r) => r.status !== 'pass'))).toEqual([]);
      expect(report.results.length).toBe(passes);
      expect(report.conforms).toBe(true);
    });
  }

  // [quirk, suite, the checks that must fail]
  const defects = [
    ['challenge-ttl', 'agent-enrollment', ['AE01']],
    ['challenge-repeat', 'agent-enrollment', ['AE01']],
    ['no-pop', 'agent-enrollment', ['AE04']],
    ['any-challenge', 'agent-enrollment', ['AE05']],
    ['no-approval', 'agent-enrollment', ['AE06']],
    ['approval-unbound', 'agent-enrollment', ['AE06']],
    ['challenge-reuse', 'agent-enrollment', ['AE11']],
    ['overwrite-key', 'agent-enrollment', ['AE12']],
    ['managed-enroll', 'agent-enrollment', ['AE13']],
    ['jwks-private', 'agent-enrollment', ['AE14']],
    ['jwks-kid', 'agent-enrollment', ['AE14']],
    ['ticket-reuse', 'agent-enrollment', ['AE20']],
    ['ticket-any-agent', 'agent-enrollment', ['AE20']],
    ['garbage-bearer', 'agent-enrollment', ['AE21']],
    ['rotate-keeps-old', 'agent-enrollment', ['AE30']],
    ['rotate-keeps-old', 'fleet-enrollment', ['FE08']],
    ['fleet-any-caller', 'fleet-enrollment', ['FE02']],
    ['fleet-no-proof', 'fleet-enrollment', ['FE06']],
    ['fleet-challenge-reuse', 'fleet-enrollment', ['FE06']],
    ['fleet-duplicate', 'fleet-enrollment', ['FE04']],
    ['fleet-name-ignored', 'fleet-enrollment', ['FE05']],
    ['fleet-open-rotation', 'fleet-enrollment', ['FE08', 'FE09']],
    ['fleet-extra-members', 'fleet-enrollment', ['FE07']],
    ['fleet-worker-enrolls', 'fleet-enrollment', ['FE10']],
    ['fleet-long-lease', 'fleet-enrollment', ['FE03']],
    ['verify-valid-false', 'passport-online', ['PO03']],
    ['verify-no-signature', 'passport-online', ['PO03']],
    ['verify-alg-none', 'passport-online', ['PO03']],
    ['verify-500', 'passport-online', ['PO03']],
    ['revocation-ignored', 'passport-online', ['PO04', 'PO05', 'PO06', 'PO07']],
    ['no-cascade', 'passport-online', ['PO05', 'PC01']],
    ['mission-keeps', 'passport-online', ['PO06', 'PC02']],
    ['revoke-agent-all', 'passport-online', ['PO07']],
    ['depth-unlimited', 'passport-online', ['PD03']],
    ['child-outlives', 'passport-online', ['PD02']],
    ['accountability-down', 'passport-online', ['PD04']],
    ['scope-escalation', 'passport-online', ['PD05', 'PD07']],
    ['drops-constraints', 'passport-online', ['PD07']],
    ['long-lived', 'passport-online', ['PO01']],
    ['channel-silent', 'passport-online', ['PC01', 'PC02']],
    ['revoked-parent-delegates', 'passport-online', ['PD06']],
  ];

  it('has a defective variant for every quirk it lists', () => {
    expect([...new Set(defects.map(([quirk]) => quirk))].sort()).toEqual(IDENTITY_QUIRKS.filter((q) => q !== 'none').sort());
  });

  for (const [quirk, suite, ids] of defects) {
    it(`fails the ${suite} suite on a server with the defect "${quirk}", at ${ids.join(' and ')}`, async () => {
      const report = await run(suite, quirk);
      expect(report.conforms).toBe(false);
      expect(mustFailed(report)).toEqual(expect.arrayContaining(ids));
    });
  }
});
