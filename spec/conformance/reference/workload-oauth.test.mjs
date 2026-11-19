// The reference acceptor of a workload token and the reference check of a client metadata document run their suites,
// and the suites fail implementations that each have one deliberate defect.

import { describe, expect, it } from 'vitest';
import { formatReport, runClientMetadataSuite, runWorkloadTokenSuite } from '../src/index.mjs';
import { isMetadataClientId, validate } from './oauth-client-metadata-reference.mjs';
import { accept } from './workload-token-reference.mjs';

const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe('workload token acceptance', () => {
  it('passes the reference acceptor, with the reason of the specification for each refusal', async () => {
    const report = await runWorkloadTokenSuite({ accept });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });

  it('fails an acceptor that checks no signature, one that lets the token choose its algorithm, and one that ignores the audience', async () => {
    const noSignature = await runWorkloadTokenSuite({
      accept: async (input) => {
        const [, payload] = input.token.split('.');
        const claims = JSON.parse(Buffer.from(payload ?? '', 'base64url').toString('utf8'));
        return { subject: claims.sub, issuer: claims.iss ?? '', not_after: claims.exp };
      },
    });
    expect(mustFailedIds(noSignature)).toEqual(expect.arrayContaining(['WT13', 'WT14', 'WT15', 'WT16']));
    // Reads the algorithm from the token's header instead of from the key.
    const chooses = await runWorkloadTokenSuite({
      accept: async (input) => {
        const header = JSON.parse(Buffer.from(input.token.split('.')[0], 'base64url').toString('utf8'));
        const keys = input.jwks.keys.map((k) => ({ ...k, alg: header.alg }));
        return accept({ ...input, jwks: { keys } });
      },
    });
    expect(mustFailedIds(chooses)).toContain('WT17');
    const noAudience = await runWorkloadTokenSuite({ accept: (input) => accept({ ...input, config: { ...input.config, audience: null } }) });
    expect(mustFailedIds(noAudience)).toContain('WT15');
    const none = await runWorkloadTokenSuite({ accept: async () => { throw new Error('no'); } });
    expect(none.conforms).toBe(false);
  });

  it('accepts a SHOULD failure only as a warning: an acceptor that gives no reason still conforms', async () => {
    const report = await runWorkloadTokenSuite({ accept: async (input) => { try { return await accept(input); } catch { throw new Error('refused'); } } });
    expect(report.conforms, formatReport(report)).toBe(true);
    expect(report.warnings).toBe(1);
  });
});

describe('client metadata document check', () => {
  it('passes the reference check', async () => {
    const report = await runClientMetadataSuite({ validate, isMetadataClientId });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings).toBe(0);
    expect(report.skipped).toBe(0);
  });

  it('skips the client id check when it is not given, and fails a check that is too lax', async () => {
    const report = await runClientMetadataSuite({ validate });
    expect(report.skipped).toBe(1);
    const lax = await runClientMetadataSuite({
      validate: (id, doc) => ({ client_id: id, client_name: doc.client_name ?? 'x', redirect_uris: doc.redirect_uris ?? [], grant_types: doc.grant_types ?? ['authorization_code'] }),
    });
    expect(mustFailedIds(lax)).toEqual(expect.arrayContaining(['CM02', 'CM03', 'CM04', 'CM05', 'CM06', 'CM07', 'CM08']));
  });
});
