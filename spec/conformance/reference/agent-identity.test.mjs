// The reference server and verifier must pass the agent-identity suite, and the suite must fail a
// server or a verifier that breaks one rule on purpose, and only the checks that rule is judged by.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as sdk from '@getstackrun/sdk';
import { formatReport, runAgentIdentitySuite } from '../src/index.mjs';
import { createReferenceIdentityServer, createReferenceVerifier, makeAgent } from './agent-identity-reference.mjs';

const VECTORS = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'agent-identity', 'vectors.json'), 'utf8'));
const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const skipped = (report) => report.results.filter((r) => r.status === 'skip').map((r) => r.id);

/** A server with a live agent, a closed one and one its owner switched off, and the handles to ask about them. */
async function start(options = {}, agentOver = {}) {
  // The owner is not in good standing, so that an answer that says otherwise in one place is caught.
  const known = makeAgent({ owner: { identity_verified: true, good_standing: false }, ...agentOver });
  const closed = makeAgent({ status: 'closed' });
  const hidden = makeAgent({ enabled: false });
  const server = createReferenceIdentityServer({ agents: [known, closed, hidden], ...options });
  const running = await server.listen();
  const handles = {
    url: running.url,
    known: { key_id: known.keyId, site: known.site, agent_id: known.id, showName: known.showName, ...(known.showName ? { name: known.name } : {}) },
    closed: { agent_id: closed.id, key_id: closed.keyId, site: closed.site },
    hidden: { key_id: hidden.keyId, site: hidden.site, agent_id: hidden.id },
    timeoutMs: 5000,
  };
  return { running, handles, server };
}

async function run(options = {}, agentOver = {}, extra = {}) {
  const { running, handles } = await start(options, agentOver);
  try {
    return await runAgentIdentitySuite({ ...handles, ...extra });
  } finally {
    await running.close();
  }
}

describe('the reference server', () => {
  it('passes the server checks with a closed agent and a switched-off one, nothing skipped but the rate limit probe and the verifier', async () => {
    const report = await run();
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(skipped(report)).toEqual(['AI12', 'AV01', 'AV02', 'AV03', 'AV04', 'AV05', 'AV06', 'AV07']);
  });

  it('passes with the name shown, and checks the card and the answer carry it', async () => {
    const report = await run({}, { showName: true });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.results.find((r) => r.id === 'AI11').status).toBe('pass');
  });

  it('limits one source: a run of lookups is answered 429 before long', async () => {
    const { running, handles } = await start();
    try {
      // The suite on its own, then a probe from a fresh run: the probe is the last thing a source does.
      const report = await runAgentIdentitySuite({ url: handles.url, probeRateLimit: true, rateLimitProbe: 120, timeoutMs: 5000 });
      expect(report.results.find((r) => r.id === 'AI12'), formatReport(report)).toMatchObject({ status: 'pass' });
      expect(report.failed, formatReport(report)).toBe(0);
    } finally {
      await running.close();
    }
  });

  it('skips what needs a handle it was not given, and passes nothing it could not check', async () => {
    const { running, handles } = await start();
    try {
      const report = await runAgentIdentitySuite({ url: handles.url, timeoutMs: 5000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(skipped(report)).toEqual(['AI01', 'AI02', 'AI03', 'AI04', 'AI05', 'AI06', 'AI10', 'AI11', 'AI12', 'AF01', 'AF02', 'AF03', 'AF05', 'AV01', 'AV02', 'AV03', 'AV04', 'AV05', 'AV06', 'AV07']);
    } finally {
      await running.close();
    }
  });
});

describe('the suite fails a server with one defect', () => {
  const cases = [
    ['repeats what was asked in its 404', 'echo-in-404', ['AI08', 'AI09', 'AF04', 'AF05']],
    ['confirms a closed agent to someone who asks by its site', 'closed-by-site', ['AI09']],
    ['tells a closed agent apart in its refusal', 'closed-differs', ['AI09']],
    ['tells an agent its owner switched off apart in its refusal', 'hidden-differs', ['AI09']],
    ['signs with the audience of a Passport', 'aud-passport', ['AI05', 'AI06', 'AI10']],
    ['signs with no type', 'no-typ', ['AI05', 'AI06', 'AI10']],
    ['makes a statement good for an hour', 'ttl-1h', ['AI04', 'AI05', 'AI10']],
    ['shows the name although its owner does not', 'name-leaks', ['AI11']],
    ['adds the owner\'s email to the facts', 'extra-member', ['AI04', 'AI05', 'AI06', 'AI10']],
    ['says in its JSON what the statement does not', 'json-differs', ['AI05']],
    ['lets a shared cache keep a statement', 'cacheable', ['AI01']],
    ['takes a lookup that names two things', 'two-selectors', ['AI07']],
    ['serves an agent card nobody signed', 'unsigned-card', ['AF01']],
    ['names the agent\'s site in its card', 'card-names-site', ['AF01']],
    ['repeats the lookup in its refusal of a bad one', 'invalid-repeats', ['AI07']],
  ];
  for (const [title, defect, expected] of cases) {
    it(title, async () => {
      // The name is shown for the defect that checks the card's name when it is shown.
      const report = await run({ defect });
      expect(mustFailed(report), `${defect}\n${formatReport(report)}`).toEqual(expected);
    });
  }

  it('one that never limits a source, as a warning', async () => {
    const { running, handles } = await start({ defect: 'no-limit' });
    try {
      const report = await runAgentIdentitySuite({ url: handles.url, probeRateLimit: true, rateLimitProbe: 90, timeoutMs: 5000 });
      expect(report.results.find((r) => r.id === 'AI12')).toMatchObject({ status: 'fail', level: 'SHOULD' });
      expect(report.failed).toBe(0);
      expect(report.warnings).toBe(1);
    } finally {
      await running.close();
    }
  });
});

describe('the reference verifier', () => {
  it('passes the verifier checks on every vector', async () => {
    const report = await runAgentIdentitySuite({ verifier: createReferenceVerifier(), vectors: VECTORS });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBe(7);
  });

  it('is handed every case of the vectors by exactly one check, and the vectors name their own verdicts', () => {
    const groups = new Set(VECTORS.cases.map((c) => c.group));
    expect([...groups].sort()).toEqual(['claims', 'header', 'lifetime', 'lookup', 'signature', 'time', 'valid']);
    expect(VECTORS.cases.filter((c) => c.verdict === 'accept').length).toBe(VECTORS.cases.filter((c) => c.group === 'valid').length);
    expect(new Set(VECTORS.cases.map((c) => c.id)).size).toBe(VECTORS.cases.length);
  });
});

describe('the SDK\'s verifier', () => {
  it('passes the verifier checks on every vector, as the code a site or an agent runs to check a statement', async () => {
    const verify = (statement, { jwks, now, issuer, expect: asked }) => sdk.verifyAgentIdentity(statement, { jwks, now, issuer, expect: asked });
    const report = await runAgentIdentitySuite({ verifier: verify, vectors: VECTORS });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBe(7);
  });
});

describe('the suite fails a verifier with one defect', () => {
  const cases = [
    ['accepts any type of token', 'any-type', ['AV03']],
    ['accepts the audience of a Passport', 'passport-audience', ['AV04']],
    ['accepts another issuer', 'any-issuer', ['AV04']],
    ['ignores expiry', 'expired', ['AV02']],
    ['trusts an unsigned token', 'alg-none', ['AV03']],
    ['checks a MAC made with the public key', 'hs256', ['AV03']],
    ['ignores the version', 'ignore-version', ['AV04']],
    ['ignores the subject', 'ignore-subject', ['AV04']],
    ['ignores what was asked', 'ignore-lookup', ['AV06']],
  ];
  for (const [title, defect, expected] of cases) {
    it(title, async () => {
      const report = await runAgentIdentitySuite({ verifier: createReferenceVerifier({ defect }), vectors: VECTORS });
      expect(mustFailed(report), `${defect}\n${formatReport(report)}`).toEqual(expected);
    });
  }

  it('one that accepts a statement good for an hour, as a warning', async () => {
    const report = await runAgentIdentitySuite({ verifier: createReferenceVerifier({ defect: 'long-lived' }), vectors: VECTORS });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.results.filter((r) => r.status === 'fail').map((r) => r.id + ' ' + r.level)).toEqual(['AV07 SHOULD']);
  });

  it('one that refuses everything, and one that accepts everything', async () => {
    const refuses = await runAgentIdentitySuite({ verifier: () => false, vectors: VECTORS });
    expect(mustFailed(refuses)).toEqual(['AV01']);
    const accepts = await runAgentIdentitySuite({ verifier: (_token, _options) => ({ ok: true, claims: {} }), vectors: VECTORS });
    expect(mustFailed(accepts)).toEqual(['AV01', 'AV02', 'AV03', 'AV04', 'AV05', 'AV06']);
    expect(accepts.warnings).toBe(1);
  });
});
