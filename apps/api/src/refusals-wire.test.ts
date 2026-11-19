import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ControlDeniedError,
  ControlLimitExceededError,
  ControlSocketUnavailableError,
  ControlUnavailableError,
  LicenceRequiredError,
  ModelCostCapError,
  PolicyDefinition,
  SpendRefusedError,
  assertPolicyBounded,
  buildRecipientPins,
  evaluatePolicy,
  normalizePolicy,
  normalizeRequest,
  refusalEvidence,
} from '@stack/shared';
import { createErrorHandler } from './middleware/error-handler.js';
import { readCostCap } from './routes/llm-gateway/billing-hold.js';
import { REPO_ROOT } from './test/route-scan.js';

// The refusals of spec/rest-api sections 7, 8 and 9, as the engine's own error classes and its own error handler put them
// on the wire, judged by the `rest-api` suite of the conformance kit (the checks that need no route but the ones the
// probes name). The end to end run of the suite against the built engine is rest-api.conformance.postgres.test.ts; the
// refusals of controls and the 402 of a balance need a customer's decider or a wallet, which that run does not have, so
// they are held to the same checks here.

type Kit = { runRestApiSuite(options: Record<string, unknown>): Promise<{ results: Array<{ id: string; status: string; detail?: string }> }> };
const kit = (await import(pathToFileURL(join(REPO_ROOT, 'spec', 'conformance', 'src', 'index.mjs')).href)) as Kit;

describe('the engine\'s refusals, on the wire, against the conformance kit', () => {
  const app = Fastify({ logger: false });
  let url = '';

  beforeAll(async () => {
    app.setErrorHandler(createErrorHandler());
    const refuse = (path: string, make: () => Error) => app.post(path, async () => { throw make(); });
    refuse('/probe/denied', () => new ControlDeniedError('dec_1', 'review_required', null, { ref: 'ref_1', after_seconds: 60 }, {
      policy_id: 'pol_1', policy_revision: 3, section: 'actions', rule: 'rule_1', code: 'review_required',
    }));
    refuse('/probe/held-without-rule', () => new ControlDeniedError('dec_2', null, 'No.', null));
    refuse('/probe/limit', () => new ControlLimitExceededError('day', 'cents', 12));
    refuse('/probe/limit-action', () => new ControlLimitExceededError('action', 'cents', 0, 50));
    refuse('/probe/socket', () => new ControlSocketUnavailableError('dec_3', 'timeout'));
    refuse('/probe/hosted', () => new ControlUnavailableError('dec_4'));
    refuse('/probe/licence', () => new LicenceRequiredError('member roles', { feature: 'roles', licence: 'none' }));
    refuse('/probe/balance', () => new SpendRefusedError('The balance does not cover this.', 'INSUFFICIENT_CREDITS'));
    // A model call on the customer's own key: the header is not read, and the call goes on.
    app.post('/probe/model', async () => ({ ok: true }));
    app.post('/probe/model-deployment-key', async (request) => {
      const cap = readCostCap(request);
      if (cap !== null && 25 > cap) throw new ModelCostCapError('cost_cap_exceeded', 'Too much.', { worst_case_cents: 25, max_cost_cents: cap });
      return { ok: true };
    });
    // Recipients set per job (section 7.4): the engine's own policy rules and Mission pins behind two routes.
    const perJobRule = { id: 'reply', effect: 'allow', access: { connection_id: 'scon_mail', intents: [{ name: 'resend.send_email' }], constraints: [] } };
    app.put('/probe/job/policy', async (request) => {
      const body = request.body as { recipients?: 'per_mission' };
      assertPolicyBounded(PolicyDefinition.parse({ name: 'Replies', connections: { mode: 'listed', rules: [{ ...perJobRule, ...(body.recipients ? { recipients: body.recipients } : {}) }] } }));
      return { ok: true };
    });
    app.post('/probe/job/send', async (request) => {
      const { mission, to } = request.body as { mission: 'pinned' | 'unpinned'; to: string };
      const policy = normalizePolicy({ name: 'Replies', connections: { mode: 'listed', rules: [{ ...perJobRule, recipients: 'per_mission' }] } });
      const verdict = evaluatePolicy(policy, {
        action: 'proxy.call',
        target: { connection_id: 'scon_mail', method: 'POST', host: 'api.resend.com', path: '/emails' },
        amountCents: null,
        request: normalizeRequest({ service: 'resend', url: 'https://api.resend.com/emails', method: 'POST', body: { from: 'agent@example.test', subject: 's', text: 't', to } }),
        mission: { recipientPins: mission === 'pinned' ? buildRecipientPins({ recipients: ['ana@example.test'] }) : null },
      });
      if (verdict.verdict !== 'allow') throw new ControlDeniedError('dec_5', verdict.code, verdict.message, null, refusalEvidence({ id: 'pol_1', revision: 1 }, verdict));
      return { sent: true };
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    url = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  });
  afterAll(() => app.close());

  const probe = (path: string, extra: object = {}) => ({ method: 'POST', path, body: {}, ...extra });

  it('answers every refusal of a control as the specification says', async () => {
    const report = await kit.runRestApiSuite({
      url,
      only: ['C01'],
      probes: {
        controls: [
          { code: 'CONTROL_DENIED', ...probe('/probe/denied') },
          { code: 'CONTROL_DENIED', ...probe('/probe/held-without-rule') },
          { code: 'CONTROL_LIMIT_EXCEEDED', ...probe('/probe/limit') },
          { code: 'CONTROL_LIMIT_EXCEEDED', ...probe('/probe/limit-action') },
          { code: 'CONTROL_SOCKET_UNAVAILABLE', ...probe('/probe/socket') },
          { code: 'CONTROL_UNAVAILABLE', ...probe('/probe/hosted') },
        ],
      },
    });
    expect(report.results, JSON.stringify(report.results)).toEqual([expect.objectContaining({ id: 'C01', status: 'pass' })]);
  });

  it('answers recipients set per job as the specification says, with the engine\'s own rules and pins', async () => {
    const put = (path: string, body: object) => ({ method: 'PUT', path, body });
    const report = await kit.runRestApiSuite({
      url,
      only: ['C02'],
      probes: {
        perJob: {
          unbounded: put('/probe/job/policy', {}),
          policy: put('/probe/job/policy', { recipients: 'per_mission' }),
          unpinned: probe('/probe/job/send', { body: { mission: 'unpinned', to: 'ana@example.test' } }),
          stranger: probe('/probe/job/send', { body: { mission: 'pinned', to: 'eve@evil.test' } }),
          pinned: probe('/probe/job/send', { body: { mission: 'pinned', to: 'ana@example.test' } }),
          recipients: ['eve@evil.test', 'ana@example.test'],
        },
      },
    });
    expect(report.results, JSON.stringify(report.results)).toEqual([expect.objectContaining({ id: 'C02', status: 'pass' })]);
  });

  it('answers a licence and a balance as a 402 in the envelope', async () => {
    const licence = await kit.runRestApiSuite({ url, only: ['P01'], probes: { payment: { ...probe('/probe/licence'), code: 'LICENCE_REQUIRED' } } });
    expect(licence.results, JSON.stringify(licence.results)).toEqual([expect.objectContaining({ id: 'P01', status: 'pass' })]);
    const balance = await kit.runRestApiSuite({ url, only: ['P01'], probes: { payment: { ...probe('/probe/balance'), code: 'INSUFFICIENT_CREDITS' } } });
    expect(balance.results, JSON.stringify(balance.results)).toEqual([expect.objectContaining({ id: 'P01', status: 'pass' })]);
  });

  it('reads and refuses the cost cap as the specification says, on either kind of key', async () => {
    // On the customer's own key the header is ignored: the call goes on, whatever the header holds.
    const own = await kit.runRestApiSuite({ url, only: ['M01', 'M02'], probes: { costCap: { mode: 'own_key_ignored', ...probe('/probe/model') } } });
    expect(own.results.map((r) => r.status), JSON.stringify(own.results)).toEqual(['skip', 'pass']);
    const deployment = await kit.runRestApiSuite({ url, only: ['M01', 'M02'], probes: { costCap: { mode: 'deployment_key', ...probe('/probe/model-deployment-key') } } });
    expect(deployment.results.map((r) => r.status), JSON.stringify(deployment.results)).toEqual(['pass', 'pass']);
  });
});
