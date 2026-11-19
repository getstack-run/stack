import { describe, expect, it, vi } from 'vitest';
import { buildRecipientPins, normalizePolicy, normalizeRequest, type ControlActionType, type PolicyDefinitionInput, type RecipientPin } from '@stack/shared';
import type { EffectivePolicy, MissionRecipients } from '@stack/vault';
import { PolicyHostedCheck } from './policy-check.js';
import { buildDecisionRequest } from './request-builder.js';
import { controlTargets } from './targets.js';
import type { DecisionContext } from './types.js';

// Recipients set per job, through the hosted check: what a Mission pinned decides who a send under a per-job rule may reach.

const OPERATOR = 'op_perjob';
const ACCOUNT = 'acct_perjob';
const MISSION = 'ms_reply';
const PARENT = 'agt_parent';
const CHILD = 'agt_child';

type Sections = Omit<PolicyDefinitionInput, 'name'>;
const policy = (definition: Sections, agentId = PARENT, id = 'cpl_job'): EffectivePolicy => ({
  id, agentId, revision: 2, name: 'p', definition: normalizePolicy({ name: 'p', ...definition }), source: 'agent',
});

const perJobMail: Sections = {
  connections: {
    mode: 'listed',
    rules: [{ id: 'reply', effect: 'allow', recipients: 'per_mission', access: { connection_id: 'scon_resend', intents: [{ name: 'resend.send_email' }], constraints: [] } }],
  },
};

function context(agentId: string, missionId: string | null, action: ControlActionType, target: Record<string, unknown>, request?: ReturnType<typeof normalizeRequest>): DecisionContext {
  const built = buildDecisionRequest({
    decisionId: 'dec_aaaaaaaaaaaaaaaaaaaaaaaa',
    now: new Date('2026-10-30T10:00:00Z'),
    deadlineMs: 2_000,
    test: false,
    operatorId: OPERATOR,
    socketId: 'csk_x',
    accountId: ACCOUNT,
    agent: { id: agentId, passportJti: 'jti_1', missionId },
    actorKind: 'agent',
    action,
    target,
    amount: null,
    purpose: null,
    retryRef: null,
  });
  return { request: built.request, body: built.body, operatorId: OPERATOR, socket: {} as DecisionContext['socket'], ...(request ? { privileged: { request } } : {}) };
}

const resendSend = (agentId: string, missionId: string | null, body: Record<string, unknown>) =>
  context(
    agentId,
    missionId,
    'proxy.call',
    { service: 'resend', connection_id: 'scon_resend', method: 'POST', host: 'api.resend.com', path: '/emails' },
    normalizeRequest({ service: 'resend', url: 'https://api.resend.com/emails', method: 'POST', body: { from: 'agent@example.com', subject: 's', text: 't', ...body } }),
  );

const sender = buildRecipientPins({ recipients: ['ana@example.com'] });

/** `policies` is each agent's own policy; `missions` what each Mission pinned and the agent it was opened for. */
function build(policies: Record<string, EffectivePolicy | null>, missions: Record<string, { pins: RecipientPin[] | null; agent: string | null }>, parents: string[] | Error = []) {
  const agentsAbove = vi.fn(async (): Promise<string[]> => { if (parents instanceof Error) throw parents; return parents; });
  const read = vi.fn(async (_operatorId: string, missionId: string): Promise<MissionRecipients> => {
    const found = missions[missionId];
    return { pins: found?.pins ?? null, assignedAgentId: found?.agent ?? null };
  });
  const effective = vi.fn(async (_operatorId: string, agentId: string | null) => (agentId ? policies[agentId] ?? null : null));
  const check = new PolicyHostedCheck({
    policies: { effective },
    reviews: { open: vi.fn(), reserve: vi.fn(), consume: vi.fn(), release: vi.fn() } as never,
    limits: { consumeActions: vi.fn(), releaseActions: vi.fn() } as never,
    concurrency: { acquire: vi.fn(), release: vi.fn() } as never,
    missions: { read },
    lineage: { agentsAbove },
  });
  return { check, read, effective, agentsAbove };
}

const pinnedMission = { [MISSION]: { pins: sender, agent: PARENT } };

describe('a send under a rule that leaves its recipients to each Mission', () => {
  it('passes for the pinned sender and names the rule when it refuses anyone else', async () => {
    const { check } = build({ [PARENT]: policy(perJobMail) }, pinnedMission);
    expect(await check.evaluate(resendSend(PARENT, MISSION, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'allow' });
    const refused = await check.evaluate(resendSend(PARENT, MISSION, { to: ['ana@example.com', 'eve@evil.com'] }));
    expect(refused).toMatchObject({
      verdict: 'deny',
      reason: { code: 'recipient_not_allowed' },
      evidence: { policy_id: 'cpl_job', section: 'connections', rule: 'reply', code: 'recipient_not_allowed' },
    });
    // The refusal says which rule, never who.
    expect(JSON.stringify(refused)).not.toContain('eve@evil.com');
    expect(JSON.stringify(refused)).not.toContain('ana@example.com');
  });

  it('refuses a Mission that pins no one, and a call under no Mission, as not pinned', async () => {
    const { check } = build({ [PARENT]: policy(perJobMail) }, { [MISSION]: { pins: null, agent: PARENT } });
    expect(await check.evaluate(resendSend(PARENT, MISSION, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'deny', reason: { code: 'recipients_not_pinned' }, evidence: { code: 'recipients_not_pinned' } });
    expect(await check.evaluate(resendSend(PARENT, null, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'deny', reason: { code: 'recipients_not_pinned' } });
  });

  it('holds a delegated child to the same pins, though its own agent has no policy that says so', async () => {
    // The child carries the parent's Mission unchanged. It is another agent with no per-job rule of its own, so the
    // per-job rules of the agent the Mission was opened for bind it too.
    const { check } = build({ [PARENT]: policy(perJobMail) }, pinnedMission);
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'allow' });
    const refused = await check.evaluate(resendSend(CHILD, MISSION, { to: 'eve@evil.com' }));
    expect(refused).toMatchObject({ verdict: 'deny', reason: { code: 'recipient_not_allowed' }, evidence: { policy_id: 'cpl_job', rule: 'reply' } });
  });

  it('holds a child of a Mission that pinned no one to the same refusal', async () => {
    const { check } = build({ [PARENT]: policy(perJobMail) }, { [MISSION]: { pins: null, agent: PARENT } });
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'deny', reason: { code: 'recipients_not_pinned' } });
  });

  it('cannot be widened by the child\'s own policy: the stricter of the two applies, and the parent\'s rules reach only per-job sends', async () => {
    const childPolicy = policy({ connections: { mode: 'any', rules: [{ id: 'no-slack', effect: 'deny', access: { connection_id: 'scon_slack' } }] } }, CHILD, 'cpl_child');
    const { check } = build({ [PARENT]: policy(perJobMail), [CHILD]: childPolicy }, pinnedMission);
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'eve@evil.com' }))).toMatchObject({ verdict: 'deny', evidence: { policy_id: 'cpl_job', code: 'recipient_not_allowed' } });
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'allow' });
    // What the parent's per-job rule does not judge is the child's own policy's to decide.
    const slack = context(CHILD, MISSION, 'proxy.call', { service: 'slack', connection_id: 'scon_slack', method: 'POST', host: 'slack.com', path: '/api/chat.postMessage' },
      normalizeRequest({ service: 'slack', url: 'https://slack.com/api/chat.postMessage', method: 'POST', body: { channel: 'C1', text: 'hi' } }));
    expect(await check.evaluate(slack)).toMatchObject({ verdict: 'deny', evidence: { policy_id: 'cpl_child', rule: 'no-slack' } });
  });

  it('does not judge twice for the agent the Mission was opened for, and reads the owner\'s policy only for another agent', async () => {
    const { check, effective } = build({ [PARENT]: policy(perJobMail) }, pinnedMission);
    await check.evaluate(resendSend(PARENT, MISSION, { to: 'ana@example.com' }));
    expect(effective.mock.calls.map((c) => c[1])).toEqual([PARENT]);
  });

  it('cannot be slipped past by parallel calls: every call reads the same pins, and only the pinned recipient passes', async () => {
    const { check } = build({ [PARENT]: policy(perJobMail) }, pinnedMission);
    const targets = Array.from({ length: 60 }, (_, i) => (i % 3 === 0 ? 'ana@example.com' : i % 3 === 1 ? 'eve@evil.com' : 'ana@example.com.evil.net'));
    const callers = [PARENT, CHILD];
    const answers = await Promise.all(targets.map((to, i) => check.evaluate(resendSend(callers[i % 2]!, MISSION, { to }))));
    answers.forEach((answer, i) => expect(answer.verdict).toBe(targets[i] === 'ana@example.com' ? 'allow' : 'deny'));
    expect(answers.filter((a) => a.verdict === 'allow')).toHaveLength(20);
  });

  it('fails closed when the Mission cannot be read', async () => {
    const check = new PolicyHostedCheck({
      policies: { effective: vi.fn(async () => policy(perJobMail)) },
      reviews: {} as never,
      limits: {} as never,
      concurrency: {} as never,
      missions: { read: vi.fn(async () => { throw new Error('database down'); }) },
    });
    await expect(check.evaluate(resendSend(PARENT, MISSION, { to: 'ana@example.com' }))).rejects.toThrow('database down');
  });

  it('reads no Mission for an action no per-job rule judges, and judges a policy with no per-job rule as before', async () => {
    const plain = policy({ connections: { mode: 'any', rules: [] } });
    const { check, read } = build({ [PARENT]: plain }, pinnedMission);
    expect(await check.evaluate(resendSend(PARENT, MISSION, { to: 'anyone@example.com' }))).toMatchObject({ verdict: 'allow' });
    expect(await check.evaluate(context(PARENT, MISSION, 'model.call', { provider: 'openai', model: 'gpt-4o' }))).toMatchObject({ verdict: 'allow' });
    expect(read).toHaveBeenCalledTimes(1);
  });
});

// The account's own email, texts and calls: a send that names the message it answers carries who wrote it, and a rule
// that leaves the account's recipients to each send allows it to them and no one else.

describe('the account\'s own sends under recipients set per job', () => {
  const emailRule: Sections = { recipients: { email: 'per_mission', sms: 'per_mission', call: 'per_mission' } };
  const accountSend = (action: 'email.send' | 'sms.send' | 'call.start', target: Record<string, unknown>, pins: RecipientPin[] | null): DecisionContext => ({
    ...context(PARENT, 'ms_standing', action, target),
    ...(pins ? { privileged: { recipient_pins: pins } } : {}),
  });
  const mail = (to: string | string[]) => controlTargets.emailSend({ to });

  it('lets an email go to the stored sender, in any case, and refuses anyone else', async () => {
    const { check } = build({ [PARENT]: policy(emailRule) }, {});
    expect(await check.evaluate(accountSend('email.send', mail('Ana@Example.com'), sender))).toMatchObject({ verdict: 'allow' });
    const refused = await check.evaluate(accountSend('email.send', mail(['ana@example.com', 'eve@evil.com']), sender));
    expect(refused).toMatchObject({
      verdict: 'deny',
      reason: { code: 'recipient_not_allowed' },
      evidence: { section: 'recipients', rule: 'email', code: 'recipient_not_allowed' },
    });
    expect(JSON.stringify(refused)).not.toContain('evil.com');
    expect(JSON.stringify(refused)).not.toContain('ana@example.com');
  });

  it('judges a send that names no message (a forward or a new one) against the pins the owner gave the account\'s Mission', async () => {
    const { check, read } = build({ [PARENT]: policy(emailRule) }, { ms_standing: { pins: sender, agent: PARENT } });
    expect(await check.evaluate(accountSend('email.send', mail('ana@example.com'), null))).toMatchObject({ verdict: 'allow' });
    expect(await check.evaluate(accountSend('email.send', mail('eve@evil.com'), null))).toMatchObject({
      verdict: 'deny', reason: { code: 'recipient_not_allowed' },
    });
    expect(read).toHaveBeenCalledWith(OPERATOR, 'ms_standing');
  });

  it('refuses a send that names no message as not pinned when the account\'s Mission pins no one', async () => {
    const { check } = build({ [PARENT]: policy(emailRule) }, { ms_standing: { pins: null, agent: PARENT } });
    expect(await check.evaluate(accountSend('email.send', mail('ana@example.com'), null))).toMatchObject({
      verdict: 'deny', reason: { code: 'recipients_not_pinned' }, evidence: { section: 'recipients', rule: 'email', code: 'recipients_not_pinned' },
    });
  });

  it('reads no Mission for a send that carries who wrote the message it answers', async () => {
    const { check, read } = build({ [PARENT]: policy(emailRule) }, { ms_standing: { pins: null, agent: PARENT } });
    expect(await check.evaluate(accountSend('email.send', mail('ana@example.com'), sender))).toMatchObject({ verdict: 'allow' });
    expect(read).not.toHaveBeenCalled();
  });

  it('holds a text and a call to the exact number of the stored sender', async () => {
    const number = buildRecipientPins({ recipients: ['+14155550123'] });
    const { check } = build({ [PARENT]: policy(emailRule) }, {});
    expect(await check.evaluate(accountSend('sms.send', controlTargets.smsSend({ to: '+14155550123' }), number))).toMatchObject({ verdict: 'allow' });
    expect(await check.evaluate(accountSend('call.start', controlTargets.callStart({ to: '+14155550123', maxSeconds: 60 }), number))).toMatchObject({ verdict: 'allow' });
    expect(await check.evaluate(accountSend('sms.send', controlTargets.smsSend({ to: '+14155550199' }), number))).toMatchObject({ verdict: 'deny', evidence: { rule: 'sms', code: 'recipient_not_allowed' } });
    expect(await check.evaluate(accountSend('call.start', controlTargets.callStart({ to: '+14155550199', maxSeconds: 60 }), number))).toMatchObject({ verdict: 'deny', evidence: { rule: 'call', code: 'recipient_not_allowed' } });
    // The pin of an email message never matches a number, and a number's never an address.
    expect(await check.evaluate(accountSend('sms.send', controlTargets.smsSend({ to: '+14155550123' }), sender))).toMatchObject({ verdict: 'deny', evidence: { code: 'recipient_not_allowed' } });
    expect(await check.evaluate(accountSend('email.send', mail('ana@example.com'), number))).toMatchObject({ verdict: 'deny', evidence: { code: 'recipient_not_allowed' } });
  });

  it('leaves a send under a plain list as it was, with or without a pin', async () => {
    const { check } = build({ [PARENT]: policy({ recipients: { email: ['@example.com'] } }) }, {});
    expect(await check.evaluate(accountSend('email.send', mail('bob@example.com'), null))).toMatchObject({ verdict: 'allow' });
    expect(await check.evaluate(accountSend('email.send', mail('bob@example.com'), sender))).toMatchObject({ verdict: 'allow' });
    expect(await check.evaluate(accountSend('email.send', mail('eve@evil.com'), sender))).toMatchObject({ verdict: 'deny', evidence: { rule: 'email', code: 'recipient_not_allowed' } });
  });

  it('cannot be slipped past by parallel sends: only the stored sender passes', async () => {
    const { check } = build({ [PARENT]: policy(emailRule) }, {});
    const targets = Array.from({ length: 60 }, (_, i) => (i % 3 === 0 ? 'ana@example.com' : i % 3 === 1 ? 'eve@evil.com' : 'ana@example.com.evil.net'));
    const answers = await Promise.all(targets.map((to) => check.evaluate(accountSend('email.send', mail(to), sender))));
    answers.forEach((answer, i) => expect(answer.verdict).toBe(targets[i] === 'ana@example.com' ? 'allow' : 'deny'));
  });
});

describe('a delegated child is bound by every agent that delegated it', () => {
  const parentPolicy = policy(perJobMail);
  const noAgent = { [MISSION]: { pins: sender, agent: null } };

  it('holds a child under a Mission opened for no agent to the per-job rules of the agent that delegated it', async () => {
    const { check } = build({ [PARENT]: parentPolicy }, noAgent, [PARENT]);
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'allow' });
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'eve@evil.com' }))).toMatchObject({
      verdict: 'deny', reason: { code: 'recipient_not_allowed' }, evidence: { policy_id: 'cpl_job', rule: 'reply' },
    });
  });

  it('holds a grandchild to the rules of every agent above it, not only the nearest', async () => {
    const middle = policy({ connections: { mode: 'any', rules: [] } }, 'agt_middle', 'cpl_middle');
    const { check } = build({ [PARENT]: parentPolicy, agt_middle: middle }, noAgent, ['agt_middle', PARENT]);
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'eve@evil.com' }))).toMatchObject({ verdict: 'deny', evidence: { policy_id: 'cpl_job', code: 'recipient_not_allowed' } });
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'ana@example.com' }))).toMatchObject({ verdict: 'allow' });
  });

  it('binds the agent the Mission was opened for as well, when it is not one that delegated', async () => {
    const { check } = build({ [PARENT]: parentPolicy }, pinnedMission, []);
    expect(await check.evaluate(resendSend(CHILD, MISSION, { to: 'eve@evil.com' }))).toMatchObject({ verdict: 'deny', evidence: { rule: 'reply' } });
  });

  it('refuses when the delegation cannot be read, and reads it only for a call through the proxy', async () => {
    const { check } = build({ [PARENT]: parentPolicy }, noAgent, new Error('database down'));
    await expect(check.evaluate(resendSend(CHILD, MISSION, { to: 'ana@example.com' }))).rejects.toThrow('database down');
    const quiet = build({ [PARENT]: parentPolicy }, noAgent, [PARENT]);
    await quiet.check.evaluate(context(CHILD, MISSION, 'model.call', { provider: 'openai', model: 'gpt-4o' }));
    expect(quiet.agentsAbove).not.toHaveBeenCalled();
  });
});
