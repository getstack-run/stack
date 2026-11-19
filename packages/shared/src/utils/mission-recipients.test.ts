import { describe, expect, it } from 'vitest';
import { UnboundedSendRuleError } from '../errors/index.js';
import { PolicyDefinition, type PolicyDefinitionInput } from '../schemas/control-policy.js';
import { normalizeRequest } from './constraints.js';
import {
  assertPolicyBounded,
  classifyPolicyRevision,
  evaluatePolicy,
  normalizePolicy,
  policyUsesPerMission,
  type PolicyCall,
} from './control-policy.js';
import { buildRecipientPins, judgeAccountRecipients, judgePerMissionSend, mergeRecipientPins, phoneE164, readRecipientPins, type RecipientPin } from './mission-recipients.js';
import { MissionRecipientList } from '../schemas/mission-recipients.js';
import { findUnboundSendRules, perMissionRecipientPaths } from './send-bounds.js';

const providerOf = (id: string) => (id === 'scon_resend' ? 'resend' : id === 'scon_gmail' ? 'gmail' : undefined);
type Sections = Omit<PolicyDefinitionInput, 'name'> & { name?: string };
const policy = (input: Sections = {}) => normalizePolicy({ name: 'p', ...input });

const perJobRule = { id: 'reply', effect: 'allow', recipients: 'per_mission', access: { connection_id: 'scon_resend', intents: [{ name: 'resend.send_email' }], constraints: [] } } as const;
const listed = (...rules: Array<Record<string, unknown>>) => policy({ connections: { mode: 'listed', rules: rules as never } });
const resend = (body: Record<string, unknown>) =>
  normalizeRequest({ service: 'resend', url: 'https://api.resend.com/emails', method: 'POST', body: { from: 'a@x.com', subject: 's', text: 't', ...body } });
const sendCall = (request: ReturnType<typeof resend>, pins: readonly RecipientPin[] | null | undefined, mission = true): PolicyCall => ({
  action: 'proxy.call',
  target: { service: 'resend', connection_id: 'scon_resend', method: 'POST', host: 'api.resend.com', path: '/emails' },
  amountCents: null,
  request,
  ...(mission ? { mission: { recipientPins: pins ?? null } } : {}),
});
const pinned = buildRecipientPins({ recipients: ['Ana@Example.com'] })!;

describe('a send rule whose recipients are set per job', () => {
  it('is accepted when written, where the same rule without it is refused', () => {
    const plain = listed({ ...perJobRule, recipients: undefined });
    expect(() => assertPolicyBounded(plain, providerOf)).toThrow(UnboundedSendRuleError);
    expect(() => assertPolicyBounded(listed(perJobRule), providerOf)).not.toThrow();
  });

  it('is refused for a rule that names no send with a recipient field, and for review and deny rules', () => {
    const gmailDraft = { id: 'draft', effect: 'allow', recipients: 'per_mission', access: { connection_id: 'scon_gmail', intents: [{ name: 'gmail.send_draft' }] } };
    expect(findUnboundSendRules({ rules: [gmailDraft as never] }, providerOf)).toHaveLength(1);
    const raw = { id: 'raw', effect: 'allow', recipients: 'per_mission', access: { connection_id: 'scon_resend', intents: [], constraints: [{ path: 'method', op: 'eq', value: 'POST' }] } };
    expect(findUnboundSendRules({ rules: [raw as never] }, providerOf)).toHaveLength(1);
    expect(PolicyDefinition.safeParse({ name: 'x', connections: { rules: [{ ...perJobRule, effect: 'review' }] } }).success).toBe(false);
  });

  it('reads its recipient fields from the send intents it names', () => {
    expect(perMissionRecipientPaths(perJobRule)).toEqual({ enforced: ['body.to', 'body.cc', 'body.bcc'], required: ['body.to', 'body.cc', 'body.bcc'] });
    const partlyBound = { ...perJobRule, access: { ...perJobRule.access, constraints: [{ path: 'body.cc', op: 'not_exists', value: true }] } };
    expect(perMissionRecipientPaths(partlyBound as never)?.required).toEqual(['body.to', 'body.bcc']);
  });

  it('allows a reply to the pinned sender', () => {
    const p = listed(perJobRule);
    expect(evaluatePolicy(p, sendCall(resend({ to: 'ana@example.com' }), pinned)).verdict).toBe('allow');
    // The address as it was written to the Mission, in any case the pin lists.
    expect(evaluatePolicy(p, sendCall(resend({ to: ['Ana@Example.com'] }), pinned)).verdict).toBe('allow');
  });

  it('refuses a send to anyone else under the same Mission, however many recipients ride along', () => {
    const p = listed(perJobRule);
    for (const body of [{ to: 'eve@evil.com' }, { to: ['ana@example.com', 'eve@evil.com'] }, { to: 'ana@example.com', cc: 'eve@evil.com' }, { to: 'ana@example.com', bcc: ['eve@evil.com'] }]) {
      expect(evaluatePolicy(p, sendCall(resend(body), pinned))).toMatchObject({ verdict: 'deny', section: 'connections', rule: 'reply', code: 'recipient_not_allowed' });
    }
  });

  it('refuses a send that names no recipient it can read', () => {
    const p = listed(perJobRule);
    expect(evaluatePolicy(p, sendCall(resend({}), pinned))).toMatchObject({ verdict: 'deny', code: 'recipient_not_allowed' });
    expect(evaluatePolicy(p, sendCall(resend({ to: [] }), pinned))).toMatchObject({ verdict: 'deny', code: 'recipient_not_allowed' });
    expect(evaluatePolicy(p, sendCall(resend({ to: { address: 'ana@example.com' } }), pinned))).toMatchObject({ verdict: 'deny' });
  });

  it('refuses a Mission without a pin, and a call under no Mission, with a plain code', () => {
    const p = listed(perJobRule);
    const ok = resend({ to: 'ana@example.com' });
    expect(evaluatePolicy(p, sendCall(ok, null))).toMatchObject({ verdict: 'deny', code: 'recipients_not_pinned', rule: 'reply' });
    expect(evaluatePolicy(p, sendCall(ok, null, false))).toMatchObject({ verdict: 'deny', code: 'recipients_not_pinned' });
    expect(evaluatePolicy(p, sendCall(ok, []))).toMatchObject({ verdict: 'deny', code: 'recipients_not_pinned' });
  });

  it('needs a pin of its own for a recipient fixed by the Mission only for fields it leaves open', () => {
    // A pin on one field leaves the others open: cc has no pin, so the Mission does not pin every recipient field.
    const onlyTo: RecipientPin[] = [{ path: 'body.to', op: 'eq', value: 'ana@example.com' }];
    const p = listed(perJobRule);
    expect(evaluatePolicy(p, sendCall(resend({ to: 'ana@example.com' }), onlyTo))).toMatchObject({ verdict: 'deny', code: 'recipients_not_pinned' });
    const all: RecipientPin[] = [...onlyTo, { path: 'body.cc', op: 'in', value: ['ana@example.com'] }, { path: 'body.bcc', op: 'in', value: ['ana@example.com'] }];
    expect(evaluatePolicy(p, sendCall(resend({ to: 'ana@example.com' }), all)).verdict).toBe('allow');
    expect(evaluatePolicy(p, sendCall(resend({ to: 'ana@example.com', cc: 'bob@example.com' }), all))).toMatchObject({ verdict: 'deny', code: 'recipient_not_allowed' });
  });

  it('is judged in every connections mode, and another allow rule that names its own recipients still allows', () => {
    const anyMode = policy({ connections: { mode: 'any', rules: [perJobRule as never] } });
    expect(evaluatePolicy(anyMode, sendCall(resend({ to: 'eve@evil.com' }), pinned)).verdict).toBe('deny');
    expect(evaluatePolicy(anyMode, sendCall(resend({ to: 'ana@example.com' }), pinned)).verdict).toBe('allow');
    const withOwn = listed(perJobRule, { id: 'cfo', effect: 'allow', access: { connection_id: 'scon_resend', intents: [{ name: 'resend.send_email_to', params: { to: ['cfo@acme.com'] } }], constraints: [{ path: 'body.cc', op: 'not_exists', value: true }, { path: 'body.bcc', op: 'not_exists', value: true }] } });
    expect(evaluatePolicy(withOwn, sendCall(resend({ to: 'cfo@acme.com' }), null)).verdict).toBe('allow');
    expect(evaluatePolicy(withOwn, sendCall(resend({ to: 'eve@evil.com' }), pinned))).toMatchObject({ verdict: 'deny' });
  });

  it('does not touch calls that are not sends under the rule', () => {
    const p = listed(perJobRule, { id: 'read', effect: 'allow', access: { connection_id: 'scon_resend', intents: [], constraints: [{ path: 'method', op: 'eq', value: 'GET' }] } });
    const get = normalizeRequest({ service: 'resend', url: 'https://api.resend.com/emails', method: 'GET' });
    expect(evaluatePolicy(p, { ...sendCall(get, null), target: { connection_id: 'scon_resend', method: 'GET' } }).verdict).toBe('allow');
  });
});

describe('Mission pins', () => {
  it('builds from the list shorthand and field pins, one pin per field', () => {
    expect(buildRecipientPins({})).toBeNull();
    expect(buildRecipientPins({ recipients: ['Ana@Example.com'] })).toEqual([{ path: '*', op: 'in', value: ['Ana@Example.com', 'ana@example.com'] }]);
    const both = buildRecipientPins({ recipients: ['ana@example.com'], recipient_pins: [{ path: 'url.pathname', op: 'eq', value: '/channels/1/messages' }] });
    expect(both).toHaveLength(2);
    expect(() => buildRecipientPins({ recipients: ['a@x.com'], recipient_pins: [{ path: '*', op: 'eq', value: 'b@x.com' }] })).toThrow(/once/);
  });

  it('counts a person once however the address is cased, and keeps both spellings of every mixed-case address within the cap', () => {
    const same = buildRecipientPins({ recipients: ['Ana@Example.com', 'ana@example.com'] });
    expect(same).toEqual([{ path: '*', op: 'in', value: ['Ana@Example.com', 'ana@example.com'] }]);
    const many = Array.from({ length: 200 }, (_, i) => 'Person' + i + '@Example.com');
    const pins = buildRecipientPins({ recipients: many })!;
    expect(pins[0]!.value).toHaveLength(400);
  });

  it('reads stored pins back, and a stored value that does not parse is no pin', () => {
    expect(readRecipientPins(null)).toBeNull();
    expect(readRecipientPins([{ path: '*', op: 'in', value: ['a@x.com'] }])).toEqual([{ path: '*', op: 'in', value: ['a@x.com'] }]);
    expect(readRecipientPins([{ path: '*', op: 'matches', value: '.*' }])).toBeNull();
    expect(readRecipientPins('garbage')).toBeNull();
  });

  it('lets the * list cover a recipient inside the URL: the whole path or one of its segments is a listed value', () => {
    const rule = { enforced: ['url.pathname'], required: ['url.pathname'] };
    const at = (id: string) => normalizeRequest({ service: 'discord', url: `https://discord.com/api/v10/channels/${id}/messages`, method: 'POST', body: { content: 'hi' } });
    const channel = buildRecipientPins({ recipients: ['123'] });
    expect(judgePerMissionSend(rule, channel, at('123'))).toEqual({ ok: true });
    expect(judgePerMissionSend(rule, channel, at('999'))).toMatchObject({ ok: false, code: 'recipient_not_allowed' });
    expect(judgePerMissionSend(rule, channel, at('1234'))).toMatchObject({ ok: false, code: 'recipient_not_allowed' });
    const wholePath = buildRecipientPins({ recipients: ['/api/v10/channels/123/messages'] });
    expect(judgePerMissionSend(rule, wholePath, at('123'))).toEqual({ ok: true });
    // An email list does not let a send to a channel through.
    expect(judgePerMissionSend(rule, pinned, at('123'))).toMatchObject({ ok: false, code: 'recipient_not_allowed' });
    // A pin of its own on the path still wins over the list.
    const own = buildRecipientPins({ recipients: ['999'], recipient_pins: [{ path: 'url.pathname', op: 'eq', value: '/api/v10/channels/123/messages' }] });
    expect(judgePerMissionSend(rule, own, at('123'))).toEqual({ ok: true });
    expect(judgePerMissionSend(rule, own, at('999'))).toMatchObject({ ok: false, code: 'recipient_not_allowed' });
    expect(judgePerMissionSend({ enforced: ['url.pathname'], required: [] }, null, at('123'))).toMatchObject({ ok: false, code: 'recipients_not_pinned' });
  });

  it('merges pins the owner adds into a running Mission\'s, and only widens', () => {
    const start = buildRecipientPins({ recipients: ['ana@example.com'], recipient_pins: [{ path: 'body.cc', op: 'eq', value: 'x@example.com' }] })!;
    expect(mergeRecipientPins(start, [{ path: '*', op: 'in', value: ['bob@example.com', 'ana@example.com'] }, { path: 'body.bcc', op: 'eq', value: 'z@example.com' }, { path: 'body.cc', op: 'eq', value: 'y@example.com' }])).toEqual([
      { path: '*', op: 'in', value: ['ana@example.com', 'bob@example.com'] },
      { path: 'body.cc', op: 'in', value: ['x@example.com', 'y@example.com'] },
      { path: 'body.bcc', op: 'eq', value: 'z@example.com' },
    ]);
    expect(mergeRecipientPins(null, [{ path: 'body.chat_id', op: 'eq', value: 5 }])).toEqual([{ path: 'body.chat_id', op: 'eq', value: 5 }]);
    expect(() => mergeRecipientPins([{ path: 'body.chat_id', op: 'eq', value: 5 }], [{ path: 'body.chat_id', op: 'eq', value: 6 }])).toThrow(/one value/);
    const full = Array.from({ length: 64 }, (_, i) => ({ path: `body.f${i}`, op: 'eq' as const, value: 'x' }));
    expect(() => mergeRecipientPins(full, [{ path: 'body.more', op: 'eq', value: 'x' }])).toThrow(/64/);
  });

  it('compares numbers in E.164 form', () => {
    expect(phoneE164('+1 (415) 555-0123')).toBe('+14155550123');
    expect(phoneE164('0044 20 7946 0958')).toBe('+442079460958');
    expect(phoneE164('not a number')).toBe('not a number');
    const pins = buildRecipientPins({ recipients: ['+1 415 555 0123'] });
    expect(judgeAccountRecipients(pins, 'sms', ['+14155550123'])).toEqual({ ok: true });
    expect(judgeAccountRecipients(pins, 'call', ['+14155550124'])).toMatchObject({ ok: false, code: 'recipient_not_allowed' });
  });

  it('drops a recipient listed twice, in any case, instead of refusing the list', () => {
    expect(MissionRecipientList.parse(['Ana@Example.com', 'bob@example.com', 'ana@example.com', 'bob@example.com'])).toEqual(['Ana@Example.com', 'bob@example.com']);
  });

  it('takes 64 pins and 1,000 recipients in a list', () => {
    const recipients = Array.from({ length: 1000 }, (_, i) => `person${i}@example.com`);
    const pins = buildRecipientPins({
      recipients,
      recipient_pins: Array.from({ length: 63 }, (_, i) => ({ path: `body.field${i}`, op: 'eq' as const, value: 'x' })),
    })!;
    expect(pins).toHaveLength(64);
    expect(pins[0]!.value).toHaveLength(1000);
    expect(() => buildRecipientPins({
      recipients,
      recipient_pins: Array.from({ length: 64 }, (_, i) => ({ path: `body.field${i}`, op: 'eq' as const, value: 'x' })),
    })).toThrow(/64/);
  });
});

describe('revising a policy with per-job recipients', () => {
  const plain = listed({ ...perJobRule, recipients: undefined, access: { ...perJobRule.access, constraints: [{ path: 'body.to', op: 'in', value: ['cfo@acme.com'] }, { path: 'body.cc', op: 'not_exists', value: true }, { path: 'body.bcc', op: 'not_exists', value: true }] } });
  const perJob = listed(perJobRule);

  it('treats making a rule per job as a tightening and leaving it as a loosening', () => {
    const plainUnpinned = listed({ id: 'reply', effect: 'review', access: perJobRule.access });
    expect(classifyPolicyRevision(listed(perJobRule), listed({ ...perJobRule, recipients: undefined, effect: 'review' }))).toBe('loosen');
    expect(classifyPolicyRevision(listed({ ...perJobRule, effect: 'allow', recipients: 'per_mission' }), plainUnpinned)).toBe('loosen');
    // a rule that names its recipients is tightened by also asking for a Mission's pin
    expect(classifyPolicyRevision(listed({ ...perJob.connections.rules[0]!, access: (plain.connections.rules[0] as never as { access: never }).access }), plain)).toBe('tighten');
  });

  it('treats dropping the per-job rule, or replacing it with a plain allowance, as a loosening', () => {
    expect(classifyPolicyRevision(policy({ connections: { mode: 'any', rules: [] } }), policy({ connections: { mode: 'any', rules: [perJobRule as never] } }))).toBe('loosen');
    expect(classifyPolicyRevision(plain, perJob)).toBe('loosen');
  });

  it('knows whether a policy leaves recipients to each Mission', () => {
    expect(policyUsesPerMission(perJob)).toBe(true);
    expect(policyUsesPerMission(plain)).toBe(false);
  });
});

describe('the account\'s own sends under a per-job rule', () => {
  const sender = buildRecipientPins({ recipients: ['Ana@Example.com'] })!;
  const account = (recipients: Record<string, 'per_mission' | string[]>) => policy({ recipients: recipients as never });
  const mailTo = (...addresses: string[]): PolicyCall => ({
    action: 'email.send',
    target: { recipients: addresses.map((address) => ({ address })) },
    amountCents: null,
    mission: { recipientPins: sender },
  });

  it('allows the pinned sender in any case and refuses anyone else, with the same codes and words', () => {
    const rule = account({ email: 'per_mission' });
    expect(evaluatePolicy(rule, mailTo('ana@example.com'))).toEqual({ verdict: 'allow' });
    expect(evaluatePolicy(rule, mailTo('ana@example.com', 'eve@evil.com'))).toMatchObject({
      verdict: 'deny', section: 'recipients', rule: 'email', code: 'recipient_not_allowed', message: 'This recipient is not one this Mission may send to.',
    });
    expect(evaluatePolicy(rule, { ...mailTo('ana@example.com'), mission: null })).toMatchObject({ verdict: 'deny', code: 'recipients_not_pinned' });
    expect(evaluatePolicy(rule, { ...mailTo(), target: { recipients: [] } })).toMatchObject({ verdict: 'deny', code: 'recipient_not_allowed' });
  });

  it('is accepted by the schema in place of a list, and by nothing else', () => {
    expect(PolicyDefinition.safeParse({ name: 'p', recipients: { email: 'per_mission', sms: 'per_mission', call: 'per_mission' } }).success).toBe(true);
    expect(PolicyDefinition.safeParse({ name: 'p', recipients: { email: 'anyone' } }).success).toBe(false);
  });

  it('treats per-job recipients as a tightening of no list and a loosening of a change to or from a list', () => {
    expect(classifyPolicyRevision(account({ email: 'per_mission' }), policy())).toBe('tighten');
    expect(classifyPolicyRevision(account({ email: 'per_mission' }), account({ email: ['@example.com'] }))).toBe('loosen');
    expect(classifyPolicyRevision(account({ email: ['@example.com'] }), account({ email: 'per_mission' }))).toBe('loosen');
    expect(classifyPolicyRevision(policy(), account({ email: 'per_mission' }))).toBe('loosen');
    expect(classifyPolicyRevision(account({ sms: 'per_mission', email: 'per_mission' }), account({ sms: 'per_mission', email: 'per_mission' }))).toBe('unchanged');
    expect(classifyPolicyRevision(account({ call: 'per_mission', email: 'per_mission' }), account({ email: 'per_mission' }))).toBe('tighten');
  });
});

describe('a per-job rule in connections mode any refuses only the calls it covers', () => {
  const fromRule = { id: 'reply', effect: 'allow', recipients: 'per_mission', access: { connection_id: 'scon_resend', intents: [{ name: 'resend.send_email_from', params: { from: 'me@x.com' } }], constraints: [] } };
  const anyMode = policy({ connections: { mode: 'any', rules: [fromRule as never] } });
  const send = (from: string, to: string) => resend({ from, to });

  it('leaves a send the rule does not cover (its own constraints fail) to the connections mode, which allows it', () => {
    expect(evaluatePolicy(anyMode, sendCall(send('other@x.com', 'eve@evil.com'), pinned)).verdict).toBe('allow');
    expect(evaluatePolicy(anyMode, sendCall(send('other@x.com', 'ana@example.com'), pinned)).verdict).toBe('allow');
    expect(evaluatePolicy(anyMode, sendCall(send('other@x.com', 'eve@evil.com'), null)).verdict).toBe('allow');
  });

  it('still allows the send the rule describes, to the pinned sender only', () => {
    expect(evaluatePolicy(anyMode, sendCall(send('me@x.com', 'ana@example.com'), pinned)).verdict).toBe('allow');
    expect(evaluatePolicy(anyMode, sendCall(send('me@x.com', 'eve@evil.com'), pinned))).toMatchObject({ verdict: 'deny', code: 'recipient_not_allowed' });
    expect(evaluatePolicy(anyMode, sendCall(send('me@x.com', 'ana@example.com'), null))).toMatchObject({ verdict: 'deny', code: 'recipients_not_pinned' });
  });

  it('leaves calls that are not at the rule\'s send endpoints alone, and another connection', () => {
    const get = normalizeRequest({ service: 'resend', url: 'https://api.resend.com/emails/abc', method: 'GET' });
    expect(evaluatePolicy(anyMode, { ...sendCall(get, null), target: { connection_id: 'scon_resend', method: 'GET' } }).verdict).toBe('allow');
    const other = { ...sendCall(send('other@x.com', 'eve@evil.com'), null), target: { connection_id: 'scon_other', method: 'POST' } };
    expect(evaluatePolicy(anyMode, other).verdict).toBe('allow');
  });

  it('lets another allow rule that matches the call still allow it', () => {
    const own = { id: 'cfo', effect: 'allow', access: { connection_id: 'scon_resend', intents: [{ name: 'resend.send_email_to', params: { to: ['cfo@acme.com'] } }], constraints: [{ path: 'body.cc', op: 'not_exists', value: true }, { path: 'body.bcc', op: 'not_exists', value: true }] } };
    const both = policy({ connections: { mode: 'any', rules: [fromRule as never, own as never] } });
    expect(evaluatePolicy(both, sendCall(send('other@x.com', 'cfo@acme.com'), null)).verdict).toBe('allow');
    // Covered by neither rule: mode any lets it through.
    expect(evaluatePolicy(both, sendCall(send('other@x.com', 'eve@evil.com'), null)).verdict).toBe('allow');
  });
});

describe('adding an allowance next to a per-job rule', () => {
  const toEvil = { id: 'fixed', effect: 'allow', access: { connection_id: 'scon_resend', intents: [{ name: 'resend.send_email_to', params: { to: ['evil@y.com'] } }], constraints: [] } };
  const readOnly = { id: 'read', effect: 'allow', access: { connection_id: 'scon_resend', intents: [{ name: 'resend.get_email' }], constraints: [] } };
  const secondPerJob = { ...perJobRule, id: 'reply2' };
  const modes = ['any', 'listed'] as const;

  it.each(modes)('is a loosening in mode %s unless the new rule is per job itself', (mode) => {
    const make = (...rules: Array<Record<string, unknown>>) => policy({ connections: { mode, rules: rules as never } });
    const current = make(perJobRule);
    expect(classifyPolicyRevision(make(perJobRule, toEvil), current)).toBe('loosen');
    expect(classifyPolicyRevision(make(perJobRule, { ...toEvil, access: { connection_id: 'scon_resend', intents: [], constraints: [] } }), current)).toBe('loosen');
    expect(classifyPolicyRevision(make(perJobRule, secondPerJob), current)).not.toBe('loosen');
  });

  it('is no loosening in mode any when the new rule is a read, or on another connection', () => {
    const make = (...rules: Array<Record<string, unknown>>) => policy({ connections: { mode: 'any', rules: rules as never } });
    expect(classifyPolicyRevision(make(perJobRule, readOnly), make(perJobRule))).toBe('tighten');
    expect(classifyPolicyRevision(make(perJobRule, { ...toEvil, access: { ...toEvil.access, connection_id: 'scon_gmail' } }), make(perJobRule))).toBe('tighten');
  });

  it('keeps a plain allowance the current policy already had, and narrows inside it', () => {
    const make = (...rules: Array<Record<string, unknown>>) => policy({ connections: { mode: 'any', rules: rules as never } });
    const current = make(perJobRule, toEvil);
    expect(classifyPolicyRevision(make(perJobRule, toEvil), current)).toBe('unchanged');
    // A plain allowance that already existed may be narrowed, though it overlaps the per-job rule.
    const narrower = { ...toEvil, access: { ...toEvil.access, constraints: [{ path: 'body.subject', op: 'eq', value: 'Hi' }] } };
    expect(classifyPolicyRevision(make(perJobRule, narrower), current)).toBe('tighten');
    // But a new plain allowance beside it is a loosening.
    expect(classifyPolicyRevision(make(perJobRule, toEvil, { ...toEvil, id: 'more', access: { ...toEvil.access, intents: [{ name: 'resend.send_email_to', params: { to: ['other@y.com'] } }] } }), current)).toBe('loosen');
  });
});
