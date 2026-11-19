import { describe, expect, it } from 'vitest';
import { UnboundedSendRuleError } from '../errors/index.js';
import type { Constraint } from '../schemas/passport.js';
import { FleetRule } from '../schemas/fleet.js';
import { expandGrantRules, expandIntents } from '../intents/index.js';
import { listIntents } from '../intents/index.js';
import { findFailingConstraint, normalizeRequest } from './constraints.js';
import {
  assertSendRulesBounded, describeUnboundSendRule, findUnboundSendRules, isEgressProvider, isFiniteLiteralPattern,
  type SendBoundRule,
} from './send-bounds.js';

type Effect = SendBoundRule['effect'];
const rule = (id: string, connection: string, intents: { name: string; params?: Record<string, unknown> }[], constraints: SendBoundRule['access']['constraints'] = [], effect: Effect = 'allow'): SendBoundRule =>
  ({ id, effect, access: { connection_id: connection, intents, constraints } });
const policy = (...rules: SendBoundRule[]) => ({ rules });
const providers: Record<string, string> = { scon_slack: 'slack', scon_gmail: 'gmail', scon_resend: 'resend', scon_sendgrid: 'sendgrid', scon_brevo: 'brevo', scon_github: 'github', scon_custom: 'custom', scon_twitter: 'twitter', scon_discord: 'discord', scon_teams: 'ms_teams', scon_twilio: 'twilio', scon_drive: 'google_drive' };
const providerOf = (id: string) => providers[id];

describe('send bounds', () => {
  it('accepts a send whose recipients are pinned', () => {
    expect(findUnboundSendRules(policy(rule('post', 'scon_slack', [{ name: 'slack.post_to_channel', params: { channel: ['C123'] } }])), providerOf)).toEqual([]);
    expect(findUnboundSendRules(policy(rule('mail', 'scon_resend', [{ name: 'resend.send_email_to', params: { to: ['cfo@acme.com'] } }])), providerOf)).toEqual([]);
  });

  it('rejects an unbounded Slack, Resend or Gmail send set to allow', () => {
    const p = policy(
      rule('gmail', 'scon_gmail', [{ name: 'gmail.send_email' }]),
      rule('resend', 'scon_resend', [{ name: 'resend.send_email' }]),
      rule('upload', 'scon_slack', [{ name: 'slack.upload_file', params: { channel: 'C123' } }]),
    );
    const findings = findUnboundSendRules(p, providerOf);
    expect(findings.map(f => [f.rule_id, f.reason, f.unbound_paths])).toEqual([
      // Gmail recipients sit inside a base64 message; the engine decodes them, so they are bound like any field.
      ['gmail', 'unbound_recipient', ['derived.email.recipients']],
      ['resend', 'unbound_recipient', ['body.to', 'body.cc', 'body.bcc']],
      // files.upload takes `channels` as well as `channel`.
      ['upload', 'unbound_recipient', ['body.channels']],
    ]);
    expect(() => assertSendRulesBounded(p, providerOf)).toThrow(UnboundedSendRuleError);
    try { assertSendRulesBounded(p, providerOf); } catch (error) {
      expect((error as Error).message).toContain('Rule "resend" allows sending on resend without naming who receives it. Bind body.to, body.cc, body.bcc with eq or in');
      expect((error as UnboundedSendRuleError).code).toBe('UNBOUNDED_SEND_RULE');
      expect((error as UnboundedSendRuleError).statusCode).toBe(400);
      expect((error as UnboundedSendRuleError).details).toEqual({ rules: findings });
    }
  });

  it('counts constraints anywhere in the rule, including not_exists', () => {
    const bound = rule('resend', 'scon_resend', [{ name: 'resend.send_email_to', params: { to: 'cfo@acme.com' } }],
      [{ path: 'body.cc', op: 'not_exists', value: true }, { path: 'body.bcc', op: 'in', value: ['audit@acme.com'] }]);
    expect(findUnboundSendRules(policy(bound), providerOf)).toEqual([]);
    const raw = rule('resend', 'scon_resend', [{ name: 'resend.send_email' }], [
      { path: 'body.to', op: 'in', value: ['a@acme.com'] }, { path: 'body.cc', op: 'not_exists', value: true }, { path: 'body.bcc', op: 'not_exists', value: true },
    ]);
    expect(findUnboundSendRules(policy(raw), providerOf)).toEqual([]);
    const regex = rule('resend', 'scon_resend', [{ name: 'resend.send_email' }], [
      { path: 'body.to', op: 'matches', value: '^.*@acme\\.com$' }, { path: 'body.cc', op: 'not_exists', value: true }, { path: 'body.bcc', op: 'not_exists', value: true },
    ]);
    expect(findUnboundSendRules(policy(regex), providerOf)[0]?.unbound_paths).toEqual(['body.to']);
  });

  it('not_exists on a container binds the fields below it, not the other way round', () => {
    const noBody = rule('resend', 'scon_resend', [{ name: 'resend.send_email' }], [{ path: 'body', op: 'not_exists', value: true }]);
    expect(findUnboundSendRules(policy(noBody), providerOf)).toEqual([]);
    const sibling = rule('resend', 'scon_resend', [{ name: 'resend.send_email' }], [{ path: 'body.t', op: 'not_exists', value: true }]);
    expect(findUnboundSendRules(policy(sibling), providerOf)[0]?.unbound_paths).toEqual(['body.to', 'body.cc', 'body.bcc']);
  });

  it('accepts a bounded "send to" on Resend with no extra constraints: cc and bcc are bound by the intent', () => {
    const p = policy(
      rule('resend', 'scon_resend', [{ name: 'resend.send_email_to', params: { to: 'cfo@acme.com' } }]),
      rule('resend-cc', 'scon_resend', [{ name: 'resend.send_email_to', params: { to: 'cfo@acme.com', cc: ['audit@acme.com'] } }]),
    );
    expect(findUnboundSendRules(p, providerOf)).toEqual([]);
    expect(() => assertSendRulesBounded(p, providerOf)).not.toThrow();
  });

  it('accepts SendGrid and Brevo "send to": their intents check every recipient of every personalization', () => {
    expect(findUnboundSendRules(policy(
      rule('sendgrid', 'scon_sendgrid', [{ name: 'sendgrid.send_mail_to', params: { to: 'cfo@acme.com' } }]),
      rule('brevo', 'scon_brevo', [{ name: 'brevo.send_transactional_email_to', params: { to: 'cfo@acme.com' } }]),
    ), providerOf)).toEqual([]);
    // The bare send intents name their recipient fields, so they are unbound until a rule pins them.
    const bare = findUnboundSendRules(policy(
      rule('sendgrid', 'scon_sendgrid', [{ name: 'sendgrid.send_mail' }]),
      rule('brevo', 'scon_brevo', [{ name: 'brevo.send_transactional_email' }]),
    ), providerOf);
    expect(bare.map(f => [f.rule_id, f.reason])).toEqual([['sendgrid', 'unbound_recipient'], ['brevo', 'unbound_recipient']]);
  });

  it('enforces those bounds on every recipient field at runtime', () => {
    const allowed = (intent: string, params: Record<string, unknown>, host: string, path: string, body: unknown) =>
      findFailingConstraint(expandIntents([{ name: intent, params }]), normalizeRequest({ method: 'POST', url: `https://${host}${path}`, body } as never)) === null;
    const resend = (body: unknown) => allowed('resend.send_email_to', { to: 'cfo@acme.com' }, 'api.resend.com', '/emails', body);
    expect(resend({ to: 'cfo@acme.com', subject: 's' })).toBe(true);
    expect(resend({ to: ['cfo@acme.com'], cc: 'attacker@evil.com' })).toBe(false);
    expect(resend({ to: 'cfo@acme.com', bcc: ['attacker@evil.com'] })).toBe(false);
    expect(allowed('resend.send_email_to', { to: 'cfo@acme.com', cc: ['audit@acme.com'] }, 'api.resend.com', '/emails', { to: 'cfo@acme.com', cc: ['audit@acme.com'] })).toBe(true);
  });

  it('accepts review and deny for any send', () => {
    const p = policy(rule('r', 'scon_gmail', [{ name: 'gmail.send_email' }], [], 'review'), rule('d', 'scon_twitter', [{ name: 'twitter.create_tweet' }], [], 'deny'));
    expect(findUnboundSendRules(p, providerOf)).toEqual([]);
    expect(() => assertSendRulesBounded(p, providerOf)).not.toThrow();
  });

  it('rejects allow on a send whose recipient cannot be named', () => {
    const findings = findUnboundSendRules(policy(rule('tweet', 'scon_twitter', [{ name: 'twitter.create_tweet' }])), providerOf);
    expect(findings).toEqual([expect.objectContaining({ reason: 'implicit_recipient', intents: ['twitter.create_tweet'] })]);
  });

  it('treats a URL-carried recipient as bound only by a finite pattern', () => {
    expect(findUnboundSendRules(policy(rule('d', 'scon_discord', [{ name: 'discord.send_channel_message', params: { channel: ['1', '2'] } }])), providerOf)).toEqual([]);
    // Teams binds the team but the channel is [^/]+: any channel in the team.
    expect(findUnboundSendRules(policy(rule('t', 'scon_teams', [{ name: 'ms_teams.send_channel_message', params: { team: 'T1' } }])), providerOf)[0]?.unbound_paths).toEqual(['url.pathname']);
    expect(isFiniteLiteralPattern('^/api/v10/channels/(1|2)/messages$')).toBe(true);
    expect(isFiniteLiteralPattern('^/a/(?:b|c)\\.json$')).toBe(true);
    for (const open of ['^/a/[^/]+$', '^/a/.*$', '^/a/\\d+$', '/a/b$', '^/a/b', '^/a/b?$', '^/a/(?=b)$', '^/a/(b$']) {
      expect(isFiniteLiteralPattern(open)).toBe(false);
    }
  });

  it('flags a rule that names no action on a provider that can send, unless it is read-only', () => {
    const open = rule('all', 'scon_slack', []);
    expect(findUnboundSendRules(policy(open), providerOf)).toEqual([expect.objectContaining({ reason: 'unpinned_operation', provider: 'slack' })]);
    expect(findUnboundSendRules(policy(rule('ro', 'scon_slack', [], [{ path: 'method', op: 'eq', value: 'GET' }])), providerOf)).toEqual([]);
    // GitHub has no send intents; custom connections cannot be judged.
    expect(findUnboundSendRules(policy(rule('gh', 'scon_github', [])), providerOf)).toEqual([]);
    expect(findUnboundSendRules(policy(rule('c', 'scon_custom', [{ name: 'custom.require_host', params: { host: 'api.example.com' } }])), providerOf)).toEqual([]);
    // Without a provider lookup (schema level) such a rule is left to the server.
    expect(findUnboundSendRules(policy(open))).toEqual([]);
    expect(isEgressProvider('slack')).toBe(true);
    expect(isEgressProvider('github')).toBe(false);
  });

  it('judges raw-constraint rules by the send operations they could still reach', () => {
    const post = [{ path: 'method', op: 'eq', value: 'POST' }, { path: 'url.pathname', op: 'eq', value: '/api/chat.postMessage' }] as const;
    // The e2e fixture shape: path and channel pinned with raw constraints.
    expect(findUnboundSendRules(policy(rule('raw', 'scon_slack', [], [...post, { path: 'body.channel', op: 'eq', value: 'C123' }])), providerOf)).toEqual([]);
    expect(findUnboundSendRules(policy(rule('raw', 'scon_slack', [], post)), providerOf)).toEqual([
      expect.objectContaining({ reason: 'unbound_recipient', unbound_paths: ['body.channel'] }),
    ]);
    // A non-send path on a sending provider is fine.
    expect(findUnboundSendRules(policy(rule('topic', 'scon_slack', [], [{ path: 'url.pathname', op: 'eq', value: '/api/conversations.setTopic' }])), providerOf)).toEqual([]);
    // Path ids from the catalog are generalised: another WhatsApp number still sends.
    providers.scon_wa = 'whatsapp_business';
    expect(findUnboundSendRules(policy(rule('wa', 'scon_wa', [], [{ path: 'url.pathname', op: 'eq', value: '/v21.0/999888/messages' }])), providerOf)[0]?.unbound_paths).toEqual(['body.to']);
    // A recipient carried in the path is bound by pinning the literal path.
    expect(findUnboundSendRules(policy(rule('d', 'scon_discord', [], [{ path: 'method', op: 'eq', value: 'POST' }, { path: 'url.pathname', op: 'eq', value: '/api/v10/channels/42/messages' }])), providerOf)).toEqual([]);
  });

  describe('a rule that holds a choice of rules is judged one alternative at a time', () => {
    const read = { constraints: [{ path: 'method', op: 'eq', value: 'GET' }] } as const;
    const boundedPost = { intents: [{ name: 'slack.post_to_channel', params: { channel: ['C123'] } }] };
    const rawPost = { constraints: [{ path: 'method', op: 'eq', value: 'POST' }, { path: 'url.pathname', op: 'eq', value: '/api/chat.postMessage' }] } as const;
    // The shape a grant's rules take in a policy: no intents, the choice stored as constraints.
    const grantRule = (alternatives: Parameters<typeof expandGrantRules>[0]['alternatives']) =>
      rule('grant', 'scon_slack', [], expandGrantRules({ alternatives }));

    it('accepts a read rule beside a post rule that names its channel', () => {
      expect(findUnboundSendRules(policy(grantRule([read, boundedPost])), providerOf)).toEqual([]);
      expect(findUnboundSendRules(policy(grantRule([read, { constraints: [...rawPost.constraints, { path: 'body.channel', op: 'eq', value: 'C123' }] }])), providerOf)).toEqual([]);
    });

    it('refuses the choice when one alternative sends without naming who receives it', () => {
      expect(findUnboundSendRules(policy(grantRule([read, rawPost])), providerOf)).toEqual([
        expect.objectContaining({ rule_id: 'grant', reason: 'unbound_recipient', unbound_paths: ['body.channel'] }),
      ]);
      expect(findUnboundSendRules(policy(grantRule([boundedPost, { constraints: [{ path: 'method', op: 'eq', value: 'POST' }] }])), providerOf)).toEqual([
        expect.objectContaining({ rule_id: 'grant', reason: 'unpinned_operation' }),
      ]);
    });

    it('judges each alternative with the limits every call must meet', () => {
      // The shared limit binds the channel for both alternatives.
      const shared = expandGrantRules({ constraints: [{ path: 'body.channel', op: 'eq', value: 'C123' }], alternatives: [read, rawPost] });
      expect(findUnboundSendRules(policy(rule('grant', 'scon_slack', [], shared)), providerOf)).toEqual([]);
    });

    it('lets a rule with no choice be judged as it always was', () => {
      expect(findUnboundSendRules(policy(grantRule([rawPost])), providerOf)).toEqual([expect.objectContaining({ reason: 'unbound_recipient' })]);
    });
  });

  it('a non-send intent pins the rule to that action', () => {
    expect(findUnboundSendRules(policy(rule('read', 'scon_slack', [{ name: 'slack.read_channel_history', params: { channel: 'C1' } }])), providerOf)).toEqual([]);
  });

  it('reports an unknown intent instead of guessing', () => {
    expect(findUnboundSendRules(policy(rule('x', 'scon_slack', [{ name: 'slack.no_such_thing' }])), providerOf)[0]?.reason).toBe('unknown_intent');
  });

  it('fails closed on params that no longer expand', () => {
    const findings = findUnboundSendRules(policy(rule('bad', 'scon_resend', [{ name: 'resend.send_email_to', params: { to: 5 } }])), providerOf);
    expect(findings).toEqual([expect.objectContaining({ rule_id: 'bad', reason: 'unknown_intent', intents: ['resend.send_email_to'] })]);
  });
});

describe('recipient pins by kind', () => {
  it('counts exact addresses, phone numbers and domains as bound', () => {
    // An exact address (to + cc + bcc).
    expect(findUnboundSendRules(policy(rule('addr', 'scon_resend', [{ name: 'resend.send_email_to', params: { to: 'cfo@acme.com' } }])), providerOf)).toEqual([]);
    // A phone number.
    expect(findUnboundSendRules(policy(rule('sms', 'scon_twilio', [{ name: 'twilio.send_sms_from', params: { from: '+14155550101' } }], [{ path: 'body.To', op: 'in', value: ['+46701740606', '+46701740607'] }])), providerOf)).toEqual([]);
    expect(findUnboundSendRules(policy(rule('sms', 'scon_twilio', [{ name: 'twilio.send_sms_from', params: { from: '+14155550101' } }])), providerOf)[0]?.unbound_paths).toEqual(['body.To']);
    // A domain, where the intent names it (a Drive permission).
    const share = rule('share', 'scon_drive', [{ name: 'google_drive.manage_permissions', params: { file_id: 'F1' } }]);
    const open = findUnboundSendRules(policy(share), providerOf);
    expect(open[0]?.unbound_paths).toEqual(['body.type', 'body.emailAddress', 'body.domain']);
    const pinned = rule('share', 'scon_drive', [{ name: 'google_drive.manage_permissions', params: { file_id: 'F1' } }], [
      { path: 'body.type', op: 'eq', value: 'domain' },
      { path: 'body.emailAddress', op: 'not_exists', value: true },
      { path: 'body.domain', op: 'eq', value: 'acme.com' },
    ]);
    expect(findUnboundSendRules(policy(pinned), providerOf)).toEqual([]);
  });

  it('does not count an empty list or an open operator as a pin', () => {
    const base = rule('sms', 'scon_twilio', [{ name: 'twilio.send_sms_from', params: { from: '+14155550101' } }]);
    const openOperators: Constraint[] = [
      { path: 'body.To', op: 'in', value: [] },
      { path: 'body.To', op: 'starts_with', value: '+46' },
      { path: 'body.To', op: 'not_eq', value: '+1' },
      { path: 'body.To', op: 'exists', value: true },
      { path: 'body.To', op: 'matches', value: '^\\+46.*$' },
    ];
    for (const c of openOperators) {
      expect(findUnboundSendRules(policy({ ...base, access: { ...base.access, constraints: [c] } }), providerOf)[0]?.unbound_paths).toEqual(['body.To']);
    }
  });

  it('reports every recipient path an intent declares, even when one is pinned', () => {
    const r = rule('mail', 'scon_resend', [{ name: 'resend.send_email' }], [{ path: 'body.to', op: 'eq', value: 'a@acme.com' }]);
    expect(findUnboundSendRules(policy(r), providerOf)[0]?.unbound_paths).toEqual(['body.cc', 'body.bcc']);
  });

  it('gives each finding a customer-facing sentence', () => {
    const [unbound] = findUnboundSendRules(policy(rule('sms', 'scon_twilio', [{ name: 'twilio.send_sms_from', params: { from: '+14155550101' } }])), providerOf);
    expect(describeUnboundSendRule(unbound!)).toBe('Rule "sms" allows sending on twilio without naming who receives it. Bind body.To with eq or in (or not_exists), set the rule\'s recipients to "per_mission" so each Mission names them, or set the rule\'s effect to "review" or "deny".');
    const [implicit] = findUnboundSendRules(policy(rule('t', 'scon_twitter', [{ name: 'twitter.create_tweet' }])), providerOf);
    expect(describeUnboundSendRule(implicit!)).toContain('whose recipients cannot be named in advance');
    const [open] = findUnboundSendRules(policy(rule('all', 'scon_slack', [])), providerOf);
    expect(describeUnboundSendRule(open!)).toContain('allows any call on slack');
    const [unknown] = findUnboundSendRules(policy(rule('x', 'scon_slack', [{ name: 'slack.nope' }])), providerOf);
    expect(describeUnboundSendRule(unknown!)).toContain('intent STACK does not know: slack.nope');
  });

  it('takes a parsed fleet rule as it stands', () => {
    const parsed = FleetRule.parse({ id: 'mail', effect: 'allow', access: { connection_id: 'scon_resend', scopes: ['x'], intents: [{ name: 'resend.send_email' }] } });
    expect(findUnboundSendRules({ rules: [parsed] }, providerOf)[0]?.reason).toBe('unbound_recipient');
  });
});

describe('send bounds over the whole catalog', () => {
  const intents = listIntents();
  const sends = intents.filter(i => i.effect === 'send');

  it('judges every send intent: unbounded as given, and bounded once its recipient paths are pinned', () => {
    const problems: string[] = [];
    for (const intent of sends) {
      const provider = intent.name.slice(0, intent.name.indexOf('.'));
      const connection = `scon_${provider}`;
      const lookup = (id: string) => (id === connection ? provider : undefined);
      const bare = rule('r', connection, [{ name: intent.name }]);
      // Params may be needed to expand; an expansion failure is reported as unknown_intent, which is fail-closed.
      const first = findUnboundSendRules(policy(bare), lookup)[0];
      if (!first) { problems.push(`${intent.name}: allowed with no recipient pin`); continue; }
      if (!intent.recipient_paths?.length) {
        if (first.reason !== 'implicit_recipient' && first.reason !== 'unknown_intent') problems.push(`${intent.name}: ${first.reason}`);
        continue;
      }
      if (first.reason === 'unknown_intent') continue; // needs params to expand; judged by the targeted tests
      const pins = intent.recipient_paths.map(path => ({ path, op: 'in' as const, value: ['x'] }));
      const after = findUnboundSendRules(policy(rule('r', connection, [{ name: intent.name }], pins)), lookup);
      if (after.length) problems.push(`${intent.name}: still unbound after pinning ${intent.recipient_paths.join(', ')}: ${after[0]!.reason}`);
    }
    expect(problems).toEqual([]);
  });

  it('has an egress provider for every send intent', () => {
    for (const intent of sends) expect(isEgressProvider(intent.name.slice(0, intent.name.indexOf('.')))).toBe(true);
  });

  it('never marks a monid intent as a send: a paid data run delivers nothing to a person', () => {
    expect(sends.filter(i => i.name.startsWith('monid.'))).toEqual([]);
    expect(isEgressProvider('monid')).toBe(false);
  });
});
