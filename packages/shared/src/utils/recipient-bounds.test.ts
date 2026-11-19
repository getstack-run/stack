import { describe, expect, it } from 'vitest';
import { UnboundedSendRuleError } from '../errors/index.js';
import type { Constraint } from '../schemas/passport.js';
import { expandIntents } from '../intents/index.js';
import { evaluateConstraint, findFailingConstraint, normalizeRequest, resolvePath } from './constraints.js';
import { assertSendRulesBounded, describeUnboundSendRule, findUnboundSendRules, type SendBoundRule } from './send-bounds.js';

// Recipient bounds on the sends whose recipients are not a plain field: Gmail and Outlook (inside an encoded
// message), SendGrid, Brevo, calendar attendees and Zendesk (inside arrays of objects). Each case runs the real
// intent's constraints against a request, the way the proxy does, so a send to anyone off the list must be refused.

type Json = Record<string, unknown>;
const request = (method: string, url: string, body?: unknown, query?: Record<string, string>) =>
  normalizeRequest({ service: 'x', method, url, headers: {}, ...(body === undefined ? {} : { body }), ...(query ? { query } : {}) } as never);

/** Does a request pass every constraint the intents (and any extra constraints) bind? */
const allowed = (refs: { name: string; params?: Json }[], req: ReturnType<typeof request>, extra: Constraint[] = []) =>
  findFailingConstraint([...expandIntents(refs.map(r => ({ name: r.name, params: r.params ?? {} }))), ...extra], req) === null;

const b64url = (text: string) => Buffer.from(text, 'utf8').toString('base64url');
const GMAIL_SEND = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';
const message = (headers: string) => `${headers}\r\nSubject: Q3\r\n\r\nBalance 1,234,567.89\r\n`;

describe('Gmail: gmail.send_email_to binds every To, Cc and Bcc address in the message', () => {
  const gmail = (headers: string | null, url = GMAIL_SEND, to: string | string[] = 'cfo@acme.com') =>
    allowed([{ name: 'gmail.send_email_to', params: { to } }], request('POST', url, headers === null ? {} : { raw: b64url(message(headers)) }));

  it('sends to an allowlisted address, however it is written', () => {
    expect(gmail('To: cfo@acme.com')).toBe(true);
    expect(gmail('To: CFO <cfo@acme.com>')).toBe(true);
    expect(gmail('To: "Chief Financial Officer" <CFO@ACME.COM>')).toBe(true);
    expect(gmail('To: cfo@acme.com\r\nCc: cfo@acme.com\r\nBcc: cfo@acme.com')).toBe(true);
    expect(gmail('to: cfo@acme.com')).toBe(true);
    expect(gmail('To: cfo@acme.com, audit@acme.com', GMAIL_SEND, ['cfo@acme.com', 'Audit@Acme.com'])).toBe(true);
  });

  it('refuses any recipient off the list, in To, Cc or Bcc, and with several recipients', () => {
    expect(gmail('To: attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com, attacker@evil.com')).toBe(false);
    expect(gmail('To: attacker@evil.com, cfo@acme.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nCc: attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nBcc: attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nCc: audit@acme.com')).toBe(false);
    expect(gmail('To: cfo@acme.com, audit@acme.com', GMAIL_SEND, 'cfo@acme.com')).toBe(false);
    expect(gmail('Subject: no recipient header at all')).toBe(false);
  });

  it('sees a recipient hidden by header tricks', () => {
    // Folded continuation lines, a second header, odd case and resent headers all still count.
    expect(gmail('To: cfo@acme.com\r\nBcc: cfo@acme.com,\r\n attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com,\r\n\tattacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nBcc:\r\n attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nTO: attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nbCc: attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nResent-To: attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nResent-Bcc: attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com\nBcc: attacker@evil.com')).toBe(false); // LF-only line ends
    // Group syntax and comments do not hide an address.
    expect(gmail('To: friends: cfo@acme.com, attacker@evil.com;')).toBe(false);
    expect(gmail('To: undisclosed: attacker@evil.com;')).toBe(false);
    expect(gmail('To: cfo@acme.com (attacker@evil.com)')).toBe(true); // a comment is not a recipient
    expect(gmail('To: (c) attacker@evil.com (d)')).toBe(false);
    // A display name that contains an address does not stand in for the real one.
    expect(gmail('To: "cfo@acme.com" <attacker@evil.com>')).toBe(false);
    expect(gmail('To: cfo@acme.com <attacker@evil.com>')).toBe(false);
  });

  it('refuses an address inside an encoded word, in any recipient header', () => {
    expect(gmail('To: =?utf-8?q?attacker=40evil.com?=')).toBe(false);
    expect(gmail('To: cfo@acme.com\r\nBcc: =?utf-8?b?YXR0YWNrZXJAZXZpbC5jb20=?=')).toBe(false);
    expect(gmail('To: =?UTF-8?Q?cfo=40acme.com?=')).toBe(false); // even an allowed one: not read, so refused
    expect(gmail('To: =?utf-8?q?CFO?= <cfo@acme.com>')).toBe(true); // a name decodes; the address is plain
    expect(gmail('To: =?utf-8?q?Name?= <attacker@evil.com>')).toBe(false);
    expect(gmail('To: =?utf-8?x?bad?= <cfo@acme.com>')).toBe(false); // an encoded word this reader cannot decode
  });

  it('refuses headers it cannot read rather than guessing', () => {
    expect(gmail('To: "cfo"@acme.com')).toBe(false); // quoted local part
    expect(gmail('To: <@relay.example:cfo@acme.com>')).toBe(false); // source route
    expect(gmail('To: cfo@acme.com\r\nBcc attacker@evil.com')).toBe(false); // a header line with no colon
    expect(gmail('To: cfo@acme.com\r\nBcc: attacker@evil.com\rX: y')).toBe(false); // bare CR
    expect(gmail('To: cfo@acme.com\r\nX-A: a\u0000\r\nBcc: attacker@evil.com')).toBe(false); // NUL
    expect(gmail('To: cfo@acme.com, , ')).toBe(true); // an empty list element is legal and adds no recipient
    expect(gmail('To: cfo@acme.com;attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@acme.com attacker@evil.com')).toBe(false);
    expect(gmail('To: cfo@müller.example')).toBe(false); // internationalised address
  });

  it('has unknown recipients, and so refuses, when the message cannot be decoded', () => {
    const send = (body: unknown) => allowed([{ name: 'gmail.send_email_to', params: { to: 'cfo@acme.com' } }], request('POST', GMAIL_SEND, body));
    expect(send({ raw: b64url(message('To: cfo@acme.com')) })).toBe(true);
    expect(send({ raw: 'this is not base64url!' })).toBe(false);
    expect(send({ raw: '%%%' })).toBe(false);
    expect(send({ raw: `${b64url(message('To: cfo@acme.com'))}!` })).toBe(false);
    expect(send({ raw: ` ${b64url(message('To: cfo@acme.com'))}` })).toBe(false); // whitespace is not skipped
    expect(send({ raw: Buffer.from(message('To: cfo@acme.com')).toString('base64').replace(/=+$/, '') + '+/' })).toBe(false); // standard alphabet
    expect(send({ raw: '' })).toBe(false);
    expect(send({ raw: 42 })).toBe(false);
    expect(send({ raw: [b64url(message('To: cfo@acme.com'))] })).toBe(false);
    expect(send({ raw: { value: b64url(message('To: cfo@acme.com')) } })).toBe(false);
    expect(send({})).toBe(false);
    expect(send(undefined)).toBe(false);
    expect(send('To: cfo@acme.com')).toBe(false);
    expect(send(null)).toBe(false);
    expect(resolvePath(request('POST', GMAIL_SEND, { raw: 'not base64!' }), 'derived.email.recipients')).toBeUndefined();
  });

  it('refuses the endpoints and uploads that carry no readable message', () => {
    const raw = b64url(message('To: cfo@acme.com'));
    const media = (uploadType: string, body: unknown, path = '/upload/gmail/v1/users/me/messages/send') =>
      allowed([{ name: 'gmail.send_email_to', params: { to: 'cfo@acme.com' } }], request('POST', `https://gmail.googleapis.com${path}`, body, { uploadType }));
    // The intent binds the plain send endpoint only, so the upload path never passes its own constraints.
    expect(media('media', message('To: cfo@acme.com'))).toBe(false);
    expect(media('multipart', message('To: cfo@acme.com'))).toBe(false);
    expect(media('resumable', message('To: cfo@acme.com'))).toBe(false);
    // And a pin written over the upload endpoint reads only the simple media form.
    const pin: Constraint = { path: 'derived.email.recipients', op: 'in', value: ['cfo@acme.com'] };
    const uploadSend = (uploadType: string, body: unknown) => evaluateConstraint(pin, request('POST', 'https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send', body, { uploadType }));
    expect(uploadSend('media', message('To: cfo@acme.com'))).toBe(true);
    expect(uploadSend('media', message('To: cfo@acme.com\r\nBcc: attacker@evil.com'))).toBe(false);
    expect(uploadSend('multipart', message('To: cfo@acme.com'))).toBe(false);
    expect(uploadSend('resumable', message('To: cfo@acme.com'))).toBe(false);
    // A draft sent by id carries no message; a draft body is read.
    expect(evaluateConstraint(pin, request('POST', 'https://gmail.googleapis.com/gmail/v1/users/me/drafts/send', { id: 'r123' }))).toBe(false);
    expect(evaluateConstraint(pin, request('POST', 'https://gmail.googleapis.com/gmail/v1/users/me/drafts', { message: { raw } }))).toBe(true);
    // Another host, or an endpoint that does not send, derives nothing.
    expect(evaluateConstraint(pin, request('POST', 'https://evil.example/gmail/v1/users/me/messages/send', { raw }))).toBe(false);
    expect(evaluateConstraint(pin, request('POST', 'https://gmail.googleapis.com/gmail/v1/users/me/messages/import', { raw }))).toBe(false);
  });

  it('gives a recipient pin on the bare send intent the same protection', () => {
    const pin: Constraint[] = [{ path: 'derived.email.recipients', op: 'in', value: ['cfo@acme.com'] }];
    const bare = (headers: string) => allowed([{ name: 'gmail.send_email' }], request('POST', GMAIL_SEND, { raw: b64url(message(headers)) }), pin);
    expect(bare('To: cfo@acme.com')).toBe(true);
    expect(bare('To: cfo@acme.com\r\nBcc: attacker@evil.com')).toBe(false);
    expect(allowed([{ name: 'gmail.send_email' }], request('POST', GMAIL_SEND, { raw: b64url(message('To: attacker@evil.com')) }))).toBe(true); // unpinned: any recipient
  });
});

describe('Outlook: recipients in JSON or MIME form are all bound', () => {
  const GRAPH_SEND = 'https://graph.microsoft.com/v1.0/me/sendMail';
  const addr = (...addresses: string[]) => addresses.map(address => ({ emailAddress: { address } }));
  const mail = (message: Json) => ({ message });
  const sendTo = (body: unknown, to = 'cfo@acme.com') => allowed([{ name: 'outlook.send_mail_to', params: { to } }], request('POST', GRAPH_SEND, body));

  it('sends to the one allowlisted address and refuses an added Cc, Bcc or second To', () => {
    expect(sendTo(mail({ subject: 's', toRecipients: addr('cfo@acme.com') }))).toBe(true);
    expect(sendTo(mail({ toRecipients: addr('cfo@acme.com'), ccRecipients: addr('attacker@evil.com') }))).toBe(false);
    expect(sendTo(mail({ toRecipients: addr('cfo@acme.com'), bccRecipients: addr('attacker@evil.com') }))).toBe(false);
    expect(sendTo(mail({ toRecipients: addr('cfo@acme.com', 'attacker@evil.com') }))).toBe(false);
    expect(sendTo(mail({ toRecipients: addr('cfo@acme.com'), ccRecipients: addr('cfo@acme.com') }))).toBe(true);
  });

  it('refuses a recipient list it cannot read', () => {
    expect(sendTo(mail({ toRecipients: [{ emailAddress: {} }] }))).toBe(false);
    expect(sendTo(mail({ toRecipients: [{ emailAddress: { address: 7 } }] }))).toBe(false);
    expect(sendTo(mail({ toRecipients: [{ emailAddress: { address: 'cfo@acme.com, attacker@evil.com' } }] }))).toBe(false);
    expect(sendTo(mail({ toRecipients: [{ emailAddress: { address: 'Name <attacker@evil.com>' } }] }))).toBe(false);
    expect(sendTo(mail({ toRecipients: addr('cfo@acme.com'), bccRecipients: 'attacker@evil.com' }))).toBe(false);
    expect(sendTo(mail({ toRecipients: addr('cfo@acme.com'), ccRecipients: { emailAddress: { address: 'attacker@evil.com' } } }))).toBe(false);
    expect(sendTo(mail({ toRecipients: addr('cfo@acme.com'), attachments: 'x' }))).toBe(false);
    expect(sendTo({ toRecipients: addr('cfo@acme.com') })).toBe(false); // not wrapped in `message`
    expect(sendTo(undefined)).toBe(false);
  });

  it('reads the recipients of a MIME message with a raw pin, and refuses a hidden one', () => {
    const pin: Constraint[] = [{ path: 'derived.email.recipients', op: 'in', value: ['cfo@acme.com'] }];
    const mime = (headers: string) => allowed([{ name: 'outlook.send_mail' }], request('POST', GRAPH_SEND, Buffer.from(message(headers)).toString('base64')), pin);
    expect(mime('To: cfo@acme.com')).toBe(true);
    expect(mime('To: cfo@acme.com\r\nBcc: cfo@acme.com,\r\n attacker@evil.com')).toBe(false);
    expect(mime('To: =?utf-8?q?attacker=40evil.com?=')).toBe(false);
    expect(allowed([{ name: 'outlook.send_mail' }], request('POST', GRAPH_SEND, 'not base64 at all!'), pin)).toBe(false);
    expect(allowed([{ name: 'outlook.send_mail' }], request('POST', GRAPH_SEND, ''), pin)).toBe(false);
    // The intent that pins the JSON fields refuses a MIME body outright: nothing to read there.
    expect(sendTo(Buffer.from(message('To: cfo@acme.com')).toString('base64'))).toBe(false);
  });

  it('keeps the domain intent to its domain across To, Cc and Bcc', () => {
    const domain = (body: unknown) => allowed([{ name: 'outlook.send_mail_to_domain', params: { domain: ['acme.com', 'corp.acme.com'] } }], request('POST', GRAPH_SEND, body));
    expect(domain(mail({ toRecipients: addr('cfo@acme.com', 'a@corp.acme.com') }))).toBe(true);
    expect(domain(mail({ toRecipients: addr('cfo@acme.com'), bccRecipients: addr('attacker@evil.com') }))).toBe(false);
    expect(domain(mail({ toRecipients: addr('cfo@acme.com', 'attacker@acme.com.evil.com') }))).toBe(false);
    expect(domain(mail({ toRecipients: addr('cfo@acme.com', 'attacker@notacme.com') }))).toBe(false);
  });

  it('reads the added recipients of a forward, and not the recipients of a reply', () => {
    const forward = (body: unknown) => allowed([{ name: 'outlook.forward_message' }], request('POST', 'https://graph.microsoft.com/v1.0/me/messages/AAA/forward', body),
      [{ path: 'derived.email.recipients', op: 'in', value: ['cfo@acme.com'] }]);
    expect(forward({ toRecipients: addr('cfo@acme.com'), comment: 'fyi' })).toBe(true);
    expect(forward({ toRecipients: addr('cfo@acme.com', 'attacker@evil.com') })).toBe(false);
    expect(forward({ message: { bccRecipients: addr('attacker@evil.com') }, toRecipients: addr('cfo@acme.com') })).toBe(false);
    expect(forward({ comment: 'no recipients' })).toBe(false);
    const reply = (path: string) => allowed([{ name: 'outlook.reply_message' }], request('POST', `https://graph.microsoft.com/v1.0/me/messages/AAA/${path}`, { comment: 'ok' }),
      [{ path: 'derived.email.recipients', op: 'in', value: ['cfo@acme.com'] }]);
    expect(reply('reply')).toBe(false);
  });

  it('pins every forwarding target of an inbox rule', () => {
    const rule = (actions: Json) => request('POST', 'https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules', { displayName: 'r', actions });
    const pins: Constraint[] = [
      { path: 'body.actions.forwardTo[].emailAddress.address', op: 'in', value: ['cfo@acme.com'] },
      { path: 'body.actions.redirectTo', op: 'not_exists', value: true },
      { path: 'body.actions.forwardAsAttachmentTo', op: 'not_exists', value: true },
    ];
    const ok = (actions: Json) => allowed([{ name: 'outlook.create_rule' }], rule(actions), pins);
    expect(ok({ forwardTo: addr('cfo@acme.com') })).toBe(true);
    expect(ok({ forwardTo: addr('cfo@acme.com', 'attacker@evil.com') })).toBe(false);
    expect(ok({ forwardTo: addr('cfo@acme.com'), redirectTo: addr('attacker@evil.com') })).toBe(false);
    expect(ok({ forwardTo: addr('cfo@acme.com'), forwardAsAttachmentTo: addr('attacker@evil.com') })).toBe(false);
    expect(ok({ forwardTo: [{ emailAddress: { name: 'x' } }, ...addr('cfo@acme.com')] })).toBe(true); // an entry with no address delivers nowhere
    expect(ok({ forwardTo: ['attacker@evil.com'] })).toBe(false);
  });
});

describe('SendGrid and Brevo: every recipient of every personalization is bound', () => {
  const SENDGRID = 'https://api.sendgrid.com/v3/mail/send';
  const BREVO = 'https://api.brevo.com/v3/smtp/email';
  const p = (...emails: string[]) => emails.map(email => ({ email }));
  const sendgrid = (body: unknown, params: Json = { to: 'cfo@acme.com' }) => allowed([{ name: 'sendgrid.send_mail_to', params }], request('POST', SENDGRID, body));
  const brevo = (body: unknown, params: Json = { to: 'cfo@acme.com' }) => allowed([{ name: 'brevo.send_transactional_email_to', params }], request('POST', BREVO, body));

  it('SendGrid: sends to the listed recipients in every personalization', () => {
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com') }], from: { email: 'a@acme.com' } })).toBe(true);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com') }, { to: p('cfo@acme.com') }] })).toBe(true);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com', 'audit@acme.com') }] }, { to: ['cfo@acme.com', 'audit@acme.com'] })).toBe(true);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com'), cc: p('audit@acme.com'), bcc: p('audit@acme.com') }] }, { to: 'cfo@acme.com', cc: 'audit@acme.com', bcc: ['audit@acme.com'] })).toBe(true);
  });

  it('SendGrid: refuses a second personalization, a second To, a Cc, a Bcc or the account-wide Bcc copy', () => {
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com') }, { to: p('attacker@evil.com') }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('attacker@evil.com') }, { to: p('cfo@acme.com') }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com', 'attacker@evil.com') }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com'), cc: p('attacker@evil.com') }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com') }, { to: p('cfo@acme.com'), bcc: p('attacker@evil.com') }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com') }], mail_settings: { bcc: { enable: true, email: 'attacker@evil.com' } } })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com'), cc: p('audit@acme.com') }] })).toBe(false); // cc not on the list
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com'), bcc: p('audit@acme.com') }] }, { to: 'cfo@acme.com', cc: 'audit@acme.com' })).toBe(false); // listed as cc, sent as bcc
  });

  it('SendGrid: refuses shapes it cannot read', () => {
    expect(sendgrid({})).toBe(false);
    expect(sendgrid({ personalizations: [] })).toBe(false);
    expect(sendgrid({ personalizations: 'x' })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: 'cfo@acme.com' }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: { email: 'cfo@acme.com' } }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: ['cfo@acme.com'] }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: [{ name: 'no address' }] }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com') }, 'x'] })).toBe(false); // an entry that is not an object is not read as empty
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com'), cc: 'attacker@evil.com' }] })).toBe(false);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com'), cc: [] }] })).toBe(true);
    expect(sendgrid({ personalizations: [{ to: p('cfo@acme.com'), cc: null }] })).toBe(false);
    expect(sendgrid(undefined)).toBe(false);
    expect(sendgrid([{ to: p('cfo@acme.com') }])).toBe(false);
  });

  it('Brevo: sends to the listed recipients and refuses every other path to an inbox', () => {
    expect(brevo({ sender: { email: 'a@acme.com' }, to: p('cfo@acme.com'), subject: 's' })).toBe(true);
    expect(brevo({ to: p('cfo@acme.com', 'audit@acme.com') }, { to: ['cfo@acme.com', 'audit@acme.com'] })).toBe(true);
    expect(brevo({ to: p('cfo@acme.com'), cc: p('audit@acme.com'), bcc: p('audit@acme.com') }, { to: 'cfo@acme.com', cc: 'audit@acme.com', bcc: 'audit@acme.com' })).toBe(true);
    expect(brevo({ to: p('cfo@acme.com', 'attacker@evil.com') })).toBe(false);
    expect(brevo({ to: p('attacker@evil.com', 'cfo@acme.com') })).toBe(false);
    expect(brevo({ to: p('cfo@acme.com'), cc: p('attacker@evil.com') })).toBe(false);
    expect(brevo({ to: p('cfo@acme.com'), bcc: p('attacker@evil.com') })).toBe(false);
    expect(brevo({ to: p('cfo@acme.com'), messageVersions: [{ to: p('attacker@evil.com') }] })).toBe(false);
    expect(brevo({ to: p('cfo@acme.com'), messageVersions: [] })).toBe(false);
    expect(brevo({ to: p('cfo@acme.com'), cc: p('audit@acme.com') })).toBe(false);
  });

  it('Brevo: refuses shapes it cannot read', () => {
    expect(brevo({})).toBe(false);
    expect(brevo({ to: [] })).toBe(false);
    expect(brevo({ to: 'cfo@acme.com' })).toBe(false);
    expect(brevo({ to: ['cfo@acme.com'] })).toBe(false);
    expect(brevo({ to: [{ name: 'x' }] })).toBe(false);
    expect(brevo({ to: p('cfo@acme.com'), cc: { email: 'attacker@evil.com' } })).toBe(false);
    expect(brevo({ to: p('cfo@acme.com'), bcc: null })).toBe(false);
    expect(brevo(undefined)).toBe(false);
  });

  it('pins the same recipient paths when a rule names the bare send intent', () => {
    const pins: Constraint[] = [
      { path: 'body.personalizations[].to[].email', op: 'in', value: ['cfo@acme.com'] },
      { path: 'body.personalizations[].cc', op: 'not_exists', value: true },
      { path: 'body.personalizations[].bcc', op: 'not_exists', value: true },
      { path: 'body.mail_settings.bcc', op: 'not_exists', value: true },
    ];
    expect(allowed([{ name: 'sendgrid.send_mail' }], request('POST', SENDGRID, { personalizations: [{ to: p('cfo@acme.com') }] }), pins)).toBe(true);
    expect(allowed([{ name: 'sendgrid.send_mail' }], request('POST', SENDGRID, { personalizations: [{ to: p('cfo@acme.com'), bcc: p('x@evil.com') }] }), pins)).toBe(false);
    expect(allowed([{ name: 'sendgrid.send_mail' }], request('POST', SENDGRID, { personalizations: [{ to: p('cfo@acme.com') }], mail_settings: { bcc: { email: 'x@evil.com' } } }), pins)).toBe(false);
  });
});

describe('calendar attendees and Zendesk side conversations: every element is bound', () => {
  const EVENTS = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
  const attendees = (...emails: string[]) => emails.map(email => ({ email }));
  const pin: Constraint[] = [{ path: 'body.attendees[].email', op: 'in', value: ['cfo@acme.com', 'audit@acme.com'] }];
  const event = (name: string, method: string, url: string, body: unknown, constraints = pin) =>
    allowed([{ name, params: { calendarId: 'primary' } }], request(method, url, body), constraints);

  it('invites only the listed attendees, on create, update and patch', () => {
    for (const [name, method, url] of [
      ['google_calendar.create_event', 'POST', EVENTS],
      ['google_calendar.update_event', 'PUT', `${EVENTS}/evt1`],
      ['google_calendar.patch_event', 'PATCH', `${EVENTS}/evt1`],
    ] as const) {
      expect(event(name, method, url, { summary: 's', attendees: attendees('cfo@acme.com') }), name).toBe(true);
      expect(event(name, method, url, { attendees: attendees('cfo@acme.com', 'audit@acme.com') }), name).toBe(true);
      expect(event(name, method, url, { attendees: attendees('cfo@acme.com', 'attacker@evil.com') }), name).toBe(false);
      expect(event(name, method, url, { attendees: attendees('attacker@evil.com', 'cfo@acme.com') }), name).toBe(false);
      expect(event(name, method, url, { attendees: ['attacker@evil.com'] }), name).toBe(false);
      expect(event(name, method, url, { attendees: { email: 'attacker@evil.com' } }), name).toBe(false);
      expect(event(name, method, url, { attendees: [{ displayName: 'no address' }] }), name).toBe(false);
      expect(event(name, method, url, { summary: 'no attendees' }), name).toBe(false); // the pin names who may be invited; none given is not a match
      // A rule that allows no invitations says so: not_exists on the list.
      expect(event(name, method, url, { summary: 'no attendees' }, [{ path: 'body.attendees', op: 'not_exists', value: true }]), name).toBe(true);
      expect(event(name, method, url, { attendees: attendees('attacker@evil.com') }, [{ path: 'body.attendees', op: 'not_exists', value: true }]), name).toBe(false);
    }
  });

  it('Zendesk: opens a side conversation only to the listed addresses', () => {
    const url = 'https://acme.zendesk.com/api/v2/tickets/42/side_conversations';
    const side = (body: unknown) => allowed([{ name: 'zendesk.create_side_conversation', params: { ticket_id: '42' } }], request('POST', url, body),
      [{ path: 'body.message.to[].email', op: 'in', value: ['cfo@acme.com'] }]);
    expect(side({ message: { subject: 's', to: attendees('cfo@acme.com') } })).toBe(true);
    expect(side({ message: { to: attendees('cfo@acme.com', 'attacker@evil.com') } })).toBe(false);
    expect(side({ message: { to: [{ group_id: 'g1' }] } })).toBe(false);
    expect(side({ message: { to: 'attacker@evil.com' } })).toBe(false);
    expect(side({ message: {} })).toBe(false);
    expect(side({})).toBe(false);
  });
});

describe('the acceptance case: sends must be bounded before a policy can allow them', () => {
  const connections: Record<string, string> = {
    scon_gmail: 'gmail', scon_outlook: 'outlook', scon_sendgrid: 'sendgrid', scon_brevo: 'brevo', scon_calendar: 'google_calendar', scon_zendesk: 'zendesk',
  };
  const providerOf = (id: string) => connections[id];
  const rule = (id: string, connection: string, intents: { name: string; params?: Json }[], constraints: Constraint[] = [], effect: SendBoundRule['effect'] = 'allow'): SendBoundRule =>
    ({ id, effect, access: { connection_id: connection, intents, constraints } });
  const policy = (...rules: SendBoundRule[]) => ({ rules });

  const unbounded = [
    rule('gmail-any', 'scon_gmail', [{ name: 'gmail.send_email' }]),
    rule('outlook-any', 'scon_outlook', [{ name: 'outlook.send_mail' }]),
    rule('sendgrid-any', 'scon_sendgrid', [{ name: 'sendgrid.send_mail' }]),
    rule('brevo-any', 'scon_brevo', [{ name: 'brevo.send_transactional_email' }]),
    rule('calendar-any', 'scon_calendar', [{ name: 'google_calendar.create_event', params: { calendarId: 'primary' } }]),
    rule('zendesk-any', 'scon_zendesk', [{ name: 'zendesk.create_side_conversation', params: { ticket_id: '42' } }]),
  ];

  it('refuses an unbounded allow on each provider, naming the fields to bind', () => {
    const findings = findUnboundSendRules(policy(...unbounded), providerOf);
    expect(findings.map(f => [f.rule_id, f.reason, f.unbound_paths])).toEqual([
      ['gmail-any', 'unbound_recipient', ['derived.email.recipients']],
      ['outlook-any', 'unbound_recipient', ['derived.email.recipients']],
      ['sendgrid-any', 'unbound_recipient', ['body.personalizations[].to[].email', 'body.personalizations[].cc[].email', 'body.personalizations[].bcc[].email', 'body.mail_settings.bcc.email']],
      ['brevo-any', 'unbound_recipient', ['body.to[].email', 'body.cc[].email', 'body.bcc[].email', 'body.messageVersions[].to[].email', 'body.messageVersions[].cc[].email', 'body.messageVersions[].bcc[].email']],
      ['calendar-any', 'unbound_recipient', ['body.attendees[].email']],
      ['zendesk-any', 'unbound_recipient', ['body.message.to[].email']],
    ]);
    expect(() => assertSendRulesBounded(policy(...unbounded), providerOf)).toThrow(UnboundedSendRuleError);
    expect(describeUnboundSendRule(findings[0]!)).toBe('Rule "gmail-any" allows sending on gmail without naming who receives it. Bind derived.email.recipients with eq or in (or not_exists), set the rule\'s recipients to "per_mission" so each Mission names them, or set the rule\'s effect to "review" or "deny".');
  });

  it('accepts the same rules as review or deny, and bounded rules', () => {
    for (const effect of ['review', 'deny'] as const) {
      expect(findUnboundSendRules(policy(...unbounded.map(r => ({ ...r, effect }))), providerOf)).toEqual([]);
    }
    const bounded = policy(
      rule('gmail-cfo', 'scon_gmail', [{ name: 'gmail.send_email_to', params: { to: ['cfo@acme.com'] } }]),
      rule('gmail-pin', 'scon_gmail', [{ name: 'gmail.send_email' }], [{ path: 'derived.email.recipients', op: 'in', value: ['cfo@acme.com'] }]),
      rule('outlook-cfo', 'scon_outlook', [{ name: 'outlook.send_mail_to', params: { to: 'cfo@acme.com' } }]),
      rule('sendgrid-cfo', 'scon_sendgrid', [{ name: 'sendgrid.send_mail_to', params: { to: 'cfo@acme.com' } }]),
      rule('sendgrid-cc', 'scon_sendgrid', [{ name: 'sendgrid.send_mail_to', params: { to: 'cfo@acme.com', cc: ['audit@acme.com'], bcc: 'audit@acme.com' } }]),
      rule('brevo-cfo', 'scon_brevo', [{ name: 'brevo.send_transactional_email_to', params: { to: ['cfo@acme.com'] } }]),
      rule('calendar-pin', 'scon_calendar', [{ name: 'google_calendar.create_event', params: { calendarId: 'primary' } }], [{ path: 'body.attendees[].email', op: 'in', value: ['cfo@acme.com'] }]),
      rule('calendar-none', 'scon_calendar', [{ name: 'google_calendar.patch_event', params: { calendarId: 'primary' } }], [{ path: 'body.attendees', op: 'not_exists', value: true }]),
      rule('zendesk-pin', 'scon_zendesk', [{ name: 'zendesk.create_side_conversation', params: { ticket_id: '42' } }], [{ path: 'body.message.to[].email', op: 'in', value: ['cfo@acme.com'] }]),
    );
    expect(findUnboundSendRules(bounded, providerOf)).toEqual([]);
    expect(() => assertSendRulesBounded(bounded, providerOf)).not.toThrow();
  });

  it('does not count absent as bounded where absent means unreadable', () => {
    // On a decoded message, not_exists passes when the message cannot be read, so it proves nothing about recipients.
    const absent = rule('gmail', 'scon_gmail', [{ name: 'gmail.send_email' }], [{ path: 'derived.email.recipients', op: 'not_exists', value: true }]);
    expect(findUnboundSendRules(policy(absent), providerOf)[0]?.unbound_paths).toEqual(['derived.email.recipients']);
    const absentOutlook = rule('outlook', 'scon_outlook', [{ name: 'outlook.send_mail' }], [{ path: 'derived.email', op: 'not_exists', value: true }]);
    expect(findUnboundSendRules(policy(absentOutlook), providerOf)[0]?.unbound_paths).toEqual(['derived.email.recipients']);
    // A pin on one of the three recipient fields leaves the others unbound.
    const half = rule('sg', 'scon_sendgrid', [{ name: 'sendgrid.send_mail' }], [{ path: 'body.personalizations[].to[].email', op: 'in', value: ['cfo@acme.com'] }]);
    expect(findUnboundSendRules(policy(half), providerOf)[0]?.unbound_paths).toEqual(['body.personalizations[].cc[].email', 'body.personalizations[].bcc[].email', 'body.mail_settings.bcc.email']);
    // Not_exists on a sibling or a different container binds nothing here.
    const sibling = rule('brevo', 'scon_brevo', [{ name: 'brevo.send_transactional_email' }], [{ path: 'body.to[].email', op: 'in', value: ['a@acme.com'] }, { path: 'body.cc', op: 'not_exists', value: true }, { path: 'body.bcc', op: 'not_exists', value: true }]);
    expect(findUnboundSendRules(policy(sibling), providerOf)[0]?.unbound_paths).toEqual(['body.messageVersions[].to[].email', 'body.messageVersions[].cc[].email', 'body.messageVersions[].bcc[].email']);
  });

  it('keeps a stored draft sent by id and a reply review-only', () => {
    for (const [connection, name] of [['scon_gmail', 'gmail.send_draft'], ['scon_outlook', 'outlook.send_draft'], ['scon_outlook', 'outlook.reply_message'], ['scon_outlook', 'outlook.reply_all_message']] as const) {
      const pinned = rule('r', connection, [{ name }], [{ path: 'derived.email.recipients', op: 'in', value: ['cfo@acme.com'] }]);
      expect(findUnboundSendRules(policy(pinned), providerOf)[0]?.reason, name).toBe('implicit_recipient');
      expect(findUnboundSendRules(policy({ ...pinned, effect: 'review' }), providerOf), name).toEqual([]);
    }
  });
});
