import { deployment } from '../deployment/index.js';
import { emailChrome, escapeHtml } from './chrome.js';
import { reconnectMessage } from '../constants/reconnect-reasons.js';
import { oneLine } from '../utils/approval-scope-lines.js';

export { escapeHtml };

export interface TransactionalEmail {
  subject: string;
  text: string;
  html: string;
}

// What each email says lives here. How it looks, and who a person is told to write to, is the deployment's chrome
// (`./chrome.ts`): neutral unless the deployment registered its own.

function humanize(value: string): string {
  return value
    .replace(/^security\./, '')
    .replace(/[._-]+/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase())
    .replace(/\bOauth\b/g, 'OAuth')
    .replace(/\bApi\b/g, 'API')
    .replace(/\bPii\b/g, 'PII');
}

export function stringField(payload: Record<string, unknown>, key: string): string | null {
  const value = payload[key];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

export function formatUtcTimestamp(value: string | null): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'UTC',
  }).format(date)} UTC`;
}

export const paragraphs = (lines: string[]): string => lines.map((line) => emailChrome().paragraph(line)).join('');

export function memberInviteEmail(input: {
  inviterEmail: string;
  inviteUrl: string;
}): TransactionalEmail {
  const c = emailChrome();
  const subject = "You've been invited to STACK";
  const text = [
    'STACK',
    '',
    `${input.inviterEmail} has invited you to their STACK account.`,
    '',
    'Join the account:',
    input.inviteUrl,
    '',
    'This link is single-use and expires in 7 days.',
    'If you were not expecting this invitation, you can ignore this email.',
  ].join('\n');

  const html = c.shell(`
    ${c.title(`Join ${input.inviterEmail} on STACK`)}
    ${c.paragraph('You have been invited to their STACK account.', 28)}
    ${c.button('Join account', input.inviteUrl)}
    ${c.note('This link is single-use and expires in 7 days. If you were not expecting this invitation, you can ignore this email.')}
  `);

  return { subject, text, html };
}

export function emailChangeConfirmEmail(input: {
  currentEmail: string;
  confirmUrl: string;
  ttlMinutes: number;
}): TransactionalEmail {
  const c = emailChrome();
  const subject = 'Confirm your new STACK email';
  const intro = `A request was made to move the STACK account signed in as ${input.currentEmail} to this address.`;
  return {
    subject,
    text: [
      'STACK',
      '',
      intro,
      '',
      'Confirm the new address:',
      input.confirmUrl,
      '',
      `This link works once and expires in ${input.ttlMinutes} minutes.`,
      'If you did not request this change, ignore this email.',
    ].join('\n'),
    html: c.shell(
      `${c.title('Confirm your new email.')}${paragraphs([intro])}${c.button('Confirm email', input.confirmUrl)}${c.note(`This link works once and expires in ${input.ttlMinutes} minutes. If you did not request this change, ignore this email.`)}`,
    ),
  };
}

export function emailChangeNoticeEmail(input: {
  newEmail: string;
  cancelUrl: string;
  ttlMinutes: number;
}): TransactionalEmail {
  const c = emailChrome();
  const subject = 'Your STACK email is being changed';
  const intro = `A request was made to move your STACK account to ${input.newEmail}. The change will happen if that address confirms within ${input.ttlMinutes} minutes.`;
  return {
    subject,
    text: [
      'STACK',
      '',
      intro,
      '',
      'If this was not you, stop the change:',
      input.cancelUrl,
      '',
      'Then rotate your operator API key and review your team access.',
    ].join('\n'),
    html: c.shell(
      `${c.title('Your email is being changed.')}${paragraphs([intro, 'If this was not you, stop the change now.'])}${c.button('Stop email change', input.cancelUrl)}${c.note('Then rotate your operator API key and review your team access.')}`,
    ),
  };
}

export function emailChangeCompletedEmail(input: { newEmail: string }): TransactionalEmail {
  const c = emailChrome();
  const subject = 'Your STACK email has changed';
  const intro = `Your STACK account now signs in as ${input.newEmail}. This address can no longer request sign-in links for it.`;
  const securityLine = c.securityLine();
  return {
    subject,
    text: ['STACK', '', intro, '', securityLine].join('\n'),
    html: c.shell(`${c.title('Your email has changed.')}${paragraphs([intro, securityLine])}`),
  };
}

export interface NotificationEmailInput {
  eventType: string;
  severity: string;
  message?: string;
  summary?: string;
  payload?: Record<string, unknown>;
}

/** Renders a notification event the engine does not know, or answers null for one it does not render either. */
export type NotificationEmailRenderer = (input: NotificationEmailInput) => TransactionalEmail | null;

let notificationRenderer: NotificationEmailRenderer | null = null;

/**
 * A deployment that sends notification events of its own registers the renderer for them once at boot; null goes back
 * to the engine's own. The engine renders `security.*` and `governance.*` itself.
 */
export function setNotificationEmailRenderer(renderer: NotificationEmailRenderer | null): void {
  notificationRenderer = renderer;
}

export function notificationEmail(input: NotificationEmailInput): TransactionalEmail {
  const c = emailChrome();
  const payload = input.payload ?? {};
  const severity = input.severity.toUpperCase();

  if (input.eventType === 'security.credential_reconnect_required') {
    const heading = 'Service reconnect required';
    const message = reconnectMessage(payload['reason']);
    const url = `${deployment().siteUrl}/services`;
    const rows: Array<[string, string | null]> = [['Connection', stringField(payload, 'connection_id')]];
    return {
      subject: `[STACK] ${heading}`,
      text: [heading, '', message, '', ...rows.filter(row => row[1]).map(([label, value]) => `${label}: ${value}`), '', `Reconnect: ${url}`].join('\n'),
      html: c.shell(`${c.title(heading)}${paragraphs([message])}${c.rows(rows)}${c.button('Reconnect', url)}`),
    };
  }

  if (input.eventType.startsWith('security.')) {
    const signal = stringField(payload, 'signal_type') ?? input.eventType.slice('security.'.length);
    const eventId = stringField(payload, 'event_id');
    const agentId = stringField(payload, 'agent_id');
    const passportId = stringField(payload, 'passport_jti');
    const occurredAt = stringField(payload, 'occurred_at');
    const heading = humanize(signal);
    const reviewUrl = eventId
      ? `${deployment().siteUrl}/app?review=${encodeURIComponent(eventId)}`
      : `${deployment().siteUrl}/app`;
    const message = input.message ?? 'STACK recorded this event.';
    const rows: Array<[string, string | null]> = [
      ['Severity', severity],
      ['Agent', agentId],
      ['Passport', passportId],
      ['Time', formatUtcTimestamp(occurredAt)],
      ['Event', eventId],
    ];
    return {
      subject: `[STACK] ${severity === 'CRITICAL' ? 'Critical security event' : 'Security event'}: ${heading}`,
      text: [
        `${severity} SECURITY EVENT`,
        '',
        heading,
        message,
        '',
        ...rows.filter((row) => row[1]).map(([label, value]) => `${label}: ${value}`),
        '',
        `Review event: ${reviewUrl}`,
      ].join('\n'),
      html: c.shell(
        `${c.eyebrow(`${severity} SECURITY EVENT`)}${c.title(heading)}${paragraphs([message])}${c.rows(rows)}${c.button('Review event', reviewUrl)}`,
      ),
    };
  }

  // An event this module does not know is a deployment's own: its registered renderer answers, or null.
  const custom = notificationRenderer?.(input);
  if (custom) return custom;

  if (input.eventType === 'governance.approval_pending') {
    // Every value below can carry text a caller wrote (an agent's name, a description): each is put on one line and
    // cut, so none can add a line to the mail, pose as one of its rows or stretch the subject.
    const line = (value: string | null | undefined, max: number): string | null => {
      const text = value ? oneLine(value).slice(0, max) : '';
      return text.length > 0 ? text : null;
    };
    const approvalId = line(stringField(payload, 'approval_id'), 80);
    const resourceId = line(stringField(payload, 'resource_id'), 200);
    const requestedVia = stringField(payload, 'requested_via');
    const expiresAt = stringField(payload, 'expires_at');
    const reviewUrl =
      stringField(payload, 'approval_url') ??
      (approvalId
        ? `${deployment().siteUrl}/app/approve/${encodeURIComponent(approvalId)}`
        : `${deployment().siteUrl}/app`);
    const summary = line(input.summary, 300) ?? 'A change is waiting for your approval.';
    const requester =
      requestedVia === 'oauth'
        ? 'An OAuth-connected client'
        : requestedVia === 'member_session'
          ? 'A team member'
          : requestedVia === 'operator_key'
            ? 'An API-key client'
            : 'A signed-in requester';
    const rows: Array<[string, string | null]> = [
      ['Request', summary],
      ['Resource', resourceId],
      ['Requested by', requester],
      ['Expires', formatUtcTimestamp(expiresAt)],
      ['Approval', approvalId],
    ];
    return {
      subject: `[STACK] Approval required: ${summary}`,
      text: [
        'APPROVAL REQUIRED',
        '',
        `${requester} requested the change below. Approving it lets that exact request retry once.`,
        '',
        ...rows.filter((row) => row[1]).map(([label, value]) => `${label}: ${value}`),
        '',
        `Review request: ${reviewUrl}`,
      ].join('\n'),
      html: c.shell(
        `${c.eyebrow('APPROVAL REQUIRED')}${c.title('Approve this change?')}${paragraphs([`${requester} requested the change below. Approving it lets that exact request retry once.`])}${c.rows(rows)}${c.button('Review request', reviewUrl)}`,
      ),
    };
  }

  const type = input.eventType.replace(/\./g, ' ').replace(/\b\w/g, (ch) => ch.toUpperCase());
  const subject = `[STACK] ${type} - ${input.severity}`;
  const body = `[STACK ${severity}] ${type}${input.message ? `: ${input.message}` : ''}${input.summary ? ` - ${input.summary}` : ''}`;
  return {
    subject,
    text: body,
    html: c.shell(
      `${c.eyebrow(severity)}${c.title(type)}${paragraphs([input.message ?? 'STACK recorded this event.', ...(input.summary ? [input.summary] : [])])}`,
    ),
  };
}

export function notificationVerificationEmail(input: {
  code: string;
  kind: 'delivery method' | 'notification channel';
}): TransactionalEmail {
  const c = emailChrome();
  const subject = `Verify your STACK ${input.kind}`;
  const text = `Your STACK verification code is: ${input.code}\n\nThis code expires in 10 minutes.`;
  return {
    subject,
    text,
    html: c.shell(`${c.title(`Verify your ${input.kind}.`)}${c.paragraph('Enter this code in STACK. It expires in 10 minutes.')}${c.code(input.code)}`),
  };
}
