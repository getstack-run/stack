import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Twilio REST API — https://www.twilio.com/docs/usage/api. Base:
// api.twilio.com/2010-04-01/Accounts/{AccountSid}/…. Auth is Basic with
// the Account SID + Auth Token.
//
// Most write endpoints take form-urlencoded params; scoping is commonly
// done on body.To (recipient E.164 number) or body.From (caller/sender
// phone or Messaging Service SID).

const phoneFmt = z
  .string()
  .min(2)
  .max(32)
  .regex(/^\+?[0-9]+$/, 'phone must be digits, optionally prefixed with +');
const phoneList = z.union([phoneFmt, z.array(phoneFmt).min(1)]);
type PhoneList = z.infer<typeof phoneList>;

const toList = (v: PhoneList): string[] => (Array.isArray(v) ? v : [v]);

function bodyPhoneConstraint(field: 'body.To' | 'body.From', p: PhoneList): Constraint {
  const list = toList(p);
  return list.length === 1
    ? { path: field, op: 'eq', value: list[0]! }
    : { path: field, op: 'in', value: list };
}

const acctPrefix = '^/2010-04-01/Accounts/[A-Z]{2}[0-9a-f]{32}';

export const twilioIntents = [
  defineIntent({
    name: 'twilio.send_sms',
    effect: 'send',
    recipient_paths: ['body.To'],
    description:
      'Send an SMS to specific E.164 recipients. Binds POST /2010-04-01/Accounts/{Sid}/Messages.json to the declared To allowlist.',
    params: z.object({ to: phoneList }),
    expand: ({ to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Messages\\.json$` },
      bodyPhoneConstraint('body.To', to),
    ],
  }),

  defineIntent({
    name: 'twilio.send_sms_from',
    effect: 'send',
    recipient_paths: ['body.To'],
    description:
      'Send an SMS from a specific From number or Messaging Service. Binds POST Messages.json scoped on body.From.',
    params: z.object({ from: phoneList }),
    expand: ({ from }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Messages\\.json$` },
      bodyPhoneConstraint('body.From', from),
    ],
  }),

  defineIntent({
    name: 'twilio.list_messages',
    effect: 'read',
    description:
      'List SMS/MMS messages on the account. Binds GET /2010-04-01/Accounts/{Sid}/Messages.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Messages\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.get_message',
    effect: 'read',
    description:
      'Fetch a single message by SID. Binds GET /2010-04-01/Accounts/{Sid}/Messages/{MessageSid}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Messages/[A-Z]{2}[0-9a-f]{32}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.delete_message',
    effect: 'destructive',
    description:
      'Delete a message record. Binds DELETE /2010-04-01/Accounts/{Sid}/Messages/{MessageSid}.json — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Messages/[A-Z]{2}[0-9a-f]{32}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.make_call',
    effect: 'send',
    recipient_paths: ['body.To'],
    description:
      'Place an outbound voice call to specific numbers. Binds POST /2010-04-01/Accounts/{Sid}/Calls.json with body.To allowlist.',
    params: z.object({ to: phoneList }),
    expand: ({ to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Calls\\.json$` },
      bodyPhoneConstraint('body.To', to),
    ],
  }),

  defineIntent({
    name: 'twilio.list_calls',
    effect: 'read',
    description:
      'List voice calls on the account. Binds GET /2010-04-01/Accounts/{Sid}/Calls.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Calls\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.get_call',
    effect: 'read',
    description:
      'Fetch a single call by SID. Binds GET /2010-04-01/Accounts/{Sid}/Calls/{CallSid}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Calls/[A-Z]{2}[0-9a-f]{32}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.end_call',
    effect: 'write',
    description:
      'Hang up an in-progress call by updating its status. Binds POST /2010-04-01/Accounts/{Sid}/Calls/{CallSid}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Calls/[A-Z]{2}[0-9a-f]{32}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.list_recordings',
    effect: 'read',
    description:
      'List call recordings on the account. Binds GET /2010-04-01/Accounts/{Sid}/Recordings.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Recordings\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.get_recording',
    effect: 'read',
    description:
      'Fetch a single recording by SID. Binds GET /2010-04-01/Accounts/{Sid}/Recordings/{RecordingSid}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Recordings/[A-Z]{2}[0-9a-f]{32}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.delete_recording',
    effect: 'destructive',
    description:
      'Delete a recording. Binds DELETE /2010-04-01/Accounts/{Sid}/Recordings/{RecordingSid}.json — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/Recordings/[A-Z]{2}[0-9a-f]{32}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.verify_start',
    effect: 'send',
    recipient_paths: ['body.To'],
    description:
      'Start a Twilio Verify challenge (send a code). Binds POST /v2/Services/{ServiceSid}/Verifications on verify.twilio.com.',
    params: z.object({ to: phoneList }),
    expand: ({ to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'verify.twilio.com' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/Services/[A-Z]{2}[0-9a-f]{32}/Verifications$' },
      bodyPhoneConstraint('body.To', to),
    ],
  }),

  defineIntent({
    name: 'twilio.verify_check',
    effect: 'write',
    description:
      'Check a Twilio Verify code. Binds POST /v2/Services/{ServiceSid}/VerificationCheck on verify.twilio.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'verify.twilio.com' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/Services/[A-Z]{2}[0-9a-f]{32}/VerificationCheck$' },
    ],
  }),

  defineIntent({
    name: 'twilio.lookup_phone',
    effect: 'read',
    description:
      'Look up carrier/caller info for a phone number. Binds GET /v2/PhoneNumbers/{PhoneNumber} on lookups.twilio.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'lookups.twilio.com' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/PhoneNumbers/\\+?[0-9]+$' },
    ],
  }),

  defineIntent({
    name: 'twilio.list_phone_numbers',
    effect: 'read',
    description:
      'List phone numbers owned by the account. Binds GET /2010-04-01/Accounts/{Sid}/IncomingPhoneNumbers.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/IncomingPhoneNumbers\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.buy_phone_number',
    effect: 'write',
    description:
      'Purchase a new phone number for the account. Binds POST /2010-04-01/Accounts/{Sid}/IncomingPhoneNumbers.json — billable.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/IncomingPhoneNumbers\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.release_phone_number',
    effect: 'destructive',
    description:
      'Release an owned phone number. Binds DELETE /2010-04-01/Accounts/{Sid}/IncomingPhoneNumbers/{Sid}.json — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: `${acctPrefix}/IncomingPhoneNumbers/[A-Z]{2}[0-9a-f]{32}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'twilio.list_messaging_services',
    effect: 'read',
    description:
      'List Messaging Services. Binds GET /v1/Services on messaging.twilio.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'messaging.twilio.com' },
      { path: 'url.pathname', op: 'eq', value: '/v1/Services' },
    ],
  }),

  defineIntent({
    name: 'twilio.create_messaging_service',
    effect: 'write',
    description:
      'Create a Messaging Service. Binds POST /v1/Services on messaging.twilio.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'messaging.twilio.com' },
      { path: 'url.pathname', op: 'eq', value: '/v1/Services' },
    ],
  }),

  defineIntent({
    name: 'twilio.list_conversations',
    effect: 'read',
    description:
      'List Twilio Conversations. Binds GET /v1/Conversations on conversations.twilio.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'conversations.twilio.com' },
      { path: 'url.pathname', op: 'eq', value: '/v1/Conversations' },
    ],
  }),

  defineIntent({
    name: 'twilio.create_conversation',
    effect: 'write',
    description:
      'Create a new Conversation. Binds POST /v1/Conversations on conversations.twilio.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'conversations.twilio.com' },
      { path: 'url.pathname', op: 'eq', value: '/v1/Conversations' },
    ],
  }),
];
