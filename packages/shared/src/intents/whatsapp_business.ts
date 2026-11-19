import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// WhatsApp Cloud API — https://developers.facebook.com/docs/whatsapp/cloud-api.
// Base: graph.facebook.com/v21.0/{PhoneNumberId}/…. Auth is a Meta
// system-user access token.
//
// The PhoneNumberId is the sender identity and lives in the path; the
// body.to field is the E.164 recipient. Most allowlisting happens on
// body.to.

const phoneFmt = z
  .string()
  .min(6)
  .max(20)
  .regex(/^\+?[0-9]+$/, 'recipient must be E.164 digits, optionally prefixed with +');
const phoneList = z.union([phoneFmt, z.array(phoneFmt).min(1)]);
type PhoneList = z.infer<typeof phoneList>;

const toList = (v: PhoneList): string[] => (Array.isArray(v) ? v : [v]);

function toConstraint(to: PhoneList): Constraint {
  const list = toList(to);
  return list.length === 1
    ? { path: 'body.to', op: 'eq', value: list[0]! }
    : { path: 'body.to', op: 'in', value: list };
}

const phoneIdFmt = z.string().min(5).max(64).regex(/^\d+$/, 'phone number ID must be numeric');
const phoneIdList = z.union([phoneIdFmt, z.array(phoneIdFmt).min(1)]);
type PhoneIdList = z.infer<typeof phoneIdList>;

function phoneIdAlt(ids: PhoneIdList): string {
  const list = Array.isArray(ids) ? ids : [ids];
  return list.length === 1 ? list[0]! : `(${list.join('|')})`;
}

function sendPath(phoneIds: PhoneIdList): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v21\\.0/${phoneIdAlt(phoneIds)}/messages$`,
  };
}

function mediaPath(phoneIds: PhoneIdList): Constraint {
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v21\\.0/${phoneIdAlt(phoneIds)}/media$`,
  };
}

export const whatsappBusinessIntents = [
  defineIntent({
    name: 'whatsapp_business.send_text',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a text message from a specific phone number ID to recipients. Binds POST /v21.0/{PhoneNumberId}/messages with body.to allowlist.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'text' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_template',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a pre-approved template message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=template.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'template' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_image',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send an image message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=image.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'image' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_document',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a document message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=document.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'document' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_video',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a video message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=video.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'video' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_audio',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send an audio / voice note message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=audio.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'audio' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_sticker',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a sticker message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=sticker.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'sticker' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_location',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a location message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=location.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'location' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_contacts',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send a contact card message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=contacts.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'contacts' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_interactive',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send an interactive message (button/list/product). Binds POST /v21.0/{PhoneNumberId}/messages with body.type=interactive.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'interactive' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.send_reaction',
    effect: 'send',
    recipient_paths: ['body.to'],
    description:
      'Send an emoji reaction to a previous message. Binds POST /v21.0/{PhoneNumberId}/messages with body.type=reaction.',
    params: z.object({ phone_number_id: phoneIdList, to: phoneList }),
    expand: ({ phone_number_id, to }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.type', op: 'eq', value: 'reaction' },
      toConstraint(to),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.mark_as_read',
    effect: 'write',
    description:
      'Mark an incoming message as read. Binds POST /v21.0/{PhoneNumberId}/messages with body.status=read.',
    params: z.object({ phone_number_id: phoneIdList }),
    expand: ({ phone_number_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sendPath(phone_number_id),
      { path: 'body.status', op: 'eq', value: 'read' },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.upload_media',
    effect: 'write',
    description:
      'Upload a media file for later send. Binds POST /v21.0/{PhoneNumberId}/media.',
    params: z.object({ phone_number_id: phoneIdList }),
    expand: ({ phone_number_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      mediaPath(phone_number_id),
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.get_media',
    effect: 'read',
    description:
      'Fetch media metadata by media ID. Binds GET /v21.0/{MediaId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/\\d+$' },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.delete_media',
    effect: 'destructive',
    description:
      'Delete an uploaded media asset. Binds DELETE /v21.0/{MediaId} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/\\d+$' },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.get_phone_number',
    effect: 'read',
    description:
      'Fetch info about a registered phone number. Binds GET /v21.0/{PhoneNumberId}.',
    params: z.object({ phone_number_id: phoneIdList }),
    expand: ({ phone_number_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${phoneIdAlt(phone_number_id)}$` },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.list_phone_numbers',
    effect: 'read',
    description:
      'List registered phone numbers on a WABA. Binds GET /v21.0/{WABAId}/phone_numbers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/\\d+/phone_numbers$' },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.register_phone_number',
    effect: 'write',
    description:
      'Register a WhatsApp Business phone number. Binds POST /v21.0/{PhoneNumberId}/register.',
    params: z.object({ phone_number_id: phoneIdList }),
    expand: ({ phone_number_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${phoneIdAlt(phone_number_id)}/register$` },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.deregister_phone_number',
    effect: 'write',
    description:
      'Deregister a WhatsApp Business phone number. Binds POST /v21.0/{PhoneNumberId}/deregister — destructive.',
    params: z.object({ phone_number_id: phoneIdList }),
    expand: ({ phone_number_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${phoneIdAlt(phone_number_id)}/deregister$` },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.list_message_templates',
    effect: 'read',
    description:
      'List approved message templates on a WABA. Binds GET /v21.0/{WABAId}/message_templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/\\d+/message_templates$' },
    ],
  }),

  defineIntent({
    name: 'whatsapp_business.create_message_template',
    effect: 'write',
    description:
      'Submit a new message template for review. Binds POST /v21.0/{WABAId}/message_templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/\\d+/message_templates$' },
    ],
  }),
];
