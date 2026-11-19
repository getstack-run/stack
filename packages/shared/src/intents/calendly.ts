import { z } from 'zod';
import { defineIntent } from './types.js';

// Calendly API v2 - https://developers.calendly.com/api-docs. Calls hit
// api.calendly.com/…. Most collection endpoints take an organization or
// user URI via query string; individual resources are addressed by UUID
// in the pathname. Intents gate on method + path shape.

export const calendlyIntents = [
  defineIntent({
    name: 'calendly.list_scheduled_events',
    effect: 'read',
    description:
      'List scheduled events for a user or organization. Binds GET /scheduled_events.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/scheduled_events' },
    ],
  }),

  defineIntent({
    name: 'calendly.get_scheduled_event',
    effect: 'read',
    description:
      'Fetch a single scheduled event by UUID. Binds GET /scheduled_events/{uuid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/scheduled_events/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'calendly.cancel_scheduled_event',
    effect: 'write',
    description:
      'Cancel a scheduled event. Binds POST /scheduled_events/{uuid}/cancellation - destructive for the invitee.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/scheduled_events/[^/]+/cancellation$' },
    ],
  }),

  defineIntent({
    name: 'calendly.list_event_invitees',
    effect: 'read',
    description:
      'List invitees for a scheduled event. Binds GET /scheduled_events/{uuid}/invitees.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/scheduled_events/[^/]+/invitees$' },
    ],
  }),

  defineIntent({
    name: 'calendly.get_event_invitee',
    effect: 'read',
    description:
      'Fetch a single invitee for a scheduled event. Binds GET /scheduled_events/{uuid}/invitees/{invitee_uuid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/scheduled_events/[^/]+/invitees/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'calendly.list_event_types',
    effect: 'read',
    description:
      'List event types for a user or organization. Binds GET /event_types.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/event_types' },
    ],
  }),

  defineIntent({
    name: 'calendly.get_event_type',
    effect: 'read',
    description:
      'Fetch a single event type by UUID. Binds GET /event_types/{uuid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/event_types/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'calendly.get_current_user',
    effect: 'read',
    description:
      'Fetch the authenticated Calendly user. Binds GET /users/me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/users/me' },
    ],
  }),

  defineIntent({
    name: 'calendly.get_user',
    effect: 'read',
    description:
      'Fetch a Calendly user by UUID. Binds GET /users/{uuid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'calendly.list_organization_memberships',
    effect: 'read',
    description:
      'List organization memberships for the authenticated user. Binds GET /organization_memberships.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/organization_memberships' },
    ],
  }),

  defineIntent({
    name: 'calendly.list_availability_schedules',
    effect: 'read',
    description:
      'List availability schedules for a user. Binds GET /user_availability_schedules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/user_availability_schedules' },
    ],
  }),

  defineIntent({
    name: 'calendly.list_webhook_subscriptions',
    effect: 'read',
    description:
      'List webhook subscriptions for an organization or user. Binds GET /webhook_subscriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/webhook_subscriptions' },
    ],
  }),

  defineIntent({
    name: 'calendly.create_webhook_subscription',
    effect: 'write',
    description:
      'Create a new webhook subscription. Binds POST /webhook_subscriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/webhook_subscriptions' },
    ],
  }),

  defineIntent({
    name: 'calendly.delete_webhook_subscription',
    effect: 'destructive',
    description:
      'Delete a webhook subscription by UUID. Binds DELETE /webhook_subscriptions/{uuid} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/webhook_subscriptions/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'calendly.request_data_compliance_delete',
    effect: 'destructive',
    description:
      'Submit a GDPR invitee-data deletion request. Binds POST /data_compliance/deletion/invitees - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/data_compliance/deletion/invitees' },
    ],
  }),

  defineIntent({
    name: 'calendly.list_routing_forms',
    effect: 'read',
    description:
      'List routing forms for an organization. Binds GET /routing_forms.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/routing_forms' },
    ],
  }),

  defineIntent({
    name: 'calendly.create_scheduling_link',
    effect: 'write',
    description:
      'Create a single-use scheduling link for an event type. Binds POST /scheduling_links.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/scheduling_links' },
    ],
  }),

  defineIntent({
    name: 'calendly.list_activity_log_entries',
    effect: 'read',
    description:
      'List activity log entries for an organization. Binds GET /activity_log_entries.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/activity_log_entries' },
    ],
  }),

  defineIntent({
    name: 'calendly.get_organization',
    effect: 'read',
    description:
      'Fetch an organization by UUID. Binds GET /organizations/{uuid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/organizations/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'calendly.list_invitee_no_shows',
    effect: 'read',
    description:
      'List invitees marked as no-show. Binds GET /invitee_no_shows.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/invitee_no_shows' },
    ],
  }),
];
