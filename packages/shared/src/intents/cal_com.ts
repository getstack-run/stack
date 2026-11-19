import { z } from 'zod';
import { defineIntent } from './types.js';

// Cal.com API v2 - https://cal.com/docs/api-reference/v2/introduction.
// Calls hit api.cal.com/v2/…. Bookings, event types, schedules, teams
// are the main resources. Intents gate on method + path shape.

export const calComIntents = [
  defineIntent({
    name: 'cal_com.list_bookings',
    effect: 'read',
    description:
      'List bookings for the authenticated user. Binds GET /v2/bookings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/bookings' },
    ],
  }),

  defineIntent({
    name: 'cal_com.get_booking',
    effect: 'read',
    description:
      'Fetch a single booking by UID. Binds GET /v2/bookings/{uid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/bookings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.create_booking',
    effect: 'write',
    description:
      'Create a booking against an event type. Binds POST /v2/bookings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/bookings' },
    ],
  }),

  defineIntent({
    name: 'cal_com.reschedule_booking',
    effect: 'write',
    description:
      'Reschedule an existing booking. Binds POST /v2/bookings/{uid}/reschedule.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/bookings/[^/]+/reschedule$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.cancel_booking',
    effect: 'write',
    description:
      'Cancel an existing booking. Binds POST /v2/bookings/{uid}/cancel - destructive for attendees.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/bookings/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.list_event_types',
    effect: 'read',
    description:
      'List event types for the authenticated user. Binds GET /v2/event-types.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/event-types' },
    ],
  }),

  defineIntent({
    name: 'cal_com.create_event_type',
    effect: 'write',
    description:
      'Create a new event type. Binds POST /v2/event-types.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/event-types' },
    ],
  }),

  defineIntent({
    name: 'cal_com.update_event_type',
    effect: 'write',
    description:
      'Update an existing event type. Binds PATCH /v2/event-types/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/event-types/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.delete_event_type',
    effect: 'destructive',
    description:
      'Delete an event type by ID. Binds DELETE /v2/event-types/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/event-types/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.list_schedules',
    effect: 'read',
    description:
      'List availability schedules for the authenticated user. Binds GET /v2/schedules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/schedules' },
    ],
  }),

  defineIntent({
    name: 'cal_com.create_schedule',
    effect: 'write',
    description:
      'Create a new availability schedule. Binds POST /v2/schedules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/schedules' },
    ],
  }),

  defineIntent({
    name: 'cal_com.update_schedule',
    effect: 'write',
    description:
      'Update an existing availability schedule. Binds PATCH /v2/schedules/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/schedules/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.delete_schedule',
    effect: 'destructive',
    description:
      'Delete an availability schedule. Binds DELETE /v2/schedules/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/schedules/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.get_current_user',
    effect: 'read',
    description:
      'Fetch the authenticated Cal.com user. Binds GET /v2/me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/me' },
    ],
  }),

  defineIntent({
    name: 'cal_com.get_available_slots',
    effect: 'read',
    description:
      'List available booking slots for an event type. Binds GET /v2/slots.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/slots' },
    ],
  }),

  defineIntent({
    name: 'cal_com.list_webhooks',
    effect: 'read',
    description:
      'List webhook subscriptions. Binds GET /v2/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/webhooks' },
    ],
  }),

  defineIntent({
    name: 'cal_com.create_webhook',
    effect: 'write',
    description:
      'Register a new webhook subscription. Binds POST /v2/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/webhooks' },
    ],
  }),

  defineIntent({
    name: 'cal_com.delete_webhook',
    effect: 'destructive',
    description:
      'Delete a webhook subscription. Binds DELETE /v2/webhooks/{id} - destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/webhooks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'cal_com.list_teams',
    effect: 'read',
    description:
      'List teams the authenticated user belongs to. Binds GET /v2/teams.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/teams' },
    ],
  }),

  defineIntent({
    name: 'cal_com.list_destination_calendars',
    effect: 'read',
    description:
      'List connected destination calendars. Binds GET /v2/destination-calendars.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/destination-calendars' },
    ],
  }),
];
