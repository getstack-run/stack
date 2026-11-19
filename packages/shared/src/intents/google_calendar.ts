import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Google Calendar API v3 — https://developers.google.com/calendar/api/v3.
// Calls hit www.googleapis.com/calendar/v3/…. Most operations are scoped
// to a calendarId (email-style or "primary") embedded in the pathname,
// so intents gate on method + path + the declared calendar allowlist.

const calendarList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type CalendarList = z.infer<typeof calendarList>;
const toList = (v: CalendarList): string[] => (Array.isArray(v) ? v : [v]);

function escapeRe(s: string): string {
  return s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
}

function calendarPathConstraint(calendarId: CalendarList, suffix: string): Constraint {
  const list = toList(calendarId);
  if (list.length === 1) {
    return {
      path: 'url.pathname',
      op: 'eq',
      value: `/calendar/v3/calendars/${encodeURIComponent(list[0]!)}${suffix}`,
    };
  }
  const escaped = list.map((c) => escapeRe(encodeURIComponent(c)));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/calendar/v3/calendars/(${escaped.join('|')})${escapeRe(suffix)}$`,
  };
}

function calendarSubpathRegex(calendarId: CalendarList, subpathRegex: string): Constraint {
  const list = toList(calendarId);
  const escaped = list.map((c) => escapeRe(encodeURIComponent(c)));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/calendar/v3/calendars/${alt}${subpathRegex}$`,
  };
}

export const googleCalendarIntents = [
  defineIntent({
    name: 'google_calendar.list_events',
    effect: 'read',
    description:
      'List events on specific calendars. Binds GET /calendar/v3/calendars/{calendarId}/events to the declared calendar allowlist.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      calendarPathConstraint(calendarId, '/events'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.get_event',
    effect: 'read',
    description:
      'Fetch a single event by ID on specific calendars. Binds GET /calendar/v3/calendars/{calendarId}/events/{eventId}.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      calendarSubpathRegex(calendarId, '/events/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.create_event',
    effect: 'send',
    recipient_paths: ['body.attendees[].email'],
    description:
      'Create a new event on specific calendars. Binds POST /calendar/v3/calendars/{calendarId}/events to the declared calendar allowlist.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      calendarPathConstraint(calendarId, '/events'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.update_event',
    effect: 'send',
    recipient_paths: ['body.attendees[].email'],
    description:
      'Replace an existing event on specific calendars. Binds PUT /calendar/v3/calendars/{calendarId}/events/{eventId}.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      calendarSubpathRegex(calendarId, '/events/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.patch_event',
    effect: 'send',
    recipient_paths: ['body.attendees[].email'],
    description:
      'Partially update an event on specific calendars. Binds PATCH /calendar/v3/calendars/{calendarId}/events/{eventId}.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      calendarSubpathRegex(calendarId, '/events/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.delete_event',
    effect: 'destructive',
    description:
      'Delete an event on specific calendars. Binds DELETE /calendar/v3/calendars/{calendarId}/events/{eventId} - destructive.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      calendarSubpathRegex(calendarId, '/events/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.move_event',
    effect: 'write',
    description:
      'Move an event from one of the declared calendars to another. Binds POST /calendar/v3/calendars/{calendarId}/events/{eventId}/move.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      calendarSubpathRegex(calendarId, '/events/[^/]+/move'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.quick_add_event',
    effect: 'write',
    description:
      'Create an event from a natural-language string on specific calendars. Binds POST /calendar/v3/calendars/{calendarId}/events/quickAdd.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      calendarPathConstraint(calendarId, '/events/quickAdd'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.list_instances',
    effect: 'read',
    description:
      'List instances of a recurring event on specific calendars. Binds GET /calendar/v3/calendars/{calendarId}/events/{eventId}/instances.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      calendarSubpathRegex(calendarId, '/events/[^/]+/instances'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.get_calendar',
    effect: 'read',
    description:
      'Read calendar metadata for specific calendars. Binds GET /calendar/v3/calendars/{calendarId}.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      calendarPathConstraint(calendarId, ''),
    ],
  }),

  defineIntent({
    name: 'google_calendar.update_calendar',
    effect: 'write',
    description:
      'Update metadata on specific calendars. Binds PATCH /calendar/v3/calendars/{calendarId}.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      calendarPathConstraint(calendarId, ''),
    ],
  }),

  defineIntent({
    name: 'google_calendar.create_calendar',
    effect: 'write',
    description:
      'Create a new secondary calendar owned by the authenticated user. Binds POST /calendar/v3/calendars.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/calendar/v3/calendars' },
    ],
  }),

  defineIntent({
    name: 'google_calendar.delete_calendar',
    effect: 'destructive',
    description:
      'Delete specific secondary calendars. Binds DELETE /calendar/v3/calendars/{calendarId} - destructive.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      calendarPathConstraint(calendarId, ''),
    ],
  }),

  defineIntent({
    name: 'google_calendar.list_calendar_list',
    effect: 'read',
    description:
      'List the calendars on the user\'s CalendarList. Binds GET /calendar/v3/users/me/calendarList.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/calendar/v3/users/me/calendarList' },
    ],
  }),

  defineIntent({
    name: 'google_calendar.insert_calendar_list',
    effect: 'write',
    description:
      'Subscribe the user to an existing calendar (add to CalendarList). Binds POST /calendar/v3/users/me/calendarList.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/calendar/v3/users/me/calendarList' },
    ],
  }),

  defineIntent({
    name: 'google_calendar.remove_calendar_list',
    effect: 'destructive',
    description:
      'Remove a calendar from the user\'s CalendarList. Binds DELETE /calendar/v3/users/me/calendarList/{calendarId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/calendar/v3/users/me/calendarList/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'google_calendar.freebusy_query',
    effect: 'read',
    description:
      'Query free/busy status across calendars. Binds POST /calendar/v3/freeBusy.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/calendar/v3/freeBusy' },
    ],
  }),

  defineIntent({
    name: 'google_calendar.list_acl',
    effect: 'read',
    description:
      'List ACL rules on specific calendars. Binds GET /calendar/v3/calendars/{calendarId}/acl.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      calendarPathConstraint(calendarId, '/acl'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.insert_acl',
    effect: 'send',
    recipient_paths: ['body.scope.value'],
    description:
      'Grant a new ACL rule on specific calendars. Binds POST /calendar/v3/calendars/{calendarId}/acl - sharing change.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      calendarPathConstraint(calendarId, '/acl'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.delete_acl',
    effect: 'destructive',
    description:
      'Remove an ACL rule on specific calendars. Binds DELETE /calendar/v3/calendars/{calendarId}/acl/{ruleId} - sharing change.',
    params: z.object({ calendarId: calendarList }),
    expand: ({ calendarId }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      calendarSubpathRegex(calendarId, '/acl/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'google_calendar.get_colors',
    effect: 'read',
    description:
      'Get the color palette for calendars and events. Binds GET /calendar/v3/colors.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/calendar/v3/colors' },
    ],
  }),

  defineIntent({
    name: 'google_calendar.list_settings',
    effect: 'read',
    description:
      'List user-level Calendar settings. Binds GET /calendar/v3/users/me/settings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/calendar/v3/users/me/settings' },
    ],
  }),

  defineIntent({
    name: 'google_calendar.stop_channel',
    effect: 'write',
    description:
      'Stop receiving push notifications on a watch channel. Binds POST /calendar/v3/channels/stop.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/calendar/v3/channels/stop' },
    ],
  }),
];
