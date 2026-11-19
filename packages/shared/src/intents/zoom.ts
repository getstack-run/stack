import { z } from 'zod';
import { defineIntent } from './types.js';

// Zoom API v2 — https://developers.zoom.us/docs/api/. Base:
// api.zoom.us/v2/…. Auth via Server-to-Server OAuth bearer token.
//
// Most scoping happens at the endpoint level. Meeting/user IDs are in
// the path — paths like /users/{userId}/meetings are user-scoped.

export const zoomIntents = [
  defineIntent({
    name: 'zoom.list_meetings',
    effect: 'read',
    description:
      'List scheduled meetings for the authenticated user. Binds GET /v2/users/me/meetings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users/me/meetings' },
    ],
  }),

  defineIntent({
    name: 'zoom.create_meeting',
    effect: 'write',
    description:
      'Schedule a new meeting for the authenticated user. Binds POST /v2/users/me/meetings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users/me/meetings' },
    ],
  }),

  defineIntent({
    name: 'zoom.get_meeting',
    effect: 'read',
    description:
      'Fetch meeting details by ID. Binds GET /v2/meetings/{meetingId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'zoom.update_meeting',
    effect: 'write',
    description:
      'Update an existing meeting. Binds PATCH /v2/meetings/{meetingId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'zoom.delete_meeting',
    effect: 'destructive',
    description:
      'Delete a scheduled meeting. Binds DELETE /v2/meetings/{meetingId} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'zoom.end_meeting',
    effect: 'write',
    description:
      'End an in-progress meeting by updating status. Binds PUT /v2/meetings/{meetingId}/status.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+/status$' },
    ],
  }),

  defineIntent({
    name: 'zoom.list_meeting_registrants',
    effect: 'read',
    description:
      'List registrants for a meeting. Binds GET /v2/meetings/{meetingId}/registrants.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+/registrants$' },
    ],
  }),

  defineIntent({
    name: 'zoom.add_meeting_registrant',
    effect: 'send',
    recipient_paths: ['body.email'],
    description:
      'Register a participant for a meeting. Binds POST /v2/meetings/{meetingId}/registrants.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+/registrants$' },
    ],
  }),

  defineIntent({
    name: 'zoom.update_registrant_status',
    effect: 'write',
    description:
      'Approve, deny, or cancel meeting registrants in bulk. Binds PUT /v2/meetings/{meetingId}/registrants/status.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+/registrants/status$' },
    ],
  }),

  defineIntent({
    name: 'zoom.list_recordings',
    effect: 'read',
    description:
      'List cloud recordings for the authenticated user. Binds GET /v2/users/me/recordings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users/me/recordings' },
    ],
  }),

  defineIntent({
    name: 'zoom.get_meeting_recording',
    effect: 'read',
    description:
      'Fetch recordings for a specific meeting. Binds GET /v2/meetings/{meetingId}/recordings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+/recordings$' },
    ],
  }),

  defineIntent({
    name: 'zoom.delete_meeting_recordings',
    effect: 'destructive',
    description:
      'Delete all recordings for a meeting. Binds DELETE /v2/meetings/{meetingId}/recordings — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+/recordings$' },
    ],
  }),

  defineIntent({
    name: 'zoom.list_users',
    effect: 'read',
    description:
      'List users in the account. Binds GET /v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users' },
    ],
  }),

  defineIntent({
    name: 'zoom.get_user',
    effect: 'read',
    description:
      'Fetch a user profile by ID or email. Binds GET /v2/users/{userId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/users/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'zoom.create_user',
    effect: 'write',
    description:
      'Provision a new Zoom user. Binds POST /v2/users — billable.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users' },
    ],
  }),

  defineIntent({
    name: 'zoom.deactivate_user',
    effect: 'write',
    description:
      'Deactivate, activate, or delete a user status. Binds PUT /v2/users/{userId}/status.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/users/[^/]+/status$' },
    ],
  }),

  defineIntent({
    name: 'zoom.list_webinars',
    effect: 'read',
    description:
      'List webinars for the authenticated user. Binds GET /v2/users/me/webinars.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users/me/webinars' },
    ],
  }),

  defineIntent({
    name: 'zoom.create_webinar',
    effect: 'write',
    description:
      'Schedule a webinar for the authenticated user. Binds POST /v2/users/me/webinars.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users/me/webinars' },
    ],
  }),

  defineIntent({
    name: 'zoom.get_past_meeting_participants',
    effect: 'read',
    description:
      'Fetch participants of a completed meeting. Binds GET /v2/past_meetings/{meetingUUID}/participants.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/past_meetings/[^/]+/participants$' },
    ],
  }),

  defineIntent({
    name: 'zoom.get_past_meeting_details',
    effect: 'read',
    description:
      'Fetch details of a completed meeting. Binds GET /v2/past_meetings/{meetingUUID}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/past_meetings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'zoom.report_usage',
    effect: 'read',
    description:
      'Generate a usage report for a date range. Binds GET /v2/report/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/report/users' },
    ],
  }),

  defineIntent({
    name: 'zoom.report_meetings',
    effect: 'read',
    description:
      'Generate a meetings report for a user. Binds GET /v2/report/users/{userId}/meetings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/report/users/[^/]+/meetings$' },
    ],
  }),

  defineIntent({
    name: 'zoom.update_meeting_status',
    effect: 'write',
    description:
      'Start or end a meeting by status action. Binds PUT /v2/meetings/{meetingId}/status.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/meetings/[^/]+/status$' },
    ],
  }),

  defineIntent({
    name: 'zoom.list_webinar_registrants',
    effect: 'read',
    description:
      'List registrants for a webinar. Binds GET /v2/webinars/{webinarId}/registrants.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/webinars/[^/]+/registrants$' },
    ],
  }),
];
