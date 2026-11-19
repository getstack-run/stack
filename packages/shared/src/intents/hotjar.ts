import { z } from 'zod';
import { defineIntent } from './types.js';

// Hotjar — the authenticated Hotjar API surface is thin and mostly
// internal (https://insights.hotjar.com/api/v2/...). Intents gate on
// method + pathname. Some endpoints are read-only and scoped to the
// authenticated site id via the path.

export const hotjarIntents = [
  defineIntent({
    name: 'hotjar.sites_list',
    effect: 'read',
    description:
      'List sites the authenticated account can access. Binds GET /api/v2/users/me/sites.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/users/me/sites' },
    ],
  }),

  defineIntent({
    name: 'hotjar.site_get',
    effect: 'read',
    description:
      'Retrieve metadata for a specific site id. Binds GET /api/v2/sites/{site_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.users_list',
    effect: 'read',
    description:
      'List users in the organization. Binds GET /api/v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/users' },
    ],
  }),

  defineIntent({
    name: 'hotjar.heatmaps_list',
    effect: 'read',
    description:
      'List heatmaps for a specific site id. Binds GET /api/v2/sites/{site_id}/heatmaps.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/heatmaps(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.recordings_list',
    effect: 'read',
    description:
      'List session recordings for a site. Binds GET /api/v2/sites/{site_id}/recordings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/recordings(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.surveys_list',
    effect: 'read',
    description:
      'List surveys for a site. Binds GET /api/v2/sites/{site_id}/surveys.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/surveys(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.survey_responses',
    effect: 'read',
    description:
      'List responses for a specific survey. Binds GET /api/v2/sites/{site_id}/surveys/{id}/responses.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/surveys/[^/]+/responses$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.feedback_widgets_list',
    effect: 'read',
    description:
      'List Incoming Feedback widgets for a site. Binds GET /api/v2/sites/{site_id}/feedback-widgets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/feedback-widgets(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.feedback_responses',
    effect: 'read',
    description:
      'List responses for a specific feedback widget. Binds GET /api/v2/sites/{site_id}/feedback-widgets/{id}/responses.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/feedback-widgets/[^/]+/responses$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.polls_list',
    effect: 'read',
    description:
      'List polls for a site. Binds GET /api/v2/sites/{site_id}/polls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/polls(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.funnels_list',
    effect: 'read',
    description:
      'List funnels for a site. Binds GET /api/v2/sites/{site_id}/funnels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/funnels(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.events_list',
    effect: 'read',
    description:
      'List custom events tracked on a site. Binds GET /api/v2/sites/{site_id}/events.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/events(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.dashboards_list',
    effect: 'read',
    description:
      'List dashboards for a site. Binds GET /api/v2/sites/{site_id}/dashboards.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/sites/[^/]+/dashboards(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hotjar.me',
    effect: 'read',
    description:
      'Read the authenticated user profile. Binds GET /api/v2/users/me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/users/me' },
    ],
  }),
];
