import { z } from 'zod';
import { defineIntent } from './types.js';

// Amplitude — https://amplitude.com/docs/apis/analytics. Surfaces:
//   HTTP V2 Events: api2.amplitude.com/2/httpapi, /batch
//   Dashboard:     amplitude.com/api/2/...
// Intents gate on method + host + pathname.

export const amplitudeIntents = [
  defineIntent({
    name: 'amplitude.httpapi_events',
    effect: 'write',
    description:
      'Send events via the HTTP V2 API. Binds POST /2/httpapi on api2.amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api2.amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/2/httpapi' },
    ],
  }),

  defineIntent({
    name: 'amplitude.batch_events',
    effect: 'write',
    description:
      'Send events via the Batch Event Upload API. Binds POST /batch on api2.amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api2.amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/batch' },
    ],
  }),

  defineIntent({
    name: 'amplitude.identify',
    effect: 'write',
    description:
      'Send identify calls to update user properties. Binds POST /identify on api2.amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api2.amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/identify' },
    ],
  }),

  defineIntent({
    name: 'amplitude.groupidentify',
    effect: 'write',
    description:
      'Send group identify calls to update group properties. Binds POST /groupidentify on api2.amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api2.amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/groupidentify' },
    ],
  }),

  defineIntent({
    name: 'amplitude.export_events',
    effect: 'read',
    description:
      'Export raw events over a time range. Binds GET /api/2/export on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2/export' },
    ],
  }),

  defineIntent({
    name: 'amplitude.query_funnels',
    effect: 'read',
    description:
      'Query a funnel analysis report. Binds GET /api/2/funnels on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2/funnels' },
    ],
  }),

  defineIntent({
    name: 'amplitude.cohorts_list',
    effect: 'read',
    description:
      'List behavioral cohorts. Binds GET /api/3/cohorts on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/3/cohorts' },
    ],
  }),

  defineIntent({
    name: 'amplitude.cohorts_download',
    effect: 'read',
    description:
      'Download cohort membership. Binds GET /api/5/cohorts/request and /api/5/cohorts/request/{id}/file on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/5/cohorts/request(/[^/]+(/file)?)?$' },
    ],
  }),

  defineIntent({
    name: 'amplitude.cohorts_upload',
    effect: 'write',
    description:
      'Upload a cohort of users. Binds POST /api/3/cohorts/upload on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/3/cohorts/upload' },
    ],
  }),

  defineIntent({
    name: 'amplitude.users_search',
    effect: 'read',
    description:
      'Search user profiles by id. Binds GET /api/2/usersearch on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2/usersearch' },
    ],
  }),

  defineIntent({
    name: 'amplitude.releases_manage',
    effect: 'destructive',
    description:
      'Create, update, or list releases annotations on the chart timeline. Binds /api/2/release on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/2/release(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'amplitude.annotations_manage',
    effect: 'destructive',
    description:
      'Create, list, or delete chart annotations. Binds /api/2/annotations on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/2/annotations(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'amplitude.attribution',
    effect: 'write',
    description:
      'Send mobile attribution data. Binds POST /attribution on api.amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/attribution' },
    ],
  }),

  defineIntent({
    name: 'amplitude.realtime_users',
    effect: 'read',
    description:
      'Query realtime active users. Binds GET /api/2/users on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2/users' },
    ],
  }),

  defineIntent({
    name: 'amplitude.query_events',
    effect: 'read',
    description:
      'Run events segmentation queries. Binds GET /api/2/events/segmentation on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2/events/segmentation' },
    ],
  }),

  defineIntent({
    name: 'amplitude.dashboard_chart',
    effect: 'read',
    description:
      'Retrieve a saved dashboard chart by id. Binds GET /api/3/chart/{id}/query on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/3/chart/[^/]+/query$' },
    ],
  }),

  defineIntent({
    name: 'amplitude.taxonomy_manage',
    effect: 'destructive',
    description:
      'Read or update the event/property taxonomy. Binds /api/2/taxonomy on amplitude.com.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'amplitude.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/2/taxonomy(/.+)?$' },
    ],
  }),
];
