import { z } from 'zod';
import { defineIntent } from './types.js';

// Mixpanel — two surfaces:
//   Ingest:  api.mixpanel.com/... (track, engage, groups, import)
//   Query:   mixpanel.com/api/... and data.mixpanel.com/api/...
// Intents gate on method + host + pathname.

export const mixpanelIntents = [
  defineIntent({
    name: 'mixpanel.track',
    effect: 'write',
    description:
      'Send event records to the ingest endpoint. Binds POST /track on api.mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/track/?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.engage_set',
    effect: 'write',
    description:
      'Set user profile properties. Binds POST /engage on api.mixpanel.com with $set/$set_once in body.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/engage/?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.engage_add',
    effect: 'write',
    description:
      'Increment numeric user profile properties via the engage endpoint. Binds POST /engage#add on api.mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/engage(#add)?/?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.engage_union',
    effect: 'write',
    description:
      'Union values into list-typed user profile properties. Binds POST /engage#union on api.mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/engage(#union)?/?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.engage_unset',
    effect: 'write',
    description:
      'Remove properties from user profiles. Binds POST /engage#unset on api.mixpanel.com. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/engage(#unset)?/?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.groups_set',
    effect: 'write',
    description:
      'Set group profile properties. Binds POST /groups on api.mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/groups/?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.import',
    effect: 'write',
    description:
      'Import historical events via the authenticated /import endpoint. Binds POST /import on api.mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api.mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/import/?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.export_events',
    effect: 'read',
    description:
      'Export raw events over a time range. Binds GET /api/2.0/export on data.mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'data.mixpanel.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2.0/export' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.query_jql',
    effect: 'read',
    description:
      'Run a JQL query on the query API. Binds POST /api/2.0/jql on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2.0/jql' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.query_insights',
    effect: 'read',
    description:
      'Query a saved insights report. Binds GET /api/2.0/insights on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2.0/insights' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.query_funnels',
    effect: 'read',
    description:
      'Query a saved funnel report. Binds GET /api/2.0/funnels on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/2.0/funnels(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.query_retention',
    effect: 'read',
    description:
      'Query retention analysis. Binds GET /api/2.0/retention on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2.0/retention' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.query_events',
    effect: 'read',
    description:
      'Query an events report. Binds GET /api/2.0/events on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/2.0/events(/properties|/top|/names)?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.query_segmentation',
    effect: 'read',
    description:
      'Run event segmentation queries. Binds GET /api/2.0/segmentation on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/2.0/segmentation(/.+)?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.users_query',
    effect: 'read',
    description:
      'Query user profiles via engage queries. Binds GET /api/2.0/engage on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'eq', value: '/api/2.0/engage' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.annotations_manage',
    effect: 'destructive',
    description:
      'Create, list, update, or delete project annotations. Binds /api/app/projects/{project_id}/annotations on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/app/projects/[^/]+/annotations(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'mixpanel.service_accounts_list',
    effect: 'read',
    description:
      'List service accounts for the organization. Binds GET /api/app/me or /api/app/projects/{id}/service-accounts on mixpanel.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'mixpanel.com' },
      { path: 'url.pathname', op: 'matches', value: '^/api/app/(me|projects/[^/]+/service-accounts)$' },
    ],
  }),
];
