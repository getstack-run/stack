import { z } from 'zod';
import { defineIntent } from './types.js';

// Datadog API — https://docs.datadoghq.com/api. Base:
// api.datadoghq.com (and regional variants). Mix of v1 and v2. Most
// resources are addressed by numeric or UUID IDs. No org-level scoping
// in path; agents are scoped via API + app key selection upstream.

export const datadogIntents = [
  defineIntent({
    name: 'datadog.submit_metrics',
    effect: 'write',
    description:
      'Submit metric data points for custom metrics. Binds POST /api/v2/series.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/series' },
    ],
  }),

  defineIntent({
    name: 'datadog.query_metrics',
    effect: 'read',
    description:
      'Query timeseries metric data. Binds GET /api/v1/query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/query' },
    ],
  }),

  defineIntent({
    name: 'datadog.post_event',
    effect: 'write',
    description:
      'Post an event to the Datadog event stream. Binds POST /api/v1/events.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/events' },
    ],
  }),

  defineIntent({
    name: 'datadog.list_events',
    effect: 'read',
    description:
      'Query the Datadog event stream. Binds GET /api/v1/events.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/events' },
    ],
  }),

  defineIntent({
    name: 'datadog.submit_logs',
    effect: 'write',
    description:
      'Submit logs via the HTTP intake. Binds POST /api/v2/logs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/logs' },
    ],
  }),

  defineIntent({
    name: 'datadog.query_logs',
    effect: 'read',
    description:
      'Search log events. Binds POST /api/v2/logs/events/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/logs/events/search' },
    ],
  }),

  defineIntent({
    name: 'datadog.list_dashboards',
    effect: 'read',
    description:
      'List dashboards on the account. Binds GET /api/v1/dashboard.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/dashboard' },
    ],
  }),

  defineIntent({
    name: 'datadog.create_dashboard',
    effect: 'write',
    description:
      'Create a new dashboard. Binds POST /api/v1/dashboard.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/dashboard' },
    ],
  }),

  defineIntent({
    name: 'datadog.update_dashboard',
    effect: 'write',
    description:
      'Replace an existing dashboard definition. Binds PUT /api/v1/dashboard/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/dashboard/[\\w-]+$' },
    ],
  }),

  defineIntent({
    name: 'datadog.delete_dashboard',
    effect: 'destructive',
    description:
      'Delete a dashboard by ID. Binds DELETE /api/v1/dashboard/{id} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/dashboard/[\\w-]+$' },
    ],
  }),

  defineIntent({
    name: 'datadog.list_monitors',
    effect: 'read',
    description:
      'List all monitors. Binds GET /api/v1/monitor.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/monitor' },
    ],
  }),

  defineIntent({
    name: 'datadog.create_monitor',
    effect: 'write',
    description:
      'Create a new monitor. Binds POST /api/v1/monitor.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/monitor' },
    ],
  }),

  defineIntent({
    name: 'datadog.update_monitor',
    effect: 'write',
    description:
      'Update an existing monitor. Binds PUT /api/v1/monitor/{monitor_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/monitor/\\d+$' },
    ],
  }),

  defineIntent({
    name: 'datadog.delete_monitor',
    effect: 'destructive',
    description:
      'Delete a monitor by ID. Binds DELETE /api/v1/monitor/{monitor_id} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/monitor/\\d+$' },
    ],
  }),

  defineIntent({
    name: 'datadog.mute_monitor',
    effect: 'write',
    description:
      'Mute a specific monitor. Binds POST /api/v1/monitor/{monitor_id}/mute.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/monitor/\\d+/mute$' },
    ],
  }),

  defineIntent({
    name: 'datadog.schedule_downtime',
    effect: 'write',
    description:
      'Schedule a downtime window. Binds POST /api/v2/downtime.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/downtime' },
    ],
  }),

  defineIntent({
    name: 'datadog.list_slos',
    effect: 'read',
    description:
      'List SLOs on the account. Binds GET /api/v1/slo.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/slo' },
    ],
  }),

  defineIntent({
    name: 'datadog.list_synthetics_tests',
    effect: 'read',
    description:
      'List Synthetic tests (API + Browser). Binds GET /api/v1/synthetics/tests.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/synthetics/tests' },
    ],
  }),

  defineIntent({
    name: 'datadog.create_incident',
    effect: 'write',
    description:
      'Create a new incident. Binds POST /api/v2/incidents.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/incidents' },
    ],
  }),

  defineIntent({
    name: 'datadog.list_incidents',
    effect: 'read',
    description:
      'List incidents. Binds GET /api/v2/incidents.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/incidents' },
    ],
  }),
];
