import { z } from 'zod';
import { defineIntent } from './types.js';

// Grafana HTTP API — https://grafana.com/docs/grafana/latest/developers/http_api.
// Base: {grafana_host}/api/…. Works for Grafana Cloud and self-hosted.
// Most resources are org-scoped via the authenticated API key. Dashboards
// are addressed by UID; folders by UID; datasources by numeric ID.

export const grafanaIntents = [
  defineIntent({
    name: 'grafana.search_dashboards',
    effect: 'read',
    description:
      'Search dashboards and folders. Binds GET /api/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/search' },
    ],
  }),

  defineIntent({
    name: 'grafana.get_dashboard',
    effect: 'read',
    description:
      'Fetch a dashboard by UID. Binds GET /api/dashboards/uid/{uid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/dashboards/uid/[\\w-]+$' },
    ],
  }),

  defineIntent({
    name: 'grafana.create_or_update_dashboard',
    effect: 'write',
    description:
      'Create a new dashboard or update an existing one. Binds POST /api/dashboards/db.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/dashboards/db' },
    ],
  }),

  defineIntent({
    name: 'grafana.delete_dashboard',
    effect: 'destructive',
    description:
      'Delete a dashboard by UID. Binds DELETE /api/dashboards/uid/{uid} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/dashboards/uid/[\\w-]+$' },
    ],
  }),

  defineIntent({
    name: 'grafana.list_folders',
    effect: 'read',
    description:
      'List dashboard folders. Binds GET /api/folders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/folders' },
    ],
  }),

  defineIntent({
    name: 'grafana.create_folder',
    effect: 'write',
    description:
      'Create a dashboard folder. Binds POST /api/folders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/folders' },
    ],
  }),

  defineIntent({
    name: 'grafana.delete_folder',
    effect: 'destructive',
    description:
      'Delete a folder by UID. Binds DELETE /api/folders/{uid} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/folders/[\\w-]+$' },
    ],
  }),

  defineIntent({
    name: 'grafana.list_data_sources',
    effect: 'read',
    description:
      'List configured data sources. Binds GET /api/datasources.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/datasources' },
    ],
  }),

  defineIntent({
    name: 'grafana.create_data_source',
    effect: 'write',
    description:
      'Add a new data source. Binds POST /api/datasources.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/datasources' },
    ],
  }),

  defineIntent({
    name: 'grafana.update_data_source',
    effect: 'write',
    description:
      'Update a data source by UID. Binds PUT /api/datasources/uid/{uid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/datasources/uid/[\\w-]+$' },
    ],
  }),

  defineIntent({
    name: 'grafana.delete_data_source',
    effect: 'destructive',
    description:
      'Delete a data source by UID. Binds DELETE /api/datasources/uid/{uid} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/datasources/uid/[\\w-]+$' },
    ],
  }),

  defineIntent({
    name: 'grafana.list_teams',
    effect: 'read',
    description:
      'Search teams in the current org. Binds GET /api/teams/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/teams/search' },
    ],
  }),

  defineIntent({
    name: 'grafana.create_team',
    effect: 'write',
    description:
      'Create a team in the current org. Binds POST /api/teams.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/teams' },
    ],
  }),

  defineIntent({
    name: 'grafana.list_users',
    effect: 'read',
    description:
      'List users in the current org. Binds GET /api/org/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/org/users' },
    ],
  }),

  defineIntent({
    name: 'grafana.list_alerts',
    effect: 'read',
    description:
      'List alert rules via the unified alerting API. Binds GET /api/v1/provisioning/alert-rules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/provisioning/alert-rules' },
    ],
  }),

  defineIntent({
    name: 'grafana.pause_alert',
    effect: 'write',
    description:
      'Pause a specific legacy alert. Binds POST /api/alerts/{id}/pause.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/alerts/\\d+/pause$' },
    ],
  }),

  defineIntent({
    name: 'grafana.list_annotations',
    effect: 'read',
    description:
      'List annotations. Binds GET /api/annotations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/annotations' },
    ],
  }),

  defineIntent({
    name: 'grafana.create_annotation',
    effect: 'write',
    description:
      'Create an annotation on a graph. Binds POST /api/annotations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/annotations' },
    ],
  }),

  defineIntent({
    name: 'grafana.delete_annotation',
    effect: 'destructive',
    description:
      'Delete an annotation by ID. Binds DELETE /api/annotations/{id} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/annotations/\\d+$' },
    ],
  }),

  defineIntent({
    name: 'grafana.list_service_accounts',
    effect: 'read',
    description:
      'Search service accounts in the current org. Binds GET /api/serviceaccounts/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/serviceaccounts/search' },
    ],
  }),
];
