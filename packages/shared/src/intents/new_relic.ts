import { z } from 'zod';
import { defineIntent } from './types.js';

// New Relic REST v2 — https://docs.newrelic.com/docs/apis/rest-api-v2.
// Base: api.newrelic.com/v2/…. Resource paths end in `.json`. The API
// uses numeric IDs for applications, policies, etc. Account-level scope
// is implicit via the API key the request carries.

export const newRelicIntents = [
  defineIntent({
    name: 'new_relic.list_applications',
    effect: 'read',
    description:
      'List APM applications reporting to the account. Binds GET /v2/applications.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/applications.json' },
    ],
  }),

  defineIntent({
    name: 'new_relic.get_application',
    effect: 'read',
    description:
      'Read details for a specific APM application. Binds GET /v2/applications/{id}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/applications/\\d+\\.json$' },
    ],
  }),

  defineIntent({
    name: 'new_relic.update_application',
    effect: 'write',
    description:
      'Update settings on a specific APM application. Binds PUT /v2/applications/{id}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/applications/\\d+\\.json$' },
    ],
  }),

  defineIntent({
    name: 'new_relic.list_alert_policies',
    effect: 'read',
    description:
      'List alert policies on the account. Binds GET /v2/alerts_policies.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/alerts_policies.json' },
    ],
  }),

  defineIntent({
    name: 'new_relic.create_alert_policy',
    effect: 'write',
    description:
      'Create an alert policy. Binds POST /v2/alerts_policies.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/alerts_policies.json' },
    ],
  }),

  defineIntent({
    name: 'new_relic.delete_alert_policy',
    effect: 'destructive',
    description:
      'Delete an alert policy by ID. Binds DELETE /v2/alerts_policies/{id}.json — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/alerts_policies/\\d+\\.json$' },
    ],
  }),

  defineIntent({
    name: 'new_relic.list_alert_conditions',
    effect: 'read',
    description:
      'List alert conditions. Binds GET /v2/alerts_conditions.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/alerts_conditions.json' },
    ],
  }),

  defineIntent({
    name: 'new_relic.create_alert_condition',
    effect: 'write',
    description:
      'Create an alert condition under a specific policy. Binds POST /v2/alerts_conditions/policies/{policy_id}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/alerts_conditions/policies/\\d+\\.json$',
      },
    ],
  }),

  defineIntent({
    name: 'new_relic.update_alert_condition',
    effect: 'write',
    description:
      'Update an alert condition. Binds PUT /v2/alerts_conditions/{id}.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/alerts_conditions/\\d+\\.json$',
      },
    ],
  }),

  defineIntent({
    name: 'new_relic.delete_alert_condition',
    effect: 'destructive',
    description:
      'Delete an alert condition by ID. Binds DELETE /v2/alerts_conditions/{id}.json — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/alerts_conditions/\\d+\\.json$',
      },
    ],
  }),

  defineIntent({
    name: 'new_relic.list_incidents',
    effect: 'read',
    description:
      'List open and recent alert incidents. Binds GET /v2/alerts_incidents.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/alerts_incidents.json' },
    ],
  }),

  defineIntent({
    name: 'new_relic.record_deployment',
    effect: 'write',
    description:
      'Record a deployment marker for an application. Binds POST /v2/applications/{id}/deployments.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/applications/\\d+/deployments\\.json$',
      },
    ],
  }),

  defineIntent({
    name: 'new_relic.list_deployments',
    effect: 'read',
    description:
      'List deployment markers for an application. Binds GET /v2/applications/{id}/deployments.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v2/applications/\\d+/deployments\\.json$',
      },
    ],
  }),

  defineIntent({
    name: 'new_relic.list_synthetics_monitors',
    effect: 'read',
    description:
      'List Synthetics monitors. Binds GET /synthetics/api/v3/monitors on synthetics.newrelic.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/synthetics/api/v3/monitors' },
    ],
  }),

  defineIntent({
    name: 'new_relic.create_synthetics_monitor',
    effect: 'write',
    description:
      'Create a Synthetics monitor. Binds POST /synthetics/api/v3/monitors.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/synthetics/api/v3/monitors' },
    ],
  }),

  defineIntent({
    name: 'new_relic.list_dashboards',
    effect: 'read',
    description:
      'List dashboards. Binds GET /v2/dashboards.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/dashboards.json' },
    ],
  }),

  defineIntent({
    name: 'new_relic.submit_custom_events',
    effect: 'write',
    description:
      'Submit custom events to Insights. Binds POST /v1/accounts/{account_id}/events on insights-collector.newrelic.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v1/accounts/\\d+/events$',
      },
    ],
  }),

  defineIntent({
    name: 'new_relic.list_users',
    effect: 'read',
    description:
      'List users on the account. Binds GET /v2/users.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/users.json' },
    ],
  }),
];
