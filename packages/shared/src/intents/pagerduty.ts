import { z } from 'zod';
import { defineIntent } from './types.js';

// PagerDuty REST API — https://developer.pagerduty.com/api-reference.
// Base: api.pagerduty.com/…. Incidents, services, schedules, etc. are
// addressed by opaque alphanumeric IDs (e.g. P1234AB). Account-level
// scope is implicit via API token.

const pdId = z.string().regex(/^P[A-Z0-9]{6}$/);
const pdIdList = z.union([pdId, z.array(pdId).min(1)]);
type PdIdList = z.infer<typeof pdIdList>;
const toList = (v: PdIdList): string[] => (Array.isArray(v) ? v : [v]);

export const pagerdutyIntents = [
  defineIntent({
    name: 'pagerduty.list_incidents',
    effect: 'read',
    description:
      'List incidents. Binds GET /incidents.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/incidents' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.create_incident',
    effect: 'write',
    description:
      'Manually create an incident. Binds POST /incidents.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/incidents' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.update_incident',
    effect: 'write',
    description:
      'Update a specific incident. Binds PUT /incidents/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/incidents/P[A-Z0-9]{6}$' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.acknowledge_incident',
    effect: 'write',
    description:
      'Acknowledge incidents via bulk update. Binds PUT /incidents with body.incidents[].status = acknowledged.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/incidents' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.resolve_incident',
    effect: 'write',
    description:
      'Resolve a specific incident. Binds PUT /incidents/{id} with body.incident.status = resolved.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/incidents/P[A-Z0-9]{6}$' },
      { path: 'body.incident.status', op: 'eq', value: 'resolved' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.snooze_incident',
    effect: 'write',
    description:
      'Snooze a specific incident. Binds POST /incidents/{id}/snooze.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/incidents/P[A-Z0-9]{6}/snooze$' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.list_services',
    effect: 'read',
    description:
      'List services. Binds GET /services.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/services' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.create_service',
    effect: 'write',
    description:
      'Create a new service. Binds POST /services.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/services' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.update_service',
    effect: 'write',
    description:
      'Update specific services. Binds PUT /services/{id} to the declared service_id allowlist.',
    params: z.object({ service_id: pdIdList }),
    expand: ({ service_id }) => {
      const list = toList(service_id);
      const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/services/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'pagerduty.list_schedules',
    effect: 'read',
    description:
      'List on-call schedules. Binds GET /schedules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/schedules' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.create_schedule',
    effect: 'write',
    description:
      'Create an on-call schedule. Binds POST /schedules.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/schedules' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.list_escalation_policies',
    effect: 'read',
    description:
      'List escalation policies. Binds GET /escalation_policies.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/escalation_policies' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.list_users',
    effect: 'read',
    description:
      'List users. Binds GET /users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/users' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.list_oncalls',
    effect: 'read',
    description:
      'List who is currently on call. Binds GET /oncalls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/oncalls' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.list_teams',
    effect: 'read',
    description:
      'List teams. Binds GET /teams.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/teams' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.create_maintenance_window',
    effect: 'write',
    description:
      'Create a maintenance window. Binds POST /maintenance_windows.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/maintenance_windows' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.list_maintenance_windows',
    effect: 'read',
    description:
      'List maintenance windows. Binds GET /maintenance_windows.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/maintenance_windows' },
    ],
  }),

  defineIntent({
    name: 'pagerduty.list_event_rules',
    effect: 'read',
    description:
      'List global event rules (ruleset catchall). Binds GET /rulesets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rulesets' },
    ],
  }),
];
