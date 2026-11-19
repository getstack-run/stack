import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Plausible Analytics — https://plausible.io/docs. Surfaces:
//   Events API:   plausible.io/api/event
//   Stats API v1: plausible.io/api/v1/stats/...
//   Sites API v2: plausible.io/api/v2/sites/...
// Intents gate on method + pathname and, where applicable, require
// query.site_id to match a site allowlist.

const siteList = z.union([
  z.string().min(1).max(256),
  z.array(z.string().min(1).max(256)).min(1),
]);
type SiteList = z.infer<typeof siteList>;
const toList = (v: SiteList): string[] => (Array.isArray(v) ? v : [v]);

function siteQueryConstraint(site: SiteList): Constraint {
  const list = toList(site);
  return list.length === 1
    ? { path: 'query.site_id', op: 'eq', value: list[0]! }
    : { path: 'query.site_id', op: 'in', value: list };
}

export const plausibleIntents = [
  defineIntent({
    name: 'plausible.events_send',
    effect: 'write',
    description:
      'Send a pageview or custom event via the Events API. Binds POST /api/event.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/event' },
    ],
  }),

  defineIntent({
    name: 'plausible.stats_aggregate',
    effect: 'read',
    description:
      'Query aggregate stats for a site allowlist. Binds GET /api/v1/stats/aggregate with query.site_id pinned.',
    params: z.object({ site: siteList }),
    expand: ({ site }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/stats/aggregate' },
      siteQueryConstraint(site),
    ],
  }),

  defineIntent({
    name: 'plausible.stats_timeseries',
    effect: 'read',
    description:
      'Query timeseries stats for a site allowlist. Binds GET /api/v1/stats/timeseries with query.site_id pinned.',
    params: z.object({ site: siteList }),
    expand: ({ site }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/stats/timeseries' },
      siteQueryConstraint(site),
    ],
  }),

  defineIntent({
    name: 'plausible.stats_breakdown',
    effect: 'read',
    description:
      'Query breakdown stats for a site allowlist. Binds GET /api/v1/stats/breakdown with query.site_id pinned.',
    params: z.object({ site: siteList }),
    expand: ({ site }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/stats/breakdown' },
      siteQueryConstraint(site),
    ],
  }),

  defineIntent({
    name: 'plausible.stats_realtime',
    effect: 'read',
    description:
      'Query realtime visitor count for a site allowlist. Binds GET /api/v1/stats/realtime/visitors with query.site_id pinned.',
    params: z.object({ site: siteList }),
    expand: ({ site }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/stats/realtime/visitors' },
      siteQueryConstraint(site),
    ],
  }),

  defineIntent({
    name: 'plausible.stats_query',
    effect: 'write',
    description:
      'Run the v2 Stats Query API. Binds POST /api/v2/query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/query' },
    ],
  }),

  defineIntent({
    name: 'plausible.sites_list',
    effect: 'read',
    description:
      'List sites in the account. Binds GET /api/v1/sites.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/sites' },
    ],
  }),

  defineIntent({
    name: 'plausible.sites_get',
    effect: 'read',
    description:
      'Retrieve a specific site by id. Binds GET /api/v1/sites/{site_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/sites/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'plausible.sites_create',
    effect: 'write',
    description:
      'Create a new site. Binds POST /api/v1/sites.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/sites' },
    ],
  }),

  defineIntent({
    name: 'plausible.sites_update',
    effect: 'write',
    description:
      'Update an existing site. Binds PUT /api/v1/sites/{site_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/sites/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'plausible.sites_delete',
    effect: 'destructive',
    description:
      'Delete a site. Binds DELETE /api/v1/sites/{site_id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/sites/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'plausible.goals_manage',
    effect: 'destructive',
    description:
      'List, create, or delete goals on a site. Binds /api/v1/sites/goals and /api/v1/sites/goals/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/sites/goals(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'plausible.shared_links_create',
    effect: 'write',
    description:
      'Create a shared dashboard link for a site. Binds PUT /api/v1/sites/shared-links.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/sites/shared-links' },
    ],
  }),

  defineIntent({
    name: 'plausible.shared_links_list',
    effect: 'read',
    description:
      'List shared dashboard links for a site. Binds GET /api/v1/sites/shared-links.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/sites/shared-links' },
    ],
  }),

  defineIntent({
    name: 'plausible.shared_links_delete',
    effect: 'destructive',
    description:
      'Delete a shared dashboard link. Binds DELETE /api/v1/sites/shared-links/{name}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/sites/shared-links/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'plausible.custom_props_manage',
    effect: 'destructive',
    description:
      'Enable, list, or disable custom property (dimension) tracking on a site. Binds /api/v1/sites/custom-props.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/sites/custom-props(/[^/]+)?$' },
    ],
  }),
];
