import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Google Analytics 4 — Data API (analyticsdata.googleapis.com) +
// Admin API (analyticsadmin.googleapis.com). Intents gate on method +
// pathname and, where relevant, scope to a GA4 property id allowlist
// via pathname regex.

const propertyList = z.union([
  z.string().min(1).max(64),
  z.array(z.string().min(1).max(64)).min(1),
]);
type PropertyList = z.infer<typeof propertyList>;
const toList = (v: PropertyList): string[] => (Array.isArray(v) ? v : [v]);

function propertyPath(property: PropertyList, suffix: string): Constraint {
  const list = toList(property);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}${suffix}$` };
}

export const googleAnalyticsIntents = [
  defineIntent({
    name: 'google_analytics.run_report',
    effect: 'write',
    description:
      'Run a standard report on a specific GA4 property allowlist. Binds POST /v1beta/properties/{id}:runReport.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      propertyPath(property, ':runReport'),
    ],
  }),

  defineIntent({
    name: 'google_analytics.run_realtime_report',
    effect: 'write',
    description:
      'Run a real-time report on a specific GA4 property allowlist. Binds POST /v1beta/properties/{id}:runRealtimeReport.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      propertyPath(property, ':runRealtimeReport'),
    ],
  }),

  defineIntent({
    name: 'google_analytics.batch_run_reports',
    effect: 'write',
    description:
      'Run multiple reports in one request on a property allowlist. Binds POST /v1beta/properties/{id}:batchRunReports.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      propertyPath(property, ':batchRunReports'),
    ],
  }),

  defineIntent({
    name: 'google_analytics.batch_run_pivot_reports',
    effect: 'write',
    description:
      'Run multiple pivot reports in one request on a property allowlist. Binds POST /v1beta/properties/{id}:batchRunPivotReports.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      propertyPath(property, ':batchRunPivotReports'),
    ],
  }),

  defineIntent({
    name: 'google_analytics.run_pivot_report',
    effect: 'write',
    description:
      'Run a pivot report on a specific GA4 property allowlist. Binds POST /v1beta/properties/{id}:runPivotReport.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      propertyPath(property, ':runPivotReport'),
    ],
  }),

  defineIntent({
    name: 'google_analytics.check_compatibility',
    effect: 'read',
    description:
      'Check report compatibility (dimensions/metrics). Binds POST /v1beta/properties/{id}:checkCompatibility.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      propertyPath(property, ':checkCompatibility'),
    ],
  }),

  defineIntent({
    name: 'google_analytics.get_metadata',
    effect: 'read',
    description:
      'Retrieve the metadata schema for a property. Binds GET /v1beta/properties/{id}/metadata.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      propertyPath(property, '/metadata'),
    ],
  }),

  defineIntent({
    name: 'google_analytics.admin_properties_list',
    effect: 'read',
    description:
      'List GA4 properties accessible to the caller. Binds GET /v1beta/properties on analyticsadmin.googleapis.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
      { path: 'url.pathname', op: 'eq', value: '/v1beta/properties' },
    ],
  }),

  defineIntent({
    name: 'google_analytics.admin_properties_get',
    effect: 'read',
    description:
      'Retrieve a specific property allowlist via the Admin API. Binds GET /v1beta/properties/{id}.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => {
      const list = toList(property);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_analytics.admin_properties_update',
    effect: 'write',
    description:
      'Update a specific GA4 property allowlist via the Admin API. Binds PATCH /v1beta/properties/{id}.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => {
      const list = toList(property);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'PATCH' },
        { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_analytics.admin_data_streams',
    effect: 'destructive',
    description:
      'Manage dataStreams under a property allowlist. Binds /v1beta/properties/{id}/dataStreams and subresources.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => {
      const list = toList(property);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}/dataStreams(/[^/]+)?$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_analytics.admin_custom_dimensions',
    effect: 'destructive',
    description:
      'Manage customDimensions under a property allowlist. Binds /v1beta/properties/{id}/customDimensions and subresources.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => {
      const list = toList(property);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}/customDimensions(/[^/]+(:archive)?)?$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_analytics.admin_custom_metrics',
    effect: 'destructive',
    description:
      'Manage customMetrics under a property allowlist. Binds /v1beta/properties/{id}/customMetrics and subresources.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => {
      const list = toList(property);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}/customMetrics(/[^/]+(:archive)?)?$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_analytics.admin_audiences',
    effect: 'destructive',
    description:
      'Manage audiences under a property allowlist. Binds /v1beta/properties/{id}/audiences and subresources.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => {
      const list = toList(property);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}/audiences(/[^/]+(:archive)?)?$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_analytics.admin_conversion_events',
    effect: 'destructive',
    description:
      'Manage conversionEvents under a property allowlist. Binds /v1beta/properties/{id}/conversionEvents and subresources.',
    params: z.object({ property: propertyList }),
    expand: ({ property }) => {
      const list = toList(property);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1beta/properties/${alt}/conversionEvents(/[^/]+)?$` },
      ];
    },
  }),

  defineIntent({
    name: 'google_analytics.admin_accounts_list',
    effect: 'read',
    description:
      'List accessible GA4 accounts. Binds GET /v1beta/accounts on analyticsadmin.googleapis.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'analyticsadmin.googleapis.com' },
      { path: 'url.pathname', op: 'matches', value: '^/v1beta/accounts(/[^/]+)?$' },
    ],
  }),
];
