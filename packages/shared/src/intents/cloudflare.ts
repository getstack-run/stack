import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Cloudflare API v4 — https://developers.cloudflare.com/api. Base:
// api.cloudflare.com/client/v4/…. Most resources are scoped under a zone
// (/zones/{zone_id}/…) or account (/accounts/{account_id}/…). Intents
// bind method + pathname so the agent can only touch the declared
// zone(s) and endpoint kind. Zone IDs are 32-char hex.

const zoneId = z.string().regex(/^[0-9a-f]{32}$/i, 'zone_id must be 32-char hex');
const zoneList = z.union([zoneId, z.array(zoneId).min(1)]);
type ZoneList = z.infer<typeof zoneList>;
const toList = (v: ZoneList): string[] => (Array.isArray(v) ? v : [v]);

function zonePathConstraint(zone: ZoneList, suffixRegex: string): Constraint {
  const list = toList(zone);
  const zoneAlt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/client/v4/zones/${zoneAlt}${suffixRegex}$`,
  };
}

export const cloudflareIntents = [
  defineIntent({
    name: 'cloudflare.list_zones',
    effect: 'read',
    description:
      'List all zones on the account. Binds GET /client/v4/zones.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/client/v4/zones' },
    ],
  }),

  defineIntent({
    name: 'cloudflare.read_zone',
    effect: 'read',
    description:
      'Read metadata for specific zones. Binds GET /client/v4/zones/{zone_id} to the declared zone allowlist.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      zonePathConstraint(zone_id, ''),
    ],
  }),

  defineIntent({
    name: 'cloudflare.list_dns_records',
    effect: 'read',
    description:
      'List DNS records in specific zones. Binds GET /client/v4/zones/{zone_id}/dns_records.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      zonePathConstraint(zone_id, '/dns_records'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.create_dns_record',
    effect: 'write',
    description:
      'Create a DNS record in specific zones. Binds POST /client/v4/zones/{zone_id}/dns_records to the declared zones.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      zonePathConstraint(zone_id, '/dns_records'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.update_dns_record',
    effect: 'write',
    description:
      'Update an existing DNS record in specific zones. Binds PUT or PATCH /client/v4/zones/{zone_id}/dns_records/{id}.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'in', value: ['PUT', 'PATCH'] },
      zonePathConstraint(zone_id, '/dns_records/[0-9a-f]+'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.delete_dns_record',
    effect: 'destructive',
    description:
      'Delete a DNS record in specific zones. Binds DELETE /client/v4/zones/{zone_id}/dns_records/{id} — destructive.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      zonePathConstraint(zone_id, '/dns_records/[0-9a-f]+'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.purge_cache',
    effect: 'destructive',
    description:
      'Purge cached files for specific zones. Binds POST /client/v4/zones/{zone_id}/purge_cache — immediate edge impact.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      zonePathConstraint(zone_id, '/purge_cache'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.list_page_rules',
    effect: 'read',
    description:
      'List page rules for specific zones. Binds GET /client/v4/zones/{zone_id}/pagerules.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      zonePathConstraint(zone_id, '/pagerules'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.create_page_rule',
    effect: 'write',
    description:
      'Create a page rule in specific zones. Binds POST /client/v4/zones/{zone_id}/pagerules.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      zonePathConstraint(zone_id, '/pagerules'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.list_firewall_rules',
    effect: 'read',
    description:
      'List firewall rules for specific zones. Binds GET /client/v4/zones/{zone_id}/firewall/rules.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      zonePathConstraint(zone_id, '/firewall/rules'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.create_firewall_rule',
    effect: 'write',
    description:
      'Create a firewall rule in specific zones. Binds POST /client/v4/zones/{zone_id}/firewall/rules.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      zonePathConstraint(zone_id, '/firewall/rules'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.delete_firewall_rule',
    effect: 'destructive',
    description:
      'Delete a firewall rule in specific zones. Binds DELETE /client/v4/zones/{zone_id}/firewall/rules/{id} — destructive.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      zonePathConstraint(zone_id, '/firewall/rules/[0-9a-f]+'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.read_analytics',
    effect: 'read',
    description:
      'Read analytics dashboard data for specific zones. Binds GET /client/v4/zones/{zone_id}/analytics/dashboard.',
    params: z.object({ zone_id: zoneList }),
    expand: ({ zone_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      zonePathConstraint(zone_id, '/analytics/dashboard'),
    ],
  }),

  defineIntent({
    name: 'cloudflare.list_workers',
    effect: 'read',
    description:
      'List Workers scripts on the account. Binds GET /client/v4/accounts/{account_id}/workers/scripts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/client/v4/accounts/[0-9a-f]+/workers/scripts$',
      },
    ],
  }),

  defineIntent({
    name: 'cloudflare.upload_worker',
    effect: 'write',
    description:
      'Upload or replace a Workers script. Binds PUT /client/v4/accounts/{account_id}/workers/scripts/{name}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/client/v4/accounts/[0-9a-f]+/workers/scripts/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'cloudflare.delete_worker',
    effect: 'destructive',
    description:
      'Delete a Workers script. Binds DELETE /client/v4/accounts/{account_id}/workers/scripts/{name} — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/client/v4/accounts/[0-9a-f]+/workers/scripts/[^/]+$',
      },
    ],
  }),

  defineIntent({
    name: 'cloudflare.list_kv_namespaces',
    effect: 'read',
    description:
      'List Workers KV namespaces on the account. Binds GET /client/v4/accounts/{account_id}/storage/kv/namespaces.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/client/v4/accounts/[0-9a-f]+/storage/kv/namespaces$',
      },
    ],
  }),

  defineIntent({
    name: 'cloudflare.write_kv_value',
    effect: 'write',
    description:
      'Write a key into a Workers KV namespace. Binds PUT /client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/client/v4/accounts/[0-9a-f]+/storage/kv/namespaces/[0-9a-f]+/values/.+$',
      },
    ],
  }),

  defineIntent({
    name: 'cloudflare.list_object_buckets',
    effect: 'read',
    description:
      'List R2 object-storage buckets on the account. Binds GET /client/v4/accounts/{account_id}/r2/buckets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/client/v4/accounts/[0-9a-f]+/r2/buckets$',
      },
    ],
  }),

  defineIntent({
    name: 'cloudflare.list_access_apps',
    effect: 'read',
    description:
      'List Cloudflare Access applications on the account. Binds GET /client/v4/accounts/{account_id}/access/apps.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/client/v4/accounts/[0-9a-f]+/access/apps$',
      },
    ],
  }),
];
