import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Netlify API — https://api.netlify.com/api/v1. Most resources live under
// /api/v1/sites/{site_id}/…. Intents bind method + pathname to the declared
// site_id allowlist.

const siteFmt = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._-]+$/, 'site_id must be alphanumeric');
const siteList = z.union([siteFmt, z.array(siteFmt).min(1)]);
type SiteList = z.infer<typeof siteList>;
const toList = (v: SiteList): string[] => (Array.isArray(v) ? v : [v]);

function sitePathPrefixConstraint(site: SiteList, suffix: string): Constraint {
  const list = toList(site);
  if (list.length === 1) {
    return { path: 'url.pathname', op: 'eq', value: `/api/v1/sites/${list[0]!}${suffix}` };
  }
  const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v1/sites/(${escaped.join('|')})${suffix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')}$`,
  };
}

function siteSubpathRegex(site: SiteList, subpathRegex: string): Constraint {
  const list = toList(site);
  const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v1/sites/${alt}${subpathRegex}$`,
  };
}

export const netlifyIntents = [
  defineIntent({
    name: 'netlify.create_site',
    effect: 'write',
    description:
      'Create a new Netlify site. Binds POST /api/v1/sites (not site-scoped).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/sites' },
    ],
  }),

  defineIntent({
    name: 'netlify.update_site',
    effect: 'write',
    description:
      'Update site settings. Binds PATCH /api/v1/sites/{site_id}.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      sitePathPrefixConstraint(siteId, ''),
    ],
  }),

  defineIntent({
    name: 'netlify.delete_site',
    effect: 'destructive',
    description:
      'Delete a Netlify site. Binds DELETE /api/v1/sites/{site_id} — destructive.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      sitePathPrefixConstraint(siteId, ''),
    ],
  }),

  defineIntent({
    name: 'netlify.read_site',
    effect: 'read',
    description:
      'Read-only access to site metadata and subresources. Binds GET /api/v1/sites/{site_id}/….',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      siteSubpathRegex(siteId, '(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'netlify.create_deploy',
    effect: 'write',
    description:
      'Create a new deploy for a site. Binds POST /api/v1/sites/{site_id}/deploys.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      sitePathPrefixConstraint(siteId, '/deploys'),
    ],
  }),

  defineIntent({
    name: 'netlify.delete_deploy',
    effect: 'destructive',
    description:
      'Delete a specific deploy. Binds DELETE /api/v1/sites/{site_id}/deploys/{deploy_id} — destructive.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      siteSubpathRegex(siteId, '/deploys/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'netlify.lock_deploy',
    effect: 'write',
    description:
      'Lock or unlock a deploy to pin or release the published state. Binds POST /api/v1/deploys/{deploy_id}/(lock|unlock).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/deploys/[^/]+/(lock|unlock)$' },
    ],
  }),

  defineIntent({
    name: 'netlify.restore_deploy',
    effect: 'write',
    description:
      'Roll back to a previous deploy by restoring it as published. Binds POST /api/v1/sites/{site_id}/deploys/{deploy_id}/restore.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      siteSubpathRegex(siteId, '/deploys/[^/]+/restore'),
    ],
  }),

  defineIntent({
    name: 'netlify.manage_functions',
    effect: 'read',
    description:
      'Read and manage serverless function metadata for a site. Binds GET /api/v1/sites/{site_id}/functions(/…)?.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      siteSubpathRegex(siteId, '/functions(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'netlify.manage_env_vars',
    effect: 'destructive',
    description:
      'Create, update, and delete environment variables on a site. Binds POST/PATCH/PUT/DELETE /api/v1/sites/{site_id}/env(/{key})? — sensitive.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'PUT', 'DELETE'] },
      siteSubpathRegex(siteId, '/env(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'netlify.manage_domains',
    effect: 'destructive',
    description:
      'Assign and remove custom domains on a site. Binds PATCH /api/v1/sites/{site_id} with custom_domain plus POST/DELETE /api/v1/sites/{site_id}/domain_aliases.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      siteSubpathRegex(siteId, '/domain_aliases(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'netlify.manage_dns_zones',
    effect: 'destructive',
    description:
      'Create, update, and delete DNS zones and records. Binds POST/PUT/DELETE /api/v1/dns_zones(/…)? (account-scoped, not per-site).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/dns_zones(/.*)?$' },
    ],
  }),

  defineIntent({
    name: 'netlify.read_forms',
    effect: 'read',
    description:
      'Read form submissions for a site. Binds GET /api/v1/sites/{site_id}/forms(/…)? and /submissions.',
    params: z.object({ siteId: siteList }),
    expand: ({ siteId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      siteSubpathRegex(siteId, '/(forms|submissions)(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'netlify.manage_hooks',
    effect: 'destructive',
    description:
      'Create, update, and delete build/deploy hooks. Binds POST/PUT/DELETE /api/v1/hooks(/{id})? — scoped via hooks API.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/hooks(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'netlify.purge_cache',
    effect: 'destructive',
    description:
      'Purge the edge cache for a site. Binds POST /api/v1/purge.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/purge' },
    ],
  }),
];
