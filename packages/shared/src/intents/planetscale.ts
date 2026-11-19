import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// PlanetScale API — https://api.planetscale.com/v1. Resources are scoped
// under /organizations/{org}/databases/{db}/…. Intents bind method +
// pathname so the agent can only touch the declared database(s) and
// endpoint kind. Database names are url-safe [A-Za-z0-9._-].

const dbName = z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/, 'database must be url-safe');
const dbList = z.union([dbName, z.array(dbName).min(1)]);
type DbList = z.infer<typeof dbList>;
const toList = (v: DbList): string[] => (Array.isArray(v) ? v : [v]);

function dbPathConstraint(db: DbList, suffixRegex: string): Constraint {
  const list = toList(db);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/organizations/[^/]+/databases/${alt}${suffixRegex}$`,
  };
}

export const planetscaleIntents = [
  defineIntent({
    name: 'planetscale.list_databases',
    effect: 'read',
    description:
      'List databases in the organization. Binds GET /v1/organizations/{org}/databases.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/databases$' },
    ],
  }),

  defineIntent({
    name: 'planetscale.read_database',
    effect: 'read',
    description:
      'Read metadata for specific PlanetScale databases. Binds GET /v1/organizations/{org}/databases/{db}.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPathConstraint(database, ''),
    ],
  }),

  defineIntent({
    name: 'planetscale.create_database',
    effect: 'write',
    description:
      'Create a new database in the organization. Binds POST /v1/organizations/{org}/databases.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/databases$' },
    ],
  }),

  defineIntent({
    name: 'planetscale.update_database',
    effect: 'write',
    description:
      'Update settings on specific PlanetScale databases. Binds PATCH /v1/organizations/{org}/databases/{db}.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      dbPathConstraint(database, ''),
    ],
  }),

  defineIntent({
    name: 'planetscale.delete_database',
    effect: 'destructive',
    description:
      'Delete specific PlanetScale databases. Binds DELETE /v1/organizations/{org}/databases/{db}. Destructive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      dbPathConstraint(database, ''),
    ],
  }),

  defineIntent({
    name: 'planetscale.list_branches',
    effect: 'read',
    description:
      'List branches in specific databases. Binds GET /v1/organizations/{org}/databases/{db}/branches.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPathConstraint(database, '/branches'),
    ],
  }),

  defineIntent({
    name: 'planetscale.create_branch',
    effect: 'write',
    description:
      'Create a new branch in specific databases. Binds POST /v1/organizations/{org}/databases/{db}/branches.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPathConstraint(database, '/branches'),
    ],
  }),

  defineIntent({
    name: 'planetscale.delete_branch',
    effect: 'destructive',
    description:
      'Delete a branch in specific databases. Binds DELETE /v1/organizations/{org}/databases/{db}/branches/{branch}. Destructive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      dbPathConstraint(database, '/branches/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'planetscale.promote_branch',
    effect: 'write',
    description:
      'Promote a development branch to production. Binds POST /v1/organizations/{org}/databases/{db}/branches/{branch}/promote.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPathConstraint(database, '/branches/[^/]+/promote'),
    ],
  }),

  defineIntent({
    name: 'planetscale.demote_branch',
    effect: 'write',
    description:
      'Demote a production branch back to development. Binds POST /v1/organizations/{org}/databases/{db}/branches/{branch}/demote.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPathConstraint(database, '/branches/[^/]+/demote'),
    ],
  }),

  defineIntent({
    name: 'planetscale.list_deploy_requests',
    effect: 'read',
    description:
      'List deploy requests on specific databases. Binds GET /v1/organizations/{org}/databases/{db}/deploy-requests.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPathConstraint(database, '/deploy-requests(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'planetscale.create_deploy_request',
    effect: 'write',
    description:
      'Open a new deploy request in specific databases. Binds POST /v1/organizations/{org}/databases/{db}/deploy-requests.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPathConstraint(database, '/deploy-requests'),
    ],
  }),

  defineIntent({
    name: 'planetscale.deploy_deploy_request',
    effect: 'write',
    description:
      'Deploy an open deploy request to production. Binds POST /v1/organizations/{org}/databases/{db}/deploy-requests/{number}/deploy.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPathConstraint(database, '/deploy-requests/\\d+/deploy'),
    ],
  }),

  defineIntent({
    name: 'planetscale.revert_deploy_request',
    effect: 'write',
    description:
      'Revert a deployed deploy request. Binds POST /v1/organizations/{org}/databases/{db}/deploy-requests/{number}/revert. Destructive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPathConstraint(database, '/deploy-requests/\\d+/revert'),
    ],
  }),

  defineIntent({
    name: 'planetscale.list_backups',
    effect: 'read',
    description:
      'List backups on specific branches. Binds GET /v1/organizations/{org}/databases/{db}/branches/{branch}/backups.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPathConstraint(database, '/branches/[^/]+/backups(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'planetscale.create_backup',
    effect: 'write',
    description:
      'Create a new backup on specific branches. Binds POST /v1/organizations/{org}/databases/{db}/branches/{branch}/backups.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPathConstraint(database, '/branches/[^/]+/backups'),
    ],
  }),

  defineIntent({
    name: 'planetscale.delete_backup',
    effect: 'destructive',
    description:
      'Delete a backup on specific branches. Binds DELETE /v1/organizations/{org}/databases/{db}/branches/{branch}/backups/{id}. Destructive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      dbPathConstraint(database, '/branches/[^/]+/backups/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'planetscale.manage_passwords',
    effect: 'destructive',
    description:
      'Create, list, and revoke connection passwords on specific branches. Binds POST/GET/DELETE /v1/organizations/{org}/databases/{db}/branches/{branch}/passwords. Sensitive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST', 'DELETE'] },
      dbPathConstraint(database, '/branches/[^/]+/passwords(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'planetscale.list_regions',
    effect: 'read',
    description:
      'List available PlanetScale regions for the organization. Binds GET /v1/organizations/{org}/regions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/regions$' },
    ],
  }),

  defineIntent({
    name: 'planetscale.read_schema',
    effect: 'read',
    description:
      'Read the current schema or schema snapshots for a branch. Binds GET /v1/organizations/{org}/databases/{db}/branches/{branch}/schema.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPathConstraint(database, '/branches/[^/]+/schema(/[^/]+)?'),
    ],
  }),
];
