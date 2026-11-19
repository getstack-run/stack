import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Turso platform API — https://api.turso.tech/v1. Resources are scoped
// under /organizations/{org}/…. Databases are named like url-safe slugs.
// Intents bind method + pathname so the agent can only touch the declared
// database(s) and endpoint kind.

const dbName = z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/, 'database must be url-safe');
const dbList = z.union([dbName, z.array(dbName).min(1)]);
type DbList = z.infer<typeof dbList>;
const toList = (v: DbList): string[] => (Array.isArray(v) ? v : [v]);

function dbPath(db: DbList, suffixRegex: string): Constraint {
  const list = toList(db);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/organizations/[^/]+/databases/${alt}${suffixRegex}$`,
  };
}

export const tursoIntents = [
  defineIntent({
    name: 'turso.list_databases',
    effect: 'read',
    description:
      'List databases in the Turso organization. Binds GET /v1/organizations/{org}/databases.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/databases$' },
    ],
  }),

  defineIntent({
    name: 'turso.read_database',
    effect: 'read',
    description:
      'Read metadata for specific Turso databases. Binds GET /v1/organizations/{org}/databases/{name}.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPath(database, ''),
    ],
  }),

  defineIntent({
    name: 'turso.create_database',
    effect: 'write',
    description:
      'Create a new Turso database. Binds POST /v1/organizations/{org}/databases.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/databases$' },
    ],
  }),

  defineIntent({
    name: 'turso.delete_database',
    effect: 'destructive',
    description:
      'Delete specific Turso databases. Binds DELETE /v1/organizations/{org}/databases/{name}. Destructive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      dbPath(database, ''),
    ],
  }),

  defineIntent({
    name: 'turso.list_locations',
    effect: 'read',
    description:
      'List regions (edge locations) available for databases. Binds GET /v1/locations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/locations' },
    ],
  }),

  defineIntent({
    name: 'turso.list_groups',
    effect: 'read',
    description:
      'List database groups in the organization. Binds GET /v1/organizations/{org}/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/groups$' },
    ],
  }),

  defineIntent({
    name: 'turso.create_group',
    effect: 'write',
    description:
      'Create a new database group. Binds POST /v1/organizations/{org}/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/groups$' },
    ],
  }),

  defineIntent({
    name: 'turso.delete_group',
    effect: 'destructive',
    description:
      'Delete a database group by name. Binds DELETE /v1/organizations/{org}/groups/{name}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/groups/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'turso.create_token',
    effect: 'write',
    description:
      'Mint an auth token for a specific database. Binds POST /v1/organizations/{org}/databases/{name}/auth/tokens. Sensitive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPath(database, '/auth/tokens'),
    ],
  }),

  defineIntent({
    name: 'turso.revoke_tokens',
    effect: 'write',
    description:
      'Invalidate all existing auth tokens for a database. Binds POST /v1/organizations/{org}/databases/{name}/auth/rotate. Sensitive.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dbPath(database, '/auth/rotate'),
    ],
  }),

  defineIntent({
    name: 'turso.update_extensions',
    effect: 'destructive',
    description:
      'Enable or disable SQLite extensions on a database group. Binds POST /v1/organizations/{org}/groups/{group}/extensions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/groups/[^/]+/extensions(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'turso.read_stats',
    effect: 'read',
    description:
      'Read usage stats for a database. Binds GET /v1/organizations/{org}/databases/{name}/usage.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPath(database, '/usage'),
    ],
  }),

  defineIntent({
    name: 'turso.list_members',
    effect: 'read',
    description:
      'List members of the Turso organization. Binds GET /v1/organizations/{org}/members.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/members$' },
    ],
  }),

  defineIntent({
    name: 'turso.list_instances',
    effect: 'read',
    description:
      'List replicated database instances across regions. Binds GET /v1/organizations/{org}/databases/{name}/instances.',
    params: z.object({ database: dbList }),
    expand: ({ database }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dbPath(database, '/instances(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'turso.read_audit_logs',
    effect: 'read',
    description:
      'Read audit log entries for the organization. Binds GET /v1/organizations/{org}/audit-logs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organizations/[^/]+/audit-logs$' },
    ],
  }),
];
