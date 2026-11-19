import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// MongoDB Atlas Admin API v2 — https://cloud.mongodb.com/api/atlas/v2/….
// Most resources are scoped under a group (project) via /groups/{groupId}/
// Intents bind method + pathname so the agent can only touch the declared
// project(s) and endpoint kind. groupId is a 24-char ObjectId-style hex.

const groupId = z.string().regex(/^[0-9a-f]{24}$/i, 'groupId must be 24-char hex');
const groupList = z.union([groupId, z.array(groupId).min(1)]);
type GroupList = z.infer<typeof groupList>;
const toList = (v: GroupList): string[] => (Array.isArray(v) ? v : [v]);

function groupPath(group: GroupList, suffixRegex: string): Constraint {
  const list = toList(group);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/atlas/v2/groups/${alt}${suffixRegex}$`,
  };
}

export const mongodbAtlasIntents = [
  defineIntent({
    name: 'mongodb_atlas.list_groups',
    effect: 'read',
    description:
      'List Atlas projects (groups) visible to the API key. Binds GET /api/atlas/v2/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/atlas/v2/groups' },
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.read_group',
    effect: 'read',
    description:
      'Read metadata for specific Atlas projects. Binds GET /api/atlas/v2/groups/{groupId}.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      groupPath(group_id, ''),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.create_group',
    effect: 'write',
    description:
      'Create a new Atlas project. Binds POST /api/atlas/v2/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/atlas/v2/groups' },
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.delete_group',
    effect: 'destructive',
    description:
      'Delete an Atlas project. Binds DELETE /api/atlas/v2/groups/{groupId}. Destructive.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      groupPath(group_id, ''),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.list_clusters',
    effect: 'read',
    description:
      'List clusters within specific Atlas projects. Binds GET /api/atlas/v2/groups/{groupId}/clusters.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      groupPath(group_id, '/clusters'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.create_cluster',
    effect: 'write',
    description:
      'Create a new cluster in specific Atlas projects. Binds POST /api/atlas/v2/groups/{groupId}/clusters.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      groupPath(group_id, '/clusters'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.update_cluster',
    effect: 'write',
    description:
      'Update an existing cluster in specific Atlas projects. Binds PATCH /api/atlas/v2/groups/{groupId}/clusters/{name}.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      groupPath(group_id, '/clusters/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.delete_cluster',
    effect: 'destructive',
    description:
      'Delete a cluster in specific Atlas projects. Binds DELETE /api/atlas/v2/groups/{groupId}/clusters/{name}. Destructive.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      groupPath(group_id, '/clusters/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.pause_cluster',
    effect: 'write',
    description:
      'Pause a running cluster (sets paused=true via PATCH). Binds PATCH /api/atlas/v2/groups/{groupId}/clusters/{name}.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      groupPath(group_id, '/clusters/[^/]+'),
      { path: 'body.paused', op: 'eq', value: true },
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.resume_cluster',
    effect: 'write',
    description:
      'Resume a paused cluster (sets paused=false via PATCH). Binds PATCH /api/atlas/v2/groups/{groupId}/clusters/{name}.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      groupPath(group_id, '/clusters/[^/]+'),
      { path: 'body.paused', op: 'eq', value: false },
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.manage_database_users',
    effect: 'destructive',
    description:
      'Create, update, and delete database users in a project. Binds POST/PATCH/DELETE /api/atlas/v2/groups/{groupId}/databaseUsers. Sensitive.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      groupPath(group_id, '/databaseUsers(/[^/]+/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.list_database_users',
    effect: 'read',
    description:
      'List database users in a project. Binds GET /api/atlas/v2/groups/{groupId}/databaseUsers.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      groupPath(group_id, '/databaseUsers(/[^/]+/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.manage_network_access',
    effect: 'destructive',
    description:
      'Add or remove IP access list entries. Binds POST/DELETE /api/atlas/v2/groups/{groupId}/accessList. Sensitive.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      groupPath(group_id, '/accessList(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.list_snapshots',
    effect: 'read',
    description:
      'List cloud-provider snapshots for a cluster. Binds GET /api/atlas/v2/groups/{groupId}/clusters/{name}/backup/snapshots.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      groupPath(group_id, '/clusters/[^/]+/backup/snapshots(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.take_snapshot',
    effect: 'write',
    description:
      'Take an on-demand snapshot of a cluster. Binds POST /api/atlas/v2/groups/{groupId}/clusters/{name}/backup/snapshots.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      groupPath(group_id, '/clusters/[^/]+/backup/snapshots'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.manage_custom_roles',
    effect: 'destructive',
    description:
      'Create, update, and delete project-level custom database roles. Binds POST/PATCH/DELETE /api/atlas/v2/groups/{groupId}/customDBRoles/roles.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      groupPath(group_id, '/customDBRoles/roles(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.manage_api_keys',
    effect: 'destructive',
    description:
      'Create, list, and delete organization API keys. Binds POST/DELETE /api/atlas/v2/orgs/{orgId}/apiKeys. Sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'GET', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/api/atlas/v2/orgs/[0-9a-f]+/apiKeys(/[0-9a-f]+)?$' },
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.list_alerts',
    effect: 'read',
    description:
      'List triggered alerts for specific Atlas projects. Binds GET /api/atlas/v2/groups/{groupId}/alerts.',
    params: z.object({ group_id: groupList }),
    expand: ({ group_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      groupPath(group_id, '/alerts(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.list_invoices',
    effect: 'read',
    description:
      'List invoices for an organization. Binds GET /api/atlas/v2/orgs/{orgId}/invoices.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/atlas/v2/orgs/[0-9a-f]+/invoices(/[0-9a-f]+)?$' },
    ],
  }),

  defineIntent({
    name: 'mongodb_atlas.read_organization',
    effect: 'read',
    description:
      'Read organization metadata and membership. Binds GET /api/atlas/v2/orgs/{orgId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/atlas/v2/orgs/[0-9a-f]+(/users)?$' },
    ],
  }),
];
