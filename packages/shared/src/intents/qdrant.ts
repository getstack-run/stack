import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Qdrant — https://api.qdrant.tech. Self-hosted or Cloud; host varies
// per deployment. Intents gate on method + pathname and, where relevant,
// scope to a collection-name allowlist via pathname regex.

const collectionList = z.union([
  z.string().min(1).max(128),
  z.array(z.string().min(1).max(128)).min(1),
]);
type CollectionList = z.infer<typeof collectionList>;
const toList = (v: CollectionList): string[] => (Array.isArray(v) ? v : [v]);

function collectionRegex(collection: CollectionList, suffix: string): Constraint {
  const list = toList(collection);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return { path: 'url.pathname', op: 'matches', value: `^/collections/${alt}${suffix}$` };
}

export const qdrantIntents = [
  defineIntent({
    name: 'qdrant.collections_list',
    effect: 'read',
    description:
      'List all collections on the cluster. Binds GET /collections.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/collections' },
    ],
  }),

  defineIntent({
    name: 'qdrant.collections_get',
    effect: 'read',
    description:
      'Retrieve metadata for a specific collection allowlist. Binds GET /collections/{collection}.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      collectionRegex(collection, ''),
    ],
  }),

  defineIntent({
    name: 'qdrant.collections_create',
    effect: 'write',
    description:
      'Create a new collection on a specific name allowlist. Binds PUT /collections/{collection}.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      collectionRegex(collection, ''),
    ],
  }),

  defineIntent({
    name: 'qdrant.collections_delete',
    effect: 'destructive',
    description:
      'Delete a collection by name. Binds DELETE /collections/{collection}. Destructive.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      collectionRegex(collection, ''),
    ],
  }),

  defineIntent({
    name: 'qdrant.points_upsert',
    effect: 'write',
    description:
      'Insert or update points in a specific collection allowlist. Binds PUT /collections/{collection}/points.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      collectionRegex(collection, '/points'),
    ],
  }),

  defineIntent({
    name: 'qdrant.points_search',
    effect: 'write',
    description:
      'Search points by vector in a specific collection allowlist. Binds POST /collections/{collection}/points/search.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/search'),
    ],
  }),

  defineIntent({
    name: 'qdrant.points_query',
    effect: 'write',
    description:
      'Run the unified query endpoint on a specific collection allowlist. Binds POST /collections/{collection}/points/query.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/query'),
    ],
  }),

  defineIntent({
    name: 'qdrant.points_scroll',
    effect: 'write',
    description:
      'Scroll through points in a specific collection allowlist. Binds POST /collections/{collection}/points/scroll.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/scroll'),
    ],
  }),

  defineIntent({
    name: 'qdrant.points_retrieve',
    effect: 'write',
    description:
      'Retrieve specific points by id in a collection allowlist. Binds POST /collections/{collection}/points.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points'),
    ],
  }),

  defineIntent({
    name: 'qdrant.points_count',
    effect: 'write',
    description:
      'Count points in a specific collection allowlist. Binds POST /collections/{collection}/points/count.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/count'),
    ],
  }),

  defineIntent({
    name: 'qdrant.points_delete',
    effect: 'destructive',
    description:
      'Delete points from a specific collection allowlist. Binds POST /collections/{collection}/points/delete. Destructive.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/delete'),
    ],
  }),

  defineIntent({
    name: 'qdrant.payload_set',
    effect: 'write',
    description:
      'Set payload on points in a specific collection allowlist. Binds POST /collections/{collection}/points/payload.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/payload'),
    ],
  }),

  defineIntent({
    name: 'qdrant.payload_overwrite',
    effect: 'write',
    description:
      'Overwrite payload on points in a specific collection allowlist. Binds PUT /collections/{collection}/points/payload.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      collectionRegex(collection, '/points/payload'),
    ],
  }),

  defineIntent({
    name: 'qdrant.payload_delete',
    effect: 'destructive',
    description:
      'Delete payload keys on points in a collection allowlist. Binds POST /collections/{collection}/points/payload/delete.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/payload/delete'),
    ],
  }),

  defineIntent({
    name: 'qdrant.payload_clear',
    effect: 'write',
    description:
      'Clear all payload on points in a collection allowlist. Binds POST /collections/{collection}/points/payload/clear.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/points/payload/clear'),
    ],
  }),

  defineIntent({
    name: 'qdrant.snapshots_create',
    effect: 'write',
    description:
      'Create a snapshot of a specific collection allowlist. Binds POST /collections/{collection}/snapshots.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      collectionRegex(collection, '/snapshots'),
    ],
  }),

  defineIntent({
    name: 'qdrant.snapshots_list',
    effect: 'read',
    description:
      'List snapshots for a specific collection allowlist. Binds GET /collections/{collection}/snapshots.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      collectionRegex(collection, '/snapshots'),
    ],
  }),

  defineIntent({
    name: 'qdrant.snapshots_delete',
    effect: 'destructive',
    description:
      'Delete a snapshot in a specific collection allowlist. Binds DELETE /collections/{collection}/snapshots/{snapshot}.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      collectionRegex(collection, '/snapshots/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'qdrant.snapshots_recover',
    effect: 'write',
    description:
      'Recover a collection from a snapshot. Binds PUT /collections/{collection}/snapshots/recover.',
    params: z.object({ collection: collectionList }),
    expand: ({ collection }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      collectionRegex(collection, '/snapshots/recover'),
    ],
  }),

  defineIntent({
    name: 'qdrant.aliases_manage',
    effect: 'destructive',
    description:
      'Read or update collection aliases. Binds /collections/aliases and /aliases.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/(collections/)?aliases$' },
    ],
  }),

  defineIntent({
    name: 'qdrant.cluster_info',
    effect: 'read',
    description:
      'Read cluster-wide status. Binds GET /cluster.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/cluster' },
    ],
  }),

  defineIntent({
    name: 'qdrant.telemetry',
    effect: 'read',
    description:
      'Read usage telemetry. Binds GET /telemetry.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/telemetry' },
    ],
  }),
];
