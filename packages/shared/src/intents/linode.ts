import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Linode API v4 — https://www.linode.com/docs/api. Base:
// api.linode.com/v4/…. Linode instances are addressed by numeric ID.
// Boot/reboot/shutdown are subresources under /linode/instances/{id}.
// Intents scope on linode_id where applicable.

const linodeId = z.union([z.string().regex(/^\d+$/), z.number().int().positive()]);
const linodeList = z.union([linodeId, z.array(linodeId).min(1)]);
type LinodeList = z.infer<typeof linodeList>;
const toStrList = (v: LinodeList): string[] =>
  (Array.isArray(v) ? v : [v]).map(String);

function linodePathConstraint(linode: LinodeList, suffix: string): Constraint {
  const list = toStrList(linode);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v4/linode/instances/${alt}${suffix}$`,
  };
}

export const linodeIntents = [
  defineIntent({
    name: 'linode.list_instances',
    effect: 'read',
    description:
      'List all Linode instances on the account. Binds GET /v4/linode/instances.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/linode/instances' },
    ],
  }),

  defineIntent({
    name: 'linode.read_instance',
    effect: 'read',
    description:
      'Read metadata for specific Linode instances. Binds GET /v4/linode/instances/{linode_id}.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      linodePathConstraint(linode_id, ''),
    ],
  }),

  defineIntent({
    name: 'linode.create_instance',
    effect: 'write',
    description:
      'Provision a new Linode instance. Binds POST /v4/linode/instances.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v4/linode/instances' },
    ],
  }),

  defineIntent({
    name: 'linode.delete_instance',
    effect: 'destructive',
    description:
      'Delete specific Linode instances. Binds DELETE /v4/linode/instances/{linode_id} — irreversible.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      linodePathConstraint(linode_id, ''),
    ],
  }),

  defineIntent({
    name: 'linode.boot_instance',
    effect: 'write',
    description:
      'Boot specific Linode instances. Binds POST /v4/linode/instances/{linode_id}/boot.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      linodePathConstraint(linode_id, '/boot'),
    ],
  }),

  defineIntent({
    name: 'linode.reboot_instance',
    effect: 'write',
    description:
      'Reboot specific Linode instances. Binds POST /v4/linode/instances/{linode_id}/reboot.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      linodePathConstraint(linode_id, '/reboot'),
    ],
  }),

  defineIntent({
    name: 'linode.shutdown_instance',
    effect: 'write',
    description:
      'Shut down specific Linode instances. Binds POST /v4/linode/instances/{linode_id}/shutdown.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      linodePathConstraint(linode_id, '/shutdown'),
    ],
  }),

  defineIntent({
    name: 'linode.clone_instance',
    effect: 'write',
    description:
      'Clone specific Linode instances. Binds POST /v4/linode/instances/{linode_id}/clone.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      linodePathConstraint(linode_id, '/clone'),
    ],
  }),

  defineIntent({
    name: 'linode.rebuild_instance',
    effect: 'write',
    description:
      'Rebuild specific Linode instances from a disk image. Binds POST /v4/linode/instances/{linode_id}/rebuild — destructive.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      linodePathConstraint(linode_id, '/rebuild'),
    ],
  }),

  defineIntent({
    name: 'linode.migrate_instance',
    effect: 'write',
    description:
      'Migrate specific Linode instances to another region. Binds POST /v4/linode/instances/{linode_id}/migrate.',
    params: z.object({ linode_id: linodeList }),
    expand: ({ linode_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      linodePathConstraint(linode_id, '/migrate'),
    ],
  }),

  defineIntent({
    name: 'linode.list_domains',
    effect: 'read',
    description:
      'List DNS domains on the account. Binds GET /v4/domains.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/domains' },
    ],
  }),

  defineIntent({
    name: 'linode.list_volumes',
    effect: 'read',
    description:
      'List block-storage volumes. Binds GET /v4/volumes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/volumes' },
    ],
  }),

  defineIntent({
    name: 'linode.list_images',
    effect: 'read',
    description:
      'List private and public images. Binds GET /v4/images.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/images' },
    ],
  }),

  defineIntent({
    name: 'linode.list_nodebalancers',
    effect: 'read',
    description:
      'List NodeBalancers on the account. Binds GET /v4/nodebalancers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/nodebalancers' },
    ],
  }),

  defineIntent({
    name: 'linode.list_firewalls',
    effect: 'read',
    description:
      'List cloud firewalls on the account. Binds GET /v4/networking/firewalls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/networking/firewalls' },
    ],
  }),

  defineIntent({
    name: 'linode.create_firewall',
    effect: 'write',
    description:
      'Create a cloud firewall. Binds POST /v4/networking/firewalls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v4/networking/firewalls' },
    ],
  }),

  defineIntent({
    name: 'linode.list_lke_clusters',
    effect: 'read',
    description:
      'List Linode Kubernetes Engine clusters. Binds GET /v4/lke/clusters.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/lke/clusters' },
    ],
  }),

  defineIntent({
    name: 'linode.list_object_storage_buckets',
    effect: 'read',
    description:
      'List Object Storage buckets on the account. Binds GET /v4/object-storage/buckets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/object-storage/buckets' },
    ],
  }),

  defineIntent({
    name: 'linode.list_ssh_keys',
    effect: 'read',
    description:
      'List SSH keys on the account profile. Binds GET /v4/profile/sshkeys.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v4/profile/sshkeys' },
    ],
  }),
];
