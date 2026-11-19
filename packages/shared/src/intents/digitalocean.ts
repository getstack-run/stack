import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// DigitalOcean API v2 — https://docs.digitalocean.com/reference/api.
// Base: api.digitalocean.com/v2/…. Droplets and most resources are
// addressed by numeric ID. Intents scope actions on droplet_id so an
// agent can only power-cycle or snapshot the declared hosts.

const dropletId = z.union([z.string().regex(/^\d+$/), z.number().int().positive()]);
const dropletList = z.union([dropletId, z.array(dropletId).min(1)]);
type DropletList = z.infer<typeof dropletList>;
const toStrList = (v: DropletList): string[] =>
  (Array.isArray(v) ? v : [v]).map(String);

function dropletPathConstraint(droplet: DropletList, suffixRegex: string): Constraint {
  const list = toStrList(droplet);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v2/droplets/${alt}${suffixRegex}$`,
  };
}

export const digitaloceanIntents = [
  defineIntent({
    name: 'digitalocean.list_droplets',
    effect: 'read',
    description:
      'List all Droplets on the account. Binds GET /v2/droplets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/droplets' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.read_droplet',
    effect: 'read',
    description:
      'Read metadata for specific Droplets. Binds GET /v2/droplets/{droplet_id} to the declared allowlist.',
    params: z.object({ droplet_id: dropletList }),
    expand: ({ droplet_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      dropletPathConstraint(droplet_id, ''),
    ],
  }),

  defineIntent({
    name: 'digitalocean.create_droplet',
    effect: 'write',
    description:
      'Create a new Droplet. Binds POST /v2/droplets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/droplets' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.delete_droplet',
    effect: 'destructive',
    description:
      'Destroy specific Droplets. Binds DELETE /v2/droplets/{droplet_id} — irreversible, use sparingly.',
    params: z.object({ droplet_id: dropletList }),
    expand: ({ droplet_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      dropletPathConstraint(droplet_id, ''),
    ],
  }),

  defineIntent({
    name: 'digitalocean.power_off_droplet',
    effect: 'write',
    description:
      'Power off specific Droplets. Binds POST /v2/droplets/{droplet_id}/actions with body.type = power_off.',
    params: z.object({ droplet_id: dropletList }),
    expand: ({ droplet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dropletPathConstraint(droplet_id, '/actions'),
      { path: 'body.type', op: 'eq', value: 'power_off' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.power_on_droplet',
    effect: 'write',
    description:
      'Power on specific Droplets. Binds POST /v2/droplets/{droplet_id}/actions with body.type = power_on.',
    params: z.object({ droplet_id: dropletList }),
    expand: ({ droplet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dropletPathConstraint(droplet_id, '/actions'),
      { path: 'body.type', op: 'eq', value: 'power_on' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.reboot_droplet',
    effect: 'write',
    description:
      'Reboot specific Droplets. Binds POST /v2/droplets/{droplet_id}/actions with body.type = reboot.',
    params: z.object({ droplet_id: dropletList }),
    expand: ({ droplet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dropletPathConstraint(droplet_id, '/actions'),
      { path: 'body.type', op: 'eq', value: 'reboot' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.snapshot_droplet',
    effect: 'write',
    description:
      'Create a snapshot of specific Droplets. Binds POST /v2/droplets/{droplet_id}/actions with body.type = snapshot.',
    params: z.object({ droplet_id: dropletList }),
    expand: ({ droplet_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      dropletPathConstraint(droplet_id, '/actions'),
      { path: 'body.type', op: 'eq', value: 'snapshot' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_domains',
    effect: 'read',
    description:
      'List domains on the account. Binds GET /v2/domains.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/domains' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.create_domain',
    effect: 'write',
    description:
      'Add a domain to the account. Binds POST /v2/domains.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/domains' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_volumes',
    effect: 'read',
    description:
      'List block-storage volumes. Binds GET /v2/volumes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/volumes' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.create_volume',
    effect: 'write',
    description:
      'Create a block-storage volume. Binds POST /v2/volumes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/volumes' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_ssh_keys',
    effect: 'read',
    description:
      'List SSH keys on the account. Binds GET /v2/account/keys.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/account/keys' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_images',
    effect: 'read',
    description:
      'List images (distributions, snapshots, backups). Binds GET /v2/images.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/images' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_firewalls',
    effect: 'read',
    description:
      'List cloud firewalls. Binds GET /v2/firewalls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/firewalls' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.create_firewall',
    effect: 'write',
    description:
      'Create a new cloud firewall. Binds POST /v2/firewalls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/firewalls' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_floating_ips',
    effect: 'read',
    description:
      'List floating IPs (reserved IPs) on the account. Binds GET /v2/floating_ips.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/floating_ips' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_kubernetes_clusters',
    effect: 'read',
    description:
      'List Kubernetes clusters (DOKS). Binds GET /v2/kubernetes/clusters.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/kubernetes/clusters' },
    ],
  }),

  defineIntent({
    name: 'digitalocean.list_spaces_keys',
    effect: 'read',
    description:
      'List Spaces access keys on the account. Binds GET /v2/spaces/keys.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/spaces/keys' },
    ],
  }),
];
