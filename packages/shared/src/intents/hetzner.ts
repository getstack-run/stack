import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Hetzner Cloud API v1 — https://docs.hetzner.cloud. Base:
// api.hetzner.cloud/v1/…. Servers are addressed by numeric ID. Actions
// are subresources like /servers/{id}/actions/poweroff. Intents scope
// on server_id where the API supports per-server addressing.

const serverId = z.union([z.string().regex(/^\d+$/), z.number().int().positive()]);
const serverList = z.union([serverId, z.array(serverId).min(1)]);
type ServerList = z.infer<typeof serverList>;
const toStrList = (v: ServerList): string[] =>
  (Array.isArray(v) ? v : [v]).map(String);

function serverPathConstraint(server: ServerList, suffix: string): Constraint {
  const list = toStrList(server);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/servers/${alt}${suffix}$`,
  };
}

export const hetznerIntents = [
  defineIntent({
    name: 'hetzner.list_servers',
    effect: 'read',
    description:
      'List all servers on the project. Binds GET /v1/servers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/servers' },
    ],
  }),

  defineIntent({
    name: 'hetzner.read_server',
    effect: 'read',
    description:
      'Read metadata for specific servers. Binds GET /v1/servers/{server_id} to the declared allowlist.',
    params: z.object({ server_id: serverList }),
    expand: ({ server_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      serverPathConstraint(server_id, ''),
    ],
  }),

  defineIntent({
    name: 'hetzner.create_server',
    effect: 'write',
    description:
      'Create a new cloud server. Binds POST /v1/servers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/servers' },
    ],
  }),

  defineIntent({
    name: 'hetzner.delete_server',
    effect: 'destructive',
    description:
      'Delete specific servers. Binds DELETE /v1/servers/{server_id} — irreversible.',
    params: z.object({ server_id: serverList }),
    expand: ({ server_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      serverPathConstraint(server_id, ''),
    ],
  }),

  defineIntent({
    name: 'hetzner.poweron_server',
    effect: 'write',
    description:
      'Power on specific servers. Binds POST /v1/servers/{server_id}/actions/poweron.',
    params: z.object({ server_id: serverList }),
    expand: ({ server_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      serverPathConstraint(server_id, '/actions/poweron'),
    ],
  }),

  defineIntent({
    name: 'hetzner.poweroff_server',
    effect: 'write',
    description:
      'Hard power off specific servers. Binds POST /v1/servers/{server_id}/actions/poweroff.',
    params: z.object({ server_id: serverList }),
    expand: ({ server_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      serverPathConstraint(server_id, '/actions/poweroff'),
    ],
  }),

  defineIntent({
    name: 'hetzner.reboot_server',
    effect: 'write',
    description:
      'Soft reboot specific servers. Binds POST /v1/servers/{server_id}/actions/reboot.',
    params: z.object({ server_id: serverList }),
    expand: ({ server_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      serverPathConstraint(server_id, '/actions/reboot'),
    ],
  }),

  defineIntent({
    name: 'hetzner.reset_server',
    effect: 'write',
    description:
      'Hard reset specific servers. Binds POST /v1/servers/{server_id}/actions/reset.',
    params: z.object({ server_id: serverList }),
    expand: ({ server_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      serverPathConstraint(server_id, '/actions/reset'),
    ],
  }),

  defineIntent({
    name: 'hetzner.list_volumes',
    effect: 'read',
    description:
      'List block-storage volumes. Binds GET /v1/volumes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/volumes' },
    ],
  }),

  defineIntent({
    name: 'hetzner.create_volume',
    effect: 'write',
    description:
      'Create a block-storage volume. Binds POST /v1/volumes.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/volumes' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_ssh_keys',
    effect: 'read',
    description:
      'List SSH keys on the project. Binds GET /v1/ssh_keys.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/ssh_keys' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_images',
    effect: 'read',
    description:
      'List available images. Binds GET /v1/images.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/images' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_networks',
    effect: 'read',
    description:
      'List private networks on the project. Binds GET /v1/networks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/networks' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_firewalls',
    effect: 'read',
    description:
      'List cloud firewalls on the project. Binds GET /v1/firewalls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/firewalls' },
    ],
  }),

  defineIntent({
    name: 'hetzner.create_firewall',
    effect: 'write',
    description:
      'Create a cloud firewall. Binds POST /v1/firewalls.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/firewalls' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_load_balancers',
    effect: 'read',
    description:
      'List load balancers on the project. Binds GET /v1/load_balancers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/load_balancers' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_floating_ips',
    effect: 'read',
    description:
      'List floating IPs on the project. Binds GET /v1/floating_ips.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/floating_ips' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_certificates',
    effect: 'read',
    description:
      'List uploaded and managed TLS certificates. Binds GET /v1/certificates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/certificates' },
    ],
  }),

  defineIntent({
    name: 'hetzner.list_placement_groups',
    effect: 'read',
    description:
      'List placement groups on the project. Binds GET /v1/placement_groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/placement_groups' },
    ],
  }),
];
