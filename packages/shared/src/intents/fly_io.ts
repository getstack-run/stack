import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Fly.io Machines API — https://api.machines.dev/v1. Every resource is
// scoped to an app at /v1/apps/{app}/…. Intents bind method + pathname
// to the declared app allowlist.

const appFmt = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'app must be a valid Fly app slug');
const appList = z.union([appFmt, z.array(appFmt).min(1)]);
type AppList = z.infer<typeof appList>;
const toList = (v: AppList): string[] => (Array.isArray(v) ? v : [v]);

function appPathPrefixConstraint(app: AppList, suffix: string): Constraint {
  const list = toList(app);
  if (list.length === 1) {
    return { path: 'url.pathname', op: 'eq', value: `/v1/apps/${list[0]!}${suffix}` };
  }
  const escaped = list.map((a) => a.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/apps/(${escaped.join('|')})${suffix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')}$`,
  };
}

function appSubpathRegex(app: AppList, subpathRegex: string): Constraint {
  const list = toList(app);
  const escaped = list.map((a) => a.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/apps/${alt}${subpathRegex}$`,
  };
}

export const flyIoIntents = [
  defineIntent({
    name: 'fly_io.create_app',
    effect: 'write',
    description:
      'Create a new Fly app. Binds POST /v1/apps (not app-scoped — the app is created in the request body).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/apps' },
    ],
  }),

  defineIntent({
    name: 'fly_io.delete_app',
    effect: 'destructive',
    description:
      'Delete a Fly app. Binds DELETE /v1/apps/{app} — destructive, tears down all machines.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      appPathPrefixConstraint(app, ''),
    ],
  }),

  defineIntent({
    name: 'fly_io.read_app',
    effect: 'read',
    description:
      'Read-only access to app metadata and subresources. Binds GET /v1/apps/{app}/….',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      appSubpathRegex(app, '(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'fly_io.list_machines',
    effect: 'read',
    description:
      'List machines in a Fly app. Binds GET /v1/apps/{app}/machines.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      appPathPrefixConstraint(app, '/machines'),
    ],
  }),

  defineIntent({
    name: 'fly_io.create_machine',
    effect: 'write',
    description:
      'Create a new machine in a Fly app. Binds POST /v1/apps/{app}/machines.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      appPathPrefixConstraint(app, '/machines'),
    ],
  }),

  defineIntent({
    name: 'fly_io.start_machine',
    effect: 'write',
    description:
      'Start a stopped machine. Binds POST /v1/apps/{app}/machines/{id}/start.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      appSubpathRegex(app, '/machines/[^/]+/start'),
    ],
  }),

  defineIntent({
    name: 'fly_io.stop_machine',
    effect: 'write',
    description:
      'Stop a running machine. Binds POST /v1/apps/{app}/machines/{id}/stop.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      appSubpathRegex(app, '/machines/[^/]+/stop'),
    ],
  }),

  defineIntent({
    name: 'fly_io.restart_machine',
    effect: 'write',
    description:
      'Restart a machine. Binds POST /v1/apps/{app}/machines/{id}/restart.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      appSubpathRegex(app, '/machines/[^/]+/restart'),
    ],
  }),

  defineIntent({
    name: 'fly_io.destroy_machine',
    effect: 'destructive',
    description:
      'Destroy a machine. Binds DELETE /v1/apps/{app}/machines/{id} — destructive.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      appSubpathRegex(app, '/machines/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'fly_io.update_machine',
    effect: 'write',
    description:
      'Update a machine configuration in place. Binds POST /v1/apps/{app}/machines/{id}.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      appSubpathRegex(app, '/machines/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'fly_io.manage_volumes',
    effect: 'destructive',
    description:
      'Create and delete persistent volumes for an app. Binds POST/DELETE /v1/apps/{app}/volumes(/{id})?.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      appSubpathRegex(app, '/volumes(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'fly_io.manage_secrets',
    effect: 'destructive',
    description:
      'Set or unset app secrets. Binds POST/DELETE /v1/apps/{app}/secrets(/{name})? — sensitive.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      appSubpathRegex(app, '/secrets(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'fly_io.list_releases',
    effect: 'read',
    description:
      'Read release history for an app. Binds GET /v1/apps/{app}/releases(/{id})?.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      appSubpathRegex(app, '/releases(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'fly_io.manage_certs',
    effect: 'destructive',
    description:
      'Add or remove SSL certificates on an app. Binds POST/DELETE /v1/apps/{app}/certificates(/{hostname})?.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      appSubpathRegex(app, '/certificates(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'fly_io.wait_machine',
    effect: 'read',
    description:
      'Wait for a machine to reach a desired state. Binds GET /v1/apps/{app}/machines/{id}/wait.',
    params: z.object({ app: appList }),
    expand: ({ app }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      appSubpathRegex(app, '/machines/[^/]+/wait'),
    ],
  }),
];
