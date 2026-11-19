import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Render API — https://api.render.com/v1. Most resources live under
// /v1/services/{serviceId}/…. Intents bind method + pathname to the
// declared service allowlist.

const svcFmt = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._-]+$/, 'serviceId must be alphanumeric');
const svcList = z.union([svcFmt, z.array(svcFmt).min(1)]);
type SvcList = z.infer<typeof svcList>;
const toList = (v: SvcList): string[] => (Array.isArray(v) ? v : [v]);

function svcPathPrefixConstraint(svc: SvcList, suffix: string): Constraint {
  const list = toList(svc);
  if (list.length === 1) {
    return { path: 'url.pathname', op: 'eq', value: `/v1/services/${list[0]!}${suffix}` };
  }
  const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/services/(${escaped.join('|')})${suffix.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')}$`,
  };
}

function svcSubpathRegex(svc: SvcList, subpathRegex: string): Constraint {
  const list = toList(svc);
  const escaped = list.map((s) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v1/services/${alt}${subpathRegex}$`,
  };
}

export const renderIntents = [
  defineIntent({
    name: 'render.create_service',
    effect: 'write',
    description:
      'Create a new Render service. Binds POST /v1/services (not service-scoped).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/services' },
    ],
  }),

  defineIntent({
    name: 'render.update_service',
    effect: 'write',
    description:
      'Update service configuration. Binds PATCH /v1/services/{serviceId}.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      svcPathPrefixConstraint(serviceId, ''),
    ],
  }),

  defineIntent({
    name: 'render.delete_service',
    effect: 'destructive',
    description:
      'Delete a service. Binds DELETE /v1/services/{serviceId} — destructive.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      svcPathPrefixConstraint(serviceId, ''),
    ],
  }),

  defineIntent({
    name: 'render.read_service',
    effect: 'read',
    description:
      'Read-only access to service metadata and subresources. Binds GET /v1/services/{serviceId}/….',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      svcSubpathRegex(serviceId, '(/.*)?'),
    ],
  }),

  defineIntent({
    name: 'render.trigger_deploy',
    effect: 'write',
    description:
      'Trigger a new deploy on a service. Binds POST /v1/services/{serviceId}/deploys.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      svcPathPrefixConstraint(serviceId, '/deploys'),
    ],
  }),

  defineIntent({
    name: 'render.cancel_deploy',
    effect: 'write',
    description:
      'Cancel an in-progress deploy. Binds POST /v1/services/{serviceId}/deploys/{deployId}/cancel.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      svcSubpathRegex(serviceId, '/deploys/[^/]+/cancel'),
    ],
  }),

  defineIntent({
    name: 'render.rollback_deploy',
    effect: 'write',
    description:
      'Roll back to a specific earlier deploy. Binds POST /v1/services/{serviceId}/rollback.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      svcPathPrefixConstraint(serviceId, '/rollback'),
    ],
  }),

  defineIntent({
    name: 'render.suspend_service',
    effect: 'write',
    description:
      'Suspend a running service. Binds POST /v1/services/{serviceId}/suspend.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      svcPathPrefixConstraint(serviceId, '/suspend'),
    ],
  }),

  defineIntent({
    name: 'render.resume_service',
    effect: 'write',
    description:
      'Resume a suspended service. Binds POST /v1/services/{serviceId}/resume.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      svcPathPrefixConstraint(serviceId, '/resume'),
    ],
  }),

  defineIntent({
    name: 'render.scale_service',
    effect: 'write',
    description:
      'Change the instance count for a service. Binds POST /v1/services/{serviceId}/scale.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      svcPathPrefixConstraint(serviceId, '/scale'),
    ],
  }),

  defineIntent({
    name: 'render.manage_env_vars',
    effect: 'destructive',
    description:
      'Create, update, and delete environment variables on a service. Binds PUT/DELETE /v1/services/{serviceId}/env-vars(/{key})? — sensitive.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'in', value: ['PUT', 'DELETE'] },
      svcSubpathRegex(serviceId, '/env-vars(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'render.manage_env_groups',
    effect: 'destructive',
    description:
      'Create, update, and delete shared env groups. Binds POST/PUT/DELETE /v1/env-groups(/{id})? (account-scoped).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PUT', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/v1/env-groups(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'render.manage_custom_domains',
    effect: 'destructive',
    description:
      'Add or remove custom domains on a service. Binds POST/DELETE /v1/services/{serviceId}/custom-domains(/{id})?.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      svcSubpathRegex(serviceId, '/custom-domains(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'render.run_job',
    effect: 'write',
    description:
      'Create a new one-off job on a service. Binds POST /v1/services/{serviceId}/jobs.',
    params: z.object({ serviceId: svcList }),
    expand: ({ serviceId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      svcPathPrefixConstraint(serviceId, '/jobs'),
    ],
  }),

  defineIntent({
    name: 'render.query_logs',
    effect: 'read',
    description:
      'Read log entries for an owner, optionally filtered to a service. Binds GET /v1/logs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/logs' },
    ],
  }),
];
