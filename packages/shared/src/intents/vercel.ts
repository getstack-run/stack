import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Vercel REST API — https://api.vercel.com. Scoping is typically by
// projectId (body.projectId or query.projectId) or teamId (query.teamId).
// Intents bind method + pathname; project/team scoping is enforced where
// feasible via query/body param allowlists. Scope names are declared but
// not always bindable to URL path alone — use query.projectId allowlists
// where the endpoint is team-wide.

const idFmt = z.string().min(1).max(128);
const idList = z.union([idFmt, z.array(idFmt).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function queryAllowConstraint(key: string, ids: IdList): Constraint {
  const list = toList(ids);
  if (list.length === 1) {
    return { path: `query.${key}`, op: 'eq', value: list[0]! };
  }
  return { path: `query.${key}`, op: 'in', value: list };
}

function projectSubpathRegex(projectId: IdList, subpathRegex: string): Constraint {
  const list = toList(projectId);
  const escaped = list.map((p) => p.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? escaped[0]! : `(${escaped.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/v\\d+/projects/${alt}${subpathRegex}$`,
  };
}

export const vercelIntents = [
  defineIntent({
    name: 'vercel.list_deployments',
    effect: 'read',
    description:
      'List recent deployments, optionally scoped to a team. Binds GET /v*/deployments.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/deployments$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.create_deployment',
    effect: 'write',
    description:
      'Trigger a new deployment. Binds POST /v*/deployments — scoped by teamId when provided.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/deployments$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.get_deployment',
    effect: 'read',
    description:
      'Read deployment details by ID. Binds GET /v*/deployments/{id}.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/deployments/[^/]+$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.cancel_deployment',
    effect: 'write',
    description:
      'Cancel an in-progress deployment. Binds PATCH /v*/deployments/{id}/cancel.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/deployments/[^/]+/cancel$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.promote_deployment',
    effect: 'write',
    description:
      'Promote a deployment to production on a project. Binds POST /v*/projects/{projectId}/promote/{deploymentId}.',
    params: z.object({ projectId: idList }),
    expand: ({ projectId }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectSubpathRegex(projectId, '/promote/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_projects',
    effect: 'destructive',
    description:
      'Create, update, and delete projects. Binds POST/PATCH/DELETE /v*/projects(/{id})? — scoped by teamId when provided.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/projects(/[^/]+)?$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_env_vars',
    effect: 'destructive',
    description:
      'Create, update, and delete environment variables on a project. Binds POST/PATCH/DELETE /v*/projects/{projectId}/env(/{id})? — sensitive.',
    params: z.object({ projectId: idList }),
    expand: ({ projectId }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      projectSubpathRegex(projectId, '/env(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_domains',
    effect: 'destructive',
    description:
      'Add, update, and remove domains on a project. Binds POST/PATCH/DELETE /v*/projects/{projectId}/domains(/{domain})?.',
    params: z.object({ projectId: idList }),
    expand: ({ projectId }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      projectSubpathRegex(projectId, '/domains(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_dns',
    effect: 'destructive',
    description:
      'Create, update, and delete DNS records on a domain. Binds POST/PATCH/DELETE /v*/domains/{domain}/records(/{id})?.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/domains/[^/]+/records(/[^/]+)?$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_aliases',
    effect: 'destructive',
    description:
      'Assign or remove deployment aliases. Binds POST/DELETE /v*/deployments/{id}/aliases(/{alias})? and /v*/aliases/{id}.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/v\\d+/(deployments/[^/]+/aliases(/[^/]+)?|aliases/[^/]+)$',
      },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_log_drains',
    effect: 'destructive',
    description:
      'Create and delete log drains. Binds POST/DELETE /v*/log-drains(/{id})? — scoped by teamId when provided.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/log-drains(/[^/]+)?$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.read_teams',
    effect: 'read',
    description:
      'Read-only access to team details and membership. Binds GET /v*/teams(/{id})?.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/teams(/[^/]+)?$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_certs',
    effect: 'destructive',
    description:
      'Issue and remove SSL certificates. Binds POST/DELETE /v*/certs(/{id})? — scoped by teamId when provided.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/certs(/[^/]+)?$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.manage_secrets',
    effect: 'destructive',
    description:
      'Create and delete team-wide secrets. Binds POST/DELETE /v*/secrets(/{name})? — sensitive.',
    params: z.object({ teamId: idList.optional() }),
    expand: ({ teamId }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/v\\d+/secrets(/[^/]+)?$' },
      ...(teamId ? [queryAllowConstraint('teamId', teamId)] : []),
    ],
  }),

  defineIntent({
    name: 'vercel.read_project',
    effect: 'read',
    description:
      'Read-only access to a specific project and its subresources. Binds GET /v*/projects/{projectId}/….',
    params: z.object({ projectId: idList }),
    expand: ({ projectId }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectSubpathRegex(projectId, '(/.*)?'),
    ],
  }),
];
