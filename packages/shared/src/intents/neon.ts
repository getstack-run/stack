import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Neon API v2 — https://api-docs.neon.tech. Base:
// console.neon.tech/api/v2/…. Most resources are scoped under a project
// (/projects/{project_id}/…). Intents bind method + pathname so the
// agent can only touch the declared project(s) and endpoint kind.
// Project IDs look like "snowy-cloud-12345678".

const projectId = z.string().min(3).max(128).regex(/^[A-Za-z0-9._-]+$/, 'project_id must be url-safe');
const projectList = z.union([projectId, z.array(projectId).min(1)]);
type ProjectList = z.infer<typeof projectList>;
const toList = (v: ProjectList): string[] => (Array.isArray(v) ? v : [v]);

function projectPathConstraint(project: ProjectList, suffixRegex: string): Constraint {
  const list = toList(project);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/api/v2/projects/${alt}${suffixRegex}$`,
  };
}

export const neonIntents = [
  defineIntent({
    name: 'neon.list_projects',
    effect: 'read',
    description:
      'List all Neon projects accessible to the API key. Binds GET /api/v2/projects.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/projects' },
    ],
  }),

  defineIntent({
    name: 'neon.read_project',
    effect: 'read',
    description:
      'Read metadata for specific Neon projects. Binds GET /api/v2/projects/{project_id} to the declared project allowlist.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPathConstraint(project_id, ''),
    ],
  }),

  defineIntent({
    name: 'neon.create_project',
    effect: 'write',
    description:
      'Create a new Neon project on the account. Binds POST /api/v2/projects.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/projects' },
    ],
  }),

  defineIntent({
    name: 'neon.update_project',
    effect: 'write',
    description:
      'Update settings on specific Neon projects. Binds PATCH /api/v2/projects/{project_id}.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      projectPathConstraint(project_id, ''),
    ],
  }),

  defineIntent({
    name: 'neon.delete_project',
    effect: 'destructive',
    description:
      'Delete specific Neon projects. Binds DELETE /api/v2/projects/{project_id}. Destructive.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      projectPathConstraint(project_id, ''),
    ],
  }),

  defineIntent({
    name: 'neon.list_branches',
    effect: 'read',
    description:
      'List branches within specific Neon projects. Binds GET /api/v2/projects/{project_id}/branches.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPathConstraint(project_id, '/branches'),
    ],
  }),

  defineIntent({
    name: 'neon.create_branch',
    effect: 'write',
    description:
      'Create a new branch in specific Neon projects. Binds POST /api/v2/projects/{project_id}/branches.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathConstraint(project_id, '/branches'),
    ],
  }),

  defineIntent({
    name: 'neon.delete_branch',
    effect: 'destructive',
    description:
      'Delete a branch in specific Neon projects. Binds DELETE /api/v2/projects/{project_id}/branches/{branch_id}. Destructive.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      projectPathConstraint(project_id, '/branches/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'neon.restore_branch',
    effect: 'write',
    description:
      'Restore a branch to an earlier point in time. Binds POST /api/v2/projects/{project_id}/branches/{branch_id}/restore.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathConstraint(project_id, '/branches/[^/]+/restore'),
    ],
  }),

  defineIntent({
    name: 'neon.set_default_branch',
    effect: 'write',
    description:
      'Mark a branch as the default for the project. Binds POST /api/v2/projects/{project_id}/branches/{branch_id}/set_as_default.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathConstraint(project_id, '/branches/[^/]+/set_as_default'),
    ],
  }),

  defineIntent({
    name: 'neon.list_endpoints',
    effect: 'read',
    description:
      'List compute endpoints in specific Neon projects. Binds GET /api/v2/projects/{project_id}/endpoints.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPathConstraint(project_id, '/endpoints'),
    ],
  }),

  defineIntent({
    name: 'neon.create_endpoint',
    effect: 'write',
    description:
      'Create a new compute endpoint in specific projects. Binds POST /api/v2/projects/{project_id}/endpoints.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathConstraint(project_id, '/endpoints'),
    ],
  }),

  defineIntent({
    name: 'neon.suspend_endpoint',
    effect: 'write',
    description:
      'Suspend a running compute endpoint. Binds POST /api/v2/projects/{project_id}/endpoints/{endpoint_id}/suspend.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathConstraint(project_id, '/endpoints/[^/]+/suspend'),
    ],
  }),

  defineIntent({
    name: 'neon.start_endpoint',
    effect: 'write',
    description:
      'Start a suspended compute endpoint. Binds POST /api/v2/projects/{project_id}/endpoints/{endpoint_id}/start.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPathConstraint(project_id, '/endpoints/[^/]+/start'),
    ],
  }),

  defineIntent({
    name: 'neon.manage_databases',
    effect: 'destructive',
    description:
      'Create, update, and delete databases on a branch. Binds POST/PATCH/DELETE /api/v2/projects/{project_id}/branches/{branch_id}/databases.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'in', value: ['POST', 'PATCH', 'DELETE'] },
      projectPathConstraint(project_id, '/branches/[^/]+/databases(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'neon.list_databases',
    effect: 'read',
    description:
      'List databases on a branch. Binds GET /api/v2/projects/{project_id}/branches/{branch_id}/databases.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPathConstraint(project_id, '/branches/[^/]+/databases(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'neon.manage_roles',
    effect: 'destructive',
    description:
      'Create, delete, and reset passwords on branch roles. Binds POST/DELETE /api/v2/projects/{project_id}/branches/{branch_id}/roles.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      projectPathConstraint(project_id, '/branches/[^/]+/roles(/[^/]+(/reset_password|/reveal_password)?)?'),
    ],
  }),

  defineIntent({
    name: 'neon.list_operations',
    effect: 'read',
    description:
      'List background operations on a project. Binds GET /api/v2/projects/{project_id}/operations.',
    params: z.object({ project_id: projectList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPathConstraint(project_id, '/operations(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'neon.manage_api_keys',
    effect: 'destructive',
    description:
      'Create and revoke account-level API keys. Binds POST/DELETE /api/v2/api_keys(/{key_id})?. Sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'DELETE'] },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/api_keys(/\\d+)?$' },
    ],
  }),

  defineIntent({
    name: 'neon.read_consumption',
    effect: 'read',
    description:
      'Read consumption metrics for projects (compute hours, storage). Binds GET /api/v2/consumption_history/projects.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/consumption_history/projects$' },
    ],
  }),

  defineIntent({
    name: 'neon.read_organizations',
    effect: 'read',
    description:
      'Read organization metadata and membership. Binds GET /api/v2/organizations(/{org_id}(/members)?)?.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/organizations(/[^/]+(/members)?)?$' },
    ],
  }),
];
