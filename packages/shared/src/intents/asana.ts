import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Asana API 1.0 — https://developers.asana.com/reference. All requests go
// to app.asana.com/api/1.0/…. Resources identified by numeric gid. Most
// scoping is via project_gid, workspace_gid or body.data.projects.

const gidList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type GidList = z.infer<typeof gidList>;
const toList = (v: GidList): string[] => (Array.isArray(v) ? v : [v]);

function eqOrIn(path: string, ids: GidList): Constraint {
  const list = toList(ids);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

export const asanaIntents = [
  defineIntent({
    name: 'asana.create_task',
    effect: 'write',
    description:
      'Create an Asana task and attach it to a specific project. Binds POST /api/1.0/tasks with body.data.projects pinned to the project gid allowlist.',
    params: z.object({ project_gid: gidList }),
    expand: ({ project_gid }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/1.0/tasks' },
      eqOrIn('body.data.projects', project_gid),
    ],
  }),

  defineIntent({
    name: 'asana.update_task',
    effect: 'write',
    description:
      'Update an existing Asana task. Binds PUT /api/1.0/tasks/{task_gid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/tasks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'asana.delete_task',
    effect: 'destructive',
    description:
      'Delete an Asana task. Binds DELETE /api/1.0/tasks/{task_gid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/tasks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'asana.read_task',
    effect: 'read',
    description:
      'Read an Asana task. Binds GET /api/1.0/tasks/{task_gid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/tasks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'asana.create_subtask',
    effect: 'write',
    description:
      'Create a subtask under an Asana task. Binds POST /api/1.0/tasks/{task_gid}/subtasks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/tasks/[^/]+/subtasks$' },
    ],
  }),

  defineIntent({
    name: 'asana.list_tasks_in_project',
    effect: 'read',
    description:
      'List tasks within a specific Asana project. Binds GET /api/1.0/projects/{project_gid}/tasks.',
    params: z.object({ project_gid: gidList }),
    expand: ({ project_gid }) => {
      const list = toList(project_gid);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/api/1\\.0/projects/${alt}/tasks$` },
      ];
    },
  }),

  defineIntent({
    name: 'asana.create_story',
    effect: 'write',
    description:
      'Post a comment (story) on an Asana task. Binds POST /api/1.0/tasks/{task_gid}/stories.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/tasks/[^/]+/stories$' },
    ],
  }),

  defineIntent({
    name: 'asana.list_stories',
    effect: 'read',
    description:
      'List stories (comments and activity) on an Asana task. Binds GET /api/1.0/tasks/{task_gid}/stories.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/tasks/[^/]+/stories$' },
    ],
  }),

  defineIntent({
    name: 'asana.create_section',
    effect: 'write',
    description:
      'Create a section within an Asana project. Binds POST /api/1.0/projects/{project_gid}/sections.',
    params: z.object({ project_gid: gidList }),
    expand: ({ project_gid }) => {
      const list = toList(project_gid);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/api/1\\.0/projects/${alt}/sections$` },
      ];
    },
  }),

  defineIntent({
    name: 'asana.create_project',
    effect: 'write',
    description:
      'Create a new Asana project in a workspace. Binds POST /api/1.0/projects.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/1.0/projects' },
    ],
  }),

  defineIntent({
    name: 'asana.update_project',
    effect: 'write',
    description:
      'Update an Asana project. Binds PUT /api/1.0/projects/{project_gid}.',
    params: z.object({ project_gid: gidList }),
    expand: ({ project_gid }) => {
      const list = toList(project_gid);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/api/1\\.0/projects/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'asana.list_projects',
    effect: 'read',
    description:
      'List Asana projects visible to the caller. Binds GET /api/1.0/projects.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/1.0/projects' },
    ],
  }),

  defineIntent({
    name: 'asana.list_workspaces',
    effect: 'read',
    description:
      'List Asana workspaces the user belongs to. Binds GET /api/1.0/workspaces.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/1.0/workspaces' },
    ],
  }),

  defineIntent({
    name: 'asana.list_teams',
    effect: 'read',
    description:
      'List teams within an Asana workspace. Binds GET /api/1.0/workspaces/{workspace_gid}/teams.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/workspaces/[^/]+/teams$' },
    ],
  }),

  defineIntent({
    name: 'asana.list_tags',
    effect: 'read',
    description:
      'List tags in an Asana workspace. Binds GET /api/1.0/workspaces/{workspace_gid}/tags.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/workspaces/[^/]+/tags$' },
    ],
  }),

  defineIntent({
    name: 'asana.add_attachment',
    effect: 'write',
    description:
      'Upload an attachment to an Asana resource. Binds POST /api/1.0/attachments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/1.0/attachments' },
    ],
  }),

  defineIntent({
    name: 'asana.list_custom_fields',
    effect: 'read',
    description:
      'List custom field definitions in an Asana workspace. Binds GET /api/1.0/workspaces/{workspace_gid}/custom_fields.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/workspaces/[^/]+/custom_fields$' },
    ],
  }),

  defineIntent({
    name: 'asana.create_webhook',
    effect: 'write',
    description:
      'Create an Asana webhook subscription. Binds POST /api/1.0/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/1.0/webhooks' },
    ],
  }),

  defineIntent({
    name: 'asana.list_portfolios',
    effect: 'read',
    description:
      'List Asana portfolios owned by the user. Binds GET /api/1.0/portfolios.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/1.0/portfolios' },
    ],
  }),

  defineIntent({
    name: 'asana.search_tasks',
    effect: 'read',
    description:
      'Run a typeahead search for Asana tasks in a workspace. Binds GET /api/1.0/workspaces/{workspace_gid}/typeahead.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/1\\.0/workspaces/[^/]+/typeahead$' },
    ],
  }),
];
