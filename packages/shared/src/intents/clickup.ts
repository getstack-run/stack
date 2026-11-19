import { z } from 'zod';
import { defineIntent } from './types.js';

// ClickUp API v2 — https://clickup.com/api. All requests go to
// api.clickup.com/api/v2/…. Most task operations live under a list_id; a
// few under space_id, folder_id, or team_id. IDs are numeric strings.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function altRegex(ids: IdList): string {
  const list = toList(ids);
  const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
}

export const clickupIntents = [
  defineIntent({
    name: 'clickup.create_task',
    effect: 'write',
    description:
      'Create a ClickUp task in a specific list. Binds POST /api/v2/list/{list_id}/task to the declared list IDs.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `^/api/v2/list/${altRegex(list_id)}/task$` },
    ],
  }),

  defineIntent({
    name: 'clickup.update_task',
    effect: 'write',
    description:
      'Update a ClickUp task. Binds PUT /api/v2/task/{task_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/task/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clickup.delete_task',
    effect: 'destructive',
    description:
      'Delete a ClickUp task. Binds DELETE /api/v2/task/{task_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/task/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clickup.read_task',
    effect: 'read',
    description:
      'Read a ClickUp task by ID. Binds GET /api/v2/task/{task_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/task/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clickup.list_tasks_in_list',
    effect: 'read',
    description:
      'List tasks within a ClickUp list. Binds GET /api/v2/list/{list_id}/task.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/api/v2/list/${altRegex(list_id)}/task$` },
    ],
  }),

  defineIntent({
    name: 'clickup.create_task_comment',
    effect: 'write',
    description:
      'Post a comment on a ClickUp task. Binds POST /api/v2/task/{task_id}/comment.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/task/[^/]+/comment$' },
    ],
  }),

  defineIntent({
    name: 'clickup.list_task_comments',
    effect: 'read',
    description:
      'List comments on a ClickUp task. Binds GET /api/v2/task/{task_id}/comment.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/task/[^/]+/comment$' },
    ],
  }),

  defineIntent({
    name: 'clickup.create_list',
    effect: 'write',
    description:
      'Create a list inside a ClickUp folder. Binds POST /api/v2/folder/{folder_id}/list.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/folder/[^/]+/list$' },
    ],
  }),

  defineIntent({
    name: 'clickup.update_list',
    effect: 'write',
    description:
      'Update a ClickUp list. Binds PUT /api/v2/list/{list_id}.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: `^/api/v2/list/${altRegex(list_id)}$` },
    ],
  }),

  defineIntent({
    name: 'clickup.list_folders',
    effect: 'read',
    description:
      'List folders in a ClickUp space. Binds GET /api/v2/space/{space_id}/folder.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/api/v2/space/${altRegex(space_id)}/folder$` },
    ],
  }),

  defineIntent({
    name: 'clickup.list_spaces',
    effect: 'read',
    description:
      'List ClickUp spaces in a workspace (team). Binds GET /api/v2/team/{team_id}/space.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/team/[^/]+/space$' },
    ],
  }),

  defineIntent({
    name: 'clickup.list_teams',
    effect: 'read',
    description:
      'List ClickUp workspaces (teams) the user belongs to. Binds GET /api/v2/team.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v2/team' },
    ],
  }),

  defineIntent({
    name: 'clickup.list_goals',
    effect: 'read',
    description:
      'List ClickUp goals for a workspace. Binds GET /api/v2/team/{team_id}/goal.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/team/[^/]+/goal$' },
    ],
  }),

  defineIntent({
    name: 'clickup.create_goal',
    effect: 'write',
    description:
      'Create a ClickUp goal in a workspace. Binds POST /api/v2/team/{team_id}/goal.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/team/[^/]+/goal$' },
    ],
  }),

  defineIntent({
    name: 'clickup.create_checklist',
    effect: 'write',
    description:
      'Add a checklist to a ClickUp task. Binds POST /api/v2/task/{task_id}/checklist.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/task/[^/]+/checklist$' },
    ],
  }),

  defineIntent({
    name: 'clickup.start_time_entry',
    effect: 'write',
    description:
      'Start a running ClickUp time entry for a workspace. Binds POST /api/v2/team/{team_id}/time_entries/start.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/team/[^/]+/time_entries/start$' },
    ],
  }),

  defineIntent({
    name: 'clickup.list_time_entries',
    effect: 'read',
    description:
      'List ClickUp time entries for a workspace. Binds GET /api/v2/team/{team_id}/time_entries.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/team/[^/]+/time_entries$' },
    ],
  }),

  defineIntent({
    name: 'clickup.list_custom_fields',
    effect: 'read',
    description:
      'List custom fields available on a ClickUp list. Binds GET /api/v2/list/{list_id}/field.',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/api/v2/list/${altRegex(list_id)}/field$` },
    ],
  }),

  defineIntent({
    name: 'clickup.set_custom_field',
    effect: 'write',
    description:
      'Set a custom field value on a ClickUp task. Binds POST /api/v2/task/{task_id}/field/{field_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/task/[^/]+/field/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'clickup.search_docs',
    effect: 'read',
    description:
      'Search ClickUp Docs in a workspace. Binds GET /api/v2/workspaces/{workspace_id}/docs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v2/workspaces/[^/]+/docs$' },
    ],
  }),
];
