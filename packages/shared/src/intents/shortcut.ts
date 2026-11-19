import { z } from 'zod';
import { defineIntent } from './types.js';

// Shortcut REST API v3 — https://developer.shortcut.com/api/rest/v3. Base
// URL is api.app.shortcut.com/api/v3/…. Resources are identified by
// numeric IDs. Most create endpoints are workspace-global, so scoping is
// via body.project_id or body.team_id (group_id) where supported.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1), z.number()]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => {
  if (Array.isArray(v)) return v;
  return [String(v)];
};

export const shortcutIntents = [
  defineIntent({
    name: 'shortcut.create_story',
    effect: 'write',
    description:
      'Create a Shortcut story. Binds POST /api/v3/stories, optionally pinned to a project via body.project_id.',
    params: z.object({ project_id: idList.optional() }),
    expand: ({ project_id }) => {
      const base: import('../schemas/passport.js').Constraint[] = [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/api/v3/stories' },
      ];
      if (project_id !== undefined) {
        const list = toList(project_id);
        base.push(
          list.length === 1
            ? { path: 'body.project_id', op: 'eq', value: list[0]! }
            : { path: 'body.project_id', op: 'in', value: list },
        );
      }
      return base;
    },
  }),

  defineIntent({
    name: 'shortcut.update_story',
    effect: 'write',
    description:
      'Update a Shortcut story. Binds PUT /api/v3/stories/{story_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/stories/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'shortcut.delete_story',
    effect: 'destructive',
    description:
      'Delete a Shortcut story. Binds DELETE /api/v3/stories/{story_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/stories/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'shortcut.read_story',
    effect: 'read',
    description:
      'Read a Shortcut story. Binds GET /api/v3/stories/{story_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/stories/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'shortcut.search_stories',
    effect: 'read',
    description:
      'Search Shortcut stories. Binds GET /api/v3/search/stories.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/search/stories' },
    ],
  }),

  defineIntent({
    name: 'shortcut.create_story_comment',
    effect: 'write',
    description:
      'Create a comment on a Shortcut story. Binds POST /api/v3/stories/{story_id}/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/stories/[^/]+/comments$' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_story_comments',
    effect: 'read',
    description:
      'List comments on a Shortcut story. Binds GET /api/v3/stories/{story_id}/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/stories/[^/]+/comments$' },
    ],
  }),

  defineIntent({
    name: 'shortcut.create_story_task',
    effect: 'write',
    description:
      'Add a task to a Shortcut story. Binds POST /api/v3/stories/{story_id}/tasks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/stories/[^/]+/tasks$' },
    ],
  }),

  defineIntent({
    name: 'shortcut.create_epic',
    effect: 'write',
    description:
      'Create a Shortcut epic. Binds POST /api/v3/epics.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/epics' },
    ],
  }),

  defineIntent({
    name: 'shortcut.update_epic',
    effect: 'write',
    description:
      'Update a Shortcut epic. Binds PUT /api/v3/epics/{epic_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v3/epics/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_epics',
    effect: 'read',
    description:
      'List Shortcut epics. Binds GET /api/v3/epics.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/epics' },
    ],
  }),

  defineIntent({
    name: 'shortcut.create_iteration',
    effect: 'write',
    description:
      'Create a Shortcut iteration. Binds POST /api/v3/iterations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/iterations' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_iterations',
    effect: 'read',
    description:
      'List Shortcut iterations. Binds GET /api/v3/iterations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/iterations' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_workflows',
    effect: 'read',
    description:
      'List Shortcut workflows and their states. Binds GET /api/v3/workflows.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/workflows' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_members',
    effect: 'read',
    description:
      'List Shortcut workspace members. Binds GET /api/v3/members.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/members' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_groups',
    effect: 'read',
    description:
      'List Shortcut teams (groups). Binds GET /api/v3/groups.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/groups' },
    ],
  }),

  defineIntent({
    name: 'shortcut.create_label',
    effect: 'write',
    description:
      'Create a Shortcut label. Binds POST /api/v3/labels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/labels' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_labels',
    effect: 'read',
    description:
      'List Shortcut labels. Binds GET /api/v3/labels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/labels' },
    ],
  }),

  defineIntent({
    name: 'shortcut.create_linked_file',
    effect: 'write',
    description:
      'Create a linked file entry in Shortcut. Binds POST /api/v3/linked-files.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/linked-files' },
    ],
  }),

  defineIntent({
    name: 'shortcut.list_projects',
    effect: 'read',
    description:
      'List Shortcut projects. Binds GET /api/v3/projects.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v3/projects' },
    ],
  }),
];
