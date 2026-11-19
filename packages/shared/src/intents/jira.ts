import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Jira Cloud REST API v3 — https://developer.atlassian.com/cloud/jira/platform/rest/v3/.
// Calls go through the instance URL, then /rest/api/3/…. Intents gate on
// method + pathname + (for create_issue) the project.key in the body.

const keyList = z.union([
  z.string().min(1).max(64),
  z.array(z.string().min(1).max(64)).min(1),
]);
type KeyList = z.infer<typeof keyList>;
const toList = (v: KeyList): string[] => (Array.isArray(v) ? v : [v]);

function eqOrIn(path: string, keys: KeyList): Constraint {
  const list = toList(keys);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

export const jiraIntents = [
  defineIntent({
    name: 'jira.create_issue',
    effect: 'write',
    description:
      'Create a Jira issue in specific projects. Binds POST /rest/api/3/issue with body.fields.project.key pinned to the allowlist.',
    params: z.object({ project_key: keyList }),
    expand: ({ project_key }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/issue' },
      eqOrIn('body.fields.project.key', project_key),
    ],
  }),

  defineIntent({
    name: 'jira.transition_issue',
    effect: 'write',
    description:
      'Transition an existing Jira issue through workflow states. Binds POST /rest/api/3/issue/{key}/transitions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: '^/rest/api/3/issue/[^/]+/transitions$',
      },
    ],
  }),

  defineIntent({
    name: 'jira.comment_issue',
    effect: 'write',
    description:
      'Add a comment to a Jira issue. Binds POST /rest/api/3/issue/{key}/comment.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/comment$' },
    ],
  }),

  defineIntent({
    name: 'jira.read_issue',
    effect: 'read',
    description:
      'Read-only access to a Jira issue. Binds GET /rest/api/3/issue/{key}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'jira.update_issue',
    effect: 'write',
    description:
      'Update a Jira issue in place. Binds PUT /rest/api/3/issue/{key}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'jira.delete_issue',
    effect: 'destructive',
    description:
      'Delete a Jira issue. Binds DELETE /rest/api/3/issue/{key}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'jira.list_transitions',
    effect: 'read',
    description:
      'List available workflow transitions for a Jira issue. Binds GET /rest/api/3/issue/{key}/transitions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/transitions$' },
    ],
  }),

  defineIntent({
    name: 'jira.add_worklog',
    effect: 'write',
    description:
      'Record a worklog entry on a Jira issue. Binds POST /rest/api/3/issue/{key}/worklog.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/worklog$' },
    ],
  }),

  defineIntent({
    name: 'jira.list_worklogs',
    effect: 'read',
    description:
      'List worklogs for a Jira issue. Binds GET /rest/api/3/issue/{key}/worklog.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/worklog$' },
    ],
  }),

  defineIntent({
    name: 'jira.add_attachment',
    effect: 'write',
    description:
      'Attach a file to a Jira issue. Binds POST /rest/api/3/issue/{key}/attachments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/attachments$' },
    ],
  }),

  defineIntent({
    name: 'jira.list_comments',
    effect: 'read',
    description:
      'List comments on a Jira issue. Binds GET /rest/api/3/issue/{key}/comment.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/comment$' },
    ],
  }),

  defineIntent({
    name: 'jira.update_comment',
    effect: 'write',
    description:
      'Edit a comment on a Jira issue. Binds PUT /rest/api/3/issue/{key}/comment/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/comment/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'jira.delete_comment',
    effect: 'destructive',
    description:
      'Delete a comment on a Jira issue. Binds DELETE /rest/api/3/issue/{key}/comment/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/api/3/issue/[^/]+/comment/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'jira.search_issues',
    effect: 'read',
    description:
      'Run a JQL search for Jira issues. Binds POST /rest/api/3/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/search' },
    ],
  }),

  defineIntent({
    name: 'jira.list_projects',
    effect: 'read',
    description:
      'List or search Jira projects. Binds GET /rest/api/3/project/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/project/search' },
    ],
  }),

  defineIntent({
    name: 'jira.create_project',
    effect: 'write',
    description:
      'Create a new Jira project. Binds POST /rest/api/3/project.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/project' },
    ],
  }),

  defineIntent({
    name: 'jira.list_versions',
    effect: 'read',
    description:
      'List versions for a Jira project. Binds GET /rest/api/3/project/{key}/versions.',
    params: z.object({ project_key: keyList }),
    expand: ({ project_key }) => {
      const list = toList(project_key);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/rest/api/3/project/${alt}/versions$` },
      ];
    },
  }),

  defineIntent({
    name: 'jira.list_components',
    effect: 'read',
    description:
      'List components for a Jira project. Binds GET /rest/api/3/project/{key}/components.',
    params: z.object({ project_key: keyList }),
    expand: ({ project_key }) => {
      const list = toList(project_key);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/rest/api/3/project/${alt}/components$` },
      ];
    },
  }),

  defineIntent({
    name: 'jira.list_boards',
    effect: 'read',
    description:
      'List Jira agile boards (scrum/kanban). Binds GET /rest/agile/1.0/board.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/agile/1.0/board' },
    ],
  }),

  defineIntent({
    name: 'jira.list_sprints',
    effect: 'read',
    description:
      'List sprints for a Jira agile board. Binds GET /rest/agile/1.0/board/{boardId}/sprint.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/agile/1.0/board/[^/]+/sprint$' },
    ],
  }),

  defineIntent({
    name: 'jira.create_sprint',
    effect: 'write',
    description:
      'Create a new Jira sprint. Binds POST /rest/agile/1.0/sprint.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/agile/1.0/sprint' },
    ],
  }),

  defineIntent({
    name: 'jira.move_issues_to_sprint',
    effect: 'write',
    description:
      'Move issues into a Jira sprint. Binds POST /rest/agile/1.0/sprint/{sprintId}/issue.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/agile/1.0/sprint/[^/]+/issue$' },
    ],
  }),

  defineIntent({
    name: 'jira.create_issue_link',
    effect: 'write',
    description:
      'Create a link between two Jira issues. Binds POST /rest/api/3/issueLink.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/issueLink' },
    ],
  }),

  defineIntent({
    name: 'jira.list_users',
    effect: 'read',
    description:
      'Search for Jira users. Binds GET /rest/api/3/user/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/user/search' },
    ],
  }),

  defineIntent({
    name: 'jira.list_filters',
    effect: 'read',
    description:
      'List Jira saved filters. Binds GET /rest/api/3/filter/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/filter/search' },
    ],
  }),

  defineIntent({
    name: 'jira.list_dashboards',
    effect: 'read',
    description:
      'List Jira dashboards. Binds GET /rest/api/3/dashboard.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/api/3/dashboard' },
    ],
  }),
];
