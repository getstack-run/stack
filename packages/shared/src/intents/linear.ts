import { z } from 'zod';
import { defineIntent } from './types.js';

// Linear API — https://developers.linear.app/docs/graphql. Single GraphQL
// endpoint (POST /graphql) for everything. Intents gate on
// body.operationName and (where useful) body.query via anchored regex to
// catch clients that omit operationName. Binding deeper into
// body.variables is limited at v1 — use raw constraints for per-operation
// variable pinning.

// Anchored GraphQL operation regex. Matches either `mutation Foo(` or
// `query Foo(` / `query Foo {` / `mutation Foo {` near the start of the
// document, tolerating leading whitespace.
const opMatches = (op: 'query' | 'mutation', name: string): string =>
  `^\\s*${op}\\s+${name}[\\s({]`;

export const linearIntents = [
  defineIntent({
    name: 'linear.create_issue',
    effect: 'write',
    description:
      'Create a Linear issue via GraphQL. Binds POST /graphql to body.operationName = "IssueCreate". Note: team / project binding via variables is not enforced at this intent layer.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'IssueCreate' },
    ],
  }),

  defineIntent({
    name: 'linear.update_issue',
    effect: 'write',
    description:
      'Update an existing Linear issue via GraphQL. Binds POST /graphql to body.operationName = "IssueUpdate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'IssueUpdate' },
    ],
  }),

  defineIntent({
    name: 'linear.comment_issue',
    effect: 'write',
    description:
      'Create a comment on a Linear issue via GraphQL. Binds POST /graphql to body.operationName = "CommentCreate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'CommentCreate' },
    ],
  }),

  defineIntent({
    name: 'linear.read_only',
    effect: 'read',
    description:
      'Allow read-only GraphQL queries. Binds POST /graphql to common read operation names (Issue, Team, Project, Viewer…). Declarative allowlist; if the agent runs a different read op it will be denied.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      {
        path: 'body.operationName',
        op: 'in',
        value: ['Issue', 'Issues', 'Team', 'Teams', 'Project', 'Projects', 'Viewer', 'Organization'],
      },
    ],
  }),

  defineIntent({
    name: 'linear.archive_issue',
    effect: 'write',
    description:
      'Archive a Linear issue via GraphQL. Binds POST /graphql to body.operationName = "IssueArchive".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'IssueArchive' },
    ],
  }),

  defineIntent({
    name: 'linear.delete_issue',
    effect: 'destructive',
    description:
      'Delete a Linear issue via GraphQL. Binds POST /graphql to body.operationName = "IssueDelete".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'IssueDelete' },
    ],
  }),

  defineIntent({
    name: 'linear.list_issue_comments',
    effect: 'read',
    description:
      'List comments on a Linear issue via GraphQL. Binds POST /graphql to body.query matching the Comments query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.query', op: 'matches', value: opMatches('query', 'Comments') },
    ],
  }),

  defineIntent({
    name: 'linear.update_comment',
    effect: 'write',
    description:
      'Update a Linear issue comment via GraphQL. Binds POST /graphql to body.operationName = "CommentUpdate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'CommentUpdate' },
    ],
  }),

  defineIntent({
    name: 'linear.delete_comment',
    effect: 'destructive',
    description:
      'Delete a Linear comment via GraphQL. Binds POST /graphql to body.operationName = "CommentDelete".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'CommentDelete' },
    ],
  }),

  defineIntent({
    name: 'linear.create_project',
    effect: 'write',
    description:
      'Create a Linear project via GraphQL. Binds POST /graphql to body.operationName = "ProjectCreate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'ProjectCreate' },
    ],
  }),

  defineIntent({
    name: 'linear.update_project',
    effect: 'write',
    description:
      'Update an existing Linear project via GraphQL. Binds POST /graphql to body.operationName = "ProjectUpdate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'ProjectUpdate' },
    ],
  }),

  defineIntent({
    name: 'linear.create_cycle',
    effect: 'write',
    description:
      'Create a Linear cycle (sprint) via GraphQL. Binds POST /graphql to body.operationName = "CycleCreate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'CycleCreate' },
    ],
  }),

  defineIntent({
    name: 'linear.list_teams',
    effect: 'read',
    description:
      'List Linear teams via GraphQL. Binds POST /graphql to body.query matching the Teams query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.query', op: 'matches', value: opMatches('query', 'Teams') },
    ],
  }),

  defineIntent({
    name: 'linear.list_users',
    effect: 'read',
    description:
      'List Linear users via GraphQL. Binds POST /graphql to body.query matching the Users query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.query', op: 'matches', value: opMatches('query', 'Users') },
    ],
  }),

  defineIntent({
    name: 'linear.create_label',
    effect: 'write',
    description:
      'Create a Linear issue label via GraphQL. Binds POST /graphql to body.operationName = "IssueLabelCreate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'IssueLabelCreate' },
    ],
  }),

  defineIntent({
    name: 'linear.attach_label',
    effect: 'write',
    description:
      'Attach a label to a Linear issue via GraphQL. Binds POST /graphql to body.operationName = "IssueAddLabel".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'IssueAddLabel' },
    ],
  }),

  defineIntent({
    name: 'linear.list_workflow_states',
    effect: 'read',
    description:
      'List Linear workflow states for a team via GraphQL. Binds POST /graphql to body.query matching the WorkflowStates query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.query', op: 'matches', value: opMatches('query', 'WorkflowStates') },
    ],
  }),

  defineIntent({
    name: 'linear.list_priorities',
    effect: 'read',
    description:
      'List Linear issue priority values via GraphQL. Binds POST /graphql to body.query matching the IssuePriorityValues query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.query', op: 'matches', value: opMatches('query', 'IssuePriorityValues') },
    ],
  }),

  defineIntent({
    name: 'linear.list_integrations',
    effect: 'read',
    description:
      'List Linear workspace integrations via GraphQL. Binds POST /graphql to body.query matching the Integrations query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.query', op: 'matches', value: opMatches('query', 'Integrations') },
    ],
  }),

  defineIntent({
    name: 'linear.attachment_create',
    effect: 'write',
    description:
      'Create an attachment on a Linear issue via GraphQL. Binds POST /graphql to body.operationName = "AttachmentCreate".',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/graphql' },
      { path: 'body.operationName', op: 'eq', value: 'AttachmentCreate' },
    ],
  }),
];
