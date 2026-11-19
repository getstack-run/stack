import { z } from 'zod';
import { defineIntent } from './types.js';

// Figma REST API — https://www.figma.com/developers/api. Host is
// api.figma.com and all paths start with /v1/. File and team IDs
// are allowlisted where present on the path.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

export const figmaIntents = [
  defineIntent({
    name: 'figma.get_file',
    effect: 'read',
    description:
      'Read the full document tree for a specific Figma file. Binds GET /v1/files/{file_key} to the declared file allowlist.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.get_file_nodes',
    effect: 'read',
    description:
      'Fetch specific nodes from a Figma file. Binds GET /v1/files/{file_key}/nodes to the declared file allowlist.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/nodes$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.render_images',
    effect: 'read',
    description:
      'Render images of nodes in a specific file. Binds GET /v1/images/{file_key} to the declared file allowlist.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/images/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.list_file_versions',
    effect: 'read',
    description:
      'List version history for a specific Figma file. Binds GET /v1/files/{file_key}/versions.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/versions$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.list_file_comments',
    effect: 'read',
    description:
      'List comments on a specific Figma file. Binds GET /v1/files/{file_key}/comments.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/comments$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.post_file_comment',
    effect: 'write',
    description:
      'Post a new comment to a specific Figma file. Binds POST /v1/files/{file_key}/comments.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/comments$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.delete_file_comment',
    effect: 'destructive',
    description:
      'Delete a comment from a specific Figma file. Binds DELETE /v1/files/{file_key}/comments/{comment_id}. Destructive.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/comments/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.list_comment_reactions',
    effect: 'read',
    description:
      'List reactions on a specific comment. Binds GET /v1/files/{file_key}/comments/{comment_id}/reactions.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/comments/[^/]+/reactions$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.post_comment_reaction',
    effect: 'write',
    description:
      'Add a reaction to a specific comment. Binds POST /v1/files/{file_key}/comments/{comment_id}/reactions.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/comments/[^/]+/reactions$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.list_team_projects',
    effect: 'read',
    description:
      'List projects inside a specific team. Binds GET /v1/teams/{team_id}/projects.',
    params: z.object({ team_id: idList }),
    expand: ({ team_id }) => {
      const list = toList(team_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/teams/${alt(list)}/projects$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.list_project_files',
    effect: 'read',
    description:
      'List files within a specific project. Binds GET /v1/projects/{project_id}/files.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/projects/[^/]+/files$' },
    ],
  }),

  defineIntent({
    name: 'figma.list_team_components',
    effect: 'read',
    description:
      'List components published by a specific team. Binds GET /v1/teams/{team_id}/components.',
    params: z.object({ team_id: idList }),
    expand: ({ team_id }) => {
      const list = toList(team_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/teams/${alt(list)}/components$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.list_team_styles',
    effect: 'read',
    description:
      'List styles published by a specific team. Binds GET /v1/teams/{team_id}/styles.',
    params: z.object({ team_id: idList }),
    expand: ({ team_id }) => {
      const list = toList(team_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/teams/${alt(list)}/styles$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.list_webhooks',
    effect: 'read',
    description:
      'List webhooks registered for a specific team. Binds GET /v2/teams/{team_id}/webhooks.',
    params: z.object({ team_id: idList }),
    expand: ({ team_id }) => {
      const list = toList(team_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/teams/${alt(list)}/webhooks$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.create_webhook',
    effect: 'write',
    description:
      'Create a new webhook. Binds POST /v2/webhooks (team binding is on the body; scope via body.team_id if pinning is required).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/webhooks' },
    ],
  }),

  defineIntent({
    name: 'figma.update_webhook',
    effect: 'write',
    description:
      'Update an existing webhook. Binds PUT /v2/webhooks/{webhook_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/webhooks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'figma.delete_webhook',
    effect: 'destructive',
    description:
      'Delete a webhook. Binds DELETE /v2/webhooks/{webhook_id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/webhooks/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'figma.list_webhook_requests',
    effect: 'read',
    description:
      'List recent delivery attempts for a webhook. Binds GET /v2/webhooks/{webhook_id}/requests.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/webhooks/[^/]+/requests$' },
    ],
  }),

  defineIntent({
    name: 'figma.list_dev_resources',
    effect: 'read',
    description:
      'List dev resources associated with a specific file. Binds GET /v1/files/{file_key}/dev_resources.',
    params: z.object({ file_key: idList }),
    expand: ({ file_key }) => {
      const list = toList(file_key);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/files/${alt(list)}/dev_resources$` },
      ];
    },
  }),

  defineIntent({
    name: 'figma.get_activity_logs',
    effect: 'read',
    description:
      'Read activity log entries for a workspace. Binds GET /v1/activity_logs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/activity_logs' },
    ],
  }),
];
