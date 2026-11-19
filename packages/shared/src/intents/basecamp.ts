import { z } from 'zod';
import { defineIntent } from './types.js';

// Basecamp 4 API — https://github.com/basecamp/bc3-api. Base URL is
// 3.basecampapi.com/{account_id}/…. Resources live under projects (known
// as "buckets"). Pathname constraints anchor on /{account_id}/… with
// numeric account/project IDs.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function altRegex(ids: IdList): string {
  const list = toList(ids);
  const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
}

export const basecampIntents = [
  defineIntent({
    name: 'basecamp.list_projects',
    effect: 'read',
    description:
      'List Basecamp projects in the account. Binds GET /{account_id}/projects.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/[^/]+/projects\\.json$' },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_project',
    effect: 'write',
    description:
      'Create a new Basecamp project. Binds POST /{account_id}/projects.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/[^/]+/projects\\.json$' },
    ],
  }),

  defineIntent({
    name: 'basecamp.update_project',
    effect: 'write',
    description:
      'Update a Basecamp project. Binds PUT /{account_id}/projects/{project_id}.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: `^/[^/]+/projects/${altRegex(project_id)}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'basecamp.trash_project',
    effect: 'destructive',
    description:
      'Trash a Basecamp project. Binds DELETE /{account_id}/projects/{project_id}.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: `^/[^/]+/projects/${altRegex(project_id)}\\.json$` },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_todolist',
    effect: 'write',
    description:
      'Create a todolist inside a Basecamp project. Binds POST /{account_id}/buckets/{project_id}/todosets/{set_id}/todolists.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/todosets/[^/]+/todolists\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.list_todolists',
    effect: 'read',
    description:
      'List todolists in a Basecamp todoset. Binds GET /{account_id}/buckets/{project_id}/todosets/{set_id}/todolists.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/todosets/[^/]+/todolists\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_todo',
    effect: 'write',
    description:
      'Create a todo within a Basecamp todolist. Binds POST /{account_id}/buckets/{project_id}/todolists/{list_id}/todos.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/todolists/[^/]+/todos\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.update_todo',
    effect: 'write',
    description:
      'Update a Basecamp todo item. Binds PUT /{account_id}/buckets/{project_id}/todos/{todo_id}.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/todos/[^/]+\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.complete_todo',
    effect: 'write',
    description:
      'Mark a Basecamp todo as complete. Binds POST /{account_id}/buckets/{project_id}/todos/{todo_id}/completion.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/todos/[^/]+/completion\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.list_messages',
    effect: 'read',
    description:
      'List messages in a Basecamp message board. Binds GET /{account_id}/buckets/{project_id}/message_boards/{board_id}/messages.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/message_boards/[^/]+/messages\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_message',
    effect: 'write',
    description:
      'Post a message to a Basecamp message board. Binds POST /{account_id}/buckets/{project_id}/message_boards/{board_id}/messages.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/message_boards/[^/]+/messages\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.update_message',
    effect: 'write',
    description:
      'Edit a Basecamp message. Binds PUT /{account_id}/buckets/{project_id}/messages/{message_id}.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/messages/[^/]+\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.post_to_campfire',
    effect: 'write',
    description:
      'Post a line to a Basecamp campfire chat. Binds POST /{account_id}/buckets/{project_id}/chats/{chat_id}/lines.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/chats/[^/]+/lines\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_schedule_entry',
    effect: 'write',
    description:
      'Create a Basecamp schedule entry. Binds POST /{account_id}/buckets/{project_id}/schedules/{schedule_id}/entries.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/schedules/[^/]+/entries\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.list_people',
    effect: 'read',
    description:
      'List people with access to the Basecamp account. Binds GET /{account_id}/people.json.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/[^/]+/people\\.json$' },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_upload',
    effect: 'write',
    description:
      'Upload a file into a Basecamp project vault. Binds POST /{account_id}/buckets/{project_id}/vaults/{vault_id}/uploads.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/vaults/[^/]+/uploads\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_document',
    effect: 'write',
    description:
      'Create a Basecamp document in a project vault. Binds POST /{account_id}/buckets/{project_id}/vaults/{vault_id}/documents.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/vaults/[^/]+/documents\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.create_comment',
    effect: 'write',
    description:
      'Post a comment on a Basecamp recording (todo, message, doc, etc). Binds POST /{account_id}/buckets/{project_id}/recordings/{recording_id}/comments.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/recordings/[^/]+/comments\\.json$`,
      },
    ],
  }),

  defineIntent({
    name: 'basecamp.list_comments',
    effect: 'read',
    description:
      'List comments on a Basecamp recording. Binds GET /{account_id}/buckets/{project_id}/recordings/{recording_id}/comments.json.',
    params: z.object({ project_id: idList }),
    expand: ({ project_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: `^/[^/]+/buckets/${altRegex(project_id)}/recordings/[^/]+/comments\\.json$`,
      },
    ],
  }),
];
