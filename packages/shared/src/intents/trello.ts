import { z } from 'zod';
import { defineIntent } from './types.js';

// Trello REST API — https://developer.atlassian.com/cloud/trello/rest/.
// Base URL is api.trello.com/1/…. Resources identified by 24-char ObjectId
// hashes. Scope via board_id / list_id via anchored pathname regex.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function altRegex(ids: IdList): string {
  const list = toList(ids);
  const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  return list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
}

export const trelloIntents = [
  defineIntent({
    name: 'trello.list_boards',
    effect: 'read',
    description:
      'List Trello boards accessible to the user. Binds GET /1/members/me/boards.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/1/members/me/boards' },
    ],
  }),

  defineIntent({
    name: 'trello.create_board',
    effect: 'write',
    description:
      'Create a new Trello board. Binds POST /1/boards.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/1/boards' },
    ],
  }),

  defineIntent({
    name: 'trello.read_board',
    effect: 'read',
    description:
      'Read a specific Trello board. Binds GET /1/boards/{board_id} to the declared board IDs.',
    params: z.object({ board_id: idList }),
    expand: ({ board_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/1/boards/${altRegex(board_id)}$` },
    ],
  }),

  defineIntent({
    name: 'trello.update_board',
    effect: 'write',
    description:
      'Update a Trello board. Binds PUT /1/boards/{board_id} to the declared board IDs.',
    params: z.object({ board_id: idList }),
    expand: ({ board_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: `^/1/boards/${altRegex(board_id)}$` },
    ],
  }),

  defineIntent({
    name: 'trello.list_lists_on_board',
    effect: 'read',
    description:
      'List lists on a Trello board. Binds GET /1/boards/{board_id}/lists to the declared board IDs.',
    params: z.object({ board_id: idList }),
    expand: ({ board_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/1/boards/${altRegex(board_id)}/lists$` },
    ],
  }),

  defineIntent({
    name: 'trello.create_list',
    effect: 'write',
    description:
      'Create a list on a Trello board. Binds POST /1/lists (body.idBoard pinned to the allowlist).',
    params: z.object({ board_id: idList }),
    expand: ({ board_id }) => {
      const list = toList(board_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/1/lists' },
        list.length === 1
          ? { path: 'body.idBoard', op: 'eq', value: list[0]! }
          : { path: 'body.idBoard', op: 'in', value: list },
      ];
    },
  }),

  defineIntent({
    name: 'trello.create_card',
    effect: 'write',
    description:
      'Create a Trello card in a specific list. Binds POST /1/cards (query.idList pinned to the allowlist).',
    params: z.object({ list_id: idList }),
    expand: ({ list_id }) => {
      const list = toList(list_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/1/cards' },
        list.length === 1
          ? { path: 'query.idList', op: 'eq', value: list[0]! }
          : { path: 'query.idList', op: 'in', value: list },
      ];
    },
  }),

  defineIntent({
    name: 'trello.update_card',
    effect: 'write',
    description:
      'Update a Trello card. Binds PUT /1/cards/{card_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/1/cards/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'trello.archive_card',
    effect: 'write',
    description:
      'Archive a Trello card by setting closed=true. Binds PUT /1/cards/{card_id}/closed.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/1/cards/[^/]+/closed$' },
    ],
  }),

  defineIntent({
    name: 'trello.delete_card',
    effect: 'destructive',
    description:
      'Delete a Trello card. Binds DELETE /1/cards/{card_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/1/cards/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'trello.move_card',
    effect: 'write',
    description:
      'Move a Trello card by updating its idList. Binds PUT /1/cards/{card_id}/idList.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/1/cards/[^/]+/idList$' },
    ],
  }),

  defineIntent({
    name: 'trello.comment_card',
    effect: 'write',
    description:
      'Post a comment on a Trello card. Binds POST /1/cards/{card_id}/actions/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/1/cards/[^/]+/actions/comments$' },
    ],
  }),

  defineIntent({
    name: 'trello.add_checklist',
    effect: 'write',
    description:
      'Attach a checklist to a Trello card. Binds POST /1/cards/{card_id}/checklists.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/1/cards/[^/]+/checklists$' },
    ],
  }),

  defineIntent({
    name: 'trello.add_checklist_item',
    effect: 'write',
    description:
      'Add a checkItem to a Trello checklist. Binds POST /1/checklists/{checklist_id}/checkItems.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/1/checklists/[^/]+/checkItems$' },
    ],
  }),

  defineIntent({
    name: 'trello.add_attachment',
    effect: 'write',
    description:
      'Add an attachment to a Trello card. Binds POST /1/cards/{card_id}/attachments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/1/cards/[^/]+/attachments$' },
    ],
  }),

  defineIntent({
    name: 'trello.create_label',
    effect: 'write',
    description:
      'Create a label on a Trello board. Binds POST /1/labels (body.idBoard pinned to the allowlist).',
    params: z.object({ board_id: idList }),
    expand: ({ board_id }) => {
      const list = toList(board_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'eq', value: '/1/labels' },
        list.length === 1
          ? { path: 'body.idBoard', op: 'eq', value: list[0]! }
          : { path: 'body.idBoard', op: 'in', value: list },
      ];
    },
  }),

  defineIntent({
    name: 'trello.list_members_on_board',
    effect: 'read',
    description:
      'List members on a Trello board. Binds GET /1/boards/{board_id}/members to the declared board IDs.',
    params: z.object({ board_id: idList }),
    expand: ({ board_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/1/boards/${altRegex(board_id)}/members$` },
    ],
  }),

  defineIntent({
    name: 'trello.create_webhook',
    effect: 'write',
    description:
      'Register a Trello webhook. Binds POST /1/webhooks.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/1/webhooks' },
    ],
  }),

  defineIntent({
    name: 'trello.list_custom_fields',
    effect: 'read',
    description:
      'List custom field definitions on a Trello board. Binds GET /1/boards/{board_id}/customFields to the declared board IDs.',
    params: z.object({ board_id: idList }),
    expand: ({ board_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `^/1/boards/${altRegex(board_id)}/customFields$` },
    ],
  }),

  defineIntent({
    name: 'trello.search',
    effect: 'read',
    description:
      'Run a Trello cross-resource search. Binds GET /1/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/1/search' },
    ],
  }),
];
