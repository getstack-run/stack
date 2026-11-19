import { z } from 'zod';
import { defineIntent } from './types.js';

// Contentful Content Management API — https://www.contentful.com/developers/docs/references/content-management-api/.
// All calls go to api.contentful.com/spaces/{space_id}/environments/{env}/….
// Space and environment IDs are allowlisted on the path.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

export const contentfulIntents = [
  defineIntent({
    name: 'contentful.list_entries',
    effect: 'read',
    description:
      'List entries in a specific space + environment. Binds GET /spaces/{space_id}/environments/{env}/entries to the declared space allowlist.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.create_entry',
    effect: 'write',
    description:
      'Create a new entry in a specific space + environment. Binds POST /spaces/{space_id}/environments/{env}/entries.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.update_entry',
    effect: 'write',
    description:
      'Update a specific entry. Binds PUT /spaces/{space_id}/environments/{env}/entries/{entry_id}.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.delete_entry',
    effect: 'destructive',
    description:
      'Delete a specific entry. Binds DELETE /spaces/{space_id}/environments/{env}/entries/{entry_id}. Destructive.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.publish_entry',
    effect: 'write',
    description:
      'Publish a specific entry. Binds PUT /spaces/{space_id}/environments/{env}/entries/{entry_id}/published.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries/[^/]+/published$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.unpublish_entry',
    effect: 'destructive',
    description:
      'Unpublish a specific entry. Binds DELETE /spaces/{space_id}/environments/{env}/entries/{entry_id}/published.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries/[^/]+/published$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.archive_entry',
    effect: 'write',
    description:
      'Archive a specific entry. Binds PUT /spaces/{space_id}/environments/{env}/entries/{entry_id}/archived.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries/[^/]+/archived$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.unarchive_entry',
    effect: 'destructive',
    description:
      'Restore an archived entry. Binds DELETE /spaces/{space_id}/environments/{env}/entries/{entry_id}/archived.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/entries/[^/]+/archived$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.create_asset',
    effect: 'write',
    description:
      'Create a new asset. Binds POST /spaces/{space_id}/environments/{env}/assets.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/assets$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.process_asset',
    effect: 'write',
    description:
      'Trigger processing for an uploaded asset in a specific locale. Binds PUT /spaces/{space_id}/environments/{env}/assets/{asset_id}/files/{locale}/process.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/assets/[^/]+/files/[^/]+/process$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.publish_asset',
    effect: 'write',
    description:
      'Publish an asset. Binds PUT /spaces/{space_id}/environments/{env}/assets/{asset_id}/published.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/assets/[^/]+/published$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.unpublish_asset',
    effect: 'destructive',
    description:
      'Unpublish an asset. Binds DELETE /spaces/{space_id}/environments/{env}/assets/{asset_id}/published.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/assets/[^/]+/published$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.delete_asset',
    effect: 'destructive',
    description:
      'Delete an asset. Binds DELETE /spaces/{space_id}/environments/{env}/assets/{asset_id}. Destructive.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/assets/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.list_content_types',
    effect: 'read',
    description:
      'List content types in a specific space + environment. Binds GET /spaces/{space_id}/environments/{env}/content_types.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/content_types$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.create_content_type',
    effect: 'write',
    description:
      'Create a new content type. Binds PUT /spaces/{space_id}/environments/{env}/content_types/{id}.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/content_types/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.activate_content_type',
    effect: 'write',
    description:
      'Activate a content type. Binds PUT /spaces/{space_id}/environments/{env}/content_types/{id}/published.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/content_types/[^/]+/published$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.deactivate_content_type',
    effect: 'destructive',
    description:
      'Deactivate a content type. Binds DELETE /spaces/{space_id}/environments/{env}/content_types/{id}/published.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/content_types/[^/]+/published$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.list_locales',
    effect: 'read',
    description:
      'List configured locales for a space. Binds GET /spaces/{space_id}/environments/{env}/locales.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/environments/[^/]+/locales$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.create_webhook',
    effect: 'write',
    description:
      'Create a webhook definition on a space. Binds POST /spaces/{space_id}/webhook_definitions.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/webhook_definitions$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.list_webhooks',
    effect: 'read',
    description:
      'List webhook definitions on a space. Binds GET /spaces/{space_id}/webhook_definitions.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/webhook_definitions$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.list_scheduled_actions',
    effect: 'read',
    description:
      'List scheduled publish/unpublish actions in a space. Binds GET /spaces/{space_id}/scheduled_actions.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/scheduled_actions$` },
      ];
    },
  }),

  defineIntent({
    name: 'contentful.create_scheduled_action',
    effect: 'write',
    description:
      'Schedule a future publish or unpublish action. Binds POST /spaces/{space_id}/scheduled_actions.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/spaces/${alt(list)}/scheduled_actions$` },
      ];
    },
  }),
];
