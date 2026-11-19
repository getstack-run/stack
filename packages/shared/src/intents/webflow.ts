import { z } from 'zod';
import { defineIntent } from './types.js';

// Webflow Data API v2 — https://developers.webflow.com/data/reference.
// All calls go to api.webflow.com/v2/…. Most ops are scoped under a
// specific siteId which is allowlisted on the path.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

export const webflowIntents = [
  defineIntent({
    name: 'webflow.list_sites',
    effect: 'read',
    description:
      'List sites accessible to the token. Binds GET /v2/sites.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/sites' },
    ],
  }),

  defineIntent({
    name: 'webflow.get_site',
    effect: 'read',
    description:
      'Read a specific Webflow site. Binds GET /v2/sites/{site_id} to the declared site allowlist.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.publish_site',
    effect: 'write',
    description:
      'Publish a specific Webflow site. Binds POST /v2/sites/{site_id}/publish to the declared site allowlist.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/publish$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_collections',
    effect: 'read',
    description:
      'List collections on a specific site. Binds GET /v2/sites/{site_id}/collections.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/collections$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.create_collection',
    effect: 'write',
    description:
      'Create a new collection on a specific site. Binds POST /v2/sites/{site_id}/collections.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/collections$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_collection_items',
    effect: 'read',
    description:
      'List items in a specific collection. Binds GET /v2/collections/{collection_id}/items.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/collections/[^/]+/items$' },
    ],
  }),

  defineIntent({
    name: 'webflow.create_collection_item',
    effect: 'write',
    description:
      'Create an item in a specific collection. Binds POST /v2/collections/{collection_id}/items.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/collections/[^/]+/items$' },
    ],
  }),

  defineIntent({
    name: 'webflow.update_collection_item',
    effect: 'write',
    description:
      'Update a specific collection item. Binds PATCH /v2/collections/{collection_id}/items/{item_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/collections/[^/]+/items/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'webflow.delete_collection_item',
    effect: 'destructive',
    description:
      'Delete a specific collection item. Binds DELETE /v2/collections/{collection_id}/items/{item_id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/collections/[^/]+/items/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'webflow.publish_collection_items',
    effect: 'write',
    description:
      'Publish staged collection items live. Binds POST /v2/collections/{collection_id}/items/publish.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/collections/[^/]+/items/publish$' },
    ],
  }),

  defineIntent({
    name: 'webflow.list_pages',
    effect: 'read',
    description:
      'List pages on a specific site. Binds GET /v2/sites/{site_id}/pages.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/pages$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.update_page',
    effect: 'write',
    description:
      'Update metadata on a specific page. Binds PUT /v2/pages/{page_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/pages/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'webflow.list_site_custom_code',
    effect: 'read',
    description:
      'List custom code scripts attached to a specific site. Binds GET /v2/sites/{site_id}/custom_code.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/custom_code$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.put_site_custom_code',
    effect: 'write',
    description:
      'Attach or replace custom code on a specific site. Binds PUT /v2/sites/{site_id}/custom_code.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/custom_code$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_form_submissions',
    effect: 'read',
    description:
      'List form submissions for a specific site. Binds GET /v2/sites/{site_id}/form_submissions.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/form_submissions$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_users',
    effect: 'read',
    description:
      'List members of a user-access-enabled site. Binds GET /v2/sites/{site_id}/users.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/users$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.invite_user',
    effect: 'send',
    recipient_paths: ['body.email'],
    description:
      'Invite a user to a members-enabled site. Binds POST /v2/sites/{site_id}/users/invite.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/users/invite$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_products',
    effect: 'read',
    description:
      'List ecommerce products on a specific site. Binds GET /v2/sites/{site_id}/products.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/products$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_orders',
    effect: 'read',
    description:
      'List ecommerce orders for a specific site. Binds GET /v2/sites/{site_id}/orders.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/orders$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_webhooks',
    effect: 'read',
    description:
      'List webhooks registered on a specific site. Binds GET /v2/sites/{site_id}/webhooks.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/webhooks$` },
      ];
    },
  }),

  defineIntent({
    name: 'webflow.list_assets',
    effect: 'read',
    description:
      'List assets uploaded to a specific site. Binds GET /v2/sites/{site_id}/assets.',
    params: z.object({ site_id: idList }),
    expand: ({ site_id }) => {
      const list = toList(site_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/sites/${alt(list)}/assets$` },
      ];
    },
  }),
];
