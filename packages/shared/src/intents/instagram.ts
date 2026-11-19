import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Instagram Graph API — https://developers.facebook.com/docs/instagram-api.
// Requests go to graph.facebook.com/v21.0/…. Intents gate on pathname,
// method, and body/query allowlists scoped to the IG Business user ID.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

function eqOrIn(path: string, ids: IdList): Constraint {
  const list = toList(ids);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

export const instagramIntents = [
  defineIntent({
    name: 'instagram.create_media_container',
    effect: 'write',
    description:
      'Create a media container for a specific IG Business user. Binds POST /v21.0/{ig-user-id}/media to the declared user allowlist.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/media$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.publish_media',
    effect: 'send',
    description:
      'Publish a prepared media container to a specific IG Business user feed. Binds POST /v21.0/{ig-user-id}/media_publish.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/media_publish$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.list_media',
    effect: 'read',
    description:
      'List media posted by a specific IG Business user. Binds GET /v21.0/{ig-user-id}/media to the declared user allowlist.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/media$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.list_stories',
    effect: 'read',
    description:
      'List current stories for a specific IG Business user. Binds GET /v21.0/{ig-user-id}/stories.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/stories$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.list_tags',
    effect: 'read',
    description:
      'List media where a specific IG Business user has been tagged. Binds GET /v21.0/{ig-user-id}/tags.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/tags$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.user_insights',
    effect: 'read',
    description:
      'Fetch account-level insights for a specific IG Business user. Binds GET /v21.0/{ig-user-id}/insights.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/insights$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.media_insights',
    effect: 'read',
    description:
      'Fetch per-media insights. Binds GET /v21.0/{media-id}/insights (media IDs not pinned, user-bound via token).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+/insights$' },
    ],
  }),

  defineIntent({
    name: 'instagram.list_comments',
    effect: 'read',
    description:
      'List comments on a specific media item. Binds GET /v21.0/{media-id}/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+/comments$' },
    ],
  }),

  defineIntent({
    name: 'instagram.reply_to_comment',
    effect: 'send',
    recipient_paths: ['url.pathname'],
    description:
      'Reply to a comment by posting to its replies edge. Binds POST /v21.0/{comment-id}/replies.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+/replies$' },
    ],
  }),

  defineIntent({
    name: 'instagram.delete_comment',
    effect: 'destructive',
    description:
      'Delete a specific comment. Binds DELETE /v21.0/{comment-id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'instagram.hide_comment',
    effect: 'write',
    description:
      'Hide or unhide a comment by updating its hidden state. Binds POST /v21.0/{comment-id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'instagram.hashtag_search',
    effect: 'read',
    description:
      'Search for a hashtag ID by name scoped to a specific IG user. Binds GET /v21.0/ig_hashtag_search with query.user_id pinned.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v21.0/ig_hashtag_search' },
      eqOrIn('query.user_id', ig_user_id),
    ],
  }),

  defineIntent({
    name: 'instagram.hashtag_top_media',
    effect: 'read',
    description:
      'Fetch top-performing media for a hashtag. Binds GET /v21.0/{hashtag-id}/top_media.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+/top_media$' },
    ],
  }),

  defineIntent({
    name: 'instagram.hashtag_recent_media',
    effect: 'read',
    description:
      'Fetch recent media for a hashtag. Binds GET /v21.0/{hashtag-id}/recent_media.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+/recent_media$' },
    ],
  }),

  defineIntent({
    name: 'instagram.mentioned_media',
    effect: 'read',
    description:
      'List media where a specific IG user was @-mentioned. Binds GET /v21.0/{ig-user-id}/mentioned_media.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/mentioned_media$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.business_discovery',
    effect: 'read',
    description:
      'Inspect a public business account through a specific IG user. Binds GET /v21.0/{ig-user-id} with query.fields containing business_discovery.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}$` },
        { path: 'query.fields', op: 'matches', value: 'business_discovery' },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.get_user_profile',
    effect: 'read',
    description:
      'Read profile fields for a specific IG Business user. Binds GET /v21.0/{ig-user-id}.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.list_catalogs',
    effect: 'read',
    description:
      'List product catalogs available to a specific IG Business user. Binds GET /v21.0/{ig-user-id}/available_catalogs.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/available_catalogs$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.catalog_product_search',
    effect: 'read',
    description:
      'Search products in catalogs linked to a specific IG user. Binds GET /v21.0/{ig-user-id}/catalog_product_search.',
    params: z.object({ ig_user_id: idList }),
    expand: ({ ig_user_id }) => {
      const list = toList(ig_user_id);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v21\\.0/${alt(list)}/catalog_product_search$` },
      ];
    },
  }),

  defineIntent({
    name: 'instagram.list_product_tags',
    effect: 'read',
    description:
      'List product tags on a specific media item. Binds GET /v21.0/{media-id}/product_tags.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v21\\.0/[^/]+/product_tags$' },
    ],
  }),
];
