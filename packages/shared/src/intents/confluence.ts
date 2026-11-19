import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Atlassian Confluence Cloud REST API v2 —
// https://developer.atlassian.com/cloud/confluence/rest/v2/. Requests are
// routed through api.atlassian.com/ex/confluence/{cloudid}/wiki/api/v2/…
// so pathname regexes are rooted at the generic /wiki/api/v2/… suffix
// that the proxy sees after path normalization.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);

function eqOrIn(path: string, ids: IdList): Constraint {
  const list = toList(ids);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

const v2 = (suffix: string) => `/wiki/api/v2/${suffix}`;
const v2Re = (suffix: string) => `/wiki/api/v2/${suffix}`;

export const confluenceIntents = [
  defineIntent({
    name: 'confluence.create_page',
    effect: 'write',
    description:
      'Create a Confluence page under a specific space. Binds POST /wiki/api/v2/pages with body.spaceId pinned to the allowlist.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}$` },
      eqOrIn('body.spaceId', space_id),
    ],
  }),

  defineIntent({
    name: 'confluence.update_page',
    effect: 'write',
    description:
      'Update a Confluence page. Binds PUT /wiki/api/v2/pages/{page_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+$` },
    ],
  }),

  defineIntent({
    name: 'confluence.delete_page',
    effect: 'destructive',
    description:
      'Delete a Confluence page. Binds DELETE /wiki/api/v2/pages/{page_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+$` },
    ],
  }),

  defineIntent({
    name: 'confluence.read_page',
    effect: 'read',
    description:
      'Read a Confluence page. Binds GET /wiki/api/v2/pages/{page_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+$` },
    ],
  }),

  defineIntent({
    name: 'confluence.list_pages',
    effect: 'read',
    description:
      'List Confluence pages (optionally filtered by space via query params). Binds GET /wiki/api/v2/pages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: v2('pages') },
    ],
  }),

  defineIntent({
    name: 'confluence.list_spaces',
    effect: 'read',
    description:
      'List Confluence spaces. Binds GET /wiki/api/v2/spaces.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: v2('spaces') },
    ],
  }),

  defineIntent({
    name: 'confluence.read_space',
    effect: 'read',
    description:
      'Read a Confluence space. Binds GET /wiki/api/v2/spaces/{space_id}.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => {
      const list = toList(space_id);
      const esc = list.map((i) => i.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `${v2Re('spaces')}/${alt}$` },
      ];
    },
  }),

  defineIntent({
    name: 'confluence.create_blog_post',
    effect: 'write',
    description:
      'Create a Confluence blog post in a space. Binds POST /wiki/api/v2/blogposts with body.spaceId pinned.',
    params: z.object({ space_id: idList }),
    expand: ({ space_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('blogposts')}$` },
      eqOrIn('body.spaceId', space_id),
    ],
  }),

  defineIntent({
    name: 'confluence.update_blog_post',
    effect: 'write',
    description:
      'Update a Confluence blog post. Binds PUT /wiki/api/v2/blogposts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('blogposts')}/[^/]+$` },
    ],
  }),

  defineIntent({
    name: 'confluence.delete_blog_post',
    effect: 'destructive',
    description:
      'Delete a Confluence blog post. Binds DELETE /wiki/api/v2/blogposts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('blogposts')}/[^/]+$` },
    ],
  }),

  defineIntent({
    name: 'confluence.create_footer_comment',
    effect: 'write',
    description:
      'Create a footer comment on a Confluence page or blog post. Binds POST /wiki/api/v2/footer-comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: v2('footer-comments') },
    ],
  }),

  defineIntent({
    name: 'confluence.create_inline_comment',
    effect: 'write',
    description:
      'Create an inline comment on a Confluence page. Binds POST /wiki/api/v2/inline-comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: v2('inline-comments') },
    ],
  }),

  defineIntent({
    name: 'confluence.list_page_footer_comments',
    effect: 'read',
    description:
      'List footer comments on a Confluence page. Binds GET /wiki/api/v2/pages/{page_id}/footer-comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+/footer-comments$` },
    ],
  }),

  defineIntent({
    name: 'confluence.list_page_attachments',
    effect: 'read',
    description:
      'List attachments on a Confluence page. Binds GET /wiki/api/v2/pages/{page_id}/attachments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+/attachments$` },
    ],
  }),

  defineIntent({
    name: 'confluence.read_attachment',
    effect: 'read',
    description:
      'Read a Confluence attachment by ID. Binds GET /wiki/api/v2/attachments/{attachment_id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('attachments')}/[^/]+$` },
    ],
  }),

  defineIntent({
    name: 'confluence.list_labels',
    effect: 'read',
    description:
      'List Confluence labels across the workspace. Binds GET /wiki/api/v2/labels.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: v2('labels') },
    ],
  }),

  defineIntent({
    name: 'confluence.list_page_versions',
    effect: 'read',
    description:
      'List version history for a Confluence page. Binds GET /wiki/api/v2/pages/{page_id}/versions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+/versions$` },
    ],
  }),

  defineIntent({
    name: 'confluence.search',
    effect: 'read',
    description:
      'Run a Confluence CQL search. Binds GET /wiki/rest/api/search (v1 search endpoint; v2 has no equivalent as of this writing).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wiki/rest/api/search' },
    ],
  }),

  defineIntent({
    name: 'confluence.list_page_content_properties',
    effect: 'read',
    description:
      'List content properties on a Confluence page. Binds GET /wiki/api/v2/pages/{page_id}/properties.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+/properties$` },
    ],
  }),

  defineIntent({
    name: 'confluence.create_page_content_property',
    effect: 'write',
    description:
      'Create a content property on a Confluence page. Binds POST /wiki/api/v2/pages/{page_id}/properties.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: `${v2Re('pages')}/[^/]+/properties$` },
    ],
  }),

  defineIntent({
    name: 'confluence.list_users',
    effect: 'read',
    description:
      'Look up Confluence users in bulk. Binds POST /wiki/api/v2/users-bulk (account IDs carried in the request body).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: v2('users-bulk') },
    ],
  }),
];
