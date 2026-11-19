import { z } from 'zod';
import { defineIntent } from './types.js';

// WordPress REST API — https://developer.wordpress.org/rest-api/reference/.
// All calls go to {site}/wp-json/wp/v2/…. The site host varies per
// operator; intents gate on pathname (and method).

export const wordpressIntents = [
  defineIntent({
    name: 'wordpress.list_posts',
    effect: 'read',
    description:
      'List posts on the site. Binds GET /wp-json/wp/v2/posts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/posts' },
    ],
  }),

  defineIntent({
    name: 'wordpress.create_post',
    effect: 'write',
    description:
      'Create a new post. Binds POST /wp-json/wp/v2/posts.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/posts' },
    ],
  }),

  defineIntent({
    name: 'wordpress.update_post',
    effect: 'write',
    description:
      'Update a specific post by ID. Binds POST /wp-json/wp/v2/posts/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/posts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.delete_post',
    effect: 'destructive',
    description:
      'Delete or trash a specific post by ID. Binds DELETE /wp-json/wp/v2/posts/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/posts/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.list_post_revisions',
    effect: 'read',
    description:
      'List revisions of a specific post. Binds GET /wp-json/wp/v2/posts/{id}/revisions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/posts/[^/]+/revisions$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.list_pages',
    effect: 'read',
    description:
      'List pages on the site. Binds GET /wp-json/wp/v2/pages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/pages' },
    ],
  }),

  defineIntent({
    name: 'wordpress.create_page',
    effect: 'write',
    description:
      'Create a new page. Binds POST /wp-json/wp/v2/pages.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/pages' },
    ],
  }),

  defineIntent({
    name: 'wordpress.update_page',
    effect: 'write',
    description:
      'Update a specific page by ID. Binds POST /wp-json/wp/v2/pages/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/pages/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.upload_media',
    effect: 'write',
    description:
      'Upload a media file. Binds POST /wp-json/wp/v2/media.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/media' },
    ],
  }),

  defineIntent({
    name: 'wordpress.update_media',
    effect: 'write',
    description:
      'Update a specific media item by ID. Binds POST /wp-json/wp/v2/media/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/media/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.delete_media',
    effect: 'destructive',
    description:
      'Delete a specific media item by ID. Binds DELETE /wp-json/wp/v2/media/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/media/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.list_comments',
    effect: 'read',
    description:
      'List comments on the site. Binds GET /wp-json/wp/v2/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/comments' },
    ],
  }),

  defineIntent({
    name: 'wordpress.moderate_comment',
    effect: 'write',
    description:
      'Approve, spam, or otherwise update a specific comment. Binds POST /wp-json/wp/v2/comments/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/comments/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.delete_comment',
    effect: 'destructive',
    description:
      'Delete a specific comment. Binds DELETE /wp-json/wp/v2/comments/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/wp-json/wp/v2/comments/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'wordpress.list_users',
    effect: 'read',
    description:
      'List users on the site. Binds GET /wp-json/wp/v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/users' },
    ],
  }),

  defineIntent({
    name: 'wordpress.create_user',
    effect: 'write',
    description:
      'Create a new user. Binds POST /wp-json/wp/v2/users.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/users' },
    ],
  }),

  defineIntent({
    name: 'wordpress.list_categories',
    effect: 'read',
    description:
      'List post categories. Binds GET /wp-json/wp/v2/categories.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/categories' },
    ],
  }),

  defineIntent({
    name: 'wordpress.create_category',
    effect: 'write',
    description:
      'Create a post category. Binds POST /wp-json/wp/v2/categories.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/categories' },
    ],
  }),

  defineIntent({
    name: 'wordpress.list_tags',
    effect: 'read',
    description:
      'List post tags. Binds GET /wp-json/wp/v2/tags.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/tags' },
    ],
  }),

  defineIntent({
    name: 'wordpress.create_tag',
    effect: 'write',
    description:
      'Create a post tag. Binds POST /wp-json/wp/v2/tags.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/tags' },
    ],
  }),

  defineIntent({
    name: 'wordpress.list_plugins',
    effect: 'read',
    description:
      'List installed plugins. Binds GET /wp-json/wp/v2/plugins.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/plugins' },
    ],
  }),

  defineIntent({
    name: 'wordpress.get_settings',
    effect: 'read',
    description:
      'Read site settings. Binds GET /wp-json/wp/v2/settings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/settings' },
    ],
  }),

  defineIntent({
    name: 'wordpress.search',
    effect: 'read',
    description:
      'Search site content. Binds GET /wp-json/wp/v2/search.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/wp-json/wp/v2/search' },
    ],
  }),
];
