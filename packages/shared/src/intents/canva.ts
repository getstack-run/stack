import { z } from 'zod';
import { defineIntent } from './types.js';

// Canva Connect API — https://www.canva.dev/docs/connect/. Host is
// api.canva.com and all paths start with /rest/v1/. Intents gate
// on method + pathname; the Connect API does not expose stable
// team/user allowlist paths for most resources.

export const canvaIntents = [
  defineIntent({
    name: 'canva.create_design',
    effect: 'write',
    description:
      'Create a new Canva design. Binds POST /rest/v1/designs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/designs' },
    ],
  }),

  defineIntent({
    name: 'canva.list_designs',
    effect: 'read',
    description:
      'List the authenticated user designs. Binds GET /rest/v1/designs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/designs' },
    ],
  }),

  defineIntent({
    name: 'canva.get_design',
    effect: 'read',
    description:
      'Read a specific Canva design by ID. Binds GET /rest/v1/designs/{designId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/designs/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.export_design',
    effect: 'read',
    description:
      'Request an export for a specific design. Binds POST /rest/v1/exports.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/exports' },
    ],
  }),

  defineIntent({
    name: 'canva.get_export',
    effect: 'read',
    description:
      'Poll an export job by ID. Binds GET /rest/v1/exports/{exportId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/exports/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.import_design',
    effect: 'write',
    description:
      'Import an external file as a new Canva design. Binds POST /rest/v1/imports.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/imports' },
    ],
  }),

  defineIntent({
    name: 'canva.create_folder',
    effect: 'write',
    description:
      'Create a new folder. Binds POST /rest/v1/folders.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/folders' },
    ],
  }),

  defineIntent({
    name: 'canva.get_folder',
    effect: 'read',
    description:
      'Read a specific folder. Binds GET /rest/v1/folders/{folderId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/folders/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.update_folder',
    effect: 'write',
    description:
      'Rename or modify a specific folder. Binds PATCH /rest/v1/folders/{folderId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/folders/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.delete_folder',
    effect: 'destructive',
    description:
      'Delete a specific folder. Binds DELETE /rest/v1/folders/{folderId}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/folders/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.list_folder_items',
    effect: 'read',
    description:
      'List items contained in a specific folder. Binds GET /rest/v1/folders/{folderId}/items.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/folders/[^/]+/items$' },
    ],
  }),

  defineIntent({
    name: 'canva.upload_asset',
    effect: 'write',
    description:
      'Upload a new asset. Binds POST /rest/v1/asset-uploads.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/asset-uploads' },
    ],
  }),

  defineIntent({
    name: 'canva.get_asset',
    effect: 'read',
    description:
      'Read a specific asset. Binds GET /rest/v1/assets/{assetId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/assets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.update_asset',
    effect: 'write',
    description:
      'Update metadata on a specific asset. Binds PATCH /rest/v1/assets/{assetId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/assets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.delete_asset',
    effect: 'destructive',
    description:
      'Delete a specific asset. Binds DELETE /rest/v1/assets/{assetId}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/assets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.list_brand_templates',
    effect: 'read',
    description:
      'List available brand templates. Binds GET /rest/v1/brand-templates.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/brand-templates' },
    ],
  }),

  defineIntent({
    name: 'canva.get_brand_template',
    effect: 'read',
    description:
      'Read a specific brand template. Binds GET /rest/v1/brand-templates/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/brand-templates/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'canva.create_autofill_job',
    effect: 'write',
    description:
      'Create an autofill job for a brand template. Binds POST /rest/v1/autofills.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/autofills' },
    ],
  }),

  defineIntent({
    name: 'canva.get_me',
    effect: 'read',
    description:
      'Read the authenticated Canva user profile. Binds GET /rest/v1/users/me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/rest/v1/users/me' },
    ],
  }),

  defineIntent({
    name: 'canva.list_comments',
    effect: 'read',
    description:
      'List comments on a specific design. Binds GET /rest/v1/designs/{designId}/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/designs/[^/]+/comments$' },
    ],
  }),

  defineIntent({
    name: 'canva.create_comment',
    effect: 'write',
    description:
      'Create a comment thread on a specific design. Binds POST /rest/v1/designs/{designId}/comments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/rest/v1/designs/[^/]+/comments$' },
    ],
  }),
];
