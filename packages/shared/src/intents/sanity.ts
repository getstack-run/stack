import { z } from 'zod';
import { defineIntent } from './types.js';

// Sanity — https://www.sanity.io/docs/http-api. Requests go to
// {projectId}.api.sanity.io/v2024-01-01/…. The project lives on the
// host; datasets live on the path and are allowlisted on write ops.

const idList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type IdList = z.infer<typeof idList>;
const toList = (v: IdList): string[] => (Array.isArray(v) ? v : [v]);
const esc = (s: string) => s.replace(/[.+*?^${}()|[\]\\]/g, '\\$&');
const alt = (list: string[]) => (list.length === 1 ? esc(list[0]!) : `(${list.map(esc).join('|')})`);

export const sanityIntents = [
  defineIntent({
    name: 'sanity.query',
    effect: 'read',
    description:
      'Run a GROQ query against a specific dataset. Binds GET /v2024-01-01/data/query/{dataset} to the declared dataset allowlist.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/data/query/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.mutate',
    effect: 'write',
    description:
      'Run create / patch / delete mutations on a specific dataset. Binds POST /v2024-01-01/data/mutate/{dataset} to the declared dataset allowlist.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/data/mutate/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.upload_asset_image',
    effect: 'write',
    description:
      'Upload an image asset into a specific dataset. Binds POST /v2024-01-01/assets/images/{dataset}.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/assets/images/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.upload_asset_file',
    effect: 'write',
    description:
      'Upload a file asset into a specific dataset. Binds POST /v2024-01-01/assets/files/{dataset}.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/assets/files/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.export_dataset',
    effect: 'read',
    description:
      'Export the contents of a specific dataset. Binds GET /v2024-01-01/data/export/{dataset}.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/data/export/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.history',
    effect: 'read',
    description:
      'Fetch revision history for documents in a specific dataset. Binds GET /v2024-01-01/data/history/{dataset}.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/data/history/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.list_datasets',
    effect: 'read',
    description:
      'List datasets for the project. Binds GET /v2024-01-01/projects/{projectId}/datasets.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/datasets$' },
    ],
  }),

  defineIntent({
    name: 'sanity.create_dataset',
    effect: 'write',
    description:
      'Create a new dataset on the project. Binds PUT /v2024-01-01/projects/{projectId}/datasets/{dataset}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/datasets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'sanity.delete_dataset',
    effect: 'destructive',
    description:
      'Delete a dataset from the project. Binds DELETE /v2024-01-01/projects/{projectId}/datasets/{dataset}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/datasets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'sanity.list_project_members',
    effect: 'read',
    description:
      'List members of the project. Binds GET /v2024-01-01/projects/{projectId}/members.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/members$' },
    ],
  }),

  defineIntent({
    name: 'sanity.update_project_member',
    effect: 'write',
    description:
      'Update a project member role. Binds PATCH /v2024-01-01/projects/{projectId}/members/{memberId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/members/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'sanity.remove_project_member',
    effect: 'destructive',
    description:
      'Remove a member from the project. Binds DELETE /v2024-01-01/projects/{projectId}/members/{memberId}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/members/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'sanity.list_cors_origins',
    effect: 'read',
    description:
      'List CORS origins registered for the project. Binds GET /v2024-01-01/projects/{projectId}/cors.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/cors$' },
    ],
  }),

  defineIntent({
    name: 'sanity.create_cors_origin',
    effect: 'write',
    description:
      'Register a new CORS origin for the project. Binds POST /v2024-01-01/projects/{projectId}/cors.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/cors$' },
    ],
  }),

  defineIntent({
    name: 'sanity.delete_cors_origin',
    effect: 'destructive',
    description:
      'Remove a CORS origin. Binds DELETE /v2024-01-01/projects/{projectId}/cors/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/cors/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'sanity.list_tokens',
    effect: 'read',
    description:
      'List API tokens for the project. Binds GET /v2024-01-01/projects/{projectId}/tokens.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/tokens$' },
    ],
  }),

  defineIntent({
    name: 'sanity.create_token',
    effect: 'write',
    description:
      'Issue a new project API token. Binds POST /v2024-01-01/projects/{projectId}/tokens.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2024-01-01/projects/[^/]+/tokens$' },
    ],
  }),

  defineIntent({
    name: 'sanity.list_hooks',
    effect: 'read',
    description:
      'List webhook subscriptions for a dataset. Binds GET /v2024-01-01/hooks/projects/{projectId}/datasets/{dataset}.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/hooks/projects/[^/]+/datasets/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.create_hook',
    effect: 'write',
    description:
      'Create a webhook subscription on a dataset. Binds POST /v2024-01-01/hooks/projects/{projectId}/datasets/{dataset}.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/hooks/projects/[^/]+/datasets/${alt(list)}$` },
      ];
    },
  }),

  defineIntent({
    name: 'sanity.delete_hook',
    effect: 'destructive',
    description:
      'Delete a webhook subscription. Binds DELETE /v2024-01-01/hooks/projects/{projectId}/datasets/{dataset}/{id}.',
    params: z.object({ dataset: idList }),
    expand: ({ dataset }) => {
      const list = toList(dataset);
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.pathname', op: 'matches', value: `^/v2024-01-01/hooks/projects/[^/]+/datasets/${alt(list)}/[^/]+$` },
      ];
    },
  }),
];
