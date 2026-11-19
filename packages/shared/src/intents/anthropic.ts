import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Anthropic API — https://docs.anthropic.com/en/api. Base:
// api.anthropic.com/v1/…. Primary blast-radius is cost (wrong model) and
// prompt-injection egress; intents pin method + path and, where
// applicable, body.model to an allowlist.

const modelList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type ModelList = z.infer<typeof modelList>;
const toList = (v: ModelList): string[] => (Array.isArray(v) ? v : [v]);

function modelConstraint(model: ModelList): Constraint {
  const list = toList(model);
  return list.length === 1
    ? { path: 'body.model', op: 'eq', value: list[0]! }
    : { path: 'body.model', op: 'in', value: list };
}

export const anthropicIntents = [
  defineIntent({
    name: 'anthropic.messages_create',
    effect: 'write',
    description:
      'Create a Claude message on a specific model allowlist. Binds POST /v1/messages with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/messages' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'anthropic.messages_with_tools',
    effect: 'write',
    description:
      'Create a Claude message that uses tool use on a specific model allowlist. Binds POST /v1/messages with body.model pinned and body.tools required.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/messages' },
      modelConstraint(model),
      { path: 'body.tools', op: 'matches', value: '.+' },
    ],
  }),

  defineIntent({
    name: 'anthropic.messages_count_tokens',
    effect: 'write',
    description:
      'Count tokens for a message without generating. Binds POST /v1/messages/count_tokens.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/messages/count_tokens' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'anthropic.complete_legacy',
    effect: 'write',
    description:
      'Legacy text completion endpoint. Binds POST /v1/complete with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/complete' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'anthropic.batches_create',
    effect: 'write',
    description:
      'Create a Message Batch for asynchronous processing. Binds POST /v1/messages/batches.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/messages/batches' },
    ],
  }),

  defineIntent({
    name: 'anthropic.batches_list',
    effect: 'read',
    description:
      'List Message Batches. Binds GET /v1/messages/batches.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/messages/batches' },
    ],
  }),

  defineIntent({
    name: 'anthropic.batches_get',
    effect: 'read',
    description:
      'Retrieve a specific Message Batch by id. Binds GET /v1/messages/batches/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/messages/batches/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'anthropic.batches_cancel',
    effect: 'write',
    description:
      'Cancel an in-progress Message Batch. Binds POST /v1/messages/batches/{id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/messages/batches/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'anthropic.batches_results',
    effect: 'read',
    description:
      'Retrieve results for a completed Message Batch. Binds GET /v1/messages/batches/{id}/results.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/messages/batches/[^/]+/results$' },
    ],
  }),

  defineIntent({
    name: 'anthropic.batches_delete',
    effect: 'destructive',
    description:
      'Delete a Message Batch record. Binds DELETE /v1/messages/batches/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/messages/batches/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'anthropic.files_create',
    effect: 'write',
    description:
      'Upload a file for use with the Files API (beta). Binds POST /v1/files.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/files' },
    ],
  }),

  defineIntent({
    name: 'anthropic.files_list',
    effect: 'read',
    description:
      'List uploaded files. Binds GET /v1/files.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/files' },
    ],
  }),

  defineIntent({
    name: 'anthropic.files_get',
    effect: 'read',
    description:
      'Retrieve a file record or contents. Binds GET /v1/files/{id} and /v1/files/{id}/content.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/files/[^/]+(/content)?$' },
    ],
  }),

  defineIntent({
    name: 'anthropic.files_delete',
    effect: 'destructive',
    description:
      'Delete an uploaded file. Binds DELETE /v1/files/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/files/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'anthropic.models_list',
    effect: 'read',
    description:
      'List available Anthropic models. Binds GET /v1/models.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/models(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'anthropic.organizations_me',
    effect: 'read',
    description:
      'Read the authenticated organization profile. Binds GET /v1/organizations/me.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/organizations/me' },
    ],
  }),
];
