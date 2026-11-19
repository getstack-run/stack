import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Mistral AI — https://docs.mistral.ai/api. Base:
// api.mistral.ai/v1/…. Blast-radius is cost (wrong model) and egress;
// chat/embed intents pin body.model to an allowlist.

const modelList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type ModelList = z.infer<typeof modelList>;
const toList = (v: ModelList): string[] => (Array.isArray(v) ? v : [v]);

function modelConstraint(model: ModelList): Constraint {
  const list = toList(model);
  return list.length === 1
    ? { path: 'body.model', op: 'eq', value: list[0]! }
    : { path: 'body.model', op: 'in', value: list };
}

export const mistralIntents = [
  defineIntent({
    name: 'mistral.chat_completion',
    effect: 'write',
    description:
      'Run chat completions on a specific model allowlist. Binds POST /v1/chat/completions with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/chat/completions' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'mistral.fim_completion',
    effect: 'write',
    description:
      'Run fill-in-the-middle completions on a specific code model allowlist. Binds POST /v1/fim/completions with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/fim/completions' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'mistral.embeddings',
    effect: 'write',
    description:
      'Compute embeddings on a specific model allowlist. Binds POST /v1/embeddings with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/embeddings' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'mistral.models_list',
    effect: 'read',
    description:
      'List available Mistral models. Binds GET /v1/models.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/models' },
    ],
  }),

  defineIntent({
    name: 'mistral.models_get',
    effect: 'read',
    description:
      'Retrieve a specific model by id. Binds GET /v1/models/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/models/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'mistral.models_delete',
    effect: 'destructive',
    description:
      'Delete a fine-tuned model. Binds DELETE /v1/models/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/models/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'mistral.files_upload',
    effect: 'write',
    description:
      'Upload a file for fine-tuning or batch. Binds POST /v1/files.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/files' },
    ],
  }),

  defineIntent({
    name: 'mistral.files_list',
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
    name: 'mistral.files_get',
    effect: 'read',
    description:
      'Retrieve a file record or its contents. Binds GET /v1/files/{id} and /v1/files/{id}/content.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/files/[^/]+(/content)?$' },
    ],
  }),

  defineIntent({
    name: 'mistral.files_delete',
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
    name: 'mistral.fine_tuning_jobs',
    effect: 'destructive',
    description:
      'Create, list, retrieve, cancel, or start fine-tuning jobs. Binds /v1/fine_tuning/jobs and subresources.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/fine_tuning/jobs(/[^/]+(/cancel|/start)?)?$' },
    ],
  }),

  defineIntent({
    name: 'mistral.batch_create',
    effect: 'write',
    description:
      'Create an asynchronous batch job. Binds POST /v1/batch/jobs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/batch/jobs' },
    ],
  }),

  defineIntent({
    name: 'mistral.batch_list',
    effect: 'read',
    description:
      'List batch jobs. Binds GET /v1/batch/jobs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/batch/jobs' },
    ],
  }),

  defineIntent({
    name: 'mistral.batch_get',
    effect: 'read',
    description:
      'Retrieve a batch job by id. Binds GET /v1/batch/jobs/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/batch/jobs/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'mistral.batch_cancel',
    effect: 'write',
    description:
      'Cancel a running batch job. Binds POST /v1/batch/jobs/{id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/batch/jobs/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'mistral.moderations',
    effect: 'write',
    description:
      'Classify content for policy violations. Binds POST /v1/moderations and /v1/chat/moderations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/(chat/)?moderations$' },
    ],
  }),

  defineIntent({
    name: 'mistral.agents_completion',
    effect: 'write',
    description:
      'Run agent completions on a specific agent_id. Binds POST /v1/agents/completions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/agents/completions' },
    ],
  }),
];
