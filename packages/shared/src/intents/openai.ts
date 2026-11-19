import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// OpenAI API — https://platform.openai.com/docs/api-reference. Base:
// api.openai.com/v1/…. Main blast-radius concerns are cost (wrong model)
// and prompt-injection egress; intents bind method + path and, for
// chat/embeddings, the model allowlist.

const modelList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type ModelList = z.infer<typeof modelList>;
const toList = (v: ModelList): string[] => (Array.isArray(v) ? v : [v]);

function modelConstraint(model: ModelList): Constraint {
  const list = toList(model);
  return list.length === 1
    ? { path: 'body.model', op: 'eq', value: list[0]! }
    : { path: 'body.model', op: 'in', value: list };
}

export const openaiIntents = [
  defineIntent({
    name: 'openai.chat_completion',
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
    name: 'openai.embeddings',
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
    name: 'openai.list_models',
    effect: 'read',
    description:
      'Read-only list of available models. Binds GET /v1/models.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/models(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.completions_legacy',
    effect: 'write',
    description:
      'Run legacy text completions on a specific model allowlist. Binds POST /v1/completions with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/completions' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'openai.images_generate',
    effect: 'write',
    description:
      'Generate images from a text prompt on a specific model allowlist. Binds POST /v1/images/generations with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/images/generations' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'openai.images_edit',
    effect: 'write',
    description:
      'Edit an existing image given a prompt and mask. Binds POST /v1/images/edits.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/images/edits' },
    ],
  }),

  defineIntent({
    name: 'openai.audio_speech',
    effect: 'write',
    description:
      'Synthesize speech audio from text on a specific model allowlist. Binds POST /v1/audio/speech with body.model pinned.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/audio/speech' },
      modelConstraint(model),
    ],
  }),

  defineIntent({
    name: 'openai.audio_transcribe',
    effect: 'write',
    description:
      'Transcribe audio to text. Binds POST /v1/audio/transcriptions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/audio/transcriptions' },
    ],
  }),

  defineIntent({
    name: 'openai.audio_translate',
    effect: 'write',
    description:
      'Translate non-English audio to English text. Binds POST /v1/audio/translations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/audio/translations' },
    ],
  }),

  defineIntent({
    name: 'openai.moderations',
    effect: 'write',
    description:
      'Classify content for policy violations. Binds POST /v1/moderations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/moderations' },
    ],
  }),

  defineIntent({
    name: 'openai.files_manage',
    effect: 'destructive',
    description:
      'List, upload, read, or delete files used by fine-tuning, assistants, and batches. Binds /v1/files and /v1/files/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/files(/[^/]+(/content)?)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.fine_tuning_jobs',
    effect: 'destructive',
    description:
      'Create, list, retrieve, or cancel fine-tuning jobs. Binds /v1/fine_tuning/jobs and subresources.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/fine_tuning/jobs(/[^/]+(/cancel|/events|/checkpoints)?)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.assistants_manage',
    effect: 'destructive',
    description:
      'Create, list, update, or delete Assistants. Binds /v1/assistants and /v1/assistants/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/assistants(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.threads_manage',
    effect: 'destructive',
    description:
      'Create, retrieve, modify, or delete Assistant threads. Binds /v1/threads and /v1/threads/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/threads(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.thread_messages',
    effect: 'destructive',
    description:
      'Create, list, retrieve, or modify messages on a thread. Binds /v1/threads/{thread_id}/messages.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/threads/[^/]+/messages(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.thread_runs',
    effect: 'destructive',
    description:
      'Create, list, retrieve, cancel, or submit tool outputs for Assistant runs. Binds /v1/threads/{thread_id}/runs and subresources.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/threads/[^/]+/runs(/[^/]+(/cancel|/submit_tool_outputs|/steps(/[^/]+)?)?)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.batches_manage',
    effect: 'destructive',
    description:
      'Create, retrieve, cancel, or list batch inference jobs. Binds /v1/batches and /v1/batches/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/batches(/[^/]+(/cancel)?)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.vector_stores_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, modify, or delete vector stores used by Assistants file search. Binds /v1/vector_stores and subresources.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/vector_stores(/[^/]+(/files(/[^/]+)?|/file_batches(/[^/]+(/cancel)?)?)?)?$' },
    ],
  }),

  defineIntent({
    name: 'openai.organization_read',
    effect: 'read',
    description:
      'Read organization and project metadata (users, projects, invites). Binds GET /v1/organization/... read endpoints.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/organization/(users|projects|invites|audit_logs)(/[^/]+(/users(/[^/]+)?|/service_accounts(/[^/]+)?|/api_keys(/[^/]+)?)?)?$' },
    ],
  }),
];
