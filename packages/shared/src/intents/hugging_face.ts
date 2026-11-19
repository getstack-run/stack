import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Hugging Face — https://huggingface.co/docs. Two API surfaces:
//   Inference:  api-inference.huggingface.co/models/{model-id}
//   Hub:        huggingface.co/api/...
// Intents gate on method + path; inference intents scope on the model
// id in the path.

const modelList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type ModelList = z.infer<typeof modelList>;
const toList = (v: ModelList): string[] => (Array.isArray(v) ? v : [v]);

function inferencePathConstraint(model: ModelList): Constraint {
  const list = toList(model);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return { path: 'url.pathname', op: 'matches', value: `^/models/${alt}$` };
}

export const huggingFaceIntents = [
  defineIntent({
    name: 'hugging_face.inference_text_generation',
    effect: 'write',
    description:
      'Run text-generation inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.inference_feature_extraction',
    effect: 'write',
    description:
      'Run feature-extraction (embeddings) inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.inference_text_classification',
    effect: 'write',
    description:
      'Run text-classification inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.inference_image_classification',
    effect: 'write',
    description:
      'Run image-classification inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.inference_translation',
    effect: 'write',
    description:
      'Run translation inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.inference_summarization',
    effect: 'write',
    description:
      'Run summarization inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.inference_question_answering',
    effect: 'write',
    description:
      'Run extractive question-answering inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.inference_zero_shot',
    effect: 'write',
    description:
      'Run zero-shot classification inference against a specific model allowlist. Binds POST /models/{id} on api-inference.huggingface.co.',
    params: z.object({ model: modelList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'api-inference.huggingface.co' },
      inferencePathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_list_models',
    effect: 'read',
    description:
      'List public models on the Hub. Binds GET /api/models on huggingface.co.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'eq', value: '/api/models' },
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_get_model',
    effect: 'read',
    description:
      'Retrieve metadata for a specific Hub model. Binds GET /api/models/{repo} on huggingface.co.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'matches', value: '^/api/models/[^/]+(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_list_datasets',
    effect: 'read',
    description:
      'List public datasets on the Hub. Binds GET /api/datasets on huggingface.co.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'eq', value: '/api/datasets' },
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_get_dataset',
    effect: 'read',
    description:
      'Retrieve metadata for a specific Hub dataset. Binds GET /api/datasets/{repo} on huggingface.co.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'matches', value: '^/api/datasets/[^/]+(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_list_spaces',
    effect: 'read',
    description:
      'List Spaces on the Hub. Binds GET /api/spaces (list) and /api/spaces/{repo} (get).',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'matches', value: '^/api/spaces(/[^/]+(/[^/]+)?)?$' },
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_whoami',
    effect: 'read',
    description:
      'Identify the authenticated account. Binds GET /api/whoami-v2 on huggingface.co.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'eq', value: '/api/whoami-v2' },
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_create_repo',
    effect: 'write',
    description:
      'Create a new model, dataset, or space repo. Binds POST /api/repos/create on huggingface.co.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'eq', value: '/api/repos/create' },
    ],
  }),

  defineIntent({
    name: 'hugging_face.hub_delete_repo',
    effect: 'destructive',
    description:
      'Delete a repository. Binds DELETE /api/repos/delete on huggingface.co. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.host', op: 'eq', value: 'huggingface.co' },
      { path: 'url.pathname', op: 'eq', value: '/api/repos/delete' },
    ],
  }),
];
