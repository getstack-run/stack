import { z } from 'zod';
import { defineIntent } from './types.js';

// LangSmith — https://docs.smith.langchain.com/reference/api. Base:
// api.smith.langchain.com/…. Intents gate on method + pathname.

export const langsmithIntents = [
  defineIntent({
    name: 'langsmith.runs_list',
    effect: 'read',
    description:
      'List runs (traces) across projects. Binds GET /api/v1/runs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/runs' },
    ],
  }),

  defineIntent({
    name: 'langsmith.runs_query',
    effect: 'write',
    description:
      'Query runs with filters. Binds POST /api/v1/runs/query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/runs/query' },
    ],
  }),

  defineIntent({
    name: 'langsmith.runs_create',
    effect: 'write',
    description:
      'Ingest a new run record. Binds POST /api/v1/runs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/runs' },
    ],
  }),

  defineIntent({
    name: 'langsmith.runs_batch_ingest',
    effect: 'write',
    description:
      'Batch ingest run records. Binds POST /api/v1/runs/batch.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/runs/batch' },
    ],
  }),

  defineIntent({
    name: 'langsmith.runs_update',
    effect: 'write',
    description:
      'Update a specific run. Binds PATCH /api/v1/runs/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PATCH' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/runs/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.runs_get',
    effect: 'read',
    description:
      'Retrieve a specific run. Binds GET /api/v1/runs/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/runs/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.datasets_manage',
    effect: 'destructive',
    description:
      'Create, list, read, update, or delete datasets. Binds /api/v1/datasets and /api/v1/datasets/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/datasets(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.examples_manage',
    effect: 'destructive',
    description:
      'Create, list, read, update, or delete dataset examples. Binds /api/v1/examples and /api/v1/examples/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/examples(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.examples_bulk',
    effect: 'write',
    description:
      'Bulk create or upload examples to a dataset. Binds POST /api/v1/examples/bulk and /api/v1/examples/upload.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/examples/(bulk|upload)$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.sessions_manage',
    effect: 'destructive',
    description:
      'Create, list, read, update, or delete sessions (projects). Binds /api/v1/sessions and /api/v1/sessions/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/sessions(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.feedback_create',
    effect: 'write',
    description:
      'Create a feedback record for a run. Binds POST /api/v1/feedback.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/feedback' },
    ],
  }),

  defineIntent({
    name: 'langsmith.feedback_list',
    effect: 'read',
    description:
      'List feedback records. Binds GET /api/v1/feedback.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/feedback' },
    ],
  }),

  defineIntent({
    name: 'langsmith.feedback_manage',
    effect: 'destructive',
    description:
      'Retrieve, update, or delete a specific feedback record. Binds /api/v1/feedback/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/feedback/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.prompts_manage',
    effect: 'destructive',
    description:
      'Create, list, read, update, or delete prompts (commits and repos). Binds /api/v1/repos, /api/v1/commits, and subresources.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/(repos|commits)(/.*)?$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.evaluators_manage',
    effect: 'destructive',
    description:
      'Create, list, read, update, or delete evaluators. Binds /api/v1/evaluators and /api/v1/evaluators/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/evaluators(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.experiments_manage',
    effect: 'destructive',
    description:
      'Create, list, read, update, or delete experiments. Binds /api/v1/experiments and /api/v1/experiments/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/experiments(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.annotations_manage',
    effect: 'destructive',
    description:
      'Create, list, or update annotation queues and items. Binds /api/v1/annotation-queues and subresources.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/api/v1/annotation-queues(/.*)?$' },
    ],
  }),

  defineIntent({
    name: 'langsmith.exports_create',
    effect: 'write',
    description:
      'Create a data export job. Binds POST /api/v1/exports.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/exports' },
    ],
  }),

  defineIntent({
    name: 'langsmith.exports_list',
    effect: 'read',
    description:
      'List data export jobs. Binds GET /api/v1/exports.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api/v1/exports' },
    ],
  }),
];
