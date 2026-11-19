import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Replicate API — https://replicate.com/docs/reference/http. Base:
// api.replicate.com/v1/…. Intents gate on method + path and, where
// applicable, body.version (pinned model version hash) or owner/model
// in path.

const versionList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
type VersionList = z.infer<typeof versionList>;
const toList = (v: VersionList): string[] => (Array.isArray(v) ? v : [v]);

function versionConstraint(version: VersionList): Constraint {
  const list = toList(version);
  return list.length === 1
    ? { path: 'body.version', op: 'eq', value: list[0]! }
    : { path: 'body.version', op: 'in', value: list };
}

function modelPathConstraint(model: VersionList): Constraint {
  const list = toList(model);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return { path: 'url.pathname', op: 'matches', value: `^/v1/models/${alt}(/.*)?$` };
}

export const replicateIntents = [
  defineIntent({
    name: 'replicate.predictions_create',
    effect: 'write',
    description:
      'Run a prediction on a pinned model version allowlist. Binds POST /v1/predictions with body.version pinned.',
    params: z.object({ version: versionList }),
    expand: ({ version }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/predictions' },
      versionConstraint(version),
    ],
  }),

  defineIntent({
    name: 'replicate.predictions_create_by_model',
    effect: 'write',
    description:
      'Run a prediction against a specific owner/model path. Binds POST /v1/models/{owner}/{name}/predictions.',
    params: z.object({ model: versionList }),
    expand: ({ model }) => {
      const list = toList(model);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/models/${alt}/predictions$` },
      ];
    },
  }),

  defineIntent({
    name: 'replicate.predictions_get',
    effect: 'read',
    description:
      'Retrieve a prediction by id. Binds GET /v1/predictions/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/predictions/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'replicate.predictions_cancel',
    effect: 'write',
    description:
      'Cancel a running prediction. Binds POST /v1/predictions/{id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/predictions/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'replicate.predictions_list',
    effect: 'read',
    description:
      'List predictions for the authenticated account. Binds GET /v1/predictions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/predictions' },
    ],
  }),

  defineIntent({
    name: 'replicate.models_list',
    effect: 'read',
    description:
      'List public Replicate models. Binds GET /v1/models.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/models' },
    ],
  }),

  defineIntent({
    name: 'replicate.models_get',
    effect: 'read',
    description:
      'Retrieve details for specific owner/model identifiers. Binds GET /v1/models/{owner}/{name}.',
    params: z.object({ model: versionList }),
    expand: ({ model }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      modelPathConstraint(model),
    ],
  }),

  defineIntent({
    name: 'replicate.models_versions_list',
    effect: 'read',
    description:
      'List versions for specific owner/model identifiers. Binds GET /v1/models/{owner}/{name}/versions.',
    params: z.object({ model: versionList }),
    expand: ({ model }) => {
      const list = toList(model);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/models/${alt}/versions(/[^/]+)?$` },
      ];
    },
  }),

  defineIntent({
    name: 'replicate.trainings_create',
    effect: 'write',
    description:
      'Create a training job on a pinned model version. Binds POST /v1/models/{owner}/{name}/versions/{version}/trainings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/models/[^/]+/[^/]+/versions/[^/]+/trainings$' },
    ],
  }),

  defineIntent({
    name: 'replicate.trainings_get',
    effect: 'read',
    description:
      'Retrieve a training job by id. Binds GET /v1/trainings/{id}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/trainings/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'replicate.trainings_cancel',
    effect: 'write',
    description:
      'Cancel a running training job. Binds POST /v1/trainings/{id}/cancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/trainings/[^/]+/cancel$' },
    ],
  }),

  defineIntent({
    name: 'replicate.trainings_list',
    effect: 'read',
    description:
      'List training jobs for the authenticated account. Binds GET /v1/trainings.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/trainings' },
    ],
  }),

  defineIntent({
    name: 'replicate.deployments_list',
    effect: 'read',
    description:
      'List deployments for the account. Binds GET /v1/deployments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/deployments' },
    ],
  }),

  defineIntent({
    name: 'replicate.deployments_create',
    effect: 'write',
    description:
      'Create a new deployment. Binds POST /v1/deployments.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/deployments' },
    ],
  }),

  defineIntent({
    name: 'replicate.deployments_manage',
    effect: 'destructive',
    description:
      'Get, update, or delete a specific deployment. Binds /v1/deployments/{owner}/{name}.',
    params: z.object({}),
    expand: () => [
      { path: 'url.pathname', op: 'matches', value: '^/v1/deployments/[^/]+/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'replicate.deployments_predict',
    effect: 'write',
    description:
      'Run a prediction against a specific deployment. Binds POST /v1/deployments/{owner}/{name}/predictions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/deployments/[^/]+/[^/]+/predictions$' },
    ],
  }),

  defineIntent({
    name: 'replicate.hardware_list',
    effect: 'read',
    description:
      'List available hardware SKUs. Binds GET /v1/hardware.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/hardware' },
    ],
  }),

  defineIntent({
    name: 'replicate.account_get',
    effect: 'read',
    description:
      'Retrieve the authenticated account profile. Binds GET /v1/account.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/account' },
    ],
  }),

  defineIntent({
    name: 'replicate.collections_list',
    effect: 'read',
    description:
      'List or retrieve featured model collections. Binds GET /v1/collections and /v1/collections/{slug}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/collections(/[^/]+)?$' },
    ],
  }),
];
