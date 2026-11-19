import { z } from 'zod';
import { defineIntent } from './types.js';

// Google Cloud APIs — {service}.googleapis.com. Each service exposes a
// REST surface under a versioned prefix (e.g. /storage/v1, /pubsub/v1,
// /bigquery/v2). Intents bind host + pathname regex, and additional
// scoping is provided via project-id or bucket allowlists where useful.

const bucketName = z.string().min(3).max(63).regex(/^[a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9]$/, 'invalid bucket name');
const bucketList = z.union([bucketName, z.array(bucketName).min(1)]);
type BucketList = z.infer<typeof bucketList>;
const toBucketList = (v: BucketList): string[] => (Array.isArray(v) ? v : [v]);

const projectId = z.string().min(6).max(30).regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/, 'invalid project_id');
const projectList = z.union([projectId, z.array(projectId).min(1)]);
type ProjectList = z.infer<typeof projectList>;
const toProjectList = (v: ProjectList): string[] => (Array.isArray(v) ? v : [v]);

export const gcpIntents = [
  defineIntent({
    name: 'gcp.storage_get_object',
    effect: 'read',
    description:
      'Download an object from specific Cloud Storage buckets. Binds GET storage.googleapis.com/storage/v1/b/{bucket}/o/{object}.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => {
      const list = toBucketList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'storage.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/b/${alt}/o/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.storage_put_object',
    effect: 'write',
    description:
      'Upload an object to specific Cloud Storage buckets. Binds POST storage.googleapis.com/upload/storage/v1/b/{bucket}/o.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => {
      const list = toBucketList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'storage.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/(upload/)?storage/v1/b/${alt}/o$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.storage_delete_object',
    effect: 'destructive',
    description:
      'Delete an object from specific Cloud Storage buckets. Binds DELETE storage.googleapis.com/storage/v1/b/{bucket}/o/{object}. Destructive.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => {
      const list = toBucketList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.host', op: 'eq', value: 'storage.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/b/${alt}/o/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.storage_list_objects',
    effect: 'read',
    description:
      'List objects in specific Cloud Storage buckets. Binds GET storage.googleapis.com/storage/v1/b/{bucket}/o.',
    params: z.object({ bucket: bucketList }),
    expand: ({ bucket }) => {
      const list = toBucketList(bucket);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'storage.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/storage/v1/b/${alt}/o$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.pubsub_publish',
    effect: 'write',
    description:
      'Publish messages to a Pub/Sub topic. Binds POST pubsub.googleapis.com/v1/projects/{project}/topics/{topic}:publish.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'pubsub.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}/topics/[^/]+:publish$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.pubsub_ack',
    effect: 'write',
    description:
      'Acknowledge messages on a Pub/Sub subscription. Binds POST pubsub.googleapis.com/v1/projects/{project}/subscriptions/{sub}:acknowledge.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'pubsub.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}/subscriptions/[^/]+:acknowledge$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.pubsub_pull',
    effect: 'write',
    description:
      'Pull messages from a Pub/Sub subscription. Binds POST pubsub.googleapis.com/v1/projects/{project}/subscriptions/{sub}:pull.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'pubsub.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}/subscriptions/[^/]+:pull$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.bigquery_query',
    effect: 'write',
    description:
      'Run a synchronous BigQuery SQL query. Binds POST bigquery.googleapis.com/bigquery/v2/projects/{project}/queries.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'bigquery.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/bigquery/v2/projects/${alt}/queries$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.bigquery_insert_all',
    effect: 'write',
    description:
      'Stream rows into a BigQuery table. Binds POST bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{ds}/tables/{tbl}/insertAll.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'bigquery.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/bigquery/v2/projects/${alt}/datasets/[^/]+/tables/[^/]+/insertAll$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.bigquery_get_job',
    effect: 'read',
    description:
      'Read the status of a BigQuery job. Binds GET bigquery.googleapis.com/bigquery/v2/projects/{project}/jobs/{job}.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'bigquery.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/bigquery/v2/projects/${alt}/jobs/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.bigquery_list_datasets',
    effect: 'read',
    description:
      'List BigQuery datasets in a project. Binds GET bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'bigquery.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/bigquery/v2/projects/${alt}/datasets$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.cloud_run_invoke',
    effect: 'write',
    description:
      'Invoke a Cloud Run service via HTTPS. Binds GET/POST run.googleapis.com/v2/projects/{project}/locations/{loc}/services/{svc}:run.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'in', value: ['GET', 'POST'] },
        { path: 'url.host', op: 'eq', value: 'run.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/projects/${alt}/locations/[^/]+/services/[^/]+(:run)?$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.cloud_run_get_service',
    effect: 'read',
    description:
      'Read Cloud Run service configuration. Binds GET run.googleapis.com/v2/projects/{project}/locations/{loc}/services/{svc}.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'run.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/projects/${alt}/locations/[^/]+/services/[^/]+$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.cloud_run_list_services',
    effect: 'read',
    description:
      'List Cloud Run services in a project location. Binds GET run.googleapis.com/v2/projects/{project}/locations/{loc}/services.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'run.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/projects/${alt}/locations/[^/]+/services$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.cloud_functions_invoke',
    effect: 'write',
    description:
      'Invoke a Cloud Function (HTTP trigger, v2). Binds POST cloudfunctions.googleapis.com/v2/projects/{project}/locations/{loc}/functions/{fn}:call.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'cloudfunctions.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/projects/${alt}/locations/[^/]+/functions/[^/]+:call$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.cloud_functions_list',
    effect: 'read',
    description:
      'List Cloud Functions in a project location. Binds GET cloudfunctions.googleapis.com/v2/projects/{project}/locations/{loc}/functions.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'cloudfunctions.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v2/projects/${alt}/locations/[^/]+/functions$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.secret_access',
    effect: 'read',
    description:
      'Access a Secret Manager secret version. Binds GET secretmanager.googleapis.com/v1/projects/{project}/secrets/{name}/versions/{v}:access. Sensitive.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'eq', value: 'secretmanager.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}/secrets/[^/]+/versions/[^/]+:access$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.secret_create',
    effect: 'write',
    description:
      'Create a Secret Manager secret. Binds POST secretmanager.googleapis.com/v1/projects/{project}/secrets. Sensitive.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'secretmanager.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}/secrets$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.iam_get_policy',
    effect: 'write',
    description:
      'Read an IAM policy via the Resource Manager API. Binds POST cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'cloudresourcemanager.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}:getIamPolicy$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.iam_set_policy',
    effect: 'write',
    description:
      'Update an IAM policy on a project. Binds POST cloudresourcemanager.googleapis.com/v1/projects/{project}:setIamPolicy. Sensitive.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'cloudresourcemanager.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}:setIamPolicy$` },
      ];
    },
  }),

  defineIntent({
    name: 'gcp.iam_test_permissions',
    effect: 'write',
    description:
      'Test which IAM permissions are granted to the caller. Binds POST cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => {
      const list = toProjectList(project);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'eq', value: 'cloudresourcemanager.googleapis.com' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/projects/${alt}:testIamPermissions$` },
      ];
    },
  }),
];
