import { z } from 'zod';
import { defineIntent } from './types.js';

// Railway's public API is a GraphQL endpoint at
// https://backboard.railway.app/graphql/v2. Because all mutations and
// queries hit the same URL, path-based scoping is not meaningful; we bind
// on body.operationName (and method) instead. Callers must send a named
// GraphQL operation whose operationName matches the allowlist.
//
// This is a coarser binding than REST providers: it prevents an agent
// holding the token from running arbitrary operations, but does not
// constrain the variables (e.g. which projectId the mutation targets).
// For project-level isolation, pair with a per-project Railway token.

type OpList = string | string[];
const toList = (v: OpList): string[] => (Array.isArray(v) ? v : [v]);

const RAILWAY_PATH = '/graphql/v2';

function opConstraint(ops: OpList) {
  const list = toList(ops);
  if (list.length === 1) {
    return { path: 'body.operationName', op: 'eq' as const, value: list[0]! };
  }
  return { path: 'body.operationName', op: 'in' as const, value: list };
}

export const railwayIntents = [
  defineIntent({
    name: 'railway.create_project',
    effect: 'write',
    description:
      'Create a new Railway project. Binds POST /graphql/v2 with operationName projectCreate.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('projectCreate'),
    ],
  }),

  defineIntent({
    name: 'railway.update_project',
    effect: 'write',
    description:
      'Update project metadata. Binds POST /graphql/v2 with operationName projectUpdate.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('projectUpdate'),
    ],
  }),

  defineIntent({
    name: 'railway.delete_project',
    effect: 'destructive',
    description:
      'Delete a Railway project. Binds POST /graphql/v2 with operationName projectDelete — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('projectDelete'),
    ],
  }),

  defineIntent({
    name: 'railway.read_project',
    effect: 'read',
    description:
      'Read-only project, service, and deployment queries. Binds POST /graphql/v2 with a read operationName allowlist.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint(['project', 'projects', 'service', 'services', 'deployment', 'deployments']),
    ],
  }),

  defineIntent({
    name: 'railway.deploy_service',
    effect: 'write',
    description:
      'Trigger a new service deployment. Binds POST /graphql/v2 with operationName serviceInstanceDeploy.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('serviceInstanceDeploy'),
    ],
  }),

  defineIntent({
    name: 'railway.restart_service',
    effect: 'write',
    description:
      'Restart a running service instance. Binds POST /graphql/v2 with operationName serviceInstanceRestart.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('serviceInstanceRestart'),
    ],
  }),

  defineIntent({
    name: 'railway.create_service',
    effect: 'write',
    description:
      'Create a new service within a project. Binds POST /graphql/v2 with operationName serviceCreate.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('serviceCreate'),
    ],
  }),

  defineIntent({
    name: 'railway.delete_service',
    effect: 'destructive',
    description:
      'Delete a service. Binds POST /graphql/v2 with operationName serviceDelete — destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('serviceDelete'),
    ],
  }),

  defineIntent({
    name: 'railway.manage_variables',
    effect: 'write',
    description:
      'Upsert or delete service variables. Binds POST /graphql/v2 with operationName variableUpsert or variableDelete — sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint(['variableUpsert', 'variableDelete', 'variableCollectionUpsert']),
    ],
  }),

  defineIntent({
    name: 'railway.rollback_deployment',
    effect: 'write',
    description:
      'Roll back to a previous deployment. Binds POST /graphql/v2 with operationName deploymentRollback.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('deploymentRollback'),
    ],
  }),

  defineIntent({
    name: 'railway.redeploy_deployment',
    effect: 'write',
    description:
      'Redeploy an existing deployment artifact. Binds POST /graphql/v2 with operationName deploymentRedeploy.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('deploymentRedeploy'),
    ],
  }),

  defineIntent({
    name: 'railway.cancel_deployment',
    effect: 'write',
    description:
      'Cancel an in-flight deployment. Binds POST /graphql/v2 with operationName deploymentCancel.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint('deploymentCancel'),
    ],
  }),

  defineIntent({
    name: 'railway.manage_environments',
    effect: 'write',
    description:
      'Create, update, and delete environments within a project. Binds POST /graphql/v2 with environment-mutation operationName allowlist.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: RAILWAY_PATH },
      opConstraint(['environmentCreate', 'environmentDelete', 'environmentRename']),
    ],
  }),
];
