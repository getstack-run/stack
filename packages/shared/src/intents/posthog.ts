import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// PostHog — https://posthog.com/docs/api. Host is app.posthog.com or
// eu.posthog.com (self-hosted instances vary). Intents gate on method +
// pathname and scope to a project_id allowlist where applicable via the
// /api/projects/{project_id}/... pattern.

const projectList = z.union([
  z.string().min(1).max(64),
  z.array(z.string().min(1).max(64)).min(1),
]);
type ProjectList = z.infer<typeof projectList>;
const toList = (v: ProjectList): string[] => (Array.isArray(v) ? v : [v]);

function projectPath(project: ProjectList, suffix: string): Constraint {
  const list = toList(project);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return { path: 'url.pathname', op: 'matches', value: `^/api/projects/${alt}${suffix}$` };
}

export const posthogIntents = [
  defineIntent({
    name: 'posthog.capture_batch',
    effect: 'write',
    description:
      'Send events via the public capture endpoint. Binds POST /batch or /capture on app.posthog.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/(batch|capture)/?$' },
    ],
  }),

  defineIntent({
    name: 'posthog.decide',
    effect: 'read',
    description:
      'Evaluate feature flags for a distinct_id. Binds POST /decide on app.posthog.com.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/decide/?$' },
    ],
  }),

  defineIntent({
    name: 'posthog.feature_flags_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete feature flags in a specific project allowlist. Binds /api/projects/{project_id}/feature_flags.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/feature_flags(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.persons_manage',
    effect: 'destructive',
    description:
      'List, retrieve, update, or delete persons in a specific project allowlist. Binds /api/projects/{project_id}/persons.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/persons(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.cohorts_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete cohorts in a specific project allowlist. Binds /api/projects/{project_id}/cohorts.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/cohorts(/[^/]+(/persons)?)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.insights_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete insights in a specific project allowlist. Binds /api/projects/{project_id}/insights.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/insights(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.query',
    effect: 'read',
    description:
      'Run a HogQL or insight query for a specific project allowlist. Binds POST /api/projects/{project_id}/query.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      projectPath(project, '/query'),
    ],
  }),

  defineIntent({
    name: 'posthog.dashboards_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete dashboards in a specific project allowlist. Binds /api/projects/{project_id}/dashboards.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/dashboards(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.experiments_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete experiments in a specific project allowlist. Binds /api/projects/{project_id}/experiments.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/experiments(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.annotations_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete annotations in a specific project allowlist. Binds /api/projects/{project_id}/annotations.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/annotations(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.session_recordings_list',
    effect: 'read',
    description:
      'List session recordings in a specific project allowlist. Binds GET /api/projects/{project_id}/session_recordings.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPath(project, '/session_recordings(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.surveys_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete surveys in a specific project allowlist. Binds /api/projects/{project_id}/surveys.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/surveys(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.events_list',
    effect: 'read',
    description:
      'List events in a specific project allowlist. Binds GET /api/projects/{project_id}/events.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPath(project, '/events(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.event_definitions_list',
    effect: 'read',
    description:
      'List event definitions in a specific project allowlist. Binds GET /api/projects/{project_id}/event_definitions.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPath(project, '/event_definitions(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.property_definitions_list',
    effect: 'read',
    description:
      'List property definitions in a specific project allowlist. Binds GET /api/projects/{project_id}/property_definitions.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      projectPath(project, '/property_definitions(/[^/]+)?'),
    ],
  }),

  defineIntent({
    name: 'posthog.projects_list',
    effect: 'read',
    description:
      'List projects accessible to the caller. Binds GET /api/projects.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api/projects(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'posthog.actions_manage',
    effect: 'destructive',
    description:
      'Create, list, retrieve, update, or delete actions in a specific project allowlist. Binds /api/projects/{project_id}/actions.',
    params: z.object({ project: projectList }),
    expand: ({ project }) => [
      projectPath(project, '/actions(/[^/]+)?'),
    ],
  }),
];
